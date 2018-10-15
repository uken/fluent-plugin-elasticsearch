require 'fluent/event'
require 'fluent/error'
require_relative 'elasticsearch_constants'

class Fluent::Plugin::ElasticsearchErrorHandler
  include Fluent::Plugin::ElasticsearchConstants

  attr_accessor :bulk_message_count
  class ElasticsearchVersionMismatch < Fluent::UnrecoverableError; end
  class ElasticsearchSubmitMismatch < Fluent::UnrecoverableError; end
  class ElasticsearchRequestAbortError < Fluent::UnrecoverableError; end
  class ElasticsearchError < StandardError; end

  def initialize(plugin)
    @plugin = plugin
  end

  def unrecoverable_error_types
    ["out_of_memory_error", "es_rejected_execution_exception"]
  end

  def unrecoverable_error?(type)
    unrecoverable_error_types.include?(type)
  end

  def handle_error(response, tag, chunk, bulk_message_count, extracted_values)
    items = response['items']
    if items.nil? || !items.is_a?(Array)
      raise ElasticsearchVersionMismatch, "The response format was unrecognized: #{response}"
    end
    if bulk_message_count != items.length
      raise ElasticsearchSubmitMismatch, "The number of records submitted #{bulk_message_count} do not match the number returned #{items.length}. Unable to process bulk response."
    end
    retry_stream = Fluent::MultiEventStream.new
    stats = Hash.new(0)
    meta = {}
    header = {}
    chunk.msgpack_each do |time, rawrecord|
      bulk_message = ''
      next unless rawrecord.is_a? Hash
      begin
        # we need a deep copy for process_message to alter
        processrecord = Marshal.load(Marshal.dump(rawrecord))
        meta, header, record = @plugin.process_message(tag, meta, header, time, processrecord, extracted_values)
        next unless @plugin.append_record_to_messages(@plugin.write_operation, meta, header, record, bulk_message)
      rescue => e
        stats[:bad_chunk_record] += 1
        next
      end
      item = items.shift
      if item.has_key?(@plugin.write_operation)
        write_operation = @plugin.write_operation
      elsif INDEX_OP == @plugin.write_operation && item.has_key?(CREATE_OP)
        write_operation = CREATE_OP
      else
        # When we don't have an expected ops field, something changed in the API
        # expected return values (ES 2.x)
        stats[:errors_bad_resp] += 1
        next
      end
      if item[write_operation].has_key?('status')
        status = item[write_operation]['status']
      else
        # When we don't have a status field, something changed in the API
        # expected return values (ES 2.x)
        stats[:errors_bad_resp] += 1
        next
      end
      error = item[write_operation].fetch('error', {})
      error_type = error['type']
      error_reason = error['reason']
      case
      when [200, 201].include?(status)
        stats[:successes] += 1
      when CREATE_OP == write_operation && 409 == status
        stats[:duplicates] += 1
      when 400 == status
        stats[:bad_argument] += 1
        reason = ""
        @plugin.log.on_debug do
          if error_type
            reason = " [error type]: #{error_type}"
          end
          if error_reason
            reason += " [reason]: \'#{error_reason}\'"
          end
        end
        @plugin.router.emit_error_event(tag, time, rawrecord, ElasticsearchError.new("400 - Rejected by Elasticsearch#{reason}"))
      else
        if error_type
          stats[error_type] += 1
          retry_stream.add(time, rawrecord)
          if unrecoverable_error?(error_type)
            raise ElasticsearchRequestAbortError, "Rejected Elasticsearch due to #{error_type}"
          end
        else
          # When we don't have a type field, something changed in the API
          # expected return values (ES 2.x)
          stats[:errors_bad_resp] += 1
          @plugin.router.emit_error_event(tag, time, rawrecord, ElasticsearchError.new("#{status} - No error type provided in the response"))
          next
        end
        stats[error_type] += 1
      end
    end
    @plugin.log.on_debug do
      msg = ["Indexed (op = #{@plugin.write_operation})"]
      stats.each_pair { |key, value| msg << "#{value} #{key}" }
      @plugin.log.debug msg.join(', ')
    end
    raise Fluent::Plugin::ElasticsearchOutput::RetryStreamError.new(retry_stream) unless retry_stream.empty?
  end
end
