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
    @plugin.unrecoverable_error_types
  end

  def unrecoverable_error?(type)
    unrecoverable_error_types.include?(type)
  end

  def unrecoverable_record_error?(type)
    ['json_parse_exception'].include?(type)
  end

  def log_es_400_reason(&block)
    if @plugin.log_es_400_reason
      block.call
    else
      @plugin.log.on_debug(&block)
    end
  end

  def handle_error(response, tag, chunk, bulk_message_count, extracted_values, unpacked_msg_arr)
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
    affinity_target_indices = @plugin.get_affinity_target_indices(chunk)

    unpacked_msg_arr.each do |msg|
      time = msg[:time]
      rawrecord = msg[:record]

      bulk_message = ''
      next unless rawrecord.is_a? Hash
      begin
        # we need a deep copy for process_message to alter
        processrecord = Marshal.load(Marshal.dump(rawrecord))
        meta, header, record = @plugin.process_message(tag, meta, header, time, processrecord, affinity_target_indices, extracted_values)
        next unless @plugin.append_record_to_messages(@plugin.write_operation, meta, header, record, bulk_message)
      rescue => e
        @plugin.log.debug("Exception in error handler during deep copy: #{e}")
        stats[:bad_chunk_record] += 1
        next
      end
      item = items.shift
      if item.is_a?(Hash) && item.has_key?(@plugin.write_operation)
        write_operation = @plugin.write_operation
      elsif INDEX_OP == @plugin.write_operation && item.is_a?(Hash) && item.has_key?(CREATE_OP)
        write_operation = CREATE_OP
      elsif UPSERT_OP == @plugin.write_operation && item.is_a?(Hash) && item.has_key?(UPDATE_OP)
        write_operation = UPDATE_OP
      elsif item.nil?
        stats[:errors_nil_resp] += 1
        next
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
      case
      when [200, 201].include?(status)
        stats[:successes] += 1
      when CREATE_OP == write_operation && 409 == status
        stats[:duplicates] += 1
      when 400 == status
        stats[:bad_argument] += 1
        reason = ""
        log_es_400_reason do
          if item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('type')
            reason = " [error type]: #{item[write_operation]['error']['type']}"
          end
          if item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('reason')
            reason += " [reason]: \'#{item[write_operation]['error']['reason']}\'"
          end
        end
        @plugin.router.emit_error_event(tag, time, rawrecord, ElasticsearchError.new("400 - Rejected by Elasticsearch#{reason}"))
      else
        if item[write_operation]['error'].is_a?(String)
          reason = item[write_operation]['error']
          stats[:errors_block_resp] += 1
          @plugin.router.emit_error_event(tag, time, rawrecord, ElasticsearchError.new("#{status} - #{reason}"))
          next
        elsif item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('type')
          type = item[write_operation]['error']['type']
          stats[type] += 1
          if unrecoverable_error?(type)
            raise ElasticsearchRequestAbortError, "Rejected Elasticsearch due to #{type}"
          end
          if unrecoverable_record_error?(type)
            @plugin.router.emit_error_event(tag, time, rawrecord, ElasticsearchError.new("#{status} - #{type}: #{reason}"))
            next
          else
            retry_stream.add(time, rawrecord) unless unrecoverable_record_error?(type)
          end
        else
          # When we don't have a type field, something changed in the API
          # expected return values (ES 2.x)
          stats[:errors_bad_resp] += 1
          @plugin.router.emit_error_event(tag, time, rawrecord, ElasticsearchError.new("#{status} - No error type provided in the response"))
          next
        end
        stats[type] += 1
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
