require_relative 'elasticsearch_constants'

class Fluent::ElasticsearchErrorHandler
  include Fluent::ElasticsearchConstants

  attr_accessor :records, :bulk_message_count
  class ElasticsearchVersionMismatch < StandardError; end
  class ElasticsearchError < StandardError; end

  def initialize(plugin, records = 0, bulk_message_count = 0)
    @plugin = plugin
    @records = records
    @bulk_message_count = bulk_message_count
  end

  def handle_error(response, tag, records)
    if records.length != response['items'].length
      raise ElasticsearchError, "The number of records submitted do not match the number returned. Unable to process bulk response"
    end
    retry_records = []
    stats = Hash.new(0)
    response['items'].each_with_index do |item, index|
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
      case
      when [200, 201].include?(status)
        stats[:successes] += 1
      when CREATE_OP == write_operation && 409 == status
        stats[:duplicates] += 1
      when 400 == status
        stats[:bad_argument] += 1
        record = records[index]
        @plugin.router.emit_error_event(tag, record[:time], record[:record], '400 - Rejected by Elasticsearch')
      else
        retry_records << records[index]
        if item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('type')
          type = item[write_operation]['error']['type']
        else
          # When we don't have a type field, something changed in the API
          # expected return values (ES 2.x)
          stats[:errors_bad_resp] += 1
          record = records[index]
          @plugin.router.emit_error_event(tag, record[:time], record[:record], status + '- No error type provided in the response')
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
    raise Fluent::ElasticsearchOutput::RetryRecordsError.new(retry_records) if retry_records.length > 0
  end
end
