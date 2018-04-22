require_relative 'elasticsearch_constants'

class Fluent::ElasticsearchErrorHandler
  include Fluent::ElasticsearchConstants

  attr_accessor :records, :bulk_message_count
  class BulkIndexQueueFull < StandardError; end
  class ElasticsearchOutOfMemory < StandardError; end
  class ElasticsearchVersionMismatch < StandardError; end
  class UnrecognizedElasticsearchError < StandardError; end
  class ElasticsearchError < StandardError; end
  def initialize(plugin, records = 0, bulk_message_count = 0)
    @plugin = plugin
    @records = records
    @bulk_message_count = bulk_message_count
  end

  def handle_error(response)
    stats = Hash.new(0)
    response['items'].each do |item|
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
      else
        if item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('type')
          type = item[write_operation]['error']['type']
        else
          # When we don't have a type field, something changed in the API
          # expected return values (ES 2.x)
          stats[:errors_bad_resp] += 1
          next
        end
        stats[type] += 1
      end
    end
    if stats[:errors_bad_resp] > 0
      @plugin.log.on_debug { @plugin.log.debug("Unable to parse response from elasticsearch, likely an API version mismatch:  #{response}") }
      raise ElasticsearchVersionMismatch, "Unable to parse error response from Elasticsearch, likely an API version mismatch. Add '@log_level debug' to your config to see the full response"
    end
    @plugin.log.on_debug do
      msg = ["Indexed (op = #{@plugin.write_operation})"]
      stats.each_pair { |key, value| msg << "#{value} #{key}" }
      @plugin.log.debug msg.join(', ')
    end
    if stats[:successes] + stats[:duplicates] == bulk_message_count
      @plugin.log.debug("retry succeeded - all #{bulk_message_count} records were successfully sent")
      return
    end
    stats.each_key do |key|
      case key
      when 'out_of_memory_error'
        raise ElasticsearchOutOfMemory, 'Elasticsearch has exhausted its heap, retrying'
      when 'es_rejected_execution_exception'
        raise BulkIndexQueueFull, 'Bulk index queue is full, retrying'
      else
        @plugin.log.on_debug { @plugin.log.debug("Elasticsearch errors returned, retrying:  #{response}") }
        raise ElasticsearchError, "Elasticsearch returned errors, retrying. Add '@log_level debug' to your config to see the full response"
      end
    end
  end
end
