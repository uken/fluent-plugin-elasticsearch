require_relative 'elasticsearch_constants'

class Fluent::Plugin::ElasticsearchErrorHandler
  include Fluent::Plugin::ElasticsearchConstants

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
    errors = Hash.new(0)
    errors_bad_resp = 0
    errors_unrecognized = 0
    successes = 0
    duplicates = 0
    bad_arguments = 0
    response['items'].each do |item|
      if item.has_key?(@plugin.write_operation)
        write_operation = @plugin.write_operation
      elsif INDEX_OP == @plugin.write_operation && item.has_key?(CREATE_OP)
        write_operation = CREATE_OP
      else
        # When we don't have an expected ops field, something changed in the API
        # expected return values (ES 2.x)
        errors_bad_resp += 1
        next
      end
      if item[write_operation].has_key?('status')
        status = item[write_operation]['status']
      else
        # When we don't have a status field, something changed in the API
        # expected return values (ES 2.x)
        errors_bad_resp += 1
        next
      end
      case
      when CREATE_OP == write_operation && 409 == status
        duplicates += 1
      when 400 == status
        bad_arguments += 1
        @plugin.log.debug "Elasticsearch rejected document: #{item}"
      when [429, 500].include?(status)
        if item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('type')
          type = item[write_operation]['error']['type']
        else
          # When we don't have a type field, something changed in the API
          # expected return values (ES 2.x)
          errors_bad_resp += 1
          next
        end
        errors[type] += 1
      when [200, 201].include?(status)
        successes += 1
      else
        errors_unrecognized += 1
      end
    end
    if errors_bad_resp > 0
      msg = "Unable to parse error response from Elasticsearch, likely an API version mismatch  #{response}"
      @plugin.log.error msg
      raise ElasticsearchVersionMismatch, msg
    end
    if bad_arguments > 0
      @plugin.log.warn "Elasticsearch rejected #{bad_arguments} documents due to invalid field arguments"
    end
    if duplicates > 0
      @plugin.log.info "Encountered #{duplicates} duplicate(s) of #{successes} indexing chunk, ignoring"
    end
    msg = "Indexed (op = #{@plugin.write_operation}) #{successes} successfully, #{duplicates} duplicate(s), #{bad_arguments} bad argument(s), #{errors_unrecognized} unrecognized error(s)"
    errors.each_key do |key|
      msg << ", #{errors[key]} #{key} error(s)"
    end
    @plugin.log.debug msg
    if errors_unrecognized > 0
      raise UnrecognizedElasticsearchError, "Unrecognized elasticsearch errors returned, retrying  #{response}"
    end
    errors.each_key do |key|
      case key
      when 'out_of_memory_error'
        raise ElasticsearchOutOfMemory, "Elasticsearch has exhausted its heap, retrying"
      when 'es_rejected_execution_exception'
        raise BulkIndexQueueFull, "Bulk index queue is full, retrying"
      else
        raise ElasticsearchError, "Elasticsearch errors returned, retrying  #{response}"
      end
    end
  end
end
