require 'helper'
require 'fluent/plugin/out_elasticsearch'
require 'fluent/plugin/elasticsearch_error_handler'
require 'json'

class TestElasticsearchErrorHandler < Test::Unit::TestCase

  class TestPlugin
    attr_reader :log
    attr_reader :write_operation, :error_events
    attr_accessor :unrecoverable_error_types
    attr_accessor :log_es_400_reason
    def initialize(log, log_es_400_reason = false)
      @log = log
      @write_operation = 'index'
      @error_events = []
      @unrecoverable_error_types = ["out_of_memory_error", "es_rejected_execution_exception"]
      @log_es_400_reason = log_es_400_reason
    end

    def router
      self
    end

    def emit_error_event(tag, time, record, e)
       @error_events << {:tag => tag, :time=>time, :record=>record, :error=>e}
    end

    def process_message(tag, meta, header, time, record, extracted_values)
      return [meta, header, record]
    end

    def append_record_to_messages(op, meta, header, record, msgs)
      if record.has_key?('raise') && record['raise']
        raise Exception('process_message')
      end
      return true
    end
  end

  class MockChunk
    def initialize(records)
      @records = records
      @index = 0
    end
    def msgpack_each
      @records.each { |item| yield(item[:time],item[:record]) }
    end
  end

  def setup
    Fluent::Test.setup
    @log_device = Fluent::Test::DummyLogDevice.new
    dl_opts = {:log_level => ServerEngine::DaemonLogger::INFO}
    logger = ServerEngine::DaemonLogger.new(@log_device, dl_opts)
    @log = Fluent::Log.new(logger)
    @plugin = TestPlugin.new(@log)
    @handler = Fluent::Plugin::ElasticsearchErrorHandler.new(@plugin)
  end

  def parse_response(value)
    JSON.parse(value)
  end

  class TEST400ResponseReason < self
    def setup
      Fluent::Test.setup
      @log_device = Fluent::Test::DummyLogDevice.new
      dl_opts = {:log_level => ServerEngine::DaemonLogger::DEBUG}
      logger = ServerEngine::DaemonLogger.new(@log_device, dl_opts)
      @log = Fluent::Log.new(logger)
      @plugin = TestPlugin.new(@log)
      @handler = Fluent::Plugin::ElasticsearchErrorHandler.new(@plugin)
    end

    def test_400_responses_reason_log
      records = [{time: 123, record: {"foo" => "bar", '_id' => 'abc'}}]
      response = parse_response(%({
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "status" : 400,
            "error" : {
              "type"  : "mapper_parsing_exception",
              "reason" : "failed to parse"
            }
          }
        }
      ]
     }))
      chunk = MockChunk.new(records)
      dummy_extracted_values = []
      @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values)
      assert_equal(1, @plugin.error_events.size)
      expected_log = "failed to parse"
      exception_message = @plugin.error_events.first[:error].message
      assert_true(exception_message.include?(expected_log),
                  "Exception do not contain '#{exception_message}' '#{expected_log}'")
      assert_true(@plugin.error_events[0][:error].respond_to?(:backtrace))
    end
  end

  class TEST400ResponseReasonNoDebug < self
    def setup
      Fluent::Test.setup
      @log_device = Fluent::Test::DummyLogDevice.new
      dl_opts = {:log_level => ServerEngine::DaemonLogger::INFO}
      logger = ServerEngine::DaemonLogger.new(@log_device, dl_opts)
      @log = Fluent::Log.new(logger)
      @plugin = TestPlugin.new(@log)
      @handler = Fluent::Plugin::ElasticsearchErrorHandler.new(@plugin)
      @plugin.log_es_400_reason = true
    end

    def test_400_responses_reason_log
      records = [{time: 123, record: {"foo" => "bar", '_id' => 'abc'}}]
      response = parse_response(%({
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "status" : 400,
            "error" : {
              "type"  : "mapper_parsing_exception",
              "reason" : "failed to parse"
            }
          }
        }
      ]
     }))
      chunk = MockChunk.new(records)
      dummy_extracted_values = []
      @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values)
      assert_equal(1, @plugin.error_events.size)
      expected_log = "failed to parse"
      exception_message = @plugin.error_events.first[:error].message
      assert_true(exception_message.include?(expected_log),
                  "Exception do not contain '#{exception_message}' '#{expected_log}'")
      assert_true(@plugin.error_events[0][:error].respond_to?(:backtrace))
    end
  end

  def test_dlq_400_responses
    records = [{time: 123, record: {"foo" => "bar", '_id' => 'abc'}}]
    response = parse_response(%({
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "status" : 400,
            "_type"  : "bar",
              "reason":"unrecognized error"
            }
        }
      ]
     }))
    chunk = MockChunk.new(records)
    dummy_extracted_values = []
    @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values)
    assert_equal(1, @plugin.error_events.size)
    assert_true(@plugin.error_events[0][:error].respond_to?(:backtrace))
  end

  def test_out_of_memory_responses
    records = [{time: 123, record: {"foo" => "bar", '_id' => 'abc'}}]
    response = parse_response(%({
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "status" : 500,
            "_type"  : "bar",
            "error" : {
              "type" : "out_of_memory_error",
              "reason":"Java heap space"
            }
          }
        }
      ]
     }))

      chunk = MockChunk.new(records)
      dummy_extracted_values = []
    assert_raise(Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError) do
      @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values)
    end
  end

  def test_es_rejected_execution_exception_responses
    records = [{time: 123, record: {"foo" => "bar", '_id' => 'abc'}}]
    response = parse_response(%({
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "status" : 429,
            "_type"  : "bar",
            "error" : {
              "type" : "es_rejected_execution_exception",
              "reason":"rejected execution of org.elasticsearch.transport.TransportService"
            }
          }
        }
      ]
     }))

      chunk = MockChunk.new(records)
      dummy_extracted_values = []
    assert_raise(Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError) do
      @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values)
    end
  end

  def test_es_rejected_execution_exception_responses_as_not_error
    plugin = TestPlugin.new(@log)
    plugin.unrecoverable_error_types = ["out_of_memory_error"]
    handler = Fluent::Plugin::ElasticsearchErrorHandler.new(plugin)
    records = [{time: 123, record: {"foo" => "bar", '_id' => 'abc'}}]
    response = parse_response(%({
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "status" : 429,
            "_type"  : "bar",
            "error" : {
              "type" : "es_rejected_execution_exception",
              "reason":"rejected execution of org.elasticsearch.transport.TransportService"
            }
          }
        }
      ]
     }))

    begin
      failed = false
      chunk = MockChunk.new(records)
      dummy_extracted_values = []
      handler.handle_error(response, 'atag', chunk, response['items'].length, dummy_extracted_values)
    rescue Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError, Fluent::Plugin::ElasticsearchOutput::RetryStreamError=>e
      failed = true
      records = [].tap do |records|
        next unless e.respond_to?(:retry_stream)
        e.retry_stream.each {|time, record| records << record}
      end
      # should retry chunk when unrecoverable error is not thrown
      assert_equal 1, records.length
    end
    assert_true failed
  end

  def test_retry_error
    records = []
    error_records = Hash.new(false)
    error_records.merge!({0=>true, 4=>true, 9=>true})
    10.times do |i|
      records << {time: 12345, record: {"message"=>"record #{i}","_id"=>i,"raise"=>error_records[i]}}
    end
    chunk = MockChunk.new(records)

    response = parse_response(%({
      "took" : 1,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "1",
            "status" : 201
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "2",
            "status" : 500,
            "error" : {
              "type" : "some unrecognized type",
              "reason":"unrecognized error"
            }
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "3",
            "status" : 409
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "5",
            "status" : 500,
            "error" : {
              "reason":"unrecognized error - no type field"
            }
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "6",
            "status" : 400,
            "error" : {
              "type" : "mapper_parsing_exception",
              "reason":"failed to parse"
            }
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "7",
            "status" : 400,
            "error" : {
              "type" : "some unrecognized type",
              "reason":"unrecognized error"
            }
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "8",
            "status" : 500,
            "error" : {
              "type" : "some unrecognized type",
              "reason":"unrecognized error"
            }
          }
        }
      ]
    }))

    begin
      failed = false
      dummy_extracted_values = []
      @handler.handle_error(response, 'atag', chunk, response['items'].length, dummy_extracted_values)
    rescue Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError, Fluent::Plugin::ElasticsearchOutput::RetryStreamError=>e
      failed = true
      records = [].tap do |records|
        next unless e.respond_to?(:retry_stream)
        e.retry_stream.each {|time, record| records << record}
      end
      assert_equal 2, records.length
      assert_equal 2, records[0]['_id']
      assert_equal 8, records[1]['_id']
      error_ids = @plugin.error_events.collect {|h| h[:record]['_id']}
      assert_equal 3, error_ids.length
      assert_equal [5, 6, 7], error_ids
      @plugin.error_events.collect {|h| h[:error]}.each do |e|
        assert_true e.respond_to?(:backtrace)
      end
    end
    assert_true failed

  end

  def test_unrecoverable_error_included_in_responses
    records = []
    error_records = Hash.new(false)
    error_records.merge!({0=>true, 4=>true, 9=>true})
    10.times do |i|
      records << {time: 12345, record: {"message"=>"record #{i}","_id"=>i,"raise"=>error_records[i]}}
    end
    chunk = MockChunk.new(records)

    response = parse_response(%({
      "took" : 1,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "1",
            "status" : 201
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "2",
            "status" : 500,
            "error" : {
              "type" : "some unrecognized type",
              "reason":"unrecognized error"
            }
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "3",
            "status" : 409
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "5",
            "status" : 500,
            "error" : {
              "reason":"unrecognized error - no type field"
            }
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "6",
            "status" : 500,
            "_type"  : "bar",
            "error" : {
              "type" : "out_of_memory_error",
              "reason":"Java heap space"
            }
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "7",
            "status" : 400,
            "error" : {
              "type" : "some unrecognized type",
              "reason":"unrecognized error"
            }
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "8",
            "status" : 500,
            "error" : {
              "type" : "some unrecognized type",
              "reason":"unrecognized error"
            }
          }
        }
      ]
    }))

    begin
      failed = false
      dummy_extracted_values = []
      @handler.handle_error(response, 'atag', chunk, response['items'].length, dummy_extracted_values)
    rescue Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError, Fluent::Plugin::ElasticsearchOutput::RetryStreamError=>e
      failed = true
      records = [].tap do |records|
        next unless e.respond_to?(:retry_stream)
        e.retry_stream.each {|time, record| records << record}
      end
      # should drop entire chunk when unrecoverable error response is replied
      assert_equal 0, records.length
    end
    assert_true failed

  end

end
