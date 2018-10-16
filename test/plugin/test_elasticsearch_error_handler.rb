require 'helper'
require 'fluent/plugin/out_elasticsearch'
require 'fluent/plugin/elasticsearch_error_handler'
require 'json'

class TestElasticsearchErrorHandler < Test::Unit::TestCase

  class TestPlugin
    attr_reader :log
    attr_reader :write_operation, :error_events
    def initialize(log)
      @log = log
      @write_operation = 'index'
      @error_events = []
    end

    def router
      self
    end

    def emit_error_event(tag, time, record, e)
       @error_events << {:tag => tag, :time=>time, :record=>record, :error=>e}
    end

    def process_message(tag, meta, header, time, record, bulk_message)
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
    if defined?(ServerEngine::DaemonLogger)
      dl_opts = {:log_level => ServerEngine::DaemonLogger::INFO}
      logger = ServerEngine::DaemonLogger.new(@log_device, dl_opts)
      @log = Fluent::Log.new(logger)
    else
      @log = Fluent::Log.new(@log_device, Fluent::Log::LEVEL_INFO)
    end
    @plugin = TestPlugin.new(@log)
    @handler = Fluent::ElasticsearchErrorHandler.new(@plugin)
  end

  def parse_response(value)
    JSON.parse(value)
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
    @handler.handle_error(response, 'atag', chunk, records.length)
    assert_equal(1, @plugin.error_events.size)
    assert_true(@plugin.error_events[0][:error].respond_to?(:backtrace))
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
            "status" : 429,
            "error" : {
              "type" : "es_rejected_execution_exception",
              "reason":"unable to fulfill request at this time, try again later"
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
      @handler.handle_error(response, 'atag', chunk, response['items'].length)
    rescue Fluent::ElasticsearchOutput::RetryStreamError=>e
      failed = true
      records = [].tap do |records|
        e.retry_stream.each {|time, record| records << record}
      end
      assert_equal 3, records.length
      assert_equal 2, records[0]['_id']
      assert_equal 6, records[1]['_id']
      assert_equal 8, records[2]['_id']
      error_ids = @plugin.error_events.collect {|h| h[:record]['_id']}
      assert_equal 2, error_ids.length
      assert_equal 5, error_ids[0]
      assert_equal 7, error_ids[1]
      @plugin.error_events.collect {|h| h[:error]}.each do |e|
        assert_true e.respond_to?(:backtrace)
      end
    end
    assert_true failed

  end

  def test_old_es_1_X_responses
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
            "error" : "some unrecognized error"
          }
        }
      ]
     }))
    chunk = MockChunk.new(records)
    @handler.handle_error(response, 'atag', chunk, records.length)
    assert_equal(1, @plugin.error_events.size)
    assert_true(@plugin.error_events[0][:error].respond_to?(:backtrace))
  end

end
