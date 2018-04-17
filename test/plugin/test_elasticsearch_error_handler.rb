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
        @error_events << record
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
    records = [{time: 123, record: "record"}]
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
    @handler.handle_error(response, 'atag', records)
    assert_equal(1, @plugin.error_events.length)
  end

  def test_retry_error
    records = []
    5.times do |i|
      records << {time: 12345, record: "record #{i}"}
    end

    response = parse_response(%({
      "took" : 1,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "abc",
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
            "_id" : "abc",
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
            "_id" : "abc",
            "status" : 201
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "abc",
            "status" : 409
          }
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "abc",
            "status" : 400,
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
      @handler.handle_error(response, 'atag', records)
    rescue Fluent::ElasticsearchOutput::RetryRecordsError=>e
      failed = true
      assert_equal 2, e.records.length
    end
    assert_true failed

  end

end
