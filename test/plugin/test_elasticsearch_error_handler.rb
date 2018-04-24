require 'helper'
require 'fluent/plugin/elasticsearch_error_handler'
require 'json'

class TestElasticsearchErrorHandler < Test::Unit::TestCase

  class TestPlugin
    attr_reader :log
    attr_reader :write_operation
    def initialize(log)
      @log = log
      @write_operation = 'index'
    end
  end

  def setup
    Fluent::Test.setup
    @log_device = Fluent::Test::DummyLogDevice.new
    dl_opts = {:log_level => ServerEngine::DaemonLogger::INFO}
    logger = ServerEngine::DaemonLogger.new(@log_device, dl_opts)
    @log = Fluent::Log.new(logger)
    @plugin = TestPlugin.new(@log)
    @handler = Fluent::ElasticsearchErrorHandler.new(@plugin)
  end

  def parse_response(value)
    JSON.parse(value)
  end

  def test_errors 
    response = parse_response(%({
      "took" : 0,
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

    assert_raise Fluent::ElasticsearchErrorHandler::ElasticsearchError do 
        @handler.handle_error(response)
    end

  end

  def test_elasticsearch_version_mismatch_raises_error
    response = parse_response(%(
      {
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "abc",
            "status" : 500,
            "error" : {
              "reason":"some error to cause version mismatch"
            }
          }
        }
      ]
      }
    ))

    assert_raise Fluent::ElasticsearchErrorHandler::ElasticsearchVersionMismatch do 
        @handler.handle_error(response)
    end

  end

  def test_retry_with_successes_and_duplicates
    response = parse_response(%(
      {
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "abc",
            "status" : 409,
            "error" : {
              "reason":"duplicate ID"
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
        }
      ]
      }
    ))

    @plugin.instance_variable_set(:@write_operation, 'create')
    @handler.instance_variable_set(:@bulk_message_count, 2)
    @handler.handle_error(response)
    assert_match /retry succeeded - successes=1 duplicates=1/, @log.out.logs[0]
  end

  def test_bulk_rejection_errors
    response = parse_response(%({
      "took" : 0,
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
            "status" : 429,
            "error" : {
              "type" : "es_rejected_execution_exception",
              "reason":"Elasticsearch could not process bulk index request"
            }
          }
        }
      ]
    }))

    assert_raise Fluent::ElasticsearchErrorHandler::BulkIndexQueueFull do
        @handler.handle_error(response)
    end

  end

  def test_out_of_memory_errors
    response = parse_response(%({
      "took" : 0,
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
              "type" : "out_of_memory_error",
              "reason":"Elasticsearch exhausted its heap"
            }
          }
        }
      ]
    }))

    assert_raise Fluent::ElasticsearchErrorHandler::ElasticsearchOutOfMemory do
        @handler.handle_error(response)
    end

  end

end
