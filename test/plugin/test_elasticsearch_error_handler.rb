require 'helper'
require 'fluent/plugin/elasticsearch_error_handler'
require 'json'

class TestElasticsearchErrorHandler < Test::Unit::TestCase

  class TestPlugin
    attr_reader :log
    def initialize(log)
      @log = log
    end

    def write_operation
      'index'
    end
  end

  def setup
    Fluent::Test.setup
    @log = Fluent::Engine.log
    plugin = TestPlugin.new(@log)
    @handler =  Fluent::ElasticsearchErrorHandler.new(plugin)
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
              "reason":"some error to cause version mismatch"
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
              "reason":"some error to cause version mismatch"
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
              "reason":"some error to cause version mismatch"
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

end
