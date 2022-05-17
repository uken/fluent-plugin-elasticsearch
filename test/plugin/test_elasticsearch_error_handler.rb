require_relative '../helper'
require 'fluent/plugin/out_elasticsearch'
require 'fluent/plugin/elasticsearch_error_handler'
require 'json'
require 'msgpack'

class TestElasticsearchErrorHandler < Test::Unit::TestCase

  class TestPlugin
    attr_reader :log
    attr_reader :error_events
    attr_accessor :unrecoverable_error_types
    attr_accessor :log_es_400_reason
    attr_accessor :write_operation
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

    def process_message(tag, meta, header, time, record, affinity_target_indices, extracted_values)
      return [meta, header, record]
    end

    def get_affinity_target_indices(chunk)
      indices = Hash.new
      indices
    end

    def append_record_to_messages(op, meta, header, record, msgs)
      if record.has_key?('raise') && record['raise']
        raise 'process_message'
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

  class MockMsgpackChunk
    def initialize(chunk)
      @chunk = chunk
      @factory = MessagePack::Factory.new
      @factory.register_type(Fluent::EventTime::TYPE, Fluent::EventTime)
    end

    def msgpack_each
      @factory.unpacker(@chunk).each { |time, record| yield(time, record) }
    end
  end

  class MockUnpackedMsg
    def initialize(records)
      @records = records
    end
    def each
      @records.each { |item| yield({:time => item[:time], :record => item[:record]}) }
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
      unpacked_msg_arr = MockUnpackedMsg.new(records)
      dummy_extracted_values = []
      @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values, unpacked_msg_arr)
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
      unpacked_msg_arr = MockUnpackedMsg.new(records)
      dummy_extracted_values = []
      @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values, unpacked_msg_arr)
      assert_equal(1, @plugin.error_events.size)
      expected_log = "failed to parse"
      exception_message = @plugin.error_events.first[:error].message
      assert_true(exception_message.include?(expected_log),
                  "Exception do not contain '#{exception_message}' '#{expected_log}'")
      assert_true(@plugin.error_events[0][:error].respond_to?(:backtrace))
    end
  end

  def test_nil_items_responses
    records = [{time: 123, record: {"foo" => "bar", '_id' => 'abc'}}]
    response = parse_response(%({
      "took" : 0,
      "errors" : true,
      "items" : [{}]
     }))
    chunk = MockChunk.new(records)
    unpacked_msg_arr = MockUnpackedMsg.new(records)
    dummy_extracted_values = []
    @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values, unpacked_msg_arr)
    assert_equal(0, @plugin.error_events.size)
    assert_nil(@plugin.error_events[0])
  end

  def test_blocked_items_responses
    records = [{time: 123, record: {"foo" => "bar", '_id' => 'abc'}}]
    response = parse_response(%({
      "took" : 0,
      "errors" : true,
      "items" : [
        {
          "create" : {
            "_index" : "foo",
            "status" : 503,
            "error" : "ClusterBlockException[blocked by: [SERVICE_UNAVAILABLE/1/state not recovered / initialized];]"
          }
        }
      ]
     }))
    chunk = MockChunk.new(records)
    unpacked_msg_arr = MockUnpackedMsg.new(records)
    dummy_extracted_values = []
    @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values, unpacked_msg_arr)
    assert_equal(1, @plugin.error_events.size)
    assert_true(@plugin.error_events[0][:error].respond_to?(:backtrace))
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
    unpacked_msg_arr = MockUnpackedMsg.new(records)
    dummy_extracted_values = []
    @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values, unpacked_msg_arr)
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
    unpacked_msg_arr = MockUnpackedMsg.new(records)
    dummy_extracted_values = []
    assert_raise(Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError) do
      @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values, unpacked_msg_arr)
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
    unpacked_msg_arr = MockUnpackedMsg.new(records)
    dummy_extracted_values = []
    assert_raise(Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError) do
      @handler.handle_error(response, 'atag', chunk, records.length, dummy_extracted_values, unpacked_msg_arr)
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
      unpacked_msg_arr = MockUnpackedMsg.new(records)
      dummy_extracted_values = []
      handler.handle_error(response, 'atag', chunk, response['items'].length, dummy_extracted_values, unpacked_msg_arr)
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
    error_records.merge!({0=>true, 4=>true})
    10.times do |i|
      records << {time: 12345, record: {"message"=>"record #{i}","_id"=>i,"raise"=>error_records[i]}}
    end
    chunk = MockChunk.new(records)
    unpacked_msg_arr = MockUnpackedMsg.new(records)

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
        },
        {
          "create" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "9",
            "status" : 500,
            "error" : {
              "type" : "json_parse_exception",
              "reason":"Invalid UTF-8 start byte 0x92\\n at [Source: org.elasticsearch.transport.netty4.ByteBufStreamInput@204fe9c9; line: 1, column: 81]"
            }
          }
        }
      ]
    }))

    begin
      failed = false
      dummy_extracted_values = []
      @handler.handle_error(response, 'atag', chunk, response['items'].length, dummy_extracted_values, unpacked_msg_arr)
    rescue Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError, Fluent::Plugin::ElasticsearchOutput::RetryStreamError=>e
      failed = true
      records = [].tap do |records|
        next unless e.respond_to?(:retry_stream)
        e.retry_stream.each {|time, record| records << record}
      end
      assert_equal 2, records.length, "Exp. retry_stream to contain records"
      assert_equal 2, records[0]['_id'], "Exp record with given ID to in retry_stream"
      assert_equal 8, records[1]['_id'], "Exp record with given ID to in retry_stream"
      error_ids = @plugin.error_events.collect {|h| h[:record]['_id']}
      assert_equal 4, error_ids.length, "Exp. a certain number of records to be dropped from retry_stream"
      assert_equal [5, 6, 7, 9], error_ids, "Exp. specific records to be dropped from retry_stream"
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
    unpacked_msg_arr = MockUnpackedMsg.new(records)

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
      @handler.handle_error(response, 'atag', chunk, response['items'].length, dummy_extracted_values, unpacked_msg_arr)
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

  def test_retry_error_upsert
    @plugin.write_operation = 'upsert'
    records = []
    error_records = Hash.new(false)
    error_records.merge!({0=>true, 4=>true, 9=>true})
    10.times do |i|
      records << {time: 12345, record: {"message"=>"record #{i}","_id"=>i,"raise"=>error_records[i]}}
    end
    chunk = MockChunk.new(records)
    unpacked_msg_arr = MockUnpackedMsg.new(records)

    response = parse_response(%({
      "took" : 1,
      "errors" : true,
      "items" : [
        {
          "update" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "1",
            "status" : 201
          }
        },
        {
          "update" : {
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
          "update" : {
            "_index" : "foo",
            "_type"  : "bar",
            "_id" : "3",
            "status" : 409,
            "error" : {
              "type":"version_conflict_engine_exception",
              "reason":"document already exists"
            }
          }
        },
        {
          "update" : {
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
          "update" : {
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
          "update" : {
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
          "update" : {
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
      @handler.handle_error(response, 'atag', chunk, response['items'].length, dummy_extracted_values, unpacked_msg_arr)
    rescue Fluent::Plugin::ElasticsearchErrorHandler::ElasticsearchRequestAbortError, Fluent::Plugin::ElasticsearchOutput::RetryStreamError=>e
      failed = true
      records = [].tap do |records|
        next unless e.respond_to?(:retry_stream)
        e.retry_stream.each {|time, record| records << record}
      end
      assert_equal 3, records.length
      assert_equal 2, records[0]['_id']
      # upsert is retried in case of conflict error.
      assert_equal 3, records[1]['_id']
      assert_equal 8, records[2]['_id']
      error_ids = @plugin.error_events.collect {|h| h[:record]['_id']}
      assert_equal 3, error_ids.length
      assert_equal [5, 6, 7], error_ids
      @plugin.error_events.collect {|h| h[:error]}.each do |e|
        assert_true e.respond_to?(:backtrace)
      end
    end
    assert_true failed
  end

  def test_nested_msgpack_each
    cwd = File.dirname(__FILE__)
    chunk_path = File.join(cwd, 'mock_chunk.dat')
    chunk_file = File.open(chunk_path, 'rb', 0644)
    chunk_file.seek(0, IO::SEEK_SET)

    chunk = MockMsgpackChunk.new(chunk_file)

    unpacked_msg_arr = []
    msg_count = 0
    count_to_trigger_error_handle = 0
    chunk.msgpack_each do |time, record|
      next unless record.is_a? Hash

      unpacked_msg_arr << {:time => time, :record => record}
      msg_count += 1

      record.each_key do |k|
        if k != 'aaa' && k != 'bbb' && k != 'ccc' && k != 'log_path'
          assert_equal(:impossible, k)
        end
      end

      if msg_count % 55 == 0
        if count_to_trigger_error_handle == 1
          begin
            response = {}
            response['errors'] = true
            response['items'] = []
            item = {}
            item['index'] = {}
            item['index']['status'] = 429
            item['index']['error'] = {}
            item['index']['error']['type'] = "es_rejected_execution_exception"
            abc = 0
            while abc < unpacked_msg_arr.length
              abc += 1
              response['items'] << item
            end

            dummy_extracted_values = []
            @handler.handle_error(response, 'atag', chunk, unpacked_msg_arr.length, dummy_extracted_values, unpacked_msg_arr)
            assert_equal(0, @plugin.error_events.size)
            assert_nil(@plugin.error_events[0])
          rescue => e
            # capture ElasticsearchRequestAbortError, beacuse es_rejected_execution_exception is unrecoverable.
          end
        end

        count_to_trigger_error_handle += 1
        unpacked_msg_arr.clear
      end # end if
    end # end chunk.msgpack_each

    chunk_file.close
  end
end
