require 'helper'
require 'date'
require 'fluent/test/helpers'
require 'json'
require 'fluent/test/driver/output'
require 'flexmock/test_unit'

class ElasticsearchOutput < Test::Unit::TestCase
  include FlexMock::TestCase
  include Fluent::Test::Helpers

  attr_accessor :index_cmds, :index_command_counts

  def setup
    Fluent::Test.setup
    require 'fluent/plugin/out_elasticsearch'
    @driver = nil
    log = Fluent::Engine.log
    log.out.logs.slice!(0, log.out.logs.length)
  end

  def driver(conf='', es_version=5, client_version="\"5.0\"")
    # For request stub to detect compatibility.
    @es_version ||= es_version
    @client_version ||= client_version
    if @es_version
      Fluent::Plugin::ElasticsearchOutput.module_eval(<<-CODE)
        def detect_es_major_version
          #{@es_version}
        end
      CODE
    end
    Fluent::Plugin::ElasticsearchOutput.module_eval(<<-CODE)
      def client_library_version
        #{@client_version}
      end
    CODE
    @driver ||= Fluent::Test::Driver::Output.new(Fluent::Plugin::ElasticsearchOutput) {
      # v0.12's test driver assume format definition. This simulates ObjectBufferedOutput format
      if !defined?(Fluent::Plugin::Output)
        def format(tag, time, record)
          [time, record].to_msgpack
        end
      end
    }.configure(conf)
  end

  def default_type_name
    Fluent::Plugin::ElasticsearchOutput::DEFAULT_TYPE_NAME
  end

  def sample_record(content={})
    {'age' => 26, 'request_id' => '42', 'parent_id' => 'parent', 'routing_id' => 'routing'}.merge(content)
  end

  def nested_sample_record
    {'nested' =>
     {'age' => 26, 'parent_id' => 'parent', 'routing_id' => 'routing', 'request_id' => '42'}
    }
  end

  def stub_elastic_ping(url="http://localhost:9200")
    stub_request(:head, url).to_return(:status => 200, :body => "", :headers => {})
  end

  def stub_elastic_info(url="http://localhost:9200/", version="6.4.2")
    body ="{\"version\":{\"number\":\"#{version}\"}}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json' } })
  end

  def stub_elastic(url="http://localhost:9200/_bulk")
    stub_request(:post, url).with do |req|
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
    end
  end

  def stub_elastic_unavailable(url="http://localhost:9200/_bulk")
    stub_request(:post, url).to_return(:status => [503, "Service Unavailable"])
  end

  def stub_elastic_timeout(url="http://localhost:9200/_bulk")
    stub_request(:post, url).to_timeout
  end

  def stub_elastic_with_store_index_command_counts(url="http://localhost:9200/_bulk")
    if @index_command_counts == nil
       @index_command_counts = {}
       @index_command_counts.default = 0
    end

    stub_request(:post, url).with do |req|
      index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
      @index_command_counts[url] += index_cmds.size
    end
  end

  def make_response_body(req, error_el = nil, error_status = nil, error = nil)
    req_index_cmds = req.body.split("\n").map { |r| JSON.parse(r) }
    items = []
    count = 0
    ids = 1
    op = nil
    index = nil
    type = nil
    id = nil
    req_index_cmds.each do |cmd|
      if count.even?
        op = cmd.keys[0]
        index = cmd[op]['_index']
        type = cmd[op]['_type']
        if cmd[op].has_key?('_id')
          id = cmd[op]['_id']
        else
          # Note: this appears to be an undocumented feature of Elasticsearch
          # https://www.elastic.co/guide/en/elasticsearch/reference/2.4/docs-bulk.html
          # When you submit an "index" write_operation, with no "_id" field in the
          # metadata header, Elasticsearch will turn this into a "create"
          # operation in the response.
          if "index" == op
            op = "create"
          end
          id = ids
          ids += 1
        end
      else
        item = {
          op => {
            '_index' => index, '_type' => type, '_id' => id, '_version' => 1,
            '_shards' => { 'total' => 1, 'successful' => 1, 'failed' => 0 },
            'status' => op == 'create' ? 201 : 200
          }
        }
        items.push(item)
      end
      count += 1
    end
    if !error_el.nil? && !error_status.nil? && !error.nil?
      op = items[error_el].keys[0]
      items[error_el][op].delete('_version')
      items[error_el][op].delete('_shards')
      items[error_el][op]['error'] = error
      items[error_el][op]['status'] = error_status
      errors = true
    else
      errors = false
    end
    @index_cmds = items
    body = { 'took' => 6, 'errors' => errors, 'items' => items }
    return body.to_json
  end

  def stub_elastic_bad_argument(url="http://localhost:9200/_bulk")
    error = {
      "type" => "mapper_parsing_exception",
      "reason" => "failed to parse [...]",
      "caused_by" => {
        "type" => "illegal_argument_exception",
        "reason" => "Invalid format: \"...\""
      }
    }
    stub_request(:post, url).to_return(lambda { |req| { :status => 200, :body => make_response_body(req, 1, 400, error), :headers => { 'Content-Type' => 'json' } } })
  end

  def stub_elastic_bulk_error(url="http://localhost:9200/_bulk")
    error = {
      "type" => "some-unrecognized-error",
      "reason" => "some message printed here ...",
    }
    stub_request(:post, url).to_return(lambda { |req| { :status => 200, :body => make_response_body(req, 1, 500, error), :headers => { 'Content-Type' => 'json' } } })
  end

  def stub_elastic_bulk_rejected(url="http://localhost:9200/_bulk")
    error = {
      "status" => 500,
      "type" => "es_rejected_execution_exception",
      "reason" => "rejected execution of org.elasticsearch.transport.TransportService$4@1a34d37a on EsThreadPoolExecutor[bulk, queue capacity = 50, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@312a2162[Running, pool size = 32, active threads = 32, queued tasks = 50, completed tasks = 327053]]"
    }
    stub_request(:post, url).to_return(lambda { |req| { :status => 200, :body => make_response_body(req, 1, 429, error), :headers => { 'Content-Type' => 'json' } } })
  end

  def stub_elastic_out_of_memory(url="http://localhost:9200/_bulk")
    error = {
      "status" => 500,
      "type" => "out_of_memory_error",
      "reason" => "Java heap space"
    }
    stub_request(:post, url).to_return(lambda { |req| { :status => 200, :body => make_response_body(req, 1, 500, error), :headers => { 'Content-Type' => 'json' } } })
  end

  def stub_elastic_unexpected_response_op(url="http://localhost:9200/_bulk")
    error = {
      "category" => "some-other-type",
      "reason" => "some-other-reason"
    }
    stub_request(:post, url).to_return(lambda { |req| bodystr = make_response_body(req, 0, 500, error); body = JSON.parse(bodystr); body['items'][0]['unknown'] = body['items'][0].delete('create'); { :status => 200, :body => body.to_json, :headers => { 'Content-Type' => 'json' } } })
  end

  def assert_logs_include(logs, msg, exp_matches=1)
    matches = logs.grep /#{msg}/
    assert_equal(exp_matches, matches.length, "Logs do not contain '#{msg}' '#{logs}'")
  end

  def assert_logs_include_compare_size(exp_matches=1, operator="<=", logs="", msg="")
    matches = logs.grep /#{msg}/
    assert_compare(exp_matches, operator, matches.length, "Logs do not contain '#{msg}' '#{logs}'")
  end

  def test_configure
    config = %{
      host     logs.google.com
      port     777
      scheme   https
      path     /es/
      user     john
      password doe
    }
    instance = driver(config).instance

    assert_equal 'logs.google.com', instance.host
    assert_equal 777, instance.port
    assert_equal :https, instance.scheme
    assert_equal '/es/', instance.path
    assert_equal 'john', instance.user
    assert_equal 'doe', instance.password
    assert_equal :TLSv1, instance.ssl_version
    assert_nil instance.client_key
    assert_nil instance.client_cert
    assert_nil instance.client_key_pass
    assert_false instance.with_transporter_log
    assert_equal :"application/json", instance.content_type
    assert_equal "fluentd", default_type_name
    assert_equal :excon, instance.http_backend
    assert_false instance.prefer_oj_serializer
    assert_equal ["out_of_memory_error", "es_rejected_execution_exception"], instance.unrecoverable_error_types
    assert_true instance.verify_es_version_at_startup
    assert_equal Fluent::Plugin::ElasticsearchOutput::DEFAULT_ELASTICSEARCH_VERSION, instance.default_elasticsearch_version
    assert_false instance.log_es_400_reason
  end

  test 'configure Content-Type' do
    config = %{
      content_type application/x-ndjson
    }
    instance = driver(config).instance
    assert_equal :"application/x-ndjson", instance.content_type
  end

  test 'invalid Content-Type' do
    config = %{
      content_type nonexistent/invalid
    }
    assert_raise(Fluent::ConfigError) {
      instance = driver(config).instance
    }
  end

  test 'invalid specification of times of retrying template installation' do
    config = %{
      max_retry_putting_template -3
    }
    assert_raise(Fluent::ConfigError) {
      instance = driver(config).instance
    }
  end

  test 'Detected Elasticsearch 7' do
    config = %{
      type_name changed
    }
    instance = driver(config, 7).instance
    assert_equal '_doc', instance.type_name
  end

  test 'Detected Elasticsearch 6 and insecure security' do
    config = %{
      ssl_version TLSv1_1
      @log_level warn
      scheme https
    }
    instance = driver(config, 6).instance
    logs = driver.logs
    assert_logs_include(logs, /Detected ES 6.x or above and enabled insecure security/, 1)
  end

  test 'Detected Elasticsearch 7 and secure security' do
    config = %{
      ssl_version TLSv1_2
      @log_level warn
      scheme https
    }
    instance = driver(config, 7).instance
    logs = driver.logs
    assert_logs_include(logs, /Detected ES 6.x or above and enabled insecure security/, 0)
  end

  test 'Pass Elasticsearch and client library are same' do
    config = %{
      @log_level warn
      validate_client_version true
    }
    assert_nothing_raised do
      driver(config, 6, "\"6.1.0\"").instance
    end
  end

  test 'Detected Elasticsearch and client library mismatch' do
    config = %{
      @log_level warn
      validate_client_version true
    }
    assert_raise_message(/Detected ES 7 but you use ES client 5.0/) do
      driver(config, 7, "\"5.0.5\"").instance
    end
  end

  test 'lack of tag in chunk_keys' do
    assert_raise_message(/'tag' in chunk_keys is required./) do
      driver(Fluent::Config::Element.new(
               'ROOT', '', {
                 '@type' => 'elasticsearch',
                 'host' => 'log.google.com',
                 'port' => 777,
                 'scheme' => 'https',
                 'path' => '/es/',
                 'user' => 'john',
                 'pasword' => 'doe',
               }, [
                 Fluent::Config::Element.new('buffer', 'mykey', {
                                               'chunk_keys' => 'mykey'
                                             }, [])
               ]
             ))
    end
  end

  def test_template_already_present
    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   /abc123
    }

    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash").
      to_return(:status => 200, :body => "", :headers => {})

    driver(config)

    assert_not_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash")
  end

  def test_template_create
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   #{template_file}
    }

    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash").
      to_return(:status => 404, :body => "", :headers => {})
    # creation
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash").
      to_return(:status => 200, :body => "", :headers => {})

    driver(config)

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash", times: 1)
  end

  def test_custom_template_create
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_alias_template.json')

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   myapp_alias_template
      template_file   #{template_file}
      customize_template {"--appid--": "myapp-logs","--index_prefix--":"mylogs"}
    }

    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template").
      to_return(:status => 404, :body => "", :headers => {})
    # creation
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template").
      to_return(:status => 200, :body => "", :headers => {})
    
    driver(config)

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template", times: 1)
  end

  def test_custom_template_with_rollover_index_create
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_alias_template.json')

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   myapp_alias_template
      template_file   #{template_file}
      customize_template {"--appid--": "myapp-logs","--index_prefix--":"mylogs"}
      rollover_index  true
      index_date_pattern now/w{xxxx.ww}
      deflector_alias myapp_deflector
      index_prefix    mylogs
      application_name myapp
    }

    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template").
      to_return(:status => 404, :body => "", :headers => {})
    # creation
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template").
      to_return(:status => 200, :body => "", :headers => {})
    # creation of index which can rollover
    stub_request(:put, "https://john:doe@logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
      to_return(:status => 200, :body => "", :headers => {})
    # check if alias exists
    stub_request(:head, "https://john:doe@logs.google.com:777/es//_alias/myapp_deflector").
      to_return(:status => 404, :body => "", :headers => {})
    # put the alias for the index
    stub_request(:put, "https://john:doe@logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/_alias/myapp_deflector").
      to_return(:status => 200, :body => "", :headers => {})
    
    driver(config)

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template", times: 1)
  end


  def test_template_overwrite
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   #{template_file}
      template_overwrite true
    }

    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash").
      to_return(:status => 200, :body => "", :headers => {})
    # creation
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash").
      to_return(:status => 200, :body => "", :headers => {})

    driver(config)

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash", times: 1)
  end

  def test_custom_template_overwrite
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   myapp_alias_template
      template_file   #{template_file}
      template_overwrite true
      customize_template {"--appid--": "myapp-logs","--index_prefix--":"mylogs"}
    }

    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template").
      to_return(:status => 200, :body => "", :headers => {})
    # creation
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template").
      to_return(:status => 200, :body => "", :headers => {})
    
    driver(config)

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template", times: 1)
  end

  def test_custom_template_with_rollover_index_overwrite
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   myapp_alias_template
      template_file   #{template_file}
      template_overwrite true
      customize_template {"--appid--": "myapp-logs","--index_prefix--":"mylogs"}
      deflector_alias myapp_deflector
      rollover_index  true
      index_prefix    mylogs
      application_name myapp
    }

    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template").
      to_return(:status => 200, :body => "", :headers => {})
    # creation
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template").
      to_return(:status => 200, :body => "", :headers => {})
    # creation of index which can rollover
    stub_request(:put, "https://john:doe@logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fd%7D-000001%3E").
      to_return(:status => 200, :body => "", :headers => {})
    # check if alias exists
    stub_request(:head, "https://john:doe@logs.google.com:777/es//_alias/myapp_deflector").
      to_return(:status => 404, :body => "", :headers => {})
    # put the alias for the index
    stub_request(:put, "https://john:doe@logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fd%7D-000001%3E/_alias/myapp_deflector").
      to_return(:status => 200, :body => "", :headers => {})
  
    driver(config)

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/myapp_alias_template", times: 1)
  end

  def test_template_create_invalid_filename
    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   /abc123
    }

    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash").
      to_return(:status => 404, :body => "", :headers => {})

    assert_raise(RuntimeError) {
      driver(config)
    }
  end

  def test_template_retry_install
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')

    config = %{
      host            logs.google.com
      port            778
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   #{template_file}
      max_retry_putting_template 3
    }

    connection_resets = 0
    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:778/es//").with do |req|
      connection_resets += 1
    end
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:778/es//_template/logstash").with do |req|
      raise Fluent::Plugin::ElasticsearchOutput::ConnectionFailure, "Test message"
    end
    # creation
    stub_request(:put, "https://john:doe@logs.google.com:778/es//_template/logstash").with do |req|
      raise Fluent::Plugin::ElasticsearchOutput::ConnectionFailure, "Test message"
    end

    assert_raise(Fluent::Plugin::ElasticsearchOutput::ConnectionFailure) do
      driver(config)
    end

    assert_equal(connection_resets, 4)
  end

  def test_templates_create
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')
    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      templates       {"logstash1":"#{template_file}", "logstash2":"#{template_file}","logstash3":"#{template_file}" }
    }

    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
     # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash1").
      to_return(:status => 404, :body => "", :headers => {})
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash2").
      to_return(:status => 404, :body => "", :headers => {})

    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash3").
      to_return(:status => 200, :body => "", :headers => {}) #exists

    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash1").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash2").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash3").
      to_return(:status => 200, :body => "", :headers => {})

    driver(config)

    assert_requested( :put, "https://john:doe@logs.google.com:777/es//_template/logstash1", times: 1)
    assert_requested( :put, "https://john:doe@logs.google.com:777/es//_template/logstash2", times: 1)
    assert_not_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash3") #exists
  end

  def test_templates_overwrite
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')
    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      templates       {"logstash1":"#{template_file}", "logstash2":"#{template_file}","logstash3":"#{template_file}" }
      template_overwrite true
    }

    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
     # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash1").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash2").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash3").
      to_return(:status => 200, :body => "", :headers => {}) #exists

    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash1").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash2").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash3").
      to_return(:status => 200, :body => "", :headers => {})

    driver(config)

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash1", times: 1)
    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash2", times: 1)
    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash3", times: 1)
  end

  def test_templates_not_used
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   #{template_file}
      templates       {"logstash1":"#{template_file}", "logstash2":"#{template_file}" }
    }
    # connection start
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
    # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash").
      to_return(:status => 404, :body => "", :headers => {})
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash1").
      to_return(:status => 404, :body => "", :headers => {})
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash2").
      to_return(:status => 404, :body => "", :headers => {})
    #creation
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash1").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash2").
      to_return(:status => 200, :body => "", :headers => {})

    driver(config)

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash", times: 1)

    assert_not_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash1")
    assert_not_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash2")
  end

  def test_templates_can_be_partially_created_if_error_occurs
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')
    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      templates       {"logstash1":"#{template_file}", "logstash2":"/abc" }
    }
    stub_request(:head, "https://john:doe@logs.google.com:777/es//").
      to_return(:status => 200, :body => "", :headers => {})
     # check if template exists
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash1").
      to_return(:status => 404, :body => "", :headers => {})
    stub_request(:get, "https://john:doe@logs.google.com:777/es//_template/logstash2").
      to_return(:status => 404, :body => "", :headers => {})

    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash1").
      to_return(:status => 200, :body => "", :headers => {})
    stub_request(:put, "https://john:doe@logs.google.com:777/es//_template/logstash2").
      to_return(:status => 200, :body => "", :headers => {})

    assert_raise(RuntimeError) {
      driver(config)
    }

    assert_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash1", times: 1)
    assert_not_requested(:put, "https://john:doe@logs.google.com:777/es//_template/logstash2")
  end

  def test_legacy_hosts_list
    config = %{
      hosts    host1:50,host2:100,host3
      scheme   https
      path     /es/
      port     123
    }
    instance = driver(config).instance

    assert_equal 3, instance.get_connection_options[:hosts].length
    host1, host2, host3 = instance.get_connection_options[:hosts]

    assert_equal 'host1', host1[:host]
    assert_equal 50, host1[:port]
    assert_equal 'https', host1[:scheme]
    assert_equal '/es/', host2[:path]
    assert_equal 'host3', host3[:host]
    assert_equal 123, host3[:port]
    assert_equal 'https', host3[:scheme]
    assert_equal '/es/', host3[:path]
  end

  def test_hosts_list
    config = %{
      hosts    https://john:password@host1:443/elastic/,http://host2
      path     /default_path
      user     default_user
      password default_password
    }
    instance = driver(config).instance

    assert_equal 2, instance.get_connection_options[:hosts].length
    host1, host2 = instance.get_connection_options[:hosts]

    assert_equal 'host1', host1[:host]
    assert_equal 443, host1[:port]
    assert_equal 'https', host1[:scheme]
    assert_equal 'john', host1[:user]
    assert_equal 'password', host1[:password]
    assert_equal '/elastic/', host1[:path]

    assert_equal 'host2', host2[:host]
    assert_equal 'http', host2[:scheme]
    assert_equal 'default_user', host2[:user]
    assert_equal 'default_password', host2[:password]
    assert_equal '/default_path', host2[:path]
  end

  def test_hosts_list_with_escape_placeholders
    config = %{
      hosts    https://%{j+hn}:%{passw@rd}@host1:443/elastic/,http://host2
      path     /default_path
      user     default_user
      password default_password
    }
    instance = driver(config).instance

    assert_equal 2, instance.get_connection_options[:hosts].length
    host1, host2 = instance.get_connection_options[:hosts]

    assert_equal 'host1', host1[:host]
    assert_equal 443, host1[:port]
    assert_equal 'https', host1[:scheme]
    assert_equal 'j%2Bhn', host1[:user]
    assert_equal 'passw%40rd', host1[:password]
    assert_equal '/elastic/', host1[:path]

    assert_equal 'host2', host2[:host]
    assert_equal 'http', host2[:scheme]
    assert_equal 'default_user', host2[:user]
    assert_equal 'default_password', host2[:password]
    assert_equal '/default_path', host2[:path]
  end

  def test_single_host_params_and_defaults
    config = %{
      host     logs.google.com
      user     john
      password doe
    }
    instance = driver(config).instance

    assert_equal 1, instance.get_connection_options[:hosts].length
    host1 = instance.get_connection_options[:hosts][0]

    assert_equal 'logs.google.com', host1[:host]
    assert_equal 9200, host1[:port]
    assert_equal 'http', host1[:scheme]
    assert_equal 'john', host1[:user]
    assert_equal 'doe', host1[:password]
    assert_equal nil, host1[:path]
  end

  def test_single_host_params_and_defaults_with_escape_placeholders
    config = %{
      host     logs.google.com
      user     %{j+hn}
      password %{d@e}
    }
    instance = driver(config).instance

    assert_equal 1, instance.get_connection_options[:hosts].length
    host1 = instance.get_connection_options[:hosts][0]

    assert_equal 'logs.google.com', host1[:host]
    assert_equal 9200, host1[:port]
    assert_equal 'http', host1[:scheme]
    assert_equal 'j%2Bhn', host1[:user]
    assert_equal 'd%40e', host1[:password]
    assert_equal nil, host1[:path]
  end

  def test_content_type_header
    stub_request(:head, "http://localhost:9200/").
      to_return(:status => 200, :body => "", :headers => {})
    if Elasticsearch::VERSION >= "6.0.2"
      elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
                          with(headers: { "Content-Type" => "application/x-ndjson" })
    else
      elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
                          with(headers: { "Content-Type" => "application/json" })
    end
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_write_message_with_bad_chunk
    driver.configure("target_index_key bad_value\n@log_level debug\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed({'bad_value'=>"\255"})
    end
    error_log = driver.error_events.map {|e| e.last.message }

    assert_logs_include(error_log, /(input string invalid)|(invalid byte sequence in UTF-8)/)
  end

  def test_writes_to_default_index
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('fluentd', index_cmds.first['index']['_index'])
  end

  def test_writes_to_default_type
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(default_type_name, index_cmds.first['index']['_type'])
  end

  def test_writes_to_speficied_index
    driver.configure("index_name myindex\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('myindex', index_cmds.first['index']['_index'])
  end

  class IndexNamePlaceholdersTest < self
    def test_writes_to_speficied_index_with_tag_placeholder
      driver.configure("index_name myindex.${tag}\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(sample_record)
      end
      assert_equal('myindex.test', index_cmds.first['index']['_index'])
    end

    def test_writes_to_speficied_index_with_time_placeholder
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'index_name' => 'myindex.%Y.%m.%d',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,time', {
                                                         'chunk_keys' => ['tag', 'time'],
                                                         'timekey' => 3600,
                                                       }, [])
                         ]
                       ))
      stub_elastic_ping
      stub_elastic
      time = Time.parse Date.today.iso8601
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record)
      end
      assert_equal("myindex.#{time.utc.strftime("%Y.%m.%d")}", index_cmds.first['index']['_index'])
    end

    def test_writes_to_speficied_index_with_custom_key_placeholder
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'index_name' => 'myindex.${pipeline_id}',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,pipeline_id', {}, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      pipeline_id = "mypipeline"
      logstash_index = "myindex.#{pipeline_id}"
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record.merge({"pipeline_id" => pipeline_id}))
      end
      assert_equal(logstash_index, index_cmds.first['index']['_index'])
    end
  end

  def test_writes_to_speficied_index_uppercase
    driver.configure("index_name MyIndex\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    # Allthough index_name has upper-case characters,
    # it should be set as lower-case when sent to elasticsearch.
    assert_equal('myindex', index_cmds.first['index']['_index'])
  end

  def test_writes_to_target_index_key
    driver.configure("target_index_key @target_index\n")
    stub_elastic_ping
    stub_elastic
    record = sample_record.clone
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('@target_index' => 'local-override'))
    end
    assert_equal('local-override', index_cmds.first['index']['_index'])
    assert_nil(index_cmds[1]['@target_index'])
  end

  def test_writes_to_target_index_key_logstash
    driver.configure("target_index_key @target_index
                      logstash_format true")
    time = Time.parse Date.today.iso8601
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record.merge('@target_index' => 'local-override'))
    end
    assert_equal('local-override', index_cmds.first['index']['_index'])
  end

   def test_writes_to_target_index_key_logstash_uppercase
    driver.configure("target_index_key @target_index
                      logstash_format true")
    time = Time.parse Date.today.iso8601
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record.merge('@target_index' => 'local-override'))
    end
    # Allthough @target_index has upper-case characters,
    # it should be set as lower-case when sent to elasticsearch.
    assert_equal('local-override', index_cmds.first['index']['_index'])
  end

  def test_writes_to_default_index_with_pipeline
    pipeline = "fluentd"
    driver.configure("pipeline #{pipeline}")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(pipeline, index_cmds.first['index']['pipeline'])
  end

  def test_writes_to_target_index_key_fallack
    driver.configure("target_index_key @target_index\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('fluentd', index_cmds.first['index']['_index'])
  end

  def test_writes_to_target_index_key_fallack_logstash
    driver.configure("target_index_key @target_index\n
                      logstash_format true")
    time = Time.parse Date.today.iso8601
    logstash_index = "logstash-#{time.getutc.strftime("%Y.%m.%d")}"
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  data("border"        => {"es_version" => 6, "_type" => "mytype"},
       "fixed_behavior"=> {"es_version" => 7, "_type" => "_doc"},
      )
  def test_writes_to_speficied_type(data)
    driver('', data["es_version"]).configure("type_name mytype\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(data['_type'], index_cmds.first['index']['_type'])
  end

  data("border"        => {"es_version" => 6, "_type" => "mytype.test"},
       "fixed_behavior"=> {"es_version" => 7, "_type" => "_doc"},
      )
  def test_writes_to_speficied_type_with_placeholders(data)
    driver('', data["es_version"]).configure("type_name mytype.${tag}\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(data['_type'], index_cmds.first['index']['_type'])
  end

  data("old"           => {"es_version" => 2, "_type" => "local-override"},
       "old_behavior"  => {"es_version" => 5, "_type" => "local-override"},
       "border"        => {"es_version" => 6, "_type" => "fluentd"},
       "fixed_behavior"=> {"es_version" => 7, "_type" => "_doc"},
      )
  def test_writes_to_target_type_key(data)
    driver('', data["es_version"]).configure("target_type_key @target_type\n")
    stub_elastic_ping
    stub_elastic
    record = sample_record.clone
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('@target_type' => 'local-override'))
    end
    assert_equal(data["_type"], index_cmds.first['index']['_type'])
    assert_nil(index_cmds[1]['@target_type'])
  end

  def test_writes_to_target_type_key_fallack_to_default
    driver.configure("target_type_key @target_type\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(default_type_name, index_cmds.first['index']['_type'])
  end

  def test_writes_to_target_type_key_fallack_to_type_name
    driver.configure("target_type_key @target_type
                      type_name mytype")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('mytype', index_cmds.first['index']['_type'])
  end

  data("old"           => {"es_version" => 2, "_type" => "local-override"},
       "old_behavior"  => {"es_version" => 5, "_type" => "local-override"},
       "border"        => {"es_version" => 6, "_type" => "fluentd"},
       "fixed_behavior"=> {"es_version" => 7, "_type" => "_doc"},
      )
  def test_writes_to_target_type_key_nested(data)
    driver('', data["es_version"]).configure("target_type_key kubernetes.labels.log_type\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('kubernetes' => {
        'labels' => {
          'log_type' => 'local-override'
        }
      }))
    end
    assert_equal(data["_type"], index_cmds.first['index']['_type'])
    assert_nil(index_cmds[1]['kubernetes']['labels']['log_type'])
  end

  def test_writes_to_target_type_key_fallack_to_default_nested
    driver.configure("target_type_key kubernetes.labels.log_type\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('kubernetes' => {
        'labels' => {
          'other_labels' => 'test'
        }
      }))
    end
    assert_equal(default_type_name, index_cmds.first['index']['_type'])
  end

  def test_writes_to_speficied_host
    driver.configure("host 192.168.33.50\n")
    stub_elastic_ping("http://192.168.33.50:9200")
    elastic_request = stub_elastic("http://192.168.33.50:9200/_bulk")
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_writes_to_speficied_port
    driver.configure("port 9201\n")
    stub_elastic_ping("http://localhost:9201")
    elastic_request = stub_elastic("http://localhost:9201/_bulk")
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_writes_to_multi_hosts
    hosts = [['192.168.33.50', 9201], ['192.168.33.51', 9201], ['192.168.33.52', 9201]]
    hosts_string = hosts.map {|x| "#{x[0]}:#{x[1]}"}.compact.join(',')

    driver.configure("hosts #{hosts_string}")

    hosts.each do |host_info|
      host, port = host_info
      stub_elastic_ping("http://#{host}:#{port}")
      stub_elastic_with_store_index_command_counts("http://#{host}:#{port}/_bulk")
    end

    driver.run(default_tag: 'test') do
      1000.times do
        driver.feed(sample_record.merge('age'=>rand(100)))
      end
    end

    # @note: we cannot make multi chunks with options (flush_interval, buffer_chunk_limit)
    # it's Fluentd test driver's constraint
    # so @index_command_counts.size is always 1

    assert(@index_command_counts.size > 0, "not working with hosts options")

    total = 0
    @index_command_counts.each do |url, count|
      total += count
    end
    assert_equal(2000, total)
  end

  def test_nested_record_with_flattening_on
    driver.configure("flatten_hashes true
                      flatten_hashes_separator |")

    original_hash =  {"foo" => {"bar" => "baz"}, "people" => [
      {"age" => "25", "height" => "1ft"},
      {"age" => "30", "height" => "2ft"}
    ]}

    expected_output = {"foo|bar"=>"baz", "people" => [
      {"age" => "25", "height" => "1ft"},
      {"age" => "30", "height" => "2ft"}
    ]}

    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(original_hash)
    end
    assert_equal expected_output, index_cmds[1]
  end

  def test_nested_record_with_flattening_off
    # flattening off by default

    original_hash =  {"foo" => {"bar" => "baz"}}
    expected_output = {"foo" => {"bar" => "baz"}}

    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(original_hash)
    end
    assert_equal expected_output, index_cmds[1]
  end

  def test_makes_bulk_request
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
      driver.feed(sample_record.merge('age' => 27))
    end
    assert_equal(4, index_cmds.count)
  end

  def test_all_records_are_preserved_in_bulk
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
      driver.feed(sample_record.merge('age' => 27))
    end
    assert_equal(26, index_cmds[1]['age'])
    assert_equal(27, index_cmds[3]['age'])
  end

  def test_writes_to_logstash_index
    driver.configure("logstash_format true\n")
    #
    # This is 1 second past midnight in BST, so the UTC index should be the day before
    dt = DateTime.new(2015, 6, 1, 0, 0, 1, "+01:00")
    logstash_index = "logstash-2015.05.31"
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(dt.to_time.to_i, sample_record)
    end
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  def test_writes_to_logstash_non_utc_index
    driver.configure("logstash_format true
                      utc_index false")
    # When using `utc_index false` the index time will be the local day of
    # ingestion time
    time = Date.today.to_time
    index = "logstash-#{time.strftime("%Y.%m.%d")}"
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(index, index_cmds.first['index']['_index'])
  end

  def test_writes_to_logstash_index_with_specified_prefix
    driver.configure("logstash_format true
                      logstash_prefix myprefix")
    time = Time.parse Date.today.iso8601
    logstash_index = "myprefix-#{time.getutc.strftime("%Y.%m.%d")}"
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  def test_writes_to_logstash_index_with_specified_prefix_and_separator
    separator = '_'
    driver.configure("logstash_format true
                      logstash_prefix_separator #{separator}
                      logstash_prefix myprefix")
    time = Time.parse Date.today.iso8601
    logstash_index = "myprefix#{separator}#{time.getutc.strftime("%Y.%m.%d")}"
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  class LogStashPrefixPlaceholdersTest < self
    def test_writes_to_logstash_index_with_specified_prefix_and_tag_placeholder
      driver.configure("logstash_format true
                      logstash_prefix myprefix-${tag}")
      time = Time.parse Date.today.iso8601
      logstash_index = "myprefix-test-#{time.getutc.strftime("%Y.%m.%d")}"
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record)
      end
      assert_equal(logstash_index, index_cmds.first['index']['_index'])
    end

    def test_writes_to_logstash_index_with_specified_prefix_and_time_placeholder
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'logstash_format' => true,
                           'logstash_prefix' => 'myprefix-%H',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,time', {
                                                         'chunk_keys' => ['tag', 'time'],
                                                         'timekey' => 3600,
                                                       }, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      logstash_index = "myprefix-#{time.getutc.strftime("%H")}-#{time.getutc.strftime("%Y.%m.%d")}"
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record)
      end
      assert_equal(logstash_index, index_cmds.first['index']['_index'])
    end

    def test_writes_to_logstash_index_with_specified_prefix_and_custom_key_placeholder
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'logstash_format' => true,
                           'logstash_prefix' => 'myprefix-${pipeline_id}',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,pipeline_id', {}, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      pipeline_id = "mypipeline"
      logstash_index = "myprefix-#{pipeline_id}-#{time.getutc.strftime("%Y.%m.%d")}"
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record.merge({"pipeline_id" => pipeline_id}))
      end
      assert_equal(logstash_index, index_cmds.first['index']['_index'])
    end
  end

  def test_writes_to_logstash_index_with_specified_prefix_uppercase
    driver.configure("logstash_format true
                      logstash_prefix MyPrefix")
    time = Time.parse Date.today.iso8601
    logstash_index = "myprefix-#{time.getutc.strftime("%Y.%m.%d")}"
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    # Allthough logstash_prefix has upper-case characters,
    # it should be set as lower-case when sent to elasticsearch.
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

    def test_writes_to_logstash_index_with_specified_dateformat
    driver.configure("logstash_format true
                      logstash_dateformat %Y.%m")
    time = Time.parse Date.today.iso8601
    logstash_index = "logstash-#{time.getutc.strftime("%Y.%m")}"
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  def test_writes_to_logstash_index_with_specified_prefix_and_dateformat
    driver.configure("logstash_format true
                      logstash_prefix myprefix
                      logstash_dateformat %Y.%m")
    time = Time.parse Date.today.iso8601
    logstash_index = "myprefix-#{time.getutc.strftime("%Y.%m")}"
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  def test_error_if_tag_not_in_chunk_keys
    assert_raise(Fluent::ConfigError) {
      config = %{
        <buffer foo>
        </buffer>
      }
      driver.configure(config)
    }
  end

  def test_can_use_custom_chunk_along_with_tag
    config = %{
      <buffer tag, foo>
      </buffer>
    }
    driver.configure(config)
  end

  def test_doesnt_add_logstash_timestamp_by_default
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds[1]['@timestamp'])
  end

  def test_adds_timestamp_when_logstash
    driver.configure("logstash_format true\n")
    stub_elastic_ping
    stub_elastic
    ts = DateTime.now
    time = Fluent::EventTime.from_time(ts.to_time)
    driver.run(default_tag: 'test') do
      driver.feed(time, sample_record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts.iso8601(9))
  end

  def test_adds_timestamp_when_include_timestamp
    driver.configure("include_timestamp true\n")
    stub_elastic_ping
    stub_elastic
    ts = DateTime.now
    time = Fluent::EventTime.from_time(ts.to_time)
    driver.run(default_tag: 'test') do
      driver.feed(time, sample_record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts.iso8601(9))
  end

  def test_uses_custom_timestamp_when_included_in_record
    driver.configure("logstash_format true\n")
    stub_elastic_ping
    stub_elastic
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end

  def test_uses_custom_timestamp_when_included_in_record_without_logstash
    driver.configure("include_timestamp true\n")
    stub_elastic_ping
    stub_elastic
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end

  def test_uses_custom_time_key
    driver.configure("logstash_format true
                      time_key vtm\n")
    stub_elastic_ping
    stub_elastic
    ts = DateTime.new(2001,2,3).iso8601(9)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end

  def test_uses_custom_time_key_with_format
    driver.configure("logstash_format true
                      time_key_format %Y-%m-%d %H:%M:%S.%N%z
                      time_key vtm\n")
    stub_elastic_ping
    stub_elastic
    ts = "2001-02-03 13:14:01.673+02:00"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], DateTime.parse(ts).iso8601(9))
    assert_equal("logstash-2001.02.03", index_cmds[0]['index']['_index'])
  end

  def test_uses_custom_time_key_with_format_without_logstash
    driver.configure("include_timestamp true
                      index_name test
                      time_key_format %Y-%m-%d %H:%M:%S.%N%z
                      time_key vtm\n")
    stub_elastic_ping
    stub_elastic
    ts = "2001-02-03 13:14:01.673+02:00"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], DateTime.parse(ts).iso8601(9))
    assert_equal("test", index_cmds[0]['index']['_index'])
  end

  def test_uses_custom_time_key_exclude_timekey
    driver.configure("logstash_format true
                      time_key vtm
                      time_key_exclude_timestamp true\n")
    stub_elastic_ping
    stub_elastic
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(!index_cmds[1].key?('@timestamp'), '@timestamp should be messing')
  end

  def test_uses_custom_time_key_format
    driver.configure("logstash_format true
                      time_key_format %Y-%m-%dT%H:%M:%S.%N%z\n")
    stub_elastic_ping
    stub_elastic
    ts = "2001-02-03T13:14:01.673+02:00"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert_equal("logstash-2001.02.03", index_cmds[0]['index']['_index'])
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end

  def test_uses_custom_time_key_format_without_logstash
    driver.configure("include_timestamp true
                      index_name test
                      time_key_format %Y-%m-%dT%H:%M:%S.%N%z\n")
    stub_elastic_ping
    stub_elastic
    ts = "2001-02-03T13:14:01.673+02:00"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert_equal("test", index_cmds[0]['index']['_index'])
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end

  data(:default => nil,
       :custom_tag => 'es_plugin.output.time.error')
  def test_uses_custom_time_key_format_logs_an_error(tag_for_error)
    tag_config = tag_for_error ? "time_parse_error_tag #{tag_for_error}" : ''
    tag_for_error = 'Fluent::ElasticsearchOutput::TimeParser.error' if tag_for_error.nil?
    driver.configure("logstash_format true
                      time_key_format %Y-%m-%dT%H:%M:%S.%N%z\n#{tag_config}\n")
    stub_elastic_ping
    stub_elastic

    ts = "2001/02/03 13:14:01,673+02:00"
    index = "logstash-#{Date.today.strftime("%Y.%m.%d")}"

    flexmock(driver.instance.router).should_receive(:emit_error_event)
      .with(tag_for_error, Fluent::EventTime, Hash, ArgumentError).once
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end

    assert_equal(index, index_cmds[0]['index']['_index'])
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end


  def test_uses_custom_time_key_format_obscure_format
    driver.configure("logstash_format true
                      time_key_format %a %b %d %H:%M:%S %Z %Y\n")
    stub_elastic_ping
    stub_elastic
    ts = "Thu Nov 29 14:33:20 GMT 2001"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert_equal("logstash-2001.11.29", index_cmds[0]['index']['_index'])
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end

  def test_uses_nanosecond_precision_by_default
    driver.configure("logstash_format true\n")
    stub_elastic_ping
    stub_elastic
    time = Fluent::EventTime.new(Time.now.to_i, 123456789)
    driver.run(default_tag: 'test') do
      driver.feed(time, sample_record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], Time.at(time).iso8601(9))
  end

  def test_uses_subsecond_precision_when_configured
    driver.configure("logstash_format true
                      time_precision 3\n")
    stub_elastic_ping
    stub_elastic
    time = Fluent::EventTime.new(Time.now.to_i, 123456789)
    driver.run(default_tag: 'test') do
      driver.feed(time, sample_record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], Time.at(time).iso8601(3))
  end

  def test_doesnt_add_tag_key_by_default
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds[1]['tag'])
  end

  def test_adds_tag_key_when_configured
    driver.configure("include_tag_key true\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'mytag') do
      driver.feed(sample_record)
    end
    assert(index_cmds[1].has_key?('tag'))
    assert_equal(index_cmds[1]['tag'], 'mytag')
  end

  def test_adds_id_key_when_configured
    driver.configure("id_key request_id\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(index_cmds[0]['index']['_id'], '42')
  end

  class NestedIdKeyTest < self
    def test_adds_nested_id_key_with_dot
      driver.configure("id_key nested.request_id\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_id'], '42')
    end

    def test_adds_nested_id_key_with_dollar_dot
      driver.configure("id_key $.nested.request_id\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_id'], '42')
    end

    def test_adds_nested_id_key_with_bracket
      driver.configure("id_key $['nested']['request_id']\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_id'], '42')
    end
  end

  def test_doesnt_add_id_key_if_missing_when_configured
    driver.configure("id_key another_request_id\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_id'))
  end

  def test_adds_id_key_when_not_configured
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_id'))
  end

  def test_adds_parent_key_when_configured
    driver.configure("parent_key parent_id\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(index_cmds[0]['index']['_parent'], 'parent')
  end

  class NestedParentKeyTest < self
    def test_adds_nested_parent_key_with_dot
      driver.configure("parent_key nested.parent_id\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_parent'], 'parent')
    end

    def test_adds_nested_parent_key_with_dollar_dot
      driver.configure("parent_key $.nested.parent_id\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_parent'], 'parent')
    end

    def test_adds_nested_parent_key_with_bracket
      driver.configure("parent_key $['nested']['parent_id']\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_parent'], 'parent')
    end
  end

  def test_doesnt_add_parent_key_if_missing_when_configured
    driver.configure("parent_key another_parent_id\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_parent'))
  end

  def test_adds_parent_key_when_not_configured
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_parent'))
  end

  def test_adds_routing_key_when_configured
    driver.configure("routing_key routing_id\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(index_cmds[0]['index']['_routing'], 'routing')
  end

  class NestedRoutingKeyTest < self
    def test_adds_nested_routing_key_with_dot
      driver.configure("routing_key nested.routing_id\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_routing'], 'routing')
    end

    def test_adds_nested_routing_key_with_dollar_dot
      driver.configure("routing_key $.nested.routing_id\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_routing'], 'routing')
    end

    def test_adds_nested_routing_key_with_bracket
      driver.configure("routing_key $['nested']['routing_id']\n")
      stub_elastic_ping
      stub_elastic
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal(index_cmds[0]['index']['_routing'], 'routing')
    end
  end

  def test_doesnt_add_routing_key_if_missing_when_configured
    driver.configure("routing_key another_routing_id\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_routing'))
  end

  def test_adds_routing_key_when_not_configured
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_routing'))
  end

  def test_remove_one_key
    driver.configure("remove_keys key1\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('key1' => 'v1', 'key2' => 'v2'))
    end
    assert(!index_cmds[1].has_key?('key1'))
    assert(index_cmds[1].has_key?('key2'))
  end

  def test_remove_multi_keys
    driver.configure("remove_keys key1, key2\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('key1' => 'v1', 'key2' => 'v2'))
    end
    assert(!index_cmds[1].has_key?('key1'))
    assert(!index_cmds[1].has_key?('key2'))
  end

  def test_request_error
    stub_elastic_ping
    stub_elastic_unavailable
    assert_raise(Elasticsearch::Transport::Transport::Errors::ServiceUnavailable) {
      driver.run(default_tag: 'test') do
        driver.feed(sample_record)
      end
    }
  end

  def test_request_forever
    stub_elastic_ping
    stub_elastic
    driver.configure(Fluent::Config::Element.new(
               'ROOT', '', {
                 '@type' => 'elasticsearch',
               }, [
                 Fluent::Config::Element.new('buffer', '', {
                                               'retry_forever' => true
                                             }, [])
               ]
             ))
    stub_elastic_timeout
    driver.run(default_tag: 'test', timeout: 10) do
      driver.feed(sample_record)
    end
  end

  def test_connection_failed_retry
    connection_resets = 0

    stub_elastic_ping(url="http://localhost:9200").with do |req|
      connection_resets += 1
    end

    stub_request(:post, "http://localhost:9200/_bulk").with do |req|
      raise Faraday::ConnectionFailed, "Test message"
    end

    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(connection_resets, 3)
  end

  def test_reconnect_on_error_enabled
    connection_resets = 0

    stub_elastic_ping(url="http://localhost:9200").with do |req|
      connection_resets += 1
    end

    stub_request(:post, "http://localhost:9200/_bulk").with do |req|
      raise ZeroDivisionError, "any not host_unreachable_exceptions exception"
    end

    driver.configure("reconnect_on_error true\n")

    assert_raise(ZeroDivisionError) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }

    assert_raise(Timeout::Error) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }
    # FIXME: Consider keywords arguments in #run and how to test this later.
    # Because v0.14 test driver does not have 1 to 1 correspondence between #run and #flush in tests.
    assert_equal(connection_resets, 1)
  end

  def test_reconnect_on_error_disabled
    connection_resets = 0

    stub_elastic_ping(url="http://localhost:9200").with do |req|
      connection_resets += 1
    end

    stub_request(:post, "http://localhost:9200/_bulk").with do |req|
      raise ZeroDivisionError, "any not host_unreachable_exceptions exception"
    end

    driver.configure("reconnect_on_error false\n")

    assert_raise(ZeroDivisionError) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }

    assert_raise(Timeout::Error) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }
    assert_equal(connection_resets, 1)
  end

  def test_bulk_error_retags_when_configured
    driver.configure("retry_tag retry\n")
    stub_elastic_ping
    stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json' },
        :body => %({
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
                  "reason":"some error to cause version mismatch"
                }
              }
            }
           ]
        })
     }
    end)

    driver.run(default_tag: 'test') do
      driver.feed(1, sample_record)
    end

    assert_equal [['retry', 1, sample_record]], driver.events
  end

  def test_create_should_write_records_with_ids_and_skip_those_without
    driver.configure("write_operation create\nid_key my_id\n@log_level debug")
    stub_elastic_ping
    stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json' },
        :body => %({
          "took" : 1,
          "errors" : true,
          "items" : [
            {
              "create" : {
                "_index" : "foo",
                "_type"  : "bar",
                "_id" : "abc"
              }
            },
            {
              "create" : {
                "_index" : "foo",
                "_type"  : "bar",
                "_id" : "xyz",
                "status" : 500,
                "error" : {
                  "type" : "some unrecognized type",
                  "reason":"some error to cause version mismatch"
                }
              }
            }
           ]
        })
     }
    end)
    sample_record1 = sample_record('my_id' => 'abc')
    sample_record4 = sample_record('my_id' => 'xyz')

    driver.run(default_tag: 'test') do
      driver.feed(1, sample_record1)
      driver.feed(2, sample_record)
      driver.feed(3, sample_record)
      driver.feed(4, sample_record4)
    end

    logs = driver.logs
    # one record succeeded while the other should be 'retried'
    assert_equal [['test', 4, sample_record4]], driver.events
    assert_logs_include(logs, /(Dropping record)/, 2)
  end

  def test_create_should_write_records_with_ids_and_emit_those_without
    driver.configure("write_operation create\nid_key my_id\nemit_error_for_missing_id true\n@log_level debug")
    stub_elastic_ping
    stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json' },
        :body => %({
          "took" : 1,
          "errors" : true,
          "items" : [
            {
              "create" : {
                "_index" : "foo",
                "_type"  : "bar",
                "_id" : "abc"
              }
            },
            {
              "create" : {
                "_index" : "foo",
                "_type"  : "bar",
                "_id" : "xyz",
                "status" : 500,
                "error" : {
                  "type" : "some unrecognized type",
                  "reason":"some error to cause version mismatch"
                }
              }
            }
           ]
        })
     }
    end)
    sample_record1 = sample_record('my_id' => 'abc')
    sample_record4 = sample_record('my_id' => 'xyz')

    driver.run(default_tag: 'test') do
      driver.feed(1, sample_record1)
      driver.feed(2, sample_record)
      driver.feed(3, sample_record)
      driver.feed(4, sample_record4)
    end

    error_log = driver.error_events.map {|e| e.last.message }
    # one record succeeded while the other should be 'retried'
    assert_equal [['test', 4, sample_record4]], driver.events
    assert_logs_include(error_log, /(Missing '_id' field)/, 2)
  end

  def test_bulk_error
    stub_elastic_ping
    stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json' },
        :body => %({
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
                "_id" : "abc",
                "status" : 409
              }
            }
           ]
        })
     }
    end)

    driver.run(default_tag: 'test') do
      driver.feed(1, sample_record)
      driver.feed(2, sample_record)
      driver.feed(3, sample_record)
      driver.feed(4, sample_record)
    end

    expect = [['test', 1, sample_record],
              ['test', 3, sample_record]]
    assert_equal expect, driver.events
  end

  def test_update_should_not_write_if_theres_no_id
    driver.configure("write_operation update\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds)
  end

  def test_upsert_should_not_write_if_theres_no_id
    driver.configure("write_operation upsert\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds)
  end

  def test_create_should_not_write_if_theres_no_id
    driver.configure("write_operation create\n")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds)
  end

  def test_update_should_write_update_op_and_doc_as_upsert_is_false
    driver.configure("write_operation update
                      id_key request_id")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(index_cmds[0].has_key?("update"))
    assert(!index_cmds[1]["doc_as_upsert"])
    assert(!index_cmds[1]["upsert"])
  end

  def test_update_should_remove_keys_from_doc_when_keys_are_skipped
    driver.configure("write_operation update
                      id_key request_id
                      remove_keys_on_update parent_id")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(index_cmds[1]["doc"])
    assert(!index_cmds[1]["doc"]["parent_id"])
  end

  def test_upsert_should_write_update_op_and_doc_as_upsert_is_true
    driver.configure("write_operation upsert
                      id_key request_id")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(index_cmds[0].has_key?("update"))
    assert(index_cmds[1]["doc_as_upsert"])
    assert(!index_cmds[1]["upsert"])
  end

  def test_upsert_should_write_update_op_upsert_and_doc_when_keys_are_skipped
    driver.configure("write_operation upsert
                      id_key request_id
                      remove_keys_on_update parent_id")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(index_cmds[0].has_key?("update"))
    assert(!index_cmds[1]["doc_as_upsert"])
    assert(index_cmds[1]["upsert"])
    assert(index_cmds[1]["doc"])
  end

  def test_upsert_should_remove_keys_from_doc_when_keys_are_skipped
    driver.configure("write_operation upsert
                      id_key request_id
                      remove_keys_on_update parent_id")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(index_cmds[1]["upsert"] != index_cmds[1]["doc"])
    assert(!index_cmds[1]["doc"]["parent_id"])
    assert(index_cmds[1]["upsert"]["parent_id"])
  end

  def test_upsert_should_remove_multiple_keys_when_keys_are_skipped
    driver.configure("write_operation upsert
                      id_key id
                      remove_keys_on_update foo,baz")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed("id" => 1, "foo" => "bar", "baz" => "quix", "zip" => "zam")
    end
    assert(
      index_cmds[1]["doc"] == {
        "id" => 1,
        "zip" => "zam",
      }
    )
    assert(
      index_cmds[1]["upsert"] == {
        "id" => 1,
        "foo" => "bar",
        "baz" => "quix",
        "zip" => "zam",
      }
    )
  end

  def test_upsert_should_remove_keys_from_when_the_keys_are_in_the_record
    driver.configure("write_operation upsert
                      id_key id
                      remove_keys_on_update_key keys_to_skip")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed("id" => 1, "foo" => "bar", "baz" => "quix", "keys_to_skip" => ["baz"])
    end
    assert(
      index_cmds[1]["doc"] == {
        "id" => 1,
        "foo" => "bar",
      }
    )
    assert(
      index_cmds[1]["upsert"] == {
        "id" => 1,
        "foo" => "bar",
        "baz" => "quix",
      }
    )
  end

  def test_upsert_should_remove_keys_from_key_on_record_has_higher_presedence_than_config
    driver.configure("write_operation upsert
                      id_key id
                      remove_keys_on_update foo,bar
                      remove_keys_on_update_key keys_to_skip")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed("id" => 1, "foo" => "bar", "baz" => "quix", "keys_to_skip" => ["baz"])
    end
    assert(
      index_cmds[1]["doc"] == {
        "id" => 1,
        # we only expect baz to be stripped here, if the config was more important
        # foo would be stripped too.
        "foo" => "bar",
      }
    )
    assert(
      index_cmds[1]["upsert"] == {
        "id" => 1,
        "foo" => "bar",
        "baz" => "quix",
      }
    )
  end

  def test_create_should_write_create_op
    driver.configure("write_operation create
                      id_key request_id")
    stub_elastic_ping
    stub_elastic
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(index_cmds[0].has_key?("create"))
  end

  def test_include_index_in_url
    stub_elastic_ping
    stub_elastic('http://localhost:9200/logstash-2018.01.01/_bulk')

    driver.configure("index_name logstash-2018.01.01
                      include_index_in_url true")
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end

    assert_equal(index_cmds.length, 2)
    assert_equal(index_cmds.first['index']['_index'], nil)
  end

  def test_use_simple_sniffer
    require 'fluent/plugin/elasticsearch_simple_sniffer'
    stub_elastic_ping
    stub_elastic_info
    stub_elastic
    config = %[
      sniffer_class_name Fluent::Plugin::ElasticsearchSimpleSniffer
      log_level debug
      with_transporter_log true
      reload_connections true
      reload_after 1
    ]
    driver(config, nil)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    log = driver.logs
    # 2 or 3 - one for the ping, one for the _bulk, (and client.info)
    assert_logs_include_compare_size(4, ">", log, /In Fluent::Plugin::ElasticsearchSimpleSniffer hosts/)
    assert_logs_include_compare_size(2, "<=", log, /In Fluent::Plugin::ElasticsearchSimpleSniffer hosts/)
  end

end
