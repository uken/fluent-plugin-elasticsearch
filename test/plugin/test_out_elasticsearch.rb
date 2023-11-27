require_relative '../helper'
require 'date'
require 'fluent/test/helpers'
require 'json'
require 'fluent/test/driver/output'
require 'flexmock/test_unit'
require 'fluent/plugin/out_elasticsearch'

class ElasticsearchOutputTest < Test::Unit::TestCase
  include FlexMock::TestCase
  include Fluent::Test::Helpers

  attr_accessor :index_cmds, :index_command_counts, :index_cmds_all_requests

  def setup
    Fluent::Test.setup
    @driver = nil
    log = Fluent::Engine.log
    log.out.logs.slice!(0, log.out.logs.length)
  end

  def elasticsearch_version
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.14.0")
      TRANSPORT_CLASS::VERSION.split(".")[0..1].join(".")
    else
      "7.17".freeze
    end
  end

  def driver(conf='', es_version=elasticsearch_version.to_i, client_version="\"#{elasticsearch_version}\"")
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

  def elasticsearch_transport_layer_decoupling?
    Gem::Version.create(::TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.14.0")
  end

  def elastic_perform_request_refactored?
    Gem::Version.create(Elasticsearch::VERSION) >= Gem::Version.new("8.8.0")
  end

  def elastic_transport_layer?
    Gem::Version.create(::TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
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

  def stub_elastic_info(url="http://localhost:9200/", version=elasticsearch_version)
    body ="{\"version\":{\"number\":\"#{version}\", \"build_flavor\":\"default\"},\"tagline\" : \"You Know, for Search\"}"
    stub_request(:get, url)
      .to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json', 'X-elastic-product' => 'Elasticsearch' } })
  end

  def stub_elastic(url="http://localhost:9200/_bulk")
    stub_request(:post, url).with do |req|
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
    end.to_return({:status => 200, :body => "", :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
  end

  def stub_elastic_all_requests(url="http://localhost:9200/_bulk")
    @index_cmds_all_requests = Array.new
    stub_request(:post, url).with do |req|
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
      @index_cmds_all_requests << @index_cmds
    end.to_return({:status => 200, :body => "", :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
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
    end.to_return({:status => 200, :body => "{}", :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
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
    stub_request(:post, url).to_return(lambda { |req| { :status => 200, :body => make_response_body(req, 1, 400, error), :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'  } } })
  end

  def stub_elastic_bulk_error(url="http://localhost:9200/_bulk")
    error = {
      "type" => "some-unrecognized-error",
      "reason" => "some message printed here ...",
    }
    stub_request(:post, url).to_return(lambda { |req| { :status => 200, :body => make_response_body(req, 1, 500, error), :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'  } } })
  end

  def stub_elastic_bulk_rejected(url="http://localhost:9200/_bulk")
    error = {
      "status" => 500,
      "type" => "es_rejected_execution_exception",
      "reason" => "rejected execution of org.elasticsearch.transport.TransportService$4@1a34d37a on EsThreadPoolExecutor[bulk, queue capacity = 50, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@312a2162[Running, pool size = 32, active threads = 32, queued tasks = 50, completed tasks = 327053]]"
    }
    stub_request(:post, url).to_return(lambda { |req| { :status => 200, :body => make_response_body(req, 1, 429, error), :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'  } } })
  end

  def stub_elastic_out_of_memory(url="http://localhost:9200/_bulk")
    error = {
      "status" => 500,
      "type" => "out_of_memory_error",
      "reason" => "Java heap space"
    }
    stub_request(:post, url).to_return(lambda { |req| { :status => 200, :body => make_response_body(req, 1, 500, error), :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'  } } })
  end

  def stub_elastic_unexpected_response_op(url="http://localhost:9200/_bulk")
    error = {
      "category" => "some-other-type",
      "reason" => "some-other-reason"
    }
    stub_request(:post, url).to_return(lambda { |req| bodystr = make_response_body(req, 0, 500, error); body = JSON.parse(bodystr); body['items'][0]['unknown'] = body['items'][0].delete('create'); { :status => 200, :body => body.to_json, :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'  } } })
  end

  def assert_logs_include(logs, msg, exp_matches=1)
    matches = logs.grep /#{msg}/
    assert_equal(exp_matches, matches.length, "Logs do not contain '#{msg}' '#{logs}'")
  end

  def assert_logs_include_compare_size(exp_matches=1, operator="<=", logs="", msg="")
    matches = logs.grep /#{msg}/
    assert_compare(exp_matches, operator, matches.length, "Logs do not contain '#{msg}' '#{logs}'")
  end

  def alias_endpoint
    if Gem::Version.create(::Elasticsearch::VERSION) >= Gem::Version.create("7.5.0-pre")
      "_aliases"
    else
      "_alias"
    end
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
    assert_equal Fluent::Plugin::ElasticsearchTLS::DEFAULT_VERSION, instance.ssl_version
    assert_nil instance.ssl_max_version
    assert_nil instance.ssl_min_version
    if Fluent::Plugin::ElasticsearchTLS::USE_TLS_MINMAX_VERSION
      if defined?(OpenSSL::SSL::TLS1_3_VERSION)
        assert_equal({max_version: OpenSSL::SSL::TLS1_3_VERSION, min_version: OpenSSL::SSL::TLS1_2_VERSION},
                     instance.ssl_version_options)
      else
        assert_equal({max_version: nil, min_version: OpenSSL::SSL::TLS1_2_VERSION},
                     instance.ssl_version_options)
      end
    else
      assert_equal({version: Fluent::Plugin::ElasticsearchTLS::DEFAULT_VERSION},
                   instance.ssl_version_options)
    end
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
    assert_equal -1, Fluent::Plugin::ElasticsearchOutput::DEFAULT_TARGET_BULK_BYTES
    assert_false instance.compression
    assert_equal :no_compression, instance.compression_level
    assert_true instance.http_backend_excon_nonblock
    assert_equal({}, instance.api_key_header)
  end

  test 'configure compression' do
    omit "elastisearch-ruby v7.2.0 or later is needed." if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.2.0")

    config = %{
      compression_level best_compression
    }
    instance = driver(config).instance

    assert_equal true, instance.compression
  end

  test 'check compression strategy' do
    omit "elastisearch-ruby v7.2.0 or later is needed." if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.2.0")

    config = %{
      compression_level best_speed
    }
    instance = driver(config).instance

    assert_equal Zlib::BEST_SPEED, instance.compression_strategy
  end

  test 'check content-encoding header with compression' do
    omit "elastisearch-ruby v7.2.0 or later is needed." if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.2.0")

    config = %{
      compression_level best_compression
    }
    instance = driver(config).instance

    if elastic_transport_layer?
      assert_equal nil, instance.client.transport.options[:transport_options][:headers]["Content-Encoding"]
    elsif elasticsearch_transport_layer_decoupling?
      assert_equal nil, instance.client.transport.transport.options[:transport_options][:headers]["Content-Encoding"]
    else
      assert_equal nil, instance.client.transport.options[:transport_options][:headers]["Content-Encoding"]
    end

    stub_request(:post, "http://localhost:9200/_bulk").
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    compressable = instance.compressable_connection

    if elastic_transport_layer?
      assert_equal "gzip", instance.client(nil, compressable).transport.options[:transport_options][:headers]["Content-Encoding"]
    elsif elasticsearch_transport_layer_decoupling?
      assert_equal "gzip", instance.client(nil, compressable).transport.transport.options[:transport_options][:headers]["Content-Encoding"]
    else
      assert_equal "gzip", instance.client(nil, compressable).transport.options[:transport_options][:headers]["Content-Encoding"]
    end
  end

  test 'check compression option is passed to transport' do
    omit "elastisearch-ruby v7.2.0 or later is needed." if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.2.0")

    config = %{
      compression_level best_compression
    }
    instance = driver(config).instance

    if elastic_transport_layer?
      assert_equal false, instance.client.transport.options[:compression]
    elsif elasticsearch_transport_layer_decoupling?
      assert_equal false, instance.client.transport.transport.options[:compression]
    else
      assert_equal false, instance.client.transport.options[:compression]
    end

    stub_request(:post, "http://localhost:9200/_bulk").
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch' })
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    compressable = instance.compressable_connection

    if elastic_transport_layer?
      assert_equal true, instance.client(nil, compressable).transport.options[:compression]
    elsif elasticsearch_transport_layer_decoupling?
      assert_equal true, instance.client(nil, compressable).transport.transport.options[:compression]
    else
      assert_equal true, instance.client(nil, compressable).transport.options[:compression]
    end
  end

  test 'check configure cloud_id based client' do

    config = %{
      cloud_id "name:bG9jYWxob3N0JGFiY2QkZWZnaA=="
      cloud_auth "some:auth"
    }
    instance = driver(config).instance

    assert_equal "name:bG9jYWxob3N0JGFiY2QkZWZnaA==", instance.cloud_id
    assert_equal "some", instance.user
    assert_equal "auth", instance.password
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
      driver(config)
    }
  end

  test 'invalid specification of times of retrying template installation' do
    config = %{
      max_retry_putting_template -3
    }
    assert_raise(Fluent::ConfigError) {
      driver(config)
    }
  end

  test 'invalid specification of times of retrying get es version' do
    config = %{
      max_retry_get_es_version -3
    }
    assert_raise(Fluent::ConfigError) {
      driver(config)
    }
  end

  sub_test_case 'Check client.info response' do
    def create_driver(conf='', es_version=5, client_version="\"5.0\"")
      # For request stub to detect compatibility.
      @client_version ||= client_version
      @default_elasticsearch_version ||= es_version
      Fluent::Plugin::ElasticsearchOutput.module_eval(<<-CODE)
        def detect_es_major_version
          @_es_info ||= client.info
          begin
            unless version = @_es_info.dig("version", "number")
              version = @default_elasticsearch_version
            end
          rescue NoMethodError => e
            log.warn "#{@_es_info} can not dig version information. Assuming Elasticsearch #{@default_elasticsearch_version}", error: e
            version = @default_elasticsearch_version
          end
          version.to_i
        end
      CODE

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

    def stub_elastic_info_bad(url="http://localhost:9200/", version="6.4.2")
      body ="{\"version\":{\"number\":\"#{version}\",\"build_flavor\":\"default\"},\"tagline\":\"You Know, for Search\"}"
      stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'text/plain', 'x-elastic-product' => 'Elasticsearch'} })
    end

    test 'handle invalid client.info' do
      stub_elastic_info_bad("https://logs.fluentd.com:24225/es//", elasticsearch_version)
      config = %{
        host     logs.fluentd.com
        port     24225
        scheme   https
        path     /es/
        user     john
        password doe
        default_elasticsearch_version 7
        scheme https
        @log_level info
      }
      if elastic_perform_request_refactored?
        d = create_driver(config, 8, "\"8.8.0\"")
        logs = d.logs
        assert_logs_include(logs, /Detected ES 7.x: `_doc` will be used as the document `_type`./)
      elsif elastic_transport_layer?
        assert_raise(NoMethodError) do
          d = create_driver(config, 8, "\"8.0.0\"")
        end
      elsif elasticsearch_transport_layer_decoupling?
        assert_raise(NoMethodError) do
          d = create_driver(config, 7, "\"7.10.1\"")
        end
      else
        d = create_driver(config, 7, "\"7.10.1\"")
        logs = d.logs
        assert_logs_include(logs, /can not dig version information. Assuming Elasticsearch 7/)
      end
    end
  end

  sub_test_case 'Check TLS handshake stuck warning log' do
    test 'warning TLS log' do
      config = %{
        scheme https
        http_backend_excon_nonblock false
        ssl_version TLSv1_2
        @log_level info
      }
      driver(config)
      logs = driver.logs
      assert_logs_include(logs, /TLS handshake will be stucked with block connection.\n                    Consider to set `http_backend_excon_nonblock` as true\n/)
    end
  end

  sub_test_case 'ILM default config' do
    setup do
      if Gem::Version.new(TRANSPORT_CLASS::VERSION) < Gem::Version.new("8.0.0")
        begin
          require "elasticsearch/xpack"
        rescue LoadError
          omit "ILM testcase needs elasticsearch-xpack gem."
        end
      end
    end

    def ilm_endpoint
      '_ilm'.freeze
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    test 'valid configuration of index lifecycle management' do |data|
      if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.4.0")
        omit "elastisearch-ruby v7.4.0 or later is needed for ILM."
      end
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = File.join(cwd, 'test_template.json')

      config = %{
        enable_ilm    true
        template_name logstash
        template_file #{template_file}
        use_legacy_template #{use_legacy_template_flag}
      }
      stub_request(:get, "http://localhost:9200/#{endpoint}/fluentd").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:head, "http://localhost:9200/_alias/fluentd").
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "http://localhost:9200/%3Cfluentd-default-%7Bnow%2Fd%7D-000001%3E/#{alias_endpoint}/fluentd").
        with(body: "{\"aliases\":{\"fluentd\":{\"is_write_index\":true}}}").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "http://localhost:9200/%3Cfluentd-default-%7Bnow%2Fd%7D-000001%3E").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "http://localhost:9200/_xpack").
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}',
                  :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "http://localhost:9200/#{ilm_endpoint}/policy/logstash-policy").
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "http://localhost:9200/#{ilm_endpoint}/policy/logstash-policy").
        with(body: "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info

      assert_nothing_raised {
        driver(config)
      }
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    test 'valid configuration of overwriting ilm_policy' do |data|
      if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.4.0")
        omit "elastisearch-ruby v7.4.0 or later is needed for ILM."
      end
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = File.join(cwd, 'test_template.json')

      config = %{
        enable_ilm    true
        template_name logstash
        template_file #{template_file}
        ilm_policy_overwrite true
        ilm_policy {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"75gb","max_age": "50d"}}}}}}
        use_legacy_template #{use_legacy_template_flag}
      }
      stub_request(:get, "http://localhost:9200/#{endpoint}/fluentd").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:head, "http://localhost:9200/_alias/fluentd").
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "http://localhost:9200/%3Cfluentd-default-%7Bnow%2Fd%7D-000001%3E/#{alias_endpoint}/fluentd").
        with(body: "{\"aliases\":{\"fluentd\":{\"is_write_index\":true}}}").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "http://localhost:9200/%3Cfluentd-default-%7Bnow%2Fd%7D-000001%3E").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "http://localhost:9200/_xpack").
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}',
                  :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "http://localhost:9200/#{ilm_endpoint}/policy/logstash-policy").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "http://localhost:9200/#{ilm_endpoint}/policy/logstash-policy").
        with(body: "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"75gb\",\"max_age\":\"50d\"}}}}}}").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info

      assert_nothing_raised {
        driver(config)
      }
    end

    test 'invalid configuration of overwriting ilm_policy' do
      cwd = File.dirname(__FILE__)
      template_file = File.join(cwd, 'test_template.json')

      config = %{
        enable_ilm    true
        template_name logstash
        template_file #{template_file}
        ilm_policy_overwrite true
      }
      stub_elastic_info

      assert_raise(Fluent::ConfigError) {
        driver(config)
      }
    end
  end

  test 'Detected Elasticsearch 7' do
    config = %{
      type_name changed
    }
    instance = driver(config, 7).instance
    assert_equal '_doc', instance.type_name
  end

  test 'Detected Elasticsearch 8' do
    config = %{
      type_name noeffect
    }
    instance = driver(config, 8).instance
    assert_equal nil, instance.type_name
  end

  test 'Detected Elasticsearch 6 and insecure security' do
    config = %{
      ssl_version TLSv1_1
      @log_level warn
      scheme https
    }
    driver(config, 6)
    logs = driver.logs
    assert_logs_include(logs, /Detected ES 6.x or above and enabled insecure security/, 1)
  end

  test 'Detected Elasticsearch 7 and secure security' do
    config = %{
      ssl_version TLSv1_2
      @log_level warn
      scheme https
    }
    driver(config, 7)
    logs = driver.logs
    assert_logs_include(logs, /Detected ES 6.x or above and enabled insecure security/, 0)
  end

  test 'Pass Elasticsearch and client library are same' do
    config = %{
      @log_level warn
      validate_client_version true
    }
    assert_nothing_raised do
      driver(config, 6, "\"6.1.0\"")
    end
  end

  test 'Detected Elasticsearch and client library mismatch' do
    config = %{
      @log_level warn
      validate_client_version true
    }
    assert_raise_message(/Detected ES 7 but you use ES client 5.0/) do
      driver(config, 7, "\"5.0.5\"")
    end
  end

  sub_test_case "placeholder substitution needed?" do
    data("host placeholder" => ["host", "host-${tag}.google.com"],
         "index_name_placeholder" => ["index_name", "logstash-${tag}"],
         "template_name_placeholder" => ["template_name", "logstash-${tag}"],
         "customize_template" => ["customize_template", '{"<<TAG>>":"${tag}"}'],
         "logstash_prefix_placeholder" => ["logstash_prefix", "fluentd-${tag}"],
         "deflector_alias_placeholder" => ["deflector_alias", "fluentd-${tag}"],
         "application_name_placeholder" => ["application_name", "fluentd-${tag}"],
        )
    test 'tag placeholder' do |data|
      param, value = data
      config = Fluent::Config::Element.new(
        'ROOT', '', {
          '@type' => 'elasticsearch',
          param => value
        }, [
          Fluent::Config::Element.new('buffer', 'tag', {}, [])
        ])
      driver(config)

      assert_true driver.instance.placeholder_substitution_needed_for_template?
    end


    data("host placeholder" => ["host", "host-%Y%m%d.google.com"],
         "index_name_placeholder" => ["index_name", "logstash-%Y%m%d"],
         "template_name_placeholder" => ["template_name", "logstash-%Y%m%d"],
         "customize_template" => ["customize_template", '{"<<TAG>>":"fluentd-%Y%m%d"}'],
         "logstash_prefix_placeholder" => ["logstash_prefix", "fluentd-%Y%m%d"],
         "deflector_alias_placeholder" => ["deflector_alias", "fluentd-%Y%m%d"],
         "application_name_placeholder" => ["application_name", "fluentd-%Y%m%d"],
        )
    test 'time placeholder' do |data|
      param, value = data
      config = Fluent::Config::Element.new(
        'ROOT', '', {
          '@type' => 'elasticsearch',
          param => value
        }, [
          Fluent::Config::Element.new('buffer', 'time', {
                                        'timekey' => '1d'
                                      }, [])
        ])
      driver(config)

      assert_true driver.instance.placeholder_substitution_needed_for_template?
    end

    data("host placeholder" => ["host", "host-${mykey}.google.com"],
         "index_name_placeholder" => ["index_name", "logstash-${mykey}"],
         "template_name_placeholder" => ["template_name", "logstash-${mykey}"],
         "customize_template" => ["customize_template", '{"<<TAG>>":"${mykey}"}'],
         "logstash_prefix_placeholder" => ["logstash_prefix", "fluentd-${mykey}"],
         "logstash_dateformat_placeholder" => ["logstash_dateformat", "${mykey}"],
         "deflector_alias_placeholder" => ["deflector_alias", "fluentd-${mykey}"],
         "application_name_placeholder" => ["application_name", "fluentd-${mykey}"],
        )
    test 'custom placeholder' do |data|
      param, value = data
      config = Fluent::Config::Element.new(
        'ROOT', '', {
          '@type' => 'elasticsearch',
          param => value
        }, [
          Fluent::Config::Element.new('buffer', 'mykey', {
                                        'chunk_keys' => 'mykey',
                                        'timekey' => '1d',
                                      }, [])
        ])
      driver(config)

      assert_true driver.instance.placeholder_substitution_needed_for_template?
    end

    data("host placeholder" => ["host", "host-${tag}.google.com"],
         "index_name_placeholder" => ["index_name", "logstash-${es_index}-%Y%m%d"],
         "template_name_placeholder" => ["template_name", "logstash-${tag}-%Y%m%d"],
         "customize_template" => ["customize_template", '{"<<TAG>>":"${es_index}"}'],
         "logstash_prefix_placeholder" => ["logstash_prefix", "fluentd-${es_index}-%Y%m%d"],
         "logstash_dataformat_placeholder" => ["logstash_dateformat", "${es_index}"],
         "deflector_alias_placeholder" => ["deflector_alias", "fluentd-%Y%m%d"],
         "application_name_placeholder" => ["application_name", "fluentd-${tag}-${es_index}-%Y%m%d"],
        )
    test 'mixed placeholder' do |data|
      param, value = data
      config = Fluent::Config::Element.new(
        'ROOT', '', {
          '@type' => 'elasticsearch',
          param => value
        }, [
          Fluent::Config::Element.new('buffer', 'tag,time,es_index', {
                                        'chunk_keys' => 'es_index',
                                        'timekey' => '1d',
                                      }, [])
        ])
      driver(config)

      assert_true driver.instance.placeholder_substitution_needed_for_template?
    end
  end

  sub_test_case 'chunk_keys requirement' do
    test 'tag in chunk_keys' do
      assert_nothing_raised do
        driver(Fluent::Config::Element.new(
                 'ROOT', '', {
                   '@type' => 'elasticsearch',
                   'host' => 'log.google.com',
                   'port' => 777,
                   'scheme' => 'https',
                   'path' => '/es/',
                   'user' => 'john',
                   'password' => 'doe',
                 }, [
                   Fluent::Config::Element.new('buffer', 'tag', {
                                                 'chunk_keys' => 'tag'
                                               }, [])
                 ]
               ))
      end
    end

    test '_index in chunk_keys' do
      assert_nothing_raised do
        driver(Fluent::Config::Element.new(
                 'ROOT', '', {
                   '@type' => 'elasticsearch',
                   'host' => 'log.google.com',
                   'port' => 777,
                   'scheme' => 'https',
                   'path' => '/es/',
                   'user' => 'john',
                   'password' => 'doe',
                 }, [
                   Fluent::Config::Element.new('buffer', '_index', {
                                                 'chunk_keys' => '_index'
                                               }, [])
                 ]
               ))
      end
    end

    test 'lack of tag and _index in chunk_keys' do
      assert_raise_message(/'tag' or '_index' in chunk_keys is required./) do
        driver(Fluent::Config::Element.new(
                 'ROOT', '', {
                   '@type' => 'elasticsearch',
                   'host' => 'log.google.com',
                   'port' => 777,
                   'scheme' => 'https',
                   'path' => '/es/',
                   'user' => 'john',
                   'password' => 'doe',
                 }, [
                   Fluent::Config::Element.new('buffer', 'mykey', {
                                                 'chunk_keys' => 'mykey'
                                               }, [])
                 ]
               ))
      end
    end
  end

  test 'Detected exclusive features which are host placeholder, template installation, and verify Elasticsearch version at startup' do
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_template.json')

    assert_raise_message(/host placeholder, template installation, and verify Elasticsearch version at startup are exclusive feature at same time./) do
      config = %{
        host            logs-${tag}.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        verify_es_version_at_startup true
        default_elasticsearch_version 6
      }
      driver(config)
    end
  end

  class GetElasticsearchIncompatibleVersionTest < self
    def create_driver(conf='', client_version="7.14")
      # For request stub to detect compatibility.
      @client_version ||= client_version
      # Ensure original implementation existence.
      Fluent::Plugin::ElasticsearchOutput.module_eval(<<-CODE)
        def detect_es_major_version
          begin
            @_es_info ||= client.info
          rescue ::Elasticsearch::UnsupportedProductError => e
            raise Fluent::ConfigError, "Using Elasticsearch client #{@client_version} is not compatible for your Elasticsearch server. Please check your using elasticsearch gem version and Elasticsearch server."
          end
          begin
            unless version = @_es_info.dig("version", "number")
              version = @default_elasticsearch_version
            end
          rescue NoMethodError => e
            log.warn "#{@_es_info} can not dig version information. Assuming Elasticsearch #{@default_elasticsearch_version}", error: e
            version = @default_elasticsearch_version
          end
          version.to_i
        end
      CODE
      Fluent::Plugin::ElasticsearchOutput.module_eval(<<-CODE)
        def client_library_version
          #{@client_version}
        end
      CODE
      Fluent::Test::Driver::Output.new(Fluent::Plugin::ElasticsearchOutput).configure(conf)
    end

    def test_incompatible_es_version
      if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.14.0")
        omit "This test is not effective before elasticsearch 7.14"
      end
      config = %{
        host            logs.google.com
        port            778
        scheme          https
        path            /es/
        user            john
        password        doe
        verify_es_version_at_startup true
        max_retry_get_es_version 1
      }

      connection_resets = 0
      stub_request(:get, "https://logs.google.com:778/es//").
        with(basic_auth: ['john', 'doe']) do |req|
        connection_resets += 1
        raise ::Elasticsearch::UnsupportedProductError
      end

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end

      assert_equal(1, connection_resets)
    end
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_template_already_present(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   /abc123
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_not_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash")
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_template_create(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   #{template_file}
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_template_create_with_rollover_index_and_template_related_placeholders(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end
   config = %{
      host               logs.google.com
      port               777
      scheme             https
      path               /es/
      user               john
      password           doe
      template_name      logstash-${tag}
      template_file      #{template_file}
      rollover_index     true
      index_date_pattern ""
      index_name         fluentd-${tag}
      deflector_alias    myapp_deflector-${tag}
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
    to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash-test.template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # create template
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-test.template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if alias exists
    stub_request(:head, "https://logs.google.com:777/es//_alias/myapp_deflector-test.template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # put the alias for the index
    stub_request(:put, "https://logs.google.com:777/es//%3Cfluentd-test.template-default-000001%3E").
      with(basic_auth: ['john', 'doe']).
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//%3Cfluentd-test.template-default-000001%3E/#{alias_endpoint}/myapp_deflector-test.template").
      with(basic_auth: ['john', 'doe'],
           body: "{\"aliases\":{\"myapp_deflector-test.template\":{\"is_write_index\":true}}}").
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})

    driver(config)

    elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
    stub_elastic_info("https://logs.google.com:777/es//")
    driver.run(default_tag: 'test.template') do
      driver.feed(sample_record)
    end
    assert_equal('fluentd-test.template', index_cmds.first['index']['_index'])

    assert_equal ["myapp_deflector-test.template"], driver.instance.alias_indexes
    assert_equal ["logstash-test.template"], driver.instance.template_names

    assert_requested(elastic_request)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_template_create_with_rollover_index_and_template_related_placeholders_with_truncating_caches(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end
    config = %{
      host               logs.google.com
      port               777
      scheme             https
      path               /es/
      user               john
      password           doe
      template_name      logstash-${tag}
      template_file      #{template_file}
      rollover_index     true
      index_date_pattern ""
      index_name         fluentd-${tag}
      deflector_alias    myapp_deflector-${tag}
      truncate_caches_interval 2s
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
    to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash-test.template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # create template
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-test.template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if alias exists
    stub_request(:head, "https://logs.google.com:777/es//_alias/myapp_deflector-test.template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # put the alias for the index
    stub_request(:put, "https://logs.google.com:777/es//%3Cfluentd-test.template-default-000001%3E").
      with(basic_auth: ['john', 'doe']).
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//%3Cfluentd-test.template-default-000001%3E/#{alias_endpoint}/myapp_deflector-test.template").
      with(basic_auth: ['john', 'doe'],
           body: "{\"aliases\":{\"myapp_deflector-test.template\":{\"is_write_index\":true}}}").
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
    driver.run(default_tag: 'test.template', shutdown: false) do
      driver.feed(sample_record)
    end
    assert_equal('fluentd-test.template', index_cmds.first['index']['_index'])

    assert_equal ["myapp_deflector-test.template"], driver.instance.alias_indexes
    assert_equal ["logstash-test.template"], driver.instance.template_names

    assert_requested(elastic_request)

    sleep 0.1 until driver.instance.alias_indexes.empty?
    sleep 0.1 until driver.instance.template_names.empty?

    assert_equal [], driver.instance.alias_indexes
    assert_equal [], driver.instance.template_names
  end

  class TemplateIndexLifecycleManagementTest < self
    def setup
      if Gem::Version.new(Elasticsearch::VERSION) < Gem::Version.new("8.0.0")
        begin
          require "elasticsearch/xpack"
        rescue LoadError
          omit "ILM testcase needs elasticsearch-xpack gem."
        end
      end
      if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.4.0")
        omit "elastisearch-ruby v7.4.0 or later is needed for ILM."
      end
    end

    def ilm_endpoint
      '_ilm'.freeze
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_default_ilm(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = %{
        host            logs.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        index_date_pattern now/w{xxxx.ww}
        index_name      logstash
        enable_ilm      true
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"logstash-*\",\"order\":51}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":101}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"logstash\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_default_ilm_on_logstash_format(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = %{
        host            logs.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        index_date_pattern now/w{xxxx.ww}
        enable_ilm      true
        logstash_format true
        application_name log
        use_legacy_template #{use_legacy_template_flag}
      }

      date_str = Time.now.strftime("%Y.%m.%d")
      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash-#{date_str}").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-#{date_str}").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash-#{date_str}").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash-#{date_str}").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-#{date_str}").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash-log-#{date_str}\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"logstash-log-#{date_str}-*\",\"order\":53}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-#{date_str}").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash-log-2020.09.21-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash-2020.09.21\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":103}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-log-#{date_str}-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})

      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-log-#{date_str}-000001%3E/#{alias_endpoint}/logstash-#{date_str}").
        with(basic_auth: ['john', 'doe'],
             body: "{\"aliases\":{\"logstash-#{date_str}\":{\"is_write_index\":true}}}").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
      driver.run(default_tag: 'test') do
        driver.feed(sample_record)
      end
      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-#{date_str}", times: 1)

      assert_requested(elastic_request)
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_default_ilm_and_ilm_policy_overwrite(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = %{
        host            logs.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        index_date_pattern now/w{xxxx.ww}
        index_name      logstash
        enable_ilm      true
        ilm_policy_overwrite true
        ilm_policy {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"60gb","max_age": "45d"}}}}}}
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"logstash-*\",\"order\":51}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":101}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"logstash\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"60gb\",\"max_age\":\"45d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)
    end

    def test_template_create_with_rollover_index_and_default_ilm_with_deflector_alias
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
        index_date_pattern now/w{xxxx.ww}
        deflector_alias myapp_deflector
        index_name      logstash
        enable_ilm      true
      }

      # Should raise error because multiple alias indices IllegalArgument Error on executing ILM feature
      assert_raise(Fluent::ConfigError) do
        driver(config)
      end
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_default_ilm_with_empty_index_date_pattern(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = %{
        host            logs.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        index_date_pattern ""
        index_name      logstash
        enable_ilm      true
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_deflector").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"logstash-*\",\"order\":51}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_deflector").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":101}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-000001%3E/#{alias_endpoint}/logstash").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"logstash\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_custom_ilm(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = %{
        host            logs.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        index_date_pattern now/w{xxxx.ww}
        ilm_policy_id   fluentd-policy
        enable_ilm      true
        index_name      logstash
        ilm_policy      {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"70gb", "max_age":"30d"}}}}}}
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"myalogs\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"mylogs-*\",\"order\":51}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":101}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash").
        with(body: "{\"aliases\":{\"logstash\":{\"is_write_index\":true}}}").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"70gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_ilm_policies_and_placeholderstest_template_create_with_rollover_index_and_ilm_policies_and_placeholders(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = %{
        host            logs.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        index_date_pattern now/w{xxxx.ww}
        ilm_policy_id   fluentd-policy
        enable_ilm      true
        index_name      logstash
        ilm_policies    {"fluentd-policy":{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"70gb", "max_age":"30d"}}}}}}}
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"myalogs\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"mylogs-*\",\"order\":51}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":101}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash").
        with(body: "{\"aliases\":{\"logstash\":{\"is_write_index\":true}}}").
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"70gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
      driver.run(default_tag: 'test') do
        driver.feed(sample_record)
      end
      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)

      assert_requested(elastic_request)
    end

    class TemplateCreateWithRolloverIndexAndILMPoliciesWithPlaceholdersTest < self
      data("legacy_template" => [true, "_template"],
           "new_template"    => [false, "_index_template"])
      def test_tag_placeholder(data)
        use_legacy_template_flag, endpoint = data
        if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
          omit "elastisearch-ruby v7.8.0 or later is needed."
        end
        cwd = File.dirname(__FILE__)
        template_file = if use_legacy_template_flag
                          File.join(cwd, 'test_template.json')
                        else
                          File.join(cwd, 'test_index_template.json')
                        end

        config = %{
          host            logs.google.com
          port            777
          scheme          https
          path            /es/
          user            john
          password        doe
          template_name   logstash
          template_file   #{template_file}
          index_date_pattern now/w{xxxx.ww}
          ilm_policy_id   ${tag}
          enable_ilm      true
          index_name      logstash
          ilm_policies    {"fluentd-policy":{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"70gb", "max_age":"30d"}}}}}}}
          use_legacy_template #{use_legacy_template_flag}
        }

        # connection start
        stub_request(:head, "https://logs.google.com:777/es//").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        # check if template exists
        stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        # creation
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        # check if alias exists
        stub_request(:head, "https://logs.google.com:777/es//_alias/logstash").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe']).
          to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
        if use_legacy_template_flag
          stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
            with(basic_auth: ['john', 'doe'],
                 body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"myalogs\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"mylogs-*\",\"order\":51}").
            to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
        else
          stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
            with(basic_auth: ['john', 'doe'],
                 body: "{\"index_patterns\":\"logstash-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":101}").
            to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
        end
        # put the alias for the index
        stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash").
          with(body: "{\"aliases\":{\"logstash\":{\"is_write_index\":true}}}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
        stub_request(:get, "https://logs.google.com:777/es//_xpack").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
        stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
          with(basic_auth: ['john', 'doe'],
               body: "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"70gb\",\"max_age\":\"30d\"}}}}}}").
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        stub_elastic_info("https://logs.google.com:777/es//")

        driver(config)

        elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
        driver.run(default_tag: 'fluentd-policy') do
          driver.feed(sample_record)
        end
        assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)

        assert_requested(elastic_request)
      end

      data("legacy_template" => [true, "_template"],
           "new_template"    => [false, "_index_template"])
      def test_tag_placeholder_with_multiple_policies(data)
        use_legacy_template_flag, endpoint = data
        if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
          omit "elastisearch-ruby v7.8.0 or later is needed."
        end
        cwd = File.dirname(__FILE__)
        template_file = if use_legacy_template_flag
                          File.join(cwd, 'test_template.json')
                        else
                          File.join(cwd, 'test_index_template.json')
                        end

        config = %{
          host            logs.google.com
          port            777
          scheme          https
          path            /es/
          user            john
          password        doe
          template_name   logstash
          template_file   #{template_file}
          index_date_pattern now/w{xxxx.ww}
          ilm_policy_id   ${tag}
          enable_ilm      true
          index_name      logstash
          ilm_policies    {"fluentd-policy":{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"70gb", "max_age":"30d"}}}}}}, "fluentd-policy2":{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"80gb", "max_age":"20d"}}}}}}}
          use_legacy_template #{use_legacy_template_flag}
        }

        # connection start
        stub_request(:head, "https://logs.google.com:777/es//").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        # check if template exists
        stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        # creation
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        # check if alias exists
        stub_request(:head, "https://logs.google.com:777/es//_alias/logstash").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
          with(basic_auth: ['john', 'doe']).
          to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
        if use_legacy_template_flag
          stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
            with(basic_auth: ['john', 'doe'],
                 body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"fluentd-policy2\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"logstash-*\",\"order\":51}").
            to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
        else
          stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
            with(basic_auth: ['john', 'doe'],
                 body: "{\"index_patterns\":\"logstash-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"fluentd-policy2\",\"index.lifecycle.rollover_alias\":\"logstash\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":101}").
            to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
        end
        # put the alias for the index
        stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash").
          with(body: "{\"aliases\":{\"logstash\":{\"is_write_index\":true}}}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
        stub_request(:get, "https://logs.google.com:777/es//_xpack").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
        stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy2").
          with(basic_auth: ['john', 'doe']).
          to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy2").
          with(basic_auth: ['john', 'doe'],
               body: "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"80gb\",\"max_age\":\"20d\"}}}}}}").
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
        stub_elastic_info("https://logs.google.com:777/es//")

        driver(config)

        elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
        driver.run(default_tag: 'fluentd-policy2') do
          driver.feed(sample_record)
        end
        assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)

        assert_requested(elastic_request)
      end
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_default_ilm_and_placeholders(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = %{
        host            logs.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        index_date_pattern now/w{xxxx.ww}
        index_name logstash-${tag}
        enable_ilm      true
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash-tag1").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash-tag1").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-tag1").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash-tag1\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"logstash-tag1-*\",\"order\":52}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-tag1").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash-tag1-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash-tag1\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":102}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-tag1-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-tag1-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash-tag1").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"logstash-tag1\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash-tag2").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash-tag2").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-tag2").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash-tag2\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"logstash-tag2-*\",\"order\":52}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash-tag2").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash-tag2-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash-tag2\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":102}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-tag2-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash-tag2-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash-tag2").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"logstash-tag2\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
      driver.run(default_tag: 'test') do
        driver.feed('tag1', event_time, sample_record)
        driver.feed('tag2', event_time, sample_record)
        driver.feed('tag1', event_time, sample_record)
        driver.feed('tag2', event_time, sample_record)
      end
      assert_equal('logstash-tag2', index_cmds.first['index']['_index'])

      assert_equal ["logstash-tag1", "logstash-tag2"], driver.instance.alias_indexes

      assert_requested(elastic_request, at_least_times: 1, at_most_times: 2)
    end


    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_default_ilm_and_placeholders_and_index_separator(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = %{
        host            logs.google.com
        port            777
        scheme          https
        path            /es/
        user            john
        password        doe
        template_name   logstash
        template_file   #{template_file}
        index_date_pattern now/w{xxxx.ww}
        index_name logstash.${tag}
        enable_ilm      true
        index_separator "."
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/logstash.tag1").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash.tag1").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash.tag1").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash.tag1\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"logstash.tag1.*\",\"order\":52}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash.tag1").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"logstash.tag1.*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"logstash.tag1\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":102}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash.tag1.default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3Clogstash.tag1.default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/logstash.tag1").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"logstash.tag1\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
      driver.run(default_tag: 'test') do
        driver.feed('tag1', event_time, sample_record)
      end
      assert_equal('logstash.tag1', index_cmds.first['index']['_index'])

      assert_equal ["logstash.tag1"], driver.instance.alias_indexes

      assert_requested(elastic_request)
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_template_create_with_rollover_index_and_default_ilm_and_custom_and_time_placeholders(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_template.json')
                      else
                        File.join(cwd, 'test_index_template.json')
                      end

      config = Fluent::Config::Element.new(
        'ROOT', '', {
          '@type' => 'elasticsearch',
          'host' => 'logs.google.com',
          'port' => 777,
          'scheme' => "https",
          'path' => "/es/",
          'user' => 'john',
          'password' => 'doe',
          'template_name' => 'logstash',
          'template_file' => "#{template_file}",
          'index_date_pattern' => 'now/w{xxxx.ww}',
          'index_name' => "${taskDef}-%Y.%m",
          'enable_ilm' => true,
          'use_legacy_template' => use_legacy_template_flag,

        }, [
          Fluent::Config::Element.new('buffer', 'tag, time, taskDef', {
                                        'chunk_keys' => ['tag', 'time', 'taskDef'],
                                        'timekey' => 3600,
                                      }, [])
        ]
      )

      task_def_value = "task_definition"
      date_str = Time.now.strftime("%Y.%m")
      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/#{task_def_value}-#{date_str}").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/#{task_def_value}-#{date_str}").
          with(basic_auth: ['john', 'doe'],
               body: "{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"#{task_def_value}-#{date_str}\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}},\"index_patterns\":\"#{task_def_value}-#{date_str}-*\",\"order\":52}").
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/#{task_def_value}-#{date_str}").
          with(basic_auth: ['john', 'doe'],
               body: "{\"index_patterns\":\"task_definition-#{date_str}-*\",\"template\":{\"settings\":{\"number_of_shards\":1,\"index.lifecycle.name\":\"logstash-policy\",\"index.lifecycle.rollover_alias\":\"task_definition-#{date_str}\"},\"mappings\":{\"type1\":{\"_source\":{\"enabled\":false},\"properties\":{\"host_name\":{\"type\":\"string\",\"index\":\"not_analyzed\"},\"created_at\":{\"type\":\"date\",\"format\":\"EEE MMM dd HH:mm:ss Z YYYY\"}}}}},\"priority\":102}").
          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      end
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/#{task_def_value}-#{date_str}").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3C#{task_def_value}-#{date_str}-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//%3C#{task_def_value}-#{date_str}-default-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/#{task_def_value}-#{date_str}").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"#{task_def_value}-#{date_str}\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/logstash-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
      driver.run(default_tag: 'test') do
        driver.feed(sample_record.merge("taskDef" => task_def_value))
      end
      assert_equal("#{task_def_value}-#{date_str}", index_cmds.first['index']['_index'])

      assert_equal ["#{task_def_value}-#{date_str}"], driver.instance.alias_indexes

      assert_requested(elastic_request)
    end
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_custom_template_create(data)
    use_legacy_template_flag, endpoint = data

    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_alias_template.json')
                    else
                      File.join(cwd, 'test_index_alias_template.json')
                    end

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
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template", times: 1)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_custom_template_create_with_customize_template_related_placeholders(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_alias_template.json')
                    else
                      File.join(cwd, 'test_index_alias_template.json')
                    end

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   myapp_alias_template-${tag}
      template_file   #{template_file}
      customize_template {"--appid--": "${tag}-logs","--index_prefix--":"${tag}"}
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template-test.template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template-test.template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})

    stub_request(:put, "https://logs.google.com:777/es//%3Cfluentd-test-default-000001%3E").
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})

    driver(config)

    stub_elastic("https://logs.google.com:777/es//_bulk")
    stub_elastic_info("https://logs.google.com:777/es//")
    driver.run(default_tag: 'test.template') do
      driver.feed(sample_record)
    end

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template-test.template", times: 1)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_custom_template_installation_for_host_placeholder(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

    config = %{
      host            logs-${tag}.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   #{template_file}
      verify_es_version_at_startup false
      default_elasticsearch_version 6
      customize_template {"--appid--": "myapp-logs","--index_prefix--":"mylogs"}
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs-test.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs-test.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs-test.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})

    driver(config)

    stub_elastic("https://logs-test.google.com:777/es//_bulk")
    stub_elastic_info("https://logs-test.google.com:777/es//")
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_custom_template_with_rollover_index_create(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_alias_template.json')
                    else
                      File.join(cwd, 'test_index_alias_template.json')
                    end

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
      index_name    mylogs
      application_name myapp
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation of index which can rollover
    stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if alias exists
    stub_request(:head, "https://logs.google.com:777/es//_alias/mylogs").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # put the alias for the index
    stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/mylogs").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template", times: 1)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_custom_template_with_rollover_index_create_and_deflector_alias(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_alias_template.json')
                    else
                      File.join(cwd, 'test_index_alias_template.json')
                    end

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
      index_name    mylogs
      application_name myapp
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation of index which can rollover
    stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if alias exists
    stub_request(:head, "https://logs.google.com:777/es//_alias/myapp_deflector").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # put the alias for the index
    stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/myapp_deflector").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template", times: 1)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_custom_template_with_rollover_index_create_with_logstash_format(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_alias_template.json')
                    else
                      File.join(cwd, 'test_index_alias_template.json')
                    end

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
      logstash_format true
      logstash_prefix mylogs
      application_name myapp
      use_legacy_template #{use_legacy_template_flag}
    }

    timestr = Time.now.getutc.strftime("%Y.%m.%d")
    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation of index which can rollover
    stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-#{timestr}-000001%3E").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if alias exists
    stub_request(:head, "https://logs.google.com:777/es//_alias/mylogs-#{timestr}").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # put the alias for the index
    stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-#{timestr}-000001%3E/#{alias_endpoint}/mylogs-#{timestr}").
      with(basic_auth: ['john', 'doe'],
           body: "{\"aliases\":{\"mylogs-#{timestr}\":{\"is_write_index\":true}}}").
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})

    driver(config)

    elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
    stub_elastic_info("https://logs.google.com:777/es//")
    driver.run(default_tag: 'custom-test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  class CustomTemplateIndexLifecycleManagementTest < self
    def setup
      if Gem::Version.new(TRANSPORT_CLASS::VERSION) < Gem::Version.new("8.0.0")
        begin
          require "elasticsearch/xpack"
        rescue LoadError
          omit "ILM testcase needs elasticsearch-xpack gem."
        end
      end
      if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.4.0")
        omit "elastisearch-ruby v7.4.0 or later is needed."
      end
    end


    def ilm_endpoint
      '_ilm'.freeze
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_custom_template_with_rollover_index_create_and_default_ilm(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_alias_template.json')
                      else
                        File.join(cwd, 'test_index_alias_template.json')
                      end

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
        index_date_pattern now/w{xxxx.ww}
        index_name    mylogs
        application_name myapp
        ilm_policy_id   fluentd-policy
        enable_ilm      true
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation of index which can rollover
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/mylogs").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/mylogs").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs").
          with(basic_auth: ['john', 'doe'],
               body: "{\"order\":6,\"settings\":{\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"mylogs\"},\"mappings\":{},\"aliases\":{\"myapp-logs-alias\":{}},\"index_patterns\":\"mylogs-*\"}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs").
          with(basic_auth: ['john', 'doe'],
               body: "{\"priority\":106,\"index_patterns\":\"mylogs-*\",\"template\":{\"settings\":{\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"mylogs\"},\"mappings\":{},\"aliases\":{\"myapp-logs-alias\":{}}}}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/mylogs").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"mylogs\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")
      driver(config)

      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs", times: 1)
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_custom_template_with_rollover_index_create_and_default_ilm_and_ilm_policy_overwrite(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_alias_template.json')
                      else
                        File.join(cwd, 'test_index_alias_template.json')
                      end

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
        index_date_pattern now/w{xxxx.ww}
        index_name    mylogs
        application_name myapp
        ilm_policy_id   fluentd-policy
        enable_ilm      true
        ilm_policy_overwrite true
        ilm_policy {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"60gb","max_age": "45d"}}}}}}
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation of index which can rollover
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/mylogs").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/mylogs").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs").
          with(basic_auth: ['john', 'doe'],
               body: "{\"order\":6,\"settings\":{\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"mylogs\"},\"mappings\":{},\"aliases\":{\"myapp-logs-alias\":{}},\"index_patterns\":\"mylogs-*\"}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs").
          with(basic_auth: ['john', 'doe'],
               body: "{\"priority\":106,\"index_patterns\":\"mylogs-*\",\"template\":{\"settings\":{\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"mylogs\"},\"mappings\":{},\"aliases\":{\"myapp-logs-alias\":{}}}}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/mylogs").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"mylogs\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"60gb\",\"max_age\":\"45d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs", times: 1)
    end

    def test_custom_template_with_rollover_index_create_and_default_ilm_with_deflector_alias
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
        index_date_pattern now/w{xxxx.ww}
        deflector_alias myapp_deflector
        index_name    mylogs
        application_name myapp
        ilm_policy_id   fluentd-policy
        enable_ilm      true
      }

      # Should raise error because multiple alias indices IllegalArgument Error on executing ILM feature
      stub_elastic_info("https://logs.google.com:777/es//")
      assert_raise(Fluent::ConfigError) do
        driver(config)
      end
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_custom_template_with_rollover_index_create_and_default_ilm_and_placeholders(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_alias_template.json')
                      else
                        File.join(cwd, 'test_index_alias_template.json')
                      end

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
        index_date_pattern now/w{xxxx.ww}
        index_name mylogs-${tag}
        application_name myapp
        ilm_policy_id   fluentd-policy
        enable_ilm      true
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})

      # test-tag1
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation of index which can rollover
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-test-tag1-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/mylogs-test-tag1").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/mylogs-test-tag1").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs-test-tag1").
          with(basic_auth: ['john', 'doe'],
               body: "{\"order\":8,\"settings\":{\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"mylogs-test-tag1\"},\"mappings\":{},\"aliases\":{\"myapp-logs-alias\":{}},\"index_patterns\":\"mylogs-test-tag1-*\"}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs-test-tag1").
          with(basic_auth: ['john', 'doe'],
               body: "{\"priority\":108,\"index_patterns\":\"mylogs-test-tag1-*\",\"template\":{\"settings\":{\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"mylogs-test-tag1\"},\"mappings\":{},\"aliases\":{\"myapp-logs-alias\":{}}}}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-test-tag1-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/mylogs-test-tag1").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"mylogs-test-tag1\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})

      # test-tag2
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//_template/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//_template/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation of index which can rollover
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-test-tag2-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/mylogs-test-tag2").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/mylogs-test-tag2").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      if use_legacy_template_flag
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs-test-tag2").
          with(basic_auth: ['john', 'doe'],
               body: "{\"order\":8,\"settings\":{\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"mylogs-test-tag2\"},\"mappings\":{},\"aliases\":{\"myapp-logs-alias\":{}},\"index_patterns\":\"mylogs-test-tag2-*\"}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      else
        stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs-test-tag2").
          with(basic_auth: ['john', 'doe'],
               body: "{\"priority\":108,\"index_patterns\":\"mylogs-test-tag2-*\",\"template\":{\"settings\":{\"index.lifecycle.name\":\"fluentd-policy\",\"index.lifecycle.rollover_alias\":\"mylogs-test-tag2\"},\"mappings\":{},\"aliases\":{\"myapp-logs-alias\":{}}}}").
          to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      end
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-test-tag2-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/mylogs-test-tag2").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"mylogs-test-tag2\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")

      driver(config)

      elastic_request = stub_elastic("https://logs.google.com:777/es//_bulk")
      driver.run(default_tag: 'test') do
        driver.feed("test-tag1", event_time, sample_record)
        driver.feed("test-tag2", event_time, sample_record)
        driver.feed("test-tag1", event_time, sample_record)
        driver.feed("test-tag2", event_time, sample_record)
      end
      assert_equal('mylogs-test-tag2', index_cmds.first['index']['_index'])
      assert_equal ["mylogs-test-tag1", "mylogs-test-tag2"], driver.instance.alias_indexes

      assert_requested(elastic_request, at_least_times: 1, at_most_times: 2)
    end

    data("legacy_template" => [true, "_template"],
         "new_template"    => [false, "_index_template"])
    def test_custom_template_with_rollover_index_create_and_custom_ilm(data)
      use_legacy_template_flag, endpoint = data
      if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
        omit "elastisearch-ruby v7.8.0 or later is needed."
      end
      cwd = File.dirname(__FILE__)
      template_file = if use_legacy_template_flag
                        File.join(cwd, 'test_alias_template.json')
                      else
                        File.join(cwd, 'test_index_alias_template.json')
                      end

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
        index_date_pattern now/w{xxxx.ww}
        index_name    mylogs
        application_name myapp
        ilm_policy_id   fluentd-policy
        enable_ilm      true
        ilm_policy      {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_size":"70gb", "max_age":"30d"}}}}}}
        use_legacy_template #{use_legacy_template_flag}
      }

      # connection start
      stub_request(:head, "https://logs.google.com:777/es//").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if template exists
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # creation of index which can rollover
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      # check if alias exists
      stub_request(:head, "https://logs.google.com:777/es//_alias/mylogs").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/mylogs").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 404, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs").
        with(basic_auth: ['john', 'doe']).
        to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
      # put the alias for the index
      stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fw%7Bxxxx.ww%7D%7D-000001%3E/#{alias_endpoint}/mylogs").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"aliases\":{\"mylogs\":{\"is_write_index\":true}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//_xpack").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'})
      stub_request(:get, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe']).
        to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_request(:put, "https://logs.google.com:777/es//#{ilm_endpoint}/policy/fluentd-policy").
        with(basic_auth: ['john', 'doe'],
             :body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"70gb\",\"max_age\":\"30d\"}}}}}}").
        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
      stub_elastic_info("https://logs.google.com:777/es//")
      driver(config)

      assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/mylogs", times: 1)
    end
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_template_overwrite(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

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
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_custom_template_overwrite(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

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
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template", times: 1)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_custom_template_with_rollover_index_overwrite(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

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
      index_name    mylogs
      application_name myapp
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # creation of index which can rollover
    stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fd%7D-000001%3E").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if alias exists
    stub_request(:head, "https://logs.google.com:777/es//_alias/myapp_deflector").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # put the alias for the index
    stub_request(:put, "https://logs.google.com:777/es//%3Cmylogs-myapp-%7Bnow%2Fd%7D-000001%3E/#{alias_endpoint}/myapp_deflector").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/myapp_alias_template", times: 1)
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
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//_template/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    assert_raise(RuntimeError) {
      driver(config)
    }
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_template_create_for_host_placeholder(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

    config = %{
      host            logs-${tag}.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   #{template_file}
      verify_es_version_at_startup false
      default_elasticsearch_version 6
      use_legacy_template #{use_legacy_template_flag}
    }

    # connection start
    stub_request(:head, "https://logs-test.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs-test.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs-test.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:post, "https://logs-test.google.com:777/es//_bulk").
      with(basic_auth: ['john', 'doe']).
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})

    driver(config)

    stub_elastic("https://logs-test.google.com:777/es//_bulk")
    stub_elastic_info("https://logs-test.google.com:777/es//")
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
  end

  transport_errors_handled_separately = [TRANSPORT_CLASS::Transport::Errors::NotFound]
  transport_errors = TRANSPORT_CLASS::Transport::Errors.constants.map { |err| [err, TRANSPORT_CLASS::Transport::Errors.const_get(err)]  }
  transport_errors_hash = Hash[transport_errors.select { |err| !transport_errors_handled_separately.include?(err[1]) } ]

  data(transport_errors_hash)
  def test_template_retry_transport_errors(error)
    endpoint, use_legacy_template_flag = if Gem::Version.create(::TRANSPORT_CLASS::VERSION) >= Gem::Version.create("7.8.0")
                 ["_index_template".freeze, false]
               else
                 ["_template".freeze, true]
               end
    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_index_template.json')

    config = %{
      host            logs.google.com
      port            778
      scheme          https
      path            /es/
      user            john
      password        doe
      template_name   logstash
      template_file   #{template_file}
      max_retry_putting_template 0
      use_legacy_template #{use_legacy_template_flag}
    }

    retries = 0
    stub_request(:get, "https://logs.google.com:778/es//#{endpoint}/logstash")
      .with(basic_auth: ['john', 'doe']) do |req|
      retries += 1
      raise error
    end
    stub_elastic_info("https://logs.google.com:778/es//")

    assert_raise(Fluent::Plugin::ElasticsearchError::RetryableOperationExhaustedFailure) do
      driver(config)
    end

    assert_equal(1, retries)
  end


  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_templates_create(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      templates       {"logstash1":"#{template_file}", "logstash2":"#{template_file}","logstash3":"#{template_file}" }
      use_legacy_template #{use_legacy_template_flag}
    }

    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
     # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash1").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash2").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})

    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash3").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'}) #exists

    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash1").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash2").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash3").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested( :put, "https://logs.google.com:777/es//#{endpoint}/logstash1", times: 1)
    assert_requested( :put, "https://logs.google.com:777/es//#{endpoint}/logstash2", times: 1)
    assert_not_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash3") #exists
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_templates_overwrite(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      templates       {"logstash1":"#{template_file}", "logstash2":"#{template_file}","logstash3":"#{template_file}" }
      template_overwrite true
      use_legacy_template #{use_legacy_template_flag}
    }

    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
     # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash1").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash2").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash3").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'}) #exists

    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash1").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash2").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash3").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash1", times: 1)
    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash2", times: 1)
    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash3", times: 1)
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_templates_are_also_used(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

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
      use_legacy_template #{use_legacy_template_flag}
    }
    # connection start
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash1").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash2").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    #creation
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash1").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash2").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    driver(config)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash", times: 1)

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash1")
    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash2")
  end

  data("legacy_template" => [true, "_template"],
       "new_template"    => [false, "_index_template"])
  def test_templates_can_be_partially_created_if_error_occurs(data)
    use_legacy_template_flag, endpoint = data
    if !use_legacy_template_flag && Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.8.0")
      omit "elastisearch-ruby v7.8.0 or later is needed."
    end
    cwd = File.dirname(__FILE__)
    template_file = if use_legacy_template_flag
                      File.join(cwd, 'test_template.json')
                    else
                      File.join(cwd, 'test_index_template.json')
                    end

    config = %{
      host            logs.google.com
      port            777
      scheme          https
      path            /es/
      user            john
      password        doe
      templates       {"logstash1":"#{template_file}", "logstash2":"/abc" }
      use_legacy_template #{use_legacy_template_flag}
    }
    stub_request(:head, "https://logs.google.com:777/es//").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
     # check if template exists
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash1").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:get, "https://logs.google.com:777/es//#{endpoint}/logstash2").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})

    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash1").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "https://logs.google.com:777/es//#{endpoint}/logstash2").
      with(basic_auth: ['john', 'doe']).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info("https://logs.google.com:777/es//")

    assert_raise(RuntimeError) {
      driver(config)
    }

    assert_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash1", times: 1)
    assert_not_requested(:put, "https://logs.google.com:777/es//#{endpoint}/logstash2")
  end

  def test_legacy_hosts_list
    config = %{
      hosts    host1:50,host2:100,host3
      scheme   https
      path     /es/
      port     123
    }
    stub_elastic_info("https://host1:50")
    stub_elastic_info("https://host2:100")
    stub_elastic_info("https://host3:123")
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
    stub_elastic_info("https://john:password@host1:443/elastic/")
    stub_elastic_info("http://host2")
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

  def test_hosts_list_with_existing_connection
    stub_elastic_info("https://john:password@host1:443/elastic/")
    stub_elastic_info("http://host2")
    config = %{
      path     /default_path
      user     default_user
      password default_password
    }
    instance = driver(config).instance

    assert_equal 2, instance.get_connection_options("https://john:password@host1:443/elastic/,http://host2")[:hosts].length
    host1, host2 = instance.get_connection_options("https://john:password@host1:443/elastic/,http://host2")[:hosts]

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
    stub_elastic_info("https://j%2Bhn:passw%40rd@host1:443/elastic/")
    stub_elastic_info("http://host2")

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

  class IPv6AdressStringHostsTest < self
    def test_legacy_hosts_list
      config = %{
        hosts    "[2404:7a80:d440:3000:192a:a292:bd7f:ca19]:50,host2:100,host3"
        scheme   https
        path     /es/
        port     123
      }
      instance = driver(config).instance

      assert_raise(URI::InvalidURIError) do
        instance.get_connection_options[:hosts].length
      end
    end

    def test_hosts_list
      config = %{
        hosts    https://john:password@[2404:7a80:d440:3000:192a:a292:bd7f:ca19]:443/elastic/,http://host2
        path     /default_path
        user     default_user
        password default_password
      }
      instance = driver(config).instance

      assert_equal 2, instance.get_connection_options[:hosts].length
      host1, host2 = instance.get_connection_options[:hosts]

      assert_equal '[2404:7a80:d440:3000:192a:a292:bd7f:ca19]', host1[:host]
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

    def test_hosts_list_with_existing_connection
      config = %{
        path     /default_path
        user     default_user
        password default_password
      }
      instance = driver(config).instance

      assert_equal 2, instance.get_connection_options("https://john:password@[2404:7a80:d440:3000:192a:a292:bd7f:ca19]:443/elastic/,http://host2")[:hosts].length
      host1, host2 = instance.get_connection_options("https://john:password@[2404:7a80:d440:3000:192a:a292:bd7f:ca19]:443/elastic/,http://host2")[:hosts]

      assert_equal '[2404:7a80:d440:3000:192a:a292:bd7f:ca19]', host1[:host]
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
        hosts    https://%{j+hn}:%{passw@rd}@[2404:7a80:d440:3000:192a:a292:bd7f:ca19]:443/elastic/,http://host2
        path     /default_path
        user     default_user
        password default_password
      }
      instance = driver(config).instance

      assert_equal 2, instance.get_connection_options[:hosts].length
      host1, host2 = instance.get_connection_options[:hosts]

      assert_equal '[2404:7a80:d440:3000:192a:a292:bd7f:ca19]', host1[:host]
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

  def test_single_existing_connection
    config = %{
      user     john
      password doe
    }
    instance = driver(config).instance

    assert_equal 1, instance.get_connection_options("logs.google.com")[:hosts].length
    host1 = instance.get_connection_options("logs.google.com")[:hosts][0]

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

  def test_host_and_port_are_ignored_if_specify_hosts
    config = %{
      host  logs.google.com
      port  9200
      hosts host1:50,host2:100
    }
    instance = driver(config).instance

    params = instance.get_connection_options[:hosts]
    hosts = params.map { |p| p[:host] }
    ports = params.map { |p| p[:port] }
    assert(hosts.none? { |h| h == 'logs.google.com' })
    assert(ports.none? { |p| p == 9200 })
  end

  class IPv6AdressStringHostTest < self
    def test_single_host_params_and_defaults
      config = %{
        host     2404:7a80:d440:3000:192a:a292:bd7f:ca19
        user     john
        password doe
      }
      instance = driver(config).instance

      assert_equal 1, instance.get_connection_options[:hosts].length
      host1 = instance.get_connection_options[:hosts][0]

      assert_equal '[2404:7a80:d440:3000:192a:a292:bd7f:ca19]', host1[:host]
      assert_equal 9200, host1[:port]
      assert_equal 'http', host1[:scheme]
      assert_equal 'john', host1[:user]
      assert_equal 'doe', host1[:password]
      assert_equal nil, host1[:path]
    end

    def test_single_existing_connection
      config = %{
        user     john
        password doe
      }
      instance = driver(config).instance

      assert_equal 1, instance.get_connection_options("2404:7a80:d440:3000:192a:a292:bd7f:ca19")[:hosts].length
      host1 = instance.get_connection_options("2404:7a80:d440:3000:192a:a292:bd7f:ca19")[:hosts][0]

      assert_equal 1, instance.get_connection_options("[2404:7a80:d440:3000:192a:a292:bd7f:ca19]")[:hosts].length
      host2 = instance.get_connection_options("[2404:7a80:d440:3000:192a:a292:bd7f:ca19]")[:hosts][0]

      assert_equal '[2404:7a80:d440:3000:192a:a292:bd7f:ca19]', host1[:host]
      assert_equal 9200, host1[:port]
      assert_equal 'http', host1[:scheme]
      assert_equal 'john', host1[:user]
      assert_equal 'doe', host1[:password]
      assert_equal nil, host1[:path]

      assert_equal '[2404:7a80:d440:3000:192a:a292:bd7f:ca19]', host2[:host]
      assert_equal 9200, host2[:port]
      assert_equal 'http', host2[:scheme]
      assert_equal 'john', host2[:user]
      assert_equal 'doe', host2[:password]
      assert_equal nil, host2[:path]
    end

    def test_single_host_params_and_defaults_with_escape_placeholders
      config = %{
        host     2404:7a80:d440:3000:192a:a292:bd7f:ca19
        user     %{j+hn}
        password %{d@e}
      }
      instance = driver(config).instance

      assert_equal 1, instance.get_connection_options[:hosts].length
      host1 = instance.get_connection_options[:hosts][0]

      assert_equal '[2404:7a80:d440:3000:192a:a292:bd7f:ca19]', host1[:host]
      assert_equal 9200, host1[:port]
      assert_equal 'http', host1[:scheme]
      assert_equal 'j%2Bhn', host1[:user]
      assert_equal 'd%40e', host1[:password]
      assert_equal nil, host1[:path]
    end
  end

  def test_password_is_required_if_specify_user
    config = %{
      user john
    }

    assert_raise(Fluent::ConfigError) do
      driver(config)
    end
  end

  def test_content_type_header
    stub_request(:head, "http://localhost:9200/").
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    if Elasticsearch::VERSION >= "6.0.2"
      elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
                          with(headers: { "Content-Type" => "application/x-ndjson" }).
                          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    else
      elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
                          with(headers: { "Content-Type" => "application/json" }).
                          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    end
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_custom_headers
    stub_request(:head, "http://localhost:9200/").
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
                        with(headers: {'custom' => 'header1','and_others' => 'header2' }).
                        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info
    driver.configure(%[custom_headers {"custom":"header1", "and_others":"header2"}])
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_api_key_header
    stub_request(:head, "http://localhost:9200/").
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
                        with(headers: {'Authorization'=>'ApiKey dGVzdGF1dGhoZWFkZXI='}).
                        to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info
    driver.configure(%[api_key testauthheader])
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_write_message_with_bad_chunk
    driver.configure("target_index_key bad_value\n@log_level debug\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed({'bad_value'=>"\255"})
    end
    error_log = driver.error_events.map {|e| e.last.message }

    assert_logs_include(error_log, /(input string invalid)|(invalid byte sequence in UTF-8)/)
  end

  data('Elasticsearch 6' => [6, 'fluentd'],
       'Elasticsearch 7' => [7, 'fluentd'],
       'Elasticsearch 8' => [8, 'fluentd'],
      )
  def test_writes_to_default_index(data)
    version, index_name = data
    stub_elastic
    stub_elastic_info
    driver("", version)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(index_name, index_cmds.first['index']['_index'])
  end

  # gzip compress data
  def gzip(string, strategy)
    wio = StringIO.new("w")
    w_gz = Zlib::GzipWriter.new(wio, strategy = strategy)
    w_gz.write(string)
    w_gz.close
    wio.string
  end


  def test_writes_to_default_index_with_compression
    omit "elastisearch-ruby v7.2.0 or later is needed." if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.2.0")

    config = %[
      compression_level default_compression
    ]

    bodystr = %({
          "took" : 500,
          "errors" : false,
          "items" : [
            {
              "create": {
                "_index" : "fluentd",
                "_type"  : "fluentd"
              }
            }
           ]
        })

    compressed_body = gzip(bodystr, Zlib::DEFAULT_COMPRESSION)

    elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
        to_return(:status => 200, :headers => {'Content-Type' => 'Application/json', 'x-elastic-product' => 'Elasticsearch'}, :body => compressed_body)
    stub_elastic_info("http://localhost:9200/")

    driver(config)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end

    assert_requested(elastic_request)
  end

  data('Elasticsearch 6' => [6, Fluent::Plugin::ElasticsearchOutput::DEFAULT_TYPE_NAME],
       'Elasticsearch 7' => [7, Fluent::Plugin::ElasticsearchOutput::DEFAULT_TYPE_NAME_ES_7x],
       'Elasticsearch 8' => [8, nil],
      )
  def test_writes_to_default_type(data)
    version, index_type = data
    stub_elastic
    stub_elastic_info
    driver("", version)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(index_type, index_cmds.first['index']['_type'])
  end

  def test_writes_to_speficied_index
    driver.configure("index_name myindex\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('myindex', index_cmds.first['index']['_index'])
  end

  def test_writes_with_huge_records
    driver.configure(Fluent::Config::Element.new(
                       'ROOT', '', {
                         '@type' => 'elasticsearch',
                         'bulk_message_request_threshold' => 20 * 1024 * 1024,
                       }, [
                         Fluent::Config::Element.new('buffer', 'tag', {
                                                       'chunk_keys' => ['tag', 'time'],
                                                       'chunk_limit_size' => '64MB',
                                                     }, [])
                       ]
                     ))
    request = stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record('huge_record' => ("a" * 20 * 1024 * 1024)))
      driver.feed(sample_record('huge_record' => ("a" * 20 * 1024 * 1024)))
    end
    assert_requested(request, times: 2)
  end

  def test_writes_with_record_metadata
    chunk_id_key = "metadata_key".freeze
    driver.configure(Fluent::Config::Element.new(
                       'ROOT', '', {
                         '@type' => 'elasticsearch',
                       }, [
                         Fluent::Config::Element.new('metadata', '', {
                                                       'include_chunk_id' => true,
                                                       'chunk_id_key' => chunk_id_key,
                                                     }, [])
                       ]
                     ))
    index_part = if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
                   '{"index":{"_index":"fluentd"}}'
                 elsif Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.0.0")
                   '{"index":{"_index":"fluentd","_type":"_doc"}}'
                 else
                   '{"index":{"_index":"fluentd","_type":"fluentd"}}'
                 end
    stub_request(:post, "http://localhost:9200/_bulk").
      with(
        body: /#{index_part}\n{"age":26,"request_id":"42","parent_id":"parent","routing_id":"routing","#{chunk_id_key}":".*"}\n/) do |req|
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
    end.to_return({:status => 200, :body => "", :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
    stub_elastic_info
    driver.run(default_tag: 'test', shutdown: false) do
      driver.feed(sample_record)
    end
    assert_true index_cmds[1].has_key?(chunk_id_key)
    first_chunk_id = index_cmds[1].fetch(chunk_id_key)

    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_true index_cmds[1].has_key?(chunk_id_key)
    second_chunk_id = index_cmds[1].fetch(chunk_id_key)
    assert do
      first_chunk_id != second_chunk_id
    end
  end

  def test_writes_with_huge_records_but_uncheck
    driver.configure(Fluent::Config::Element.new(
                       'ROOT', '', {
                         '@type' => 'elasticsearch',
                         'bulk_message_request_threshold' => -1,
                       }, [
                         Fluent::Config::Element.new('buffer', 'tag', {
                                                       'chunk_keys' => ['tag', 'time'],
                                                       'chunk_limit_size' => '64MB',
                                                     }, [])
                       ]
                     ))
    request = stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record('huge_record' => ("a" * 20 * 1024 * 1024)))
      driver.feed(sample_record('huge_record' => ("a" * 20 * 1024 * 1024)))
    end
    assert_false(driver.instance.split_request?({}, nil))
    assert_requested(request, times: 1)
  end

  class IndexNamePlaceholdersTest < self
    def test_writes_to_speficied_index_with_tag_placeholder
      driver.configure("index_name myindex.${tag}\n")
      stub_elastic
      stub_elastic_info
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
      stub_elastic
      stub_elastic_info
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
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record.merge({"pipeline_id" => pipeline_id}))
      end
      assert_equal(logstash_index, index_cmds.first['index']['_index'])
    end
  end

  def test_writes_to_speficied_index_uppercase
    driver.configure("index_name MyIndex\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    # Allthough index_name has upper-case characters,
    # it should be set as lower-case when sent to elasticsearch.
    assert_equal('myindex', index_cmds.first['index']['_index'])
  end

  def test_writes_to_target_index_key
    driver.configure("target_index_key @target_index\n")
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record.merge('@target_index' => 'local-override'))
    end
    assert_equal('local-override', index_cmds.first['index']['_index'])
  end

  def test_writes_to_target_index_key_logstash_uppercase
    driver.configure("target_index_key @target_index
                      logstash_format true")
    time = Time.parse Date.today.iso8601
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record.merge('@target_index' => 'LOCAL-OVERRIDE'))
    end
    # Allthough @target_index has upper-case characters,
    # it should be set as lower-case when sent to elasticsearch.
    assert_equal('local-override', index_cmds.first['index']['_index'])
  end

  def test_writes_to_default_index_with_pipeline
    pipeline = "fluentd"
    driver.configure("pipeline #{pipeline}")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(pipeline, index_cmds.first['index']['pipeline'])
  end

  def stub_elastic_affinity_target_index_search_with_body(url="http://localhost:9200/logstash-*/_search", ids, return_body_str)
    # Note: ids used in query is unique list of ids
    stub_request(:post, url)
      .with(
        body: "{\"query\":{\"ids\":{\"values\":#{ids.uniq.to_json}}},\"_source\":false,\"sort\":[{\"_index\":{\"order\":\"desc\"}}]}",
      )
      .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'},
        :body => return_body_str
      }
    end)
  end

  def stub_elastic_affinity_target_index_search(url="http://localhost:9200/logstash-*/_search", ids, indices)
    # Example ids and indices arrays.
    #  [ "3408a2c8eecd4fbfb82e45012b54fa82", "2816fc6ef4524b3f8f7e869002005433"]
    #  [ "logstash-2021.04.28", "logstash-2021.04.29"]
    body = %({
      "took" : 31,
      "timed_out" : false,
      "_shards" : {
        "total" : 52,
        "successful" : 52,
        "skipped" : 48,
        "failed" : 0
      },
      "hits" : {
        "total" : {
          "value" : 356,
          "relation" : "eq"
        },
        "max_score" : null,
        "hits" : [
          {
            "_index" : "#{indices[0]}",
            "_type" : "_doc",
            "_id" : "#{ids[0]}",
            "_score" : null,
            "sort" : [
              "#{indices[0]}"
            ]
          },
          {
            "_index" : "#{indices[1]}",
            "_type" : "_doc",
            "_id" : "#{ids[1]}",
            "_score" : null,
            "sort" : [
              "#{indices[1]}"
            ]
          }
        ]
      }
    })
    stub_elastic_affinity_target_index_search_with_body(ids, body)
  end

  def stub_elastic_affinity_target_index_search_return_empty(url="http://localhost:9200/logstash-*/_search", ids)
    empty_body = %({
      "took" : 5,
      "timed_out" : false,
      "_shards" : {
        "total" : 54,
        "successful" : 54,
        "skipped" : 53,
        "failed" : 0
      },
      "hits" : {
        "total" : {
          "value" : 0,
          "relation" : "eq"
        },
        "max_score" : null,
        "hits" : [ ]
      }
    })
    stub_elastic_affinity_target_index_search_with_body(ids, empty_body)
  end

  def test_writes_to_affinity_target_index
    driver.configure("target_index_affinity true
                      logstash_format true
                      id_key my_id
                      write_operation update")

    my_id_value = "3408a2c8eecd4fbfb82e45012b54fa82"
    ids = [my_id_value]
    indices = ["logstash-2021.04.28"]
    stub_elastic
    stub_elastic_info
    stub_elastic_affinity_target_index_search(ids, indices)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record('my_id' => my_id_value))
    end
    assert_equal('logstash-2021.04.28', index_cmds.first['update']['_index'])
  end

  def test_writes_to_affinity_target_index_write_operation_upsert
    driver.configure("target_index_affinity true
                      logstash_format true
                      id_key my_id
                      write_operation upsert")

    my_id_value = "3408a2c8eecd4fbfb82e45012b54fa82"
    ids = [my_id_value]
    indices = ["logstash-2021.04.28"]
    stub_elastic
    stub_elastic_info
    stub_elastic_affinity_target_index_search(ids, indices)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record('my_id' => my_id_value))
    end
    assert_equal('logstash-2021.04.28', index_cmds.first['update']['_index'])
  end

  def test_writes_to_affinity_target_index_index_not_exists_yet
    driver.configure("target_index_affinity true
                      logstash_format true
                      id_key my_id
                      write_operation update")

    my_id_value = "3408a2c8eecd4fbfb82e45012b54fa82"
    ids = [my_id_value]
    stub_elastic
    stub_elastic_info
    stub_elastic_affinity_target_index_search_return_empty(ids)
    time = Time.parse Date.today.iso8601
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record('my_id' => my_id_value))
    end
    assert_equal("logstash-#{time.utc.strftime("%Y.%m.%d")}", index_cmds.first['update']['_index'])
  end

  def test_writes_to_affinity_target_index_multiple_indices
    driver.configure("target_index_affinity true
                      logstash_format true
                      id_key my_id
                      write_operation update")

    my_id_value = "2816fc6ef4524b3f8f7e869002005433"
    my_id_value2 = "3408a2c8eecd4fbfb82e45012b54fa82"
    ids = [my_id_value, my_id_value2]
    indices = ["logstash-2021.04.29", "logstash-2021.04.28"]
    stub_elastic_info
    stub_elastic_all_requests
    stub_elastic_affinity_target_index_search(ids, indices)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record('my_id' => my_id_value))
      driver.feed(sample_record('my_id' => my_id_value2))
    end
    assert_equal(2, index_cmds_all_requests.count)
    assert_equal('logstash-2021.04.29', index_cmds_all_requests[0].first['update']['_index'])
    assert_equal(my_id_value, index_cmds_all_requests[0].first['update']['_id'])
    assert_equal('logstash-2021.04.28', index_cmds_all_requests[1].first['update']['_index'])
    assert_equal(my_id_value2, index_cmds_all_requests[1].first['update']['_id'])
  end

  def test_writes_to_affinity_target_index_same_id_dublicated_write_to_oldest_index
    driver.configure("target_index_affinity true
                      logstash_format true
                      id_key my_id
                      write_operation update")

    my_id_value = "2816fc6ef4524b3f8f7e869002005433"
    # It may happen than same id has inserted to two index while data inserted during rollover period
    ids = [my_id_value, my_id_value]
    # Simulate the used sorting here, as search sorts indices in DESC order to pick only oldest index per single _id
    indices = ["logstash-2021.04.29", "logstash-2021.04.28"]

    stub_elastic_info
    stub_elastic_all_requests
    stub_elastic_affinity_target_index_search(ids, indices)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record('my_id' => my_id_value))
      driver.feed(sample_record('my_id' => my_id_value))
    end
    assert_equal('logstash-2021.04.28', index_cmds.first['update']['_index'])

    assert_equal(1, index_cmds_all_requests.count)
    assert_equal('logstash-2021.04.28', index_cmds_all_requests[0].first['update']['_index'])
    assert_equal(my_id_value, index_cmds_all_requests[0].first['update']['_id'])
  end

  class PipelinePlaceholdersTest < self
    def test_writes_to_default_index_with_pipeline_tag_placeholder
      pipeline = "fluentd-${tag}"
      driver.configure("pipeline #{pipeline}")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test.builtin.placeholder') do
        driver.feed(sample_record)
      end
      assert_equal("fluentd-test.builtin.placeholder", index_cmds.first['index']['pipeline'])
    end

    def test_writes_to_default_index_with_pipeline_time_placeholder
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'pipeline' => 'fluentd-%Y%m%d',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,time', {
                                                         'chunk_keys' => ['tag', 'time'],
                                                         'timekey' => 3600,
                                                       }, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      pipeline = "fluentd-#{time.getutc.strftime("%Y%m%d")}"
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record)
      end
      assert_equal(pipeline, index_cmds.first['index']['pipeline'])
    end

    def test_writes_to_default_index_with_pipeline_custom_key_placeholder
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'pipeline' => 'fluentd-${pipeline_id}',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,pipeline_id', {}, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      pipeline_id = "mypipeline"
      logstash_index = "fluentd-#{pipeline_id}"
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record.merge({"pipeline_id" => pipeline_id}))
      end
      assert_equal(logstash_index, index_cmds.first['index']['pipeline'])
    end
  end

  def test_writes_to_target_index_key_fallack
    driver.configure("target_index_key @target_index\n")
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  data("border"        => {"es_version" => 6, "_type" => "mytype"},
       "fixed_behavior"=> {"es_version" => 7, "_type" => "_doc"},
       "to be nil"     => {"es_version" => 8, "_type" => nil},
      )
  def test_writes_to_speficied_type(data)
    driver('', data["es_version"]).configure("type_name mytype\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(data['_type'], index_cmds.first['index']['_type'])
  end

  data("border"        => {"es_version" => 6, "_type" => "mytype.test"},
       "fixed_behavior"=> {"es_version" => 7, "_type" => "_doc"},
       "to be nil"     => {"es_version" => 8, "_type" => nil},
      )
  def test_writes_to_speficied_type_with_placeholders(data)
    driver('', data["es_version"]).configure("type_name mytype.${tag}\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(data['_type'], index_cmds.first['index']['_type'])
  end

  data("border"        => {"es_version" => 6, "_type" => "mytype.test"},
       "fixed_behavior"=> {"es_version" => 7, "_type" => nil},
       "to be nil"     => {"es_version" => 8, "_type" => nil},
      )
  def test_writes_to_speficied_type_with_suppress_type_name(data)
    driver('', data["es_version"])
      .configure("type_name mytype.${tag}\nsuppress_type_name true")
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
    record = sample_record.clone
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('@target_type' => 'local-override'))
    end
    assert_equal(data["_type"], index_cmds.first['index']['_type'])
    assert_nil(index_cmds[1]['@target_type'])
  end

  def test_writes_to_target_type_key_fallack_to_default
    driver.configure("target_type_key @target_type\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
      assert_nil(index_cmds.first['index']['_type'])
    elsif Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.0.0")
      assert_equal("_doc", index_cmds.first['index']['_type'])
    else
      assert_equal("fluentd", index_cmds.first['index']['_type'])
    end
  end

  def test_writes_to_target_type_key_fallack_to_type_name
    driver.configure("target_type_key @target_type
                      type_name mytype")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
      assert_nil(index_cmds.first['index']['_type'])
    elsif Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.0.0")
      assert_equal("_doc", index_cmds.first['index']['_type'])
    else
      assert_equal("fluentd", index_cmds.first['index']['_type'])
    end
  end

  data("old"           => {"es_version" => 2, "_type" => "local-override"},
       "old_behavior"  => {"es_version" => 5, "_type" => "local-override"},
       "border"        => {"es_version" => 6, "_type" => "fluentd"},
       "fixed_behavior"=> {"es_version" => 7, "_type" => "_doc"},
      )
  def test_writes_to_target_type_key_nested(data)
    driver('', data["es_version"]).configure("target_type_key kubernetes.labels.log_type\n")
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('kubernetes' => {
        'labels' => {
          'other_labels' => 'test'
        }
      }))
    end
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
      assert_nil(index_cmds.first['index']['_type'])
    elsif Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.0.0")
      assert_equal("_doc", index_cmds.first['index']['_type'])
    else
      assert_equal("fluentd", index_cmds.first['index']['_type'])
    end
  end

  def test_writes_to_speficied_host
    driver.configure("host 192.168.33.50\n")
    elastic_request = stub_elastic("http://192.168.33.50:9200/_bulk")
    stub_elastic_info("http://192.168.33.50:9200/")
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_writes_to_speficied_port
    driver.configure("port 9201\n")
    elastic_request = stub_elastic("http://localhost:9201/_bulk")
    stub_elastic_info("http://localhost:9201")
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
      stub_elastic_with_store_index_command_counts("http://#{host}:#{port}/_bulk")
      stub_elastic_info("http://#{host}:#{port}/")
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

    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(original_hash)
    end
    assert_equal expected_output, index_cmds[1]
  end

  def test_nested_record_with_flattening_off
    # flattening off by default

    original_hash =  {"foo" => {"bar" => "baz"}}
    expected_output = {"foo" => {"bar" => "baz"}}

    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(original_hash)
    end
    assert_equal expected_output, index_cmds[1]
  end

  def test_makes_bulk_request
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
      driver.feed(sample_record.merge('age' => 27))
    end
    assert_equal(4, index_cmds.count)
  end

  def test_all_re
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
      stub_elastic
      stub_elastic_info
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
      stub_elastic
      stub_elastic_info
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
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record.merge({"pipeline_id" => pipeline_id}))
      end
      assert_equal(logstash_index, index_cmds.first['index']['_index'])
    end
  end

  class LogStashDateformatPlaceholdersTest < self
    def test_writes_to_logstash_index_with_specified_prefix_and_dateformat_placeholder_pattern_1
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'logstash_format' => true,
                           'logstash_dateformat' => '${indexformat}',
                           'logstash_prefix' => 'myprefix',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,time,indexformat', {
                                                         'chunk_keys' => ['tag', 'time', 'indexformat'],
                                                         'timekey' => 3600,
                                                       }, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      logstash_index = "myprefix-#{time.getutc.strftime("%Y.%m.%d")}"
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record.merge('indexformat' => '%Y.%m.%d'))
      end
      assert_equal(logstash_index, index_cmds.first['index']['_index'])
    end

    def test_writes_to_logstash_index_with_specified_prefix_and_dateformat_placeholder_pattern_2
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'logstash_format' => true,
                           'logstash_dateformat' => '${indexformat}',
                           'logstash_prefix' => 'myprefix',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,time,indexformat', {
                                                         'chunk_keys' => ['tag', 'time', 'indexformat'],
                                                         'timekey' => 3600,
                                                       }, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      logstash_index = "myprefix-#{time.getutc.strftime("%Y.%m")}"
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record.merge('indexformat' => '%Y.%m'))
      end
      assert_equal(logstash_index, index_cmds.first['index']['_index'])
    end
  end

  class HostnamePlaceholders < self
    def test_writes_to_extracted_host
      driver.configure("host ${tag}\n")
      time = Time.parse Date.today.iso8601
      elastic_request = stub_elastic("http://extracted-host:9200/_bulk")
      stub_elastic_info("http://extracted-host:9200/")
      driver.run(default_tag: 'extracted-host') do
        driver.feed(time.to_i, sample_record)
      end
      assert_requested(elastic_request)
    end

    def test_writes_to_multi_hosts_with_placeholders
      hosts = [['${tag}', 9201], ['192.168.33.51', 9201], ['192.168.33.52', 9201]]
      hosts_string = hosts.map {|x| "#{x[0]}:#{x[1]}"}.compact.join(',')

      driver.configure("hosts #{hosts_string}")

      hosts.each do |host_info|
        host, port = host_info
        host = "extracted-host" if host == '${tag}'
        stub_elastic_with_store_index_command_counts("http://#{host}:#{port}/_bulk")
        stub_elastic_info("http://#{host}:#{port}")
      end

      driver.run(default_tag: 'extracted-host') do
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

    def test_writes_to_extracted_host_with_time_placeholder
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'host' => 'host-%Y%m%d',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,time', {
                                                         'chunk_keys' => ['tag', 'time'],
                                                         'timekey' => 3600,
                                                       }, [])
                         ]
                       ))
      stub_elastic
      stub_elastic_info
      time = Time.parse Date.today.iso8601
      elastic_request = stub_elastic("http://host-#{time.utc.strftime('%Y%m%d')}:9200/_bulk")
      stub_elastic_info("http://host-#{time.utc.strftime('%Y%m%d')}:9200/")
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record)
      end
      assert_requested(elastic_request)
    end

    def test_writes_to_extracted_host_with_custom_key_placeholder
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'host' => 'myhost-${pipeline_id}',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,pipeline_id', {}, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      first_pipeline_id = "1"
      second_pipeline_id = "2"
      first_request = stub_elastic("http://myhost-1:9200/_bulk")
      second_request = stub_elastic("http://myhost-2:9200/_bulk")
      stub_elastic_info("http://myhost-1:9200/")
      stub_elastic_info("http://myhost-2:9200/")
      driver.run(default_tag: 'test') do
        driver.feed(time.to_i, sample_record.merge({"pipeline_id" => first_pipeline_id}))
        driver.feed(time.to_i, sample_record.merge({"pipeline_id" => second_pipeline_id}))
      end
      assert_requested(first_request)
      assert_requested(second_request)
    end

    def test_writes_to_extracted_host_with_placeholder_replaced_in_exception_message
      driver.configure(Fluent::Config::Element.new(
                         'ROOT', '', {
                           '@type' => 'elasticsearch',
                           'host' => 'myhost-${pipeline_id}',
                         }, [
                           Fluent::Config::Element.new('buffer', 'tag,pipeline_id', {}, [])
                         ]
                       ))
      time = Time.parse Date.today.iso8601
      pipeline_id = "1"
      request = stub_elastic_unavailable("http://myhost-1:9200/_bulk")
      stub_elastic_info("http://myhost-1:9200/")
      exception = assert_raise(Fluent::Plugin::ElasticsearchOutput::RecoverableRequestFailure) {
        driver.run(default_tag: 'test') do
          driver.feed(time.to_i, sample_record.merge({"pipeline_id" => pipeline_id}))
        end
      }
      assert_equal("could not push logs to Elasticsearch cluster ({:host=>\"myhost-1\", :port=>9200, :scheme=>\"http\"}): [503] ", exception.message)
    end
  end

  def test_writes_to_logstash_index_with_specified_prefix_uppercase
    driver.configure("logstash_format true
                      logstash_prefix MyPrefix")
    time = Time.parse Date.today.iso8601
    logstash_index = "myprefix-#{time.getutc.strftime("%Y.%m.%d")}"
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds[1]['@timestamp'])
  end

  def test_adds_timestamp_when_logstash
    driver.configure("logstash_format true\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.now
    time = Fluent::EventTime.from_time(ts.to_time)
    driver.run(default_tag: 'test') do
      driver.feed(time, sample_record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts.iso8601(9), index_cmds[1]['@timestamp'])
  end

  def test_adds_timestamp_when_include_timestamp
    driver.configure("include_timestamp true\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.now
    time = Fluent::EventTime.from_time(ts.to_time)
    driver.run(default_tag: 'test') do
      driver.feed(time, sample_record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts.iso8601(9), index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_timestamp_when_included_in_record
    driver.configure("logstash_format true\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_timestamp_when_included_in_record_without_logstash
    driver.configure("include_timestamp true\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_time_key
    driver.configure("logstash_format true
                      time_key vtm\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601(9)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_time_key_with_float_record
    driver.configure("logstash_format true
                      time_precision 3
                      time_key vtm\n")
    stub_elastic
    stub_elastic_info
    time = Time.now
    float_time = time.to_f
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => float_time))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(time.to_datetime.iso8601(3), index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_time_key_with_format
    driver.configure("logstash_format true
                      time_key_format %Y-%m-%d %H:%M:%S.%N%z
                      time_key vtm\n")
    stub_elastic
    stub_elastic_info
    ts = "2001-02-03 13:14:01.673+02:00"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(DateTime.parse(ts).iso8601(9), index_cmds[1]['@timestamp'])
    assert_equal("logstash-2001.02.03", index_cmds[0]['index']['_index'])
  end

  def test_uses_custom_time_key_with_float_record_and_format
    driver.configure("logstash_format true
                      time_key_format %Y-%m-%d %H:%M:%S.%N%z
                      time_key vtm\n")
    stub_elastic
    stub_elastic_info
    ts = "2001-02-03 13:14:01.673+02:00"
    time = Time.parse(ts)
    current_zone_offset = Time.new(2001, 02, 03).to_datetime.offset
    float_time = time.to_f
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => float_time))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(DateTime.parse(ts).new_offset(current_zone_offset).iso8601(9), index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_time_key_with_format_without_logstash
    driver.configure("include_timestamp true
                      index_name test
                      time_key_format %Y-%m-%d %H:%M:%S.%N%z
                      time_key vtm\n")
    stub_elastic
    stub_elastic_info
    ts = "2001-02-03 13:14:01.673+02:00"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(DateTime.parse(ts).iso8601(9), index_cmds[1]['@timestamp'])
    assert_equal("test", index_cmds[0]['index']['_index'])
  end

  def test_uses_custom_time_key_exclude_timekey
    driver.configure("logstash_format true
                      time_key vtm
                      time_key_exclude_timestamp true\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(!index_cmds[1].key?('@timestamp'), '@timestamp should be messing')
  end

  def test_uses_custom_time_key_format
    driver.configure("logstash_format true
                      time_key_format %Y-%m-%dT%H:%M:%S.%N%z\n")
    stub_elastic
    stub_elastic_info
    ts = "2001-02-03T13:14:01.673+02:00"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert_equal("logstash-2001.02.03", index_cmds[0]['index']['_index'])
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_time_key_format_without_logstash
    driver.configure("include_timestamp true
                      index_name test
                      time_key_format %Y-%m-%dT%H:%M:%S.%N%z\n")
    stub_elastic
    stub_elastic_info
    ts = "2001-02-03T13:14:01.673+02:00"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert_equal("test", index_cmds[0]['index']['_index'])
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  data(:default => nil,
       :custom_tag => 'es_plugin.output.time.error')
  def test_uses_custom_time_key_format_logs_an_error(tag_for_error)
    tag_config = tag_for_error ? "time_parse_error_tag #{tag_for_error}" : ''
    tag_for_error = 'Fluent::ElasticsearchOutput::TimeParser.error' if tag_for_error.nil?
    driver.configure("logstash_format true
                      time_key_format %Y-%m-%dT%H:%M:%S.%N%z\n#{tag_config}\n")
    stub_elastic
    stub_elastic_info

    ts = "2001/02/03 13:14:01,673+02:00"
    index = "logstash-#{Time.now.getutc.strftime("%Y.%m.%d")}"

    flexmock(driver.instance.router).should_receive(:emit_error_event)
      .with(tag_for_error, Fluent::EventTime, Hash, ArgumentError).once
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end

    assert_equal(index, index_cmds[0]['index']['_index'])
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end


  def test_uses_custom_time_key_format_obscure_format
    driver.configure("logstash_format true
                      time_key_format %a %b %d %H:%M:%S %Z %Y\n")
    stub_elastic
    stub_elastic_info
    ts = "Thu Nov 29 14:33:20 GMT 2001"
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('@timestamp' => ts))
    end
    assert_equal("logstash-2001.11.29", index_cmds[0]['index']['_index'])
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  def test_uses_nanosecond_precision_by_default
    driver.configure("logstash_format true\n")
    stub_elastic
    stub_elastic_info
    time = Fluent::EventTime.new(Time.now.to_i, 123456789)
    driver.run(default_tag: 'test') do
      driver.feed(time, sample_record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(Time.at(time).iso8601(9), index_cmds[1]['@timestamp'])
  end

  def test_uses_subsecond_precision_when_configured
    driver.configure("logstash_format true
                      time_precision 3\n")
    stub_elastic
    stub_elastic_info
    time = Fluent::EventTime.new(Time.now.to_i, 123456789)
    driver.run(default_tag: 'test') do
      driver.feed(time, sample_record)
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(Time.at(time).iso8601(3), index_cmds[1]['@timestamp'])
  end

  def test_doesnt_add_tag_key_by_default
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds[1]['tag'])
  end

  def test_adds_tag_key_when_configured
    driver.configure("include_tag_key true\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'mytag') do
      driver.feed(sample_record)
    end
    assert(index_cmds[1].has_key?('tag'))
    assert_equal('mytag', index_cmds[1]['tag'])
  end

  def test_adds_id_key_when_configured
    driver.configure("id_key request_id\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('42', index_cmds[0]['index']['_id'])
  end

  class NestedIdKeyTest < self
    def test_adds_nested_id_key_with_dot
      driver.configure("id_key nested.request_id\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal('42', index_cmds[0]['index']['_id'])
    end

    def test_adds_nested_id_key_with_dollar_dot
      driver.configure("id_key $.nested.request_id\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal('42', index_cmds[0]['index']['_id'])
    end

    def test_adds_nested_id_key_with_bracket
      driver.configure("id_key $['nested']['request_id']\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal('42', index_cmds[0]['index']['_id'])
    end
  end

  def test_doesnt_add_id_key_if_missing_when_configured
    driver.configure("id_key another_request_id\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_id'))
  end

  def test_adds_id_key_when_not_configured
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_id'))
  end

  def test_adds_parent_key_when_configured
    driver.configure("parent_key parent_id\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('parent', index_cmds[0]['index']['_parent'])
  end

  class NestedParentKeyTest < self
    def test_adds_nested_parent_key_with_dot
      driver.configure("parent_key nested.parent_id\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal('parent', index_cmds[0]['index']['_parent'])
    end

    def test_adds_nested_parent_key_with_dollar_dot
      driver.configure("parent_key $.nested.parent_id\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal('parent', index_cmds[0]['index']['_parent'])
    end

    def test_adds_nested_parent_key_with_bracket
      driver.configure("parent_key $['nested']['parent_id']\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      assert_equal('parent', index_cmds[0]['index']['_parent'])
    end
  end

  def test_doesnt_add_parent_key_if_missing_when_configured
    driver.configure("parent_key another_parent_id\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_parent'))
  end

  def test_adds_parent_key_when_not_configured
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(!index_cmds[0]['index'].has_key?('_parent'))
  end

  class AddsRoutingKeyWhenConfiguredTest < self
    def test_es6
      driver("routing_key routing_id\n", 6)
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(sample_record)
      end
      routing_key = driver.instance.instance_variable_get(:@routing_key_name)
      assert_equal('routing', index_cmds[0]['index'][routing_key])
    end

    def test_es7
      driver("routing_key routing_id\n", 7)
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(sample_record)
      end
      routing_key = driver.instance.instance_variable_get(:@routing_key_name)
      assert_equal('routing', index_cmds[0]['index'][routing_key])
    end
  end

  class NestedRoutingKeyTest < self
    def test_adds_nested_routing_key_with_dot
      driver.configure("routing_key nested.routing_id\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      routing_key = driver.instance.instance_variable_get(:@routing_key_name)
      assert_equal('routing', index_cmds[0]['index'][routing_key])
    end

    def test_adds_nested_routing_key_with_dollar_dot
      driver.configure("routing_key $.nested.routing_id\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      routing_key = driver.instance.instance_variable_get(:@routing_key_name)
      assert_equal('routing', index_cmds[0]['index'][routing_key])
    end

    def test_adds_nested_routing_key_with_bracket
      driver.configure("routing_key $['nested']['routing_id']\n")
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(nested_sample_record)
      end
      routing_key = driver.instance.instance_variable_get(:@routing_key_name)
      assert_equal('routing', index_cmds[0]['index'][routing_key])
    end
  end

  def test_doesnt_add_routing_key_if_missing_when_configured
    driver.configure("routing_key another_routing_id\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    routing_key = driver.instance.instance_variable_get(:@routing_key_name)
    assert(!index_cmds[0]['index'].has_key?(routing_key))
  end

  def test_adds_routing_key_when_not_configured
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    routing_key = driver.instance.instance_variable_get(:@routing_key_name)
    assert(!index_cmds[0]['index'].has_key?(routing_key))
  end

  def test_remove_one_key
    driver.configure("remove_keys key1\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('key1' => 'v1', 'key2' => 'v2'))
    end
    assert(!index_cmds[1].has_key?('key1'))
    assert(index_cmds[1].has_key?('key2'))
  end

  def test_remove_multi_keys
    driver.configure("remove_keys key1, key2\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge('key1' => 'v1', 'key2' => 'v2'))
    end
    assert(!index_cmds[1].has_key?('key1'))
    assert(!index_cmds[1].has_key?('key2'))
  end

  def test_request_error
    stub_elastic_info
    stub_elastic_unavailable
    assert_raise(Fluent::Plugin::ElasticsearchOutput::RecoverableRequestFailure) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }
  end

  def test_request_forever
    omit("retry_forever test is unstable.") if ENV["CI"]
    stub_elastic
    stub_elastic_info
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
    assert_raise(Timeout::Error) {
      driver.run(default_tag: 'test', timeout: 10, force_flush_retry: true) do
        driver.feed(sample_record)
      end
    }
  end

  def test_connection_failed
    connection_resets = 0

    stub_request(:post, "http://localhost:9200/_bulk").with do |req|
      connection_resets += 1
      raise Faraday::ConnectionFailed, "Test message"
    end.to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    assert_raise(Fluent::Plugin::ElasticsearchOutput::RecoverableRequestFailure) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }
    assert_equal(1, connection_resets)
  end

  def test_reconnect_on_error_enabled
    connection_resets = 0

    stub_request(:post, "http://localhost:9200/_bulk").with do |req|
      connection_resets += 1
      raise ZeroDivisionError, "any not host_unreachable_exceptions exception"
    end.to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    driver.configure("reconnect_on_error true\n")

    assert_raise(Fluent::Plugin::ElasticsearchOutput::RecoverableRequestFailure) {
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
    assert_equal(1, connection_resets)
  end

  def test_reconnect_on_error_disabled
    connection_resets = 0

    stub_request(:post, "http://localhost:9200/_bulk").with do |req|
      connection_resets += 1
      raise ZeroDivisionError, "any not host_unreachable_exceptions exception"
    end.to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    driver.configure("reconnect_on_error false\n")

    assert_raise(Fluent::Plugin::ElasticsearchOutput::RecoverableRequestFailure) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }

    assert_raise(Timeout::Error) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }
    assert_equal(1, connection_resets)
  end

  def test_bulk_error_retags_when_configured
    driver.configure("retry_tag retry\n")
    stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'},
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
    stub_elastic_info

    driver.run(default_tag: 'test') do
      driver.feed(1, sample_record)
    end

    assert_equal [['retry', 1, sample_record]], driver.events
  end

  class FulfilledBufferRetryStreamTest < self
    def test_bulk_error_retags_with_error_when_configured_and_fullfilled_buffer
      def create_driver(conf='', es_version=5, client_version="\"5.0\"")
        @client_version ||= client_version
        Fluent::Plugin::ElasticsearchOutput.module_eval(<<-CODE)
          def retry_stream_retryable?
            false
          end
        CODE
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
        Fluent::Test::Driver::Output.new(Fluent::Plugin::ElasticsearchOutput).configure(conf)
      end
      driver = create_driver("retry_tag retry\n")
      stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
                     { :status => 200,
                       :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'},
                       :body => %({
          "took" : 1,
          "errors" : true,
          "items" : [
            {
              "create" : {
                "_index" : "foo",
                "_type"  : "bar",
                "_id" : "abc1",
                "status" : 403,
                "error" : {
                  "type" : "cluster_block_exception",
                  "reason":"index [foo] blocked by: [FORBIDDEN/8/index write (api)]"
                }
              }
            },
            {
              "create" : {
                "_index" : "foo",
                "_type"  : "bar",
                "_id" : "abc2",
                "status" : 403,
                "error" : {
                  "type" : "cluster_block_exception",
                  "reason":"index [foo] blocked by: [FORBIDDEN/8/index write (api)]"
                }
              }
            }
           ]
        })
                     }
                   end)
      stub_elastic_info

      # Check buffer fulfillment condition
      assert_raise(Fluent::Plugin::ElasticsearchOutput::RetryStreamEmitFailure) do
        driver.run(default_tag: 'test') do
          driver.feed(1, sample_record)
          driver.feed(1, sample_record)
        end
      end

      assert_equal [], driver.events
    end
  end

  def test_create_should_write_records_with_ids_and_skip_those_without
    driver.configure("write_operation create\nid_key my_id\n@log_level debug")
    stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' },
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
    stub_elastic_info

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
    stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' },
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
    stub_elastic_info

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
    stub_request(:post, 'http://localhost:9200/_bulk')
        .to_return(lambda do |req|
      { :status => 200,
        :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch'},
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
    stub_elastic_info

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
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds)
  end

  def test_upsert_should_not_write_if_theres_no_id
    driver.configure("write_operation upsert\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds)
  end

  def test_create_should_not_write_if_theres_no_id
    driver.configure("write_operation create\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds)
  end

  def test_update_should_write_update_op_and_doc_as_upsert_is_false
    driver.configure("write_operation update
                      id_key request_id")
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(index_cmds[1]["doc"])
    assert(!index_cmds[1]["doc"]["parent_id"])
  end

  def test_upsert_should_write_update_op_and_doc_as_upsert_is_true
    driver.configure("write_operation upsert
                      id_key request_id")
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
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
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert(index_cmds[0].has_key?("create"))
  end

  def test_include_index_in_url
    stub_elastic('http://localhost:9200/logstash-2018.01.01/_bulk')
    stub_elastic_info('http://localhost:9200/')

    driver.configure("index_name logstash-2018.01.01
                      include_index_in_url true")
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end

    assert_equal(2, index_cmds.length)
    assert_equal(nil, index_cmds.first['index']['_index'])
  end

  def test_use_simple_sniffer
    require 'fluent/plugin/elasticsearch_simple_sniffer'
    stub_elastic
    stub_elastic_info
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
    assert_logs_include_compare_size(3, ">", log, /In Fluent::Plugin::ElasticsearchSimpleSniffer hosts/)
    assert_logs_include_compare_size(1, "<=", log, /In Fluent::Plugin::ElasticsearchSimpleSniffer hosts/)
  end

  def test_suppress_doc_wrap
    driver.configure('write_operation update
                      id_key id
                      remove_keys id
                      suppress_doc_wrap true')
    stub_elastic
    stub_elastic_info
    doc_body = {'field' => 'value'}
    script_body = {'source' => 'ctx._source.counter += params.param1',
                   'lang' => 'painless',
                   'params' => {'param1' => 1}}
    upsert_body = {'counter' => 1}
    driver.run(default_tag: 'test') do
      driver.feed('id' => 1, 'doc' => doc_body)
      driver.feed('id' => 2, 'script' => script_body, 'upsert' => upsert_body)
    end
    assert(
      index_cmds[1] == {'doc' => doc_body}
    )
    assert(
      index_cmds[3] == {
        'script' => script_body,
        'upsert' => upsert_body
      }
    )
  end

  def test_suppress_doc_wrap_should_handle_record_as_is_at_upsert
    driver.configure('write_operation upsert
                      id_key id
                      remove_keys id
                      suppress_doc_wrap true')
    stub_elastic
    stub_elastic_info
    doc_body = {'field' => 'value'}
    script_body = {'source' => 'ctx._source.counter += params.param1',
                   'lang' => 'painless',
                   'params' => {'param1' => 1}}
    upsert_body = {'counter' => 1}
    driver.run(default_tag: 'test') do
      driver.feed('id' => 1, 'doc' => doc_body, 'doc_as_upsert' => true)
      driver.feed('id' => 2, 'script' => script_body, 'upsert' => upsert_body)
    end
    assert(
      index_cmds[1] == {
        'doc' => doc_body,
        'doc_as_upsert' => true
      }
    )
    assert(
      index_cmds[3] == {
        'script' => script_body,
        'upsert' => upsert_body
      }
    )
  end

  def test_ignore_exception
    ignore_classes = if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
                     ["Elastic::Transport::Transport::Errors::ServiceUnavailable"]
                   else
                     ["Elasticsearch::Transport::Transport::Errors::ServiceUnavailable"]
                   end
    driver.configure("ignore_exceptions #{ignore_classes}")
    stub_elastic_unavailable
    stub_elastic_info

    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
  end

  def test_ignore_exception_with_superclass
    ignore_classes = if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
                       ["Elastic::Transport::Transport::Errors::ServiceUnavailable"]
                     else
                       ["Elasticsearch::Transport::Transport::Errors::ServiceUnavailable"]
                     end
    driver.configure("ignore_exceptions #{ignore_classes}")
    stub_elastic_unavailable
    stub_elastic_info

    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
  end

  def test_ignore_excetion_handles_appropriate_ones
    driver.configure('ignore_exceptions ["Faraday::ConnectionFailed"]')
    stub_elastic_unavailable
    stub_elastic_info

    assert_raise(Fluent::Plugin::ElasticsearchOutput::RecoverableRequestFailure) {
      driver.run(default_tag: 'test', shutdown: false) do
        driver.feed(sample_record)
      end
    }
  end
end
