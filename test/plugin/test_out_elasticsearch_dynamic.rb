require_relative '../helper'
require 'date'
require 'fluent/test/helpers'
require 'fluent/test/driver/output'
require 'flexmock/test_unit'
require 'fluent/plugin/out_elasticsearch_dynamic'

class ElasticsearchOutputDynamic < Test::Unit::TestCase
  include FlexMock::TestCase
  include Fluent::Test::Helpers

  attr_accessor :index_cmds, :index_command_counts

  def setup
    Fluent::Test.setup
    @driver = nil
  end

  def elasticsearch_version
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.14.0")
      TRANSPORT_CLASS::VERSION
    else
      '6.4.2'.freeze
    end
  end

  def driver(conf='', es_version=elasticsearch_version.to_i)
    # For request stub to detect compatibility.
    @es_version ||= es_version
    Fluent::Plugin::ElasticsearchOutputDynamic.module_eval(<<-CODE)
      def detect_es_major_version
        #{@es_version}
      end
    CODE
    @driver ||= Fluent::Test::Driver::Output.new(Fluent::Plugin::ElasticsearchOutputDynamic) {
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

  def elastic_transport_layer?
    Gem::Version.create(::TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
  end

  def default_type_name
    Fluent::Plugin::ElasticsearchOutput::DEFAULT_TYPE_NAME
  end

  def sample_record
    {'age' => 26, 'request_id' => '42', 'parent_id' => 'parent', 'routing_id' => 'routing'}
  end

  def nested_sample_record
    {'nested' =>
     {'age' => 26, 'parent_id' => 'parent', 'routing_id' => 'routing', 'request_id' => '42'}
    }
  end

  def stub_elastic(url="http://localhost:9200/_bulk")
    stub_request(:post, url).with do |req|
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
    end.to_return({:status => 200, :body => "", :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
  end

  def stub_elastic_info(url="http://localhost:9200/", version=elasticsearch_version)
    body ="{\"version\":{\"number\":\"#{version}\", \"build_flavor\":\"default\"},\"tagline\" : \"You Know, for Search\"}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
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
    end.to_return({:status => 200, :body => "", :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
  end

  def assert_logs_include(logs, msg, exp_matches=1)
    matches = logs.grep /#{msg}/
    assert_equal(exp_matches, matches.length, "Logs do not contain '#{msg}' '#{logs}'")
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

    conf = instance.dynamic_config
    assert_equal 'logs.google.com', conf['host']
    assert_equal "777", conf['port']
    assert_equal :https, instance.scheme
    assert_equal 'john', instance.user
    assert_equal 'doe', instance.password
    assert_equal '/es/', instance.path
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
    assert_equal :excon, instance.http_backend
    assert_false instance.compression
    assert_equal :no_compression, instance.compression_level
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
      to_return(status: 200, body: "", headers: {'x-elastic-product' => 'Elasticsearch'})
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

  test 'Detected Elasticsearch 7' do
    config = %{
      type_name changed
    }
    instance = driver(config, 7).instance
    assert_equal '_doc', instance.type_name
  end

  def test_defaults
    config = %{
      host     logs.google.com
      scheme   https
      path     /es/
      user     john
      password doe
    }
    instance = driver(config).instance

    conf = instance.dynamic_config
    assert_equal "9200", conf['port']
    assert_equal "false", conf['logstash_format']
    assert_equal "true", conf['utc_index']
    assert_equal false, instance.time_key_exclude_timestamp
  end

  def test_legacy_hosts_list
    config = %{
      hosts    host1:50,host2:100,host3
      scheme   https
      path     /es/
      port     123
    }
    instance = driver(config).instance

    assert_equal 3, instance.get_connection_options(nil)[:hosts].length
    host1, host2, host3 = instance.get_connection_options(nil)[:hosts]

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

    assert_equal 2, instance.get_connection_options(nil)[:hosts].length
    host1, host2 = instance.get_connection_options(nil)[:hosts]

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

    assert_equal 2, instance.get_connection_options(nil)[:hosts].length
    host1, host2 = instance.get_connection_options(nil)[:hosts]

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

    assert_equal 1, instance.get_connection_options(nil)[:hosts].length
    host1 = instance.get_connection_options(nil)[:hosts][0]

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

    assert_equal 1, instance.get_connection_options(nil)[:hosts].length
    host1 = instance.get_connection_options(nil)[:hosts][0]

    assert_equal 'logs.google.com', host1[:host]
    assert_equal 9200, host1[:port]
    assert_equal 'http', host1[:scheme]
    assert_equal 'j%2Bhn', host1[:user]
    assert_equal 'd%40e', host1[:password]
    assert_equal nil, host1[:path]
  end

  def test_content_type_header
    stub_request(:head, "http://localhost:9200/").
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    if Elasticsearch::VERSION >= "6.0.2"
      elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
                          with(headers: { "Content-Type" => "application/x-ndjson"}).
                          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    else
      elastic_request = stub_request(:post, "http://localhost:9200/_bulk").
                          with(headers: { "Content-Type" => "application/json"}).
                          to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    end
    stub_elastic_info('http://localhost:9200')

    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_writes_to_default_index
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('fluentd', index_cmds.first['index']['_index'])
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
    stub_elastic_info

    driver(config)
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end

    assert_requested(elastic_request)
  end

  def test_writes_to_default_type
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

  def test_writes_to_specified_index
    driver.configure("index_name myindex\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('myindex', index_cmds.first['index']['_index'])
  end

  def test_writes_to_specified_index_uppercase
    driver.configure("index_name MyIndex\n")
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal('myindex', index_cmds.first['index']['_index'])
  end

  def test_writes_to_specified_type
    driver.configure("type_name mytype\n")
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
      assert_equal("mytype", index_cmds.first['index']['_type'])
    end
  end

  def test_writes_to_specified_host
    driver.configure("host 192.168.33.50\n")
    elastic_request = stub_elastic("http://192.168.33.50:9200/_bulk")
    stub_elastic_info("http://192.168.33.50:9200/")
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_requested(elastic_request)
  end

  def test_writes_to_specified_port
    driver.configure("port 9201\n")
    elastic_request = stub_elastic("http://localhost:9201/_bulk")
    stub_elastic_info("http://localhost:9201/")
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

  def test_all_records_are_preserved_in_bulk
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
    time = Time.parse Date.today.iso8601
    logstash_index = "logstash-#{time.getutc.strftime("%Y.%m.%d")}"
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  def test_writes_to_logstash_utc_index
    driver.configure("logstash_format true
                      utc_index false")
    time = Time.parse Date.today.iso8601
    utc_index = "logstash-#{time.strftime("%Y.%m.%d")}"
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(time.to_i, sample_record)
    end
    assert_equal(utc_index, index_cmds.first['index']['_index'])
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

  def test_doesnt_add_logstash_timestamp_by_default
    stub_elastic
    stub_elastic_info
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_nil(index_cmds[1]['@timestamp'])
  end

  def test_adds_logstash_timestamp_when_configured
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

  def test_uses_custom_timestamp_when_included_in_record
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

  def test_uses_custom_timestamp_when_included_in_record_logstash
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

  def test_uses_custom_time_key_logstash
    driver.configure("logstash_format true
                      time_key vtm\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_time_key_timestamp
    driver.configure("include_timestamp true
                      time_key vtm\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
  end

  def test_uses_custom_time_key_timestamp_custom_index
    driver.configure("include_timestamp true
                      index_name test
                      time_key vtm\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(ts, index_cmds[1]['@timestamp'])
    assert_equal('test', index_cmds.first['index']['_index'])
  end

  def test_uses_custom_time_key_exclude_timestamp
    driver.configure("include_timestamp true
                      time_key vtm
                      time_key_exclude_timestamp true\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(!index_cmds[1].key?('@timestamp'), '@timestamp should be missing')
  end

  def test_uses_custom_time_key_exclude_timestamp_logstash
    driver.configure("logstash_format true
                      time_key vtm
                      time_key_exclude_timestamp true\n")
    stub_elastic
    stub_elastic_info
    ts = DateTime.new(2001,2,3).iso8601
    driver.run(default_tag: 'test') do
      driver.feed(sample_record.merge!('vtm' => ts))
    end
    assert(!index_cmds[1].key?('@timestamp'), '@timestamp should be missing')
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
      assert_equal('routing', index_cmds[0]['index']['_routing'])
    end

    def test_es7
      driver("routing_key routing_id\n", 7)
      stub_elastic
      stub_elastic_info
      driver.run(default_tag: 'test') do
        driver.feed(sample_record)
      end
      assert_equal('routing', index_cmds[0]['index']['routing'])
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
    stub_elastic_unavailable
    stub_elastic_info
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

  def test_tag_parts_index_error_event
    stub_elastic
    stub_elastic_info
    driver.configure("logstash_prefix ${tag_parts[1]}\n")
    flexmock(driver.instance.router).should_receive(:emit_error_event)
      .with('test', Fluent::EventTime, Hash, TypeError).once
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
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
end
