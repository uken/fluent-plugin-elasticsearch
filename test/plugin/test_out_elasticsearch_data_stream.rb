require_relative '../helper'
require 'date'
require 'fluent/test/helpers'
require 'fluent/test/driver/output'
require 'flexmock/test_unit'
require 'fluent/plugin/out_elasticsearch_data_stream'

class ElasticsearchOutputDataStreamTest < Test::Unit::TestCase
  include FlexMock::TestCase
  include Fluent::Test::Helpers

  attr_accessor :bulk_records

  REQUIRED_ELASTIC_MESSAGE = "Elasticsearch 7.9.0 or later is needed."
  ELASTIC_DATA_STREAM_TYPE = "elasticsearch_data_stream"

  def setup
    Fluent::Test.setup
    @driver = nil
    log = Fluent::Engine.log
    log.out.logs.slice!(0, log.out.logs.length)
    @bulk_records = 0
  end

  def driver(conf='', es_version=5, client_version="\"5.0\"")
    # For request stub to detect compatibility.
    @es_version ||= es_version
    @client_version ||= client_version
    Fluent::Plugin::ElasticsearchOutputDataStream.module_eval(<<-CODE)
      def detect_es_major_version
        #{@es_version}
      end
    CODE
    @driver ||= Fluent::Test::Driver::Output.new(Fluent::Plugin::ElasticsearchOutputDataStream) {
      # v0.12's test driver assume format definition. This simulates ObjectBufferedOutput format
      if !defined?(Fluent::Plugin::Output)
        def format(tag, time, record)
          [time, record].to_msgpack
        end
      end
    }.configure(conf)
  end

  def sample_data_stream
    {
      'data_streams': [
                        {
                          'name' => 'foo',
                          'timestamp_field' => {
                            'name' => '@timestamp'
                          }
                        }
                      ]
    }
  end

  def sample_record
    {'@timestamp' => Time.now.iso8601, 'message' => 'Sample record'}
  end

  RESPONSE_ACKNOWLEDGED = {"acknowledged": true}
  DUPLICATED_DATA_STREAM_EXCEPTION = {"error": {}, "status": 400}
  NONEXISTENT_DATA_STREAM_EXCEPTION = {"error": {}, "status": 404}

  def stub_ilm_policy(name="foo_ilm")
    stub_request(:put, "http://localhost:9200/_ilm/policy/#{name}_policy").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_index_template(name="foo_tpl")
    stub_request(:put, "http://localhost:9200/_index_template/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_data_stream(name="foo")
    stub_request(:put, "http://localhost:9200/_data_stream/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_existent_data_stream?(name="foo")
    stub_request(:get, "http://localhost:9200/_data_stream/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_existent_ilm?(name="foo_ilm")
    stub_request(:get, "http://localhost:9200/_ilm/policy/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_existent_template?(name="foo_tpl")
    stub_request(:get, "http://localhost:9200/_index_template/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_nonexistent_data_stream?(name="foo")
    stub_request(:get, "http://localhost:9200/_data_stream/#{name}").to_return(:status => [404, Elasticsearch::Transport::Transport::Errors::NotFound])
  end

  def stub_nonexistent_ilm?(name="foo_ilm")
    stub_request(:get, "http://localhost:9200/_ilm/policy/#{name}").to_return(:status => [404, Elasticsearch::Transport::Transport::Errors::NotFound])
  end

  def stub_nonexistent_template?(name="foo_tpl")
    stub_request(:get, "http://localhost:9200/_index_template/#{name}").to_return(:status => [404, Elasticsearch::Transport::Transport::Errors::NotFound])
  end

  def stub_bulk_feed(datastream_name="foo", ilm_name="foo_ilm", template_name="foo_tpl")
    stub_request(:post, "http://localhost:9200/#{datastream_name}/_bulk").with do |req|
      # bulk data must be pair of OP and records
      # {"create": {}}\nhttp://localhost:9200/_ilm/policy/foo_ilm_bar
      # {"@timestamp": ...}
      @bulk_records += req.body.split("\n").size / 2
    end
    stub_request(:post, "http://localhost:9200/#{ilm_name}/_bulk").with do |req|
      # bulk data must be pair of OP and records
      # {"create": {}}\nhttp://localhost:9200/_ilm/policy/foo_ilm_bar
      # {"@timestamp": ...}
      @bulk_records += req.body.split("\n").size / 2
    end
    stub_request(:post, "http://localhost:9200/#{template_name}/_bulk").with do |req|
      # bulk data must be pair of OP and records
      # {"create": {}}\nhttp://localhost:9200/_ilm/policy/foo_ilm_bar
      # {"@timestamp": ...}
      @bulk_records += req.body.split("\n").size / 2
    end
  end

  def stub_elastic_info(url="http://localhost:9200/", version="7.9.0")
    body ="{\"version\":{\"number\":\"#{version}\", \"build_flavor\":\"default\"},\"tagline\" : \"You Know, for Search\"}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json' } })
  end

  def stub_default(datastream_name="foo", ilm_name="foo_ilm", template_name="foo_tpl", host="http://localhost:9200")
    stub_elastic_info(host)
    stub_nonexistent_ilm?(ilm_name)
    stub_ilm_policy(ilm_name)
    stub_nonexistent_template?(template_name)
    stub_index_template(template_name)
    stub_nonexistent_data_stream?(datastream_name)
    stub_data_stream(datastream_name)
  end

  def data_stream_supported?
    Gem::Version.create(::Elasticsearch::Transport::VERSION) >= Gem::Version.create("7.9.0")
  end

  # ref. https://www.elastic.co/guide/en/elasticsearch/reference/master/indices-create-data-stream.html
  class DataStreamNameTest < self

    def test_missing_data_stream_name
      conf = config_element(
        'ROOT', '', {
          '@type' => 'elasticsearch_datastream'
        })
      assert_raise Fluent::ConfigError.new("'data_stream_name' parameter is required") do
        driver(conf).run
      end
    end

    def test_invalid_uppercase
      conf = config_element(
        'ROOT', '', {
          '@type' => 'elasticsearch_datastream',
          'data_stream_name' => 'TEST',
          'data_stream_ilm_name' => 'TEST-ILM',
          'data_stream_template_name' => 'TEST-TPL'
        })
      assert_raise Fluent::ConfigError.new("'data_stream_name' must be lowercase only: <TEST>") do
        driver(conf)
      end
    end

    data("backslash" => "\\",
         "slash" => "/",
         "asterisk" => "*",
         "question" => "?",
         "doublequote" => "\"",
         "lt" => "<",
         "gt" => ">",
         "bar" => "|",
         "space" => " ",
         "comma" => ",",
         "sharp" => "#",
         "colon" => ":")
    def test_invalid_characters(data)
      c, _ = data
      conf = config_element(
        'ROOT', '', {
          '@type' => ELASTIC_DATA_STREAM_TYPE,
          'data_stream_name' => "TEST#{c}",
          'data_stream_ilm_name' => "TEST#{c}",
          'data_stream_template_name' => "TEST#{c}"
        })
      label = Fluent::Plugin::ElasticsearchOutputDataStream::INVALID_CHARACTERS.join(',')
      assert_raise Fluent::ConfigError.new("'data_stream_name' must not contain invalid characters #{label}: <TEST#{c}>") do
        driver(conf)
      end
    end

    data("hyphen" => "-",
         "underscore" => "_",
         "plus" => "+",
         "period" => ".")
    def test_invalid_start_characters(data)
      c, _ = data
      conf = config_element(
        'ROOT', '', {
          '@type' => ELASTIC_DATA_STREAM_TYPE,
          'data_stream_name' => "#{c}TEST",
          'data_stream_ilm_name' => "#{c}TEST",
          'data_stream_template_name' => "#{c}TEST"
        })
      label = Fluent::Plugin::ElasticsearchOutputDataStream::INVALID_START_CHRACTERS.join(',')
      assert_raise Fluent::ConfigError.new("'data_stream_name' must not start with #{label}: <#{c}TEST>") do
        driver(conf)
      end
    end

    data("current" => ".",
         "parents" => "..")
    def test_invalid_dots
      c, _ = data
      conf = config_element(
        'ROOT', '', {
          '@type' => ELASTIC_DATA_STREAM_TYPE,
          'data_stream_name' => "#{c}",
          'data_stream_ilm_name' => "#{c}",
          'data_stream_template_name' => "#{c}"
        })
      assert_raise Fluent::ConfigError.new("'data_stream_name' must not be . or ..: <#{c}>") do
        driver(conf)
      end
    end

    def test_invalid_length
      c = "a" * 256
      conf = config_element(
        'ROOT', '', {
          '@type' => ELASTIC_DATA_STREAM_TYPE,
          'data_stream_name' => "#{c}",
          'data_stream_ilm_name' => "#{c}",
          'data_stream_template_name' => "#{c}"
        })
      assert_raise Fluent::ConfigError.new("'data_stream_name' must not be longer than 255 bytes: <#{c}>") do
        driver(conf)
      end
    end
  end

  def test_datastream_configure
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    stub_default
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_ilm_name' => "foo_ilm",
        'data_stream_template_name' => "foo_tpl"
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_existent_data_stream
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    stub_ilm_policy
    stub_index_template
    stub_existent_data_stream?
    stub_data_stream
    stub_elastic_info
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_ilm_name' => "foo_ilm",
        'data_stream_template_name' => "foo_tpl"
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_placeholder
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    dsname = "foo_test"
    ilmname = "foo_ilm_test"
    tplname = "foo_tpl_test"
    stub_default(dsname, ilmname, tplname)
    stub_bulk_feed(dsname, ilmname, tplname)
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_${tag}',
        'data_stream_ilm_name' => "foo_ilm_${tag}",
        'data_stream_template_name' => "foo_tpl_${tag}"
      })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records
  end

  def test_time_placeholder
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    time = Time.now
    dsname = "foo_#{time.strftime("%Y%m%d")}"
    ilmname = "foo_ilm_#{time.strftime("%Y%m%d")}"
    tplname = "foo_tpl_#{time.strftime("%Y%m%d")}"
    stub_default(dsname, ilmname, tplname)
    stub_bulk_feed(dsname, ilmname, tplname)
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_%Y%m%d',
        'data_stream_ilm_name' => 'foo_ilm_%Y%m%d',
        'data_stream_template_name' => 'foo_tpl_%Y%m%d'
      }, [config_element('buffer', 'time', {
                          'timekey' => '1d'
                        }, [])]
      )
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records
  end

  def test_custom_record_placeholder
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    keys = ["bar", "baz"]
    keys.each do |key|
      dsname = "foo_#{key}"
      ilmname = "foo_ilm_#{key}"
      tplname = "foo_tpl_#{key}"
      stub_default(dsname, ilmname, tplname)
      stub_bulk_feed(dsname, ilmname, tplname)
    end
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_${key1}',
        'data_stream_ilm_name' => 'foo_ilm_${key1}',
        'data_stream_template_name' => 'foo_tpl_${key1}'
      }, [config_element('buffer', 'tag,key1', {
                          'timekey' => '1d'
                        }, [])]
    )
    driver(conf).run(default_tag: 'test') do
      keys.each do |key|
        record = sample_record.merge({"key1" => key})
        driver.feed(record)
      end
    end
    assert_equal keys.count, @bulk_records
  end

  def test_bulk_insert_feed
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_ilm_name' => 'foo_ilm',
        'data_stream_template_name' => 'foo_tpl'
      })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records
  end

  def test_template_retry_install_fails
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    cwd = File.dirname(__FILE__)
    template_file = File.join(cwd, 'test_index_template.json')

    config = %{
      host                       logs.google.com
      port                       778
      scheme                     https
      data_stream_name           foo
      data_stream_ilm_name       foo_ilm
      data_stream_template_name  foo_tpl
      user                       john
      password                   doe
      template_name              logstash
      template_file              #{template_file}
      max_retry_putting_template 3
    }

    connection_resets = 0
    # check if template exists
    stub_request(:get, "https://logs.google.com:778/_index_template/logstash")
      .with(basic_auth: ['john', 'doe']) do |req|
      connection_resets += 1
      raise Faraday::ConnectionFailed, "Test message"
    end
    stub_elastic_info("https://logs.google.com:778/")

    assert_raise(Fluent::Plugin::ElasticsearchError::RetryableOperationExhaustedFailure) do
      driver(config)
    end

    assert_equal(4, connection_resets)
  end
end
