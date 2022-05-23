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
    @bulk_records = []
  end

  def elasticsearch_version
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.14.0")
      TRANSPORT_CLASS::VERSION
    else
      '5.0.0'.freeze
    end
  end

  def ilm_endpoint
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
      '_enrich'.freeze
    else
      '_ilm'.freeze
    end
  end

  def driver(conf='', es_version=elasticsearch_version.to_i, client_version=elasticsearch_version)
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

  SAMPLE_RECORD_TIMESTAMP = Time.now.iso8601
  def sample_record
    {'@timestamp' => SAMPLE_RECORD_TIMESTAMP, 'message' => 'Sample record'}
  end

  def sample_record_no_timestamp
    {'message' => 'Sample record no timestamp'}
  end

  RESPONSE_ACKNOWLEDGED = {"acknowledged": true}
  DUPLICATED_DATA_STREAM_EXCEPTION = {"error": {}, "status": 400}
  NONEXISTENT_DATA_STREAM_EXCEPTION = {"error": {}, "status": 404}

  def stub_ilm_policy(name="foo_ilm_policy", url="http://localhost:9200")
    stub_request(:put, "#{url}/#{ilm_endpoint}/policy/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_index_template(name="foo_tpl", url="http://localhost:9200")
    stub_request(:put, "#{url}/_index_template/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_data_stream(name="foo", url="http://localhost:9200")
    stub_request(:put, "#{url}/_data_stream/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_existent_data_stream?(name="foo", url="http://localhost:9200")
    stub_request(:get, "#{url}/_data_stream/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_existent_ilm?(name="foo_ilm_policy", url="http://localhost:9200")

    stub_request(:get, "#{url}/#{ilm_endpoint}/policy/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_existent_template?(name="foo_tpl", url="http://localhost:9200")
    stub_request(:get, "#{url}/_index_template/#{name}").to_return(:status => [200, RESPONSE_ACKNOWLEDGED])
  end

  def stub_nonexistent_data_stream?(name="foo", url="http://localhost:9200")
    stub_request(:get, "#{url}/_data_stream/#{name}").to_return(:status => [404, TRANSPORT_CLASS::Transport::Errors::NotFound])
  end

  def stub_nonexistent_ilm?(name="foo_ilm_policy", url="http://localhost:9200")
    stub_request(:get, "#{url}/#{ilm_endpoint}/policy/#{name}").to_return(:status => [404, TRANSPORT_CLASS::Transport::Errors::NotFound])
  end

  def stub_nonexistent_template?(name="foo_tpl", url="http://localhost:9200")
    stub_request(:get, "#{url}/_index_template/#{name}").to_return(:status => [404, TRANSPORT_CLASS::Transport::Errors::NotFound])
  end


  def push_bulk_request(req_body)
    # bulk data must be pair of OP and records
    # {"create": {}}\nhttp://localhost:9200/_ilm/policy/foo_ilm_bar
    # {"@timestamp": ...}
    ops = req_body.split("\n")
    @bulk_records += ops.values_at(
      * ops.each_index.select {|i| i.odd? }
    ).map{ |i| JSON.parse(i) }
  end

  def stub_nonexistent_template_retry?(name="foo_tpl", url="http://localhost:9200")
    stub_request(:get, "#{url}/_index_template/#{name}").
      to_return({ status: 500, body: 'Internal Server Error' }, { status: 404, body: '{}' })
  end

  def stub_bulk_feed(datastream_name="foo", ilm_name="foo_ilm_policy", template_name="foo_tpl", url="http://localhost:9200")
    stub_request(:post, "#{url}/#{datastream_name}/_bulk").with do |req|
      # bulk data must be pair of OP and records
      # {"create": {}}\nhttp://localhost:9200/_ilm/policy/foo_ilm_bar
      # {"@timestamp": ...}
      push_bulk_request(req.body)
    end
    stub_request(:post, "#{url}/#{ilm_name}/_bulk").with do |req|
      # bulk data must be pair of OP and records
      # {"create": {}}\nhttp://localhost:9200/_ilm/policy/foo_ilm_bar
      # {"@timestamp": ...}
      push_bulk_request(req.body)
    end
    stub_request(:post, "#{url}/#{template_name}/_bulk").with do |req|
      # bulk data must be pair of OP and records
      # {"create": {}}\nhttp://localhost:9200/_ilm/policy/foo_ilm_bar
      # {"@timestamp": ...}
      push_bulk_request(req.body)
    end
  end

  def stub_elastic_info(url="http://localhost:9200/", version=elasticsearch_version, headers={})
    body ="{\"version\":{\"number\":\"#{version}\", \"build_flavor\":\"default\"},\"tagline\" : \"You Know, for Search\"}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' }.merge(headers) })
  end

  def stub_default(datastream_name="foo", ilm_name="foo_ilm_policy", template_name="foo_tpl", host="http://localhost:9200")
    stub_elastic_info(host)
    stub_nonexistent_ilm?(ilm_name)
    stub_ilm_policy(ilm_name)
    stub_nonexistent_template?(template_name)
    stub_index_template(template_name)
    stub_nonexistent_data_stream?(datastream_name)
    stub_data_stream(datastream_name)
  end

  def data_stream_supported?
    Gem::Version.create(::TRANSPORT_CLASS::VERSION) >= Gem::Version.create("7.9.0")
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

    sub_test_case "invalid uppercase" do
      def test_stream_name
        conf = config_element(
          'ROOT', '', {
            '@type' => 'elasticsearch_datastream',
            'data_stream_name' => 'TEST',
            'data_stream_ilm_name' => 'default-policy',
            'data_stream_template_name' => 'template'
          })
        assert_raise Fluent::ConfigError.new("'data_stream_name' must be lowercase only: <TEST>") do
          driver(conf)
        end
      end
      def test_stream_ilm_name
        conf = config_element(
          'ROOT', '', {
            '@type' => 'elasticsearch_datastream',
            'data_stream_name' => 'data_stream',
            'data_stream_ilm_name' => 'TEST-ILM',
            'data_stream_template_name' => 'template'
          })
        assert_raise Fluent::ConfigError.new("'data_stream_ilm_name' must be lowercase only: <TEST-ILM>") do
          driver(conf)
        end
      end
      def test_stream_template_name
        conf = config_element(
          'ROOT', '', {
            '@type' => 'elasticsearch_datastream',
            'data_stream_name' => 'default',
            'data_stream_ilm_name' => 'default-policy',
            'data_stream_template_name' => 'TEST-TPL'
          })
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must be lowercase only: <TEST-TPL>") do
          driver(conf)
        end
      end
    end

    sub_test_case "invalid parameters" do
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
      def test_stream_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "TEST#{c}",
            'data_stream_ilm_name' => "default_policy",
            'data_stream_template_name' => "data_stream"
          })
        label = Fluent::Plugin::ElasticsearchOutputDataStream::INVALID_CHARACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_name' must not contain invalid characters #{label}: <TEST#{c}>") do
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
      def test_stream_ilm_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_ilm_name' => "TEST#{c}",
            'data_stream_template_name' => "data_stream"
          })
        label = Fluent::Plugin::ElasticsearchOutputDataStream::INVALID_CHARACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_ilm_name' must not contain invalid characters #{label}: <TEST#{c}>") do
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
      def test_stream_template_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_ilm_name' => "default_policy",
            'data_stream_template_name' => "TEST#{c}"
          })
        label = Fluent::Plugin::ElasticsearchOutputDataStream::INVALID_CHARACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must not contain invalid characters #{label}: <TEST#{c}>") do
          driver(conf)
        end
      end
    end

    sub_test_case "invalid start characters" do
      data("hyphen" => "-",
           "underscore" => "_",
           "plus" => "+",
           "period" => ".")
      def test_stream_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "#{c}TEST",
            'data_stream_ilm_name' => "default-policy",
            'data_stream_template_name' => "template"
          })
        label = Fluent::Plugin::ElasticsearchOutputDataStream::INVALID_START_CHRACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_name' must not start with #{label}: <#{c}TEST>") do
          driver(conf)
        end
      end
      data("hyphen" => "-",
           "underscore" => "_",
           "plus" => "+",
           "period" => ".")
      def test_stream_ilm_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_ilm_name' => "#{c}TEST",
            'data_stream_template_name' => "template"
          })
        label = Fluent::Plugin::ElasticsearchOutputDataStream::INVALID_START_CHRACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_ilm_name' must not start with #{label}: <#{c}TEST>") do
          driver(conf)
        end
      end
      data("hyphen" => "-",
           "underscore" => "_",
           "plus" => "+",
           "period" => ".")
      def test_stream_template_name(data)
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_ilm_name' => "default-policy",
            'data_stream_template_name' => "#{c}TEST"
          })
        label = Fluent::Plugin::ElasticsearchOutputDataStream::INVALID_START_CHRACTERS.join(',')
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must not start with #{label}: <#{c}TEST>") do
          driver(conf)
        end
      end
    end

    sub_test_case "invalid dots" do
      data("current" => ".",
           "parents" => "..")
      def test_stream_name
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "#{c}",
            'data_stream_ilm_name' => "default-policy",
            'data_stream_template_name' => "template"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_name' must not be . or ..: <#{c}>") do
          driver(conf)
        end
      end

      data("current" => ".",
           "parents" => "..")
      def test_stream_ilm_name
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_ilm_name' => "#{c}",
            'data_stream_template_name' => "template"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_ilm_name' must not be . or ..: <#{c}>") do
          driver(conf)
        end
      end

      data("current" => ".",
           "parents" => "..")
      def test_stream_template_name
        c, _ = data
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_ilm_name' => "default-policy",
            'data_stream_template_name' => "#{c}"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must not be . or ..: <#{c}>") do
          driver(conf)
        end
      end
    end

    sub_test_case "invalid length" do
      def test_stream_name
        c = "a" * 256
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "#{c}",
            'data_stream_ilm_name' => "default-policy",
            'data_stream_template_name' => "template"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_name' must not be longer than 255 bytes: <#{c}>") do
          driver(conf)
        end
      end
      def test_stream_ilm_name
        c = "a" * 256
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_ilm_name' => "#{c}",
            'data_stream_template_name' => "template"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_ilm_name' must not be longer than 255 bytes: <#{c}>") do
          driver(conf)
        end
      end
      def test_stream_template_name
        c = "a" * 256
        conf = config_element(
          'ROOT', '', {
            '@type' => ELASTIC_DATA_STREAM_TYPE,
            'data_stream_name' => "default",
            'data_stream_ilm_name' => "default-policy",
            'data_stream_template_name' => "#{c}"
          })
        assert_raise Fluent::ConfigError.new("'data_stream_template_name' must not be longer than 255 bytes: <#{c}>") do
          driver(conf)
        end
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
        'data_stream_ilm_name' => "foo_ilm_policy",
        'data_stream_template_name' => "foo_tpl"
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_datastream_configure_retry
    stub_elastic_info
    stub_nonexistent_ilm?
    stub_ilm_policy
    stub_nonexistent_template_retry?
    stub_index_template
    stub_nonexistent_data_stream?
    stub_data_stream
    conf = config_element(
      'ROOT', '', {
      '@type' => ELASTIC_DATA_STREAM_TYPE,
      'data_stream_name' => 'foo',
      'data_stream_ilm_name' => "foo_ilm_policy",
      'data_stream_template_name' => "foo_tpl"
    })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_hosts_list_configure
    config = %{
      hosts            https://john:password@host1:443/elastic/,http://host2
      path             /default_path
      user             default_user
      password         default_password
      data_stream_name default
    }
    stub_elastic_info("https://host1:443/elastic//", elasticsearch_version,
                         {'Authorization'=>"Basic #{Base64.encode64('john:password').split.first}"})
    stub_elastic_info("http://host2/default_path/_data_stream/default", elasticsearch_version,
                         {'Authorization'=>"Basic #{Base64.encode64('john:password').split.first}"})
    stub_existent_data_stream?("default", "https://host1/elastic/")
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
        'data_stream_ilm_name' => "foo_ilm_policy",
        'data_stream_template_name' => "foo_tpl"
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
  end

  def test_template_unset
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
        'data_stream_ilm_name' => "foo_ilm_policy",
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
    assert_equal "foo_ilm_policy", driver(conf).instance.data_stream_ilm_name
    assert_equal "foo_template", driver(conf).instance.data_stream_template_name
  end

  def test_ilm_unset
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
        'data_stream_template_name' => "foo_tpl"
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
    assert_equal "foo_tpl", driver(conf).instance.data_stream_template_name
  end

  def test_template_and_ilm_unset
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
      })
    assert_equal "foo", driver(conf).instance.data_stream_name
    assert_equal "foo_template", driver(conf).instance.data_stream_template_name
    assert_equal "foo_policy", driver(conf).instance.data_stream_ilm_name
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
    assert_equal 1, @bulk_records.length
  end

  def test_placeholder_params_unset
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    dsname = "foo_test"
    ilmname = "foo_test_policy"
    tplname = "foo_test_template"
    stub_default(dsname, ilmname, tplname)
    stub_bulk_feed(dsname, ilmname, tplname)
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo_${tag}',
      })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records.length
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
    assert_equal 1, @bulk_records.length
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
    assert_equal keys.count, @bulk_records.length
  end

  def test_bulk_insert_feed
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_ilm_name' => 'foo_ilm_policy',
        'data_stream_template_name' => 'foo_tpl'
      })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records.length
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
      data_stream_ilm_name       foo_ilm_policy
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

  def test_doesnt_update_ilm_policy_if_overwrite_unset
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    config = %{
      data_stream_name                  foo
      data_stream_ilm_name              foo_ilm_policy
      data_stream_ilm_policy            {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"15d"}}}}}}
    }

    stub_elastic_info
    stub_index_template
    stub_existent_data_stream?
    stub_existent_ilm?
    stub_data_stream

    stub_request(:put, "http://localhost:9200/#{ilm_endpoint}/policy/foo_ilm_policy").
      to_return(:status => 200, :body => "", :headers => {})

    assert_nothing_raised {
      driver(config)
    }
    assert_requested(:put, "http://localhost:9200/#{ilm_endpoint}/policy/foo_ilm_policy", times: 0)
  end

  def test_updates_ilm_policy_if_overwrite_set
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    config = %{
      data_stream_name                  foo
      data_stream_ilm_name              foo_ilm_policy
      data_stream_ilm_policy            {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"15d"}}}}}}
      data_stream_ilm_policy_overwrite  true
    }

    stub_elastic_info
    stub_index_template
    stub_existent_data_stream?
    stub_existent_ilm?
    stub_data_stream

    stub_request(:put, "http://localhost:9200/#{ilm_endpoint}/policy/foo_ilm_policy").
      to_return(:status => 200, :body => "", :headers => {})

    assert_nothing_raised {
      driver(config)
    }

    assert_requested(:put, "http://localhost:9200/#{ilm_endpoint}/policy/foo_ilm_policy", times: 1)
    assert_requested(:put, "http://localhost:9200/#{ilm_endpoint}/policy/foo_ilm_policy",
      body: '{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"15d"}}}}}}',
      times: 1)
  end

  def test_creates_custom_ilm_policy_if_none_exists
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    config = %{
      data_stream_name                  foo
      data_stream_ilm_name              foo_ilm_policy
      data_stream_ilm_policy            {"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"15d"}}}}}}
    }

    stub_elastic_info
    stub_index_template("foo_template")
    stub_data_stream
    stub_nonexistent_data_stream?
    stub_nonexistent_ilm?
    stub_nonexistent_template?("foo_template")

    stub_request(:put, "http://localhost:9200/#{ilm_endpoint}/policy/foo_ilm_policy").
      to_return(:status => 200, :body => "", :headers => {})

    assert_nothing_raised {
      driver(config)
    }

    assert_requested(:put, "http://localhost:9200/#{ilm_endpoint}/policy/foo_ilm_policy", times: 1)
    assert_requested(:put, "http://localhost:9200/#{ilm_endpoint}/policy/foo_ilm_policy",
      body: '{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"15d"}}}}}}',
      times: 1)
  end

  def test_doesnt_add_tag_key_when_not_configured
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    config = %{
      data_stream_name           foo
      data_stream_template_name  foo_tpl
      data_stream_ilm_name       foo_ilm_policy
    }

    stub_default
    stub_bulk_feed
    driver(config)
    driver.run(default_tag: 'mytag') do
      driver.feed(sample_record)
    end

    assert_equal(1, @bulk_records.length)
    assert_false(@bulk_records[0].has_key?('tag'))
  end


  def test_adds_tag_key_when_configured
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    config = %{
      data_stream_name           foo
      data_stream_template_name  foo_tpl
      data_stream_ilm_name       foo_ilm_policy
      include_tag_key            true
    }

    stub_default
    stub_bulk_feed
    driver(config)
    driver.run(default_tag: 'mytag') do
      driver.feed(sample_record)
    end

    assert_equal(1, @bulk_records.length)
    assert(@bulk_records[0].has_key?('tag'))
    assert_equal('mytag', @bulk_records[0]['tag'])
  end

  def test_adds_custom_tag_key_when_configured
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    config = %{
      data_stream_name           foo
      data_stream_template_name  foo_tpl
      data_stream_ilm_name       foo_ilm_policy
      include_tag_key            true
      tag_key                    custom_tag_key
    }

    stub_default
    stub_bulk_feed
    driver(config)
    driver.run(default_tag: 'mytag') do
      driver.feed(sample_record)
    end

    assert_equal(1, @bulk_records.length)
    assert(@bulk_records[0].has_key?('custom_tag_key'))
    assert_equal('mytag', @bulk_records[0]['custom_tag_key'])
  end

  def test_use_record_timestamp_if_present
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_ilm_name' => 'foo_ilm_policy',
        'data_stream_template_name' => 'foo_tpl'
      })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal 1, @bulk_records.length
    assert(@bulk_records[0].has_key?('@timestamp'))
    assert_equal SAMPLE_RECORD_TIMESTAMP, @bulk_records[0]['@timestamp']
  end

  def test_add_timestamp_if_not_present_in_record
    omit REQUIRED_ELASTIC_MESSAGE unless data_stream_supported?

    stub_default
    stub_bulk_feed
    conf = config_element(
      'ROOT', '', {
        '@type' => ELASTIC_DATA_STREAM_TYPE,
        'data_stream_name' => 'foo',
        'data_stream_ilm_name' => 'foo_ilm_policy',
        'data_stream_template_name' => 'foo_tpl'
      })
    driver(conf).run(default_tag: 'test') do
      driver.feed(sample_record_no_timestamp)
    end
    assert_equal 1, @bulk_records.length
    assert(@bulk_records[0].has_key?('@timestamp'))
  end
end
