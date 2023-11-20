require_relative '../helper'
require 'fluent/test/driver/output'
require 'fluent/plugin/out_elasticsearch'

class ElasticsearchFallbackSelectorTest < Test::Unit::TestCase
  attr_accessor :index_cmds

  def setup
    Fluent::Test.setup
    @driver = nil
    log = Fluent::Engine.log
    log.out.logs.slice!(0, log.out.logs.length)
  end

  def stub_elastic(url="http://localhost:9200/_bulk")
    stub_request(:post, url).with do |req|
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
    end.to_return({:status => 200, :body => "{}", :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
  end

  def elasticsearch_version
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.14.0")
      TRANSPORT_CLASS::VERSION
    else
      '6.4.2'.freeze
    end
  end

  def stub_elastic_info(url="http://localhost:9200/", version=elasticsearch_version)
    body ="{\"version\":{\"number\":\"#{version}\", \"build_flavor\":\"default\"},\"tagline\" : \"You Know, for Search\"}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
  end

  def stub_elastic_info_not_found(url="http://localhost:9200/", version=elasticsearch_version)
    stub_request(:get, url).to_return(:status => [404, "Not Found"], headers: {'x-elastic-product' => 'Elasticsearch' })
  end

  def stub_elastic_info_unavailable(url="http://localhost:9200/", version=elasticsearch_version)
    stub_request(:get, url).to_return(:status => [503, "Service Unavailable"], headers: {'x-elastic-product' => 'Elasticsearch' })
  end

  def sample_record(content={})
    {'age' => 26, 'request_id' => '42', 'parent_id' => 'parent', 'routing_id' => 'routing'}.merge(content)
  end

  def driver(conf='')
    @driver ||= Fluent::Test::Driver::Output.new(Fluent::Plugin::ElasticsearchOutput) {
      # v0.12's test driver assume format definition. This simulates ObjectBufferedOutput format
      if !defined?(Fluent::Plugin::Output)
        def format(tag, time, record)
          [time, record].to_msgpack
        end
      end
    }.configure(conf)
  end

  def test_fallback_on_info
    stub_elastic_info_not_found("http://localhost:9202/")
    stub_elastic_info_unavailable("http://localhost:9201/")
    stub_elastic_info
    stub_elastic
    config = %[
      hosts localhost:9202,localhost:9201,localhost:9200
      selector_class_name Fluent::Plugin::ElasticseatchFallbackSelector
      @log_level debug
      with_transporter_log true
      reload_connections true
      reload_after 10
      catch_transport_exception_on_retry false # For fallback testing
    ]
    assert_raise(TRANSPORT_CLASS::Transport::Errors::NotFound) do
      driver(config)
    end
    driver.run(default_tag: 'test') do
      driver.feed(sample_record)
    end
    assert_equal(2, index_cmds.length)
    assert_equal("fluentd", index_cmds.first['index']['_index'])
  end

  # TODO: on feed phase test case
end
