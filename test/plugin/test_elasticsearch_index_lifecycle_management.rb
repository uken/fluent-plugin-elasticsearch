require_relative '../helper'
require 'elasticsearch'
require 'fluent/plugin/elasticsearch_index_lifecycle_management'

class TestElasticsearchIndexLifecycleManagement < Test::Unit::TestCase
  include Fluent::Plugin::ElasticsearchIndexLifecycleManagement

  def setup
    begin
      require "elasticsearch/xpack"
    rescue LoadError
      omit "ILM testcase needs elasticsearch-xpack gem."
    end
    if Gem::Version.create(::Elasticsearch::Transport::VERSION) < Gem::Version.create("7.4.0")
      omit "elastisearch-ruby v7.4.0 or later is needed for ILM."
    end
    Fluent::Plugin::ElasticsearchIndexLifecycleManagement.module_eval(<<-CODE)
      def client
        Elasticsearch::Client.new url: 'localhost:9200'
      end
      def log
        log_device = Fluent::Test::DummyLogDevice.new
        dl_opts = {:log_level => ServerEngine::DaemonLogger::INFO}
        logger = ServerEngine::DaemonLogger.new(log_device, dl_opts)
        Fluent::Log.new(logger)
      end
    CODE
  end

  def stub_elastic_info(url="http://localhost:9200/", version="7.9.0")
    body ="{\"version\":{\"number\":\"#{version}\", \"build_flavor\":\"default\"},\"tagline\" : \"You Know, for Search\"}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json' } })
  end

  def test_xpack_info
    stub_request(:get, "http://localhost:9200/_xpack").
      to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json"})
    stub_elastic_info
    expected = {"features"=>{"ilm"=>{"available"=>true, "enabled"=>true}}}
    assert_equal(expected, xpack_info)
  end

  def test_verify_ilm_working
    stub_request(:get, "http://localhost:9200/_xpack").
      to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json"})
    stub_elastic_info
    assert_nothing_raised { verify_ilm_working }
  end

  def test_ilm_policy_doesnt_exists
    stub_request(:get, "http://localhost:9200/_ilm/policy/%7B:policy_id=%3E%22fluentd-policy%22%7D").
      to_return(:status => 404, :body => "", :headers => {})
    stub_elastic_info
    assert_false(ilm_policy_exists?(policy_id: "fluentd-policy"))
  end

  def test_ilm_policy_exists
    stub_request(:get, "http://localhost:9200/_ilm/policy/%7B:policy_id=%3E%22fluent-policy%22%7D").
      to_return(:status => 200, :body => "", :headers => {})
    stub_elastic_info
    assert_true(ilm_policy_exists?(policy_id: "fluent-policy"))
  end

  def test_create_ilm_policy
    stub_request(:get, "http://localhost:9200/_ilm/policy/fluent-policy").
      to_return(:status => 404, :body => "", :headers => {})
    stub_request(:put, "http://localhost:9200/_ilm/policy/fluent-policy").
      with(:body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}",
         :headers => {'Content-Type'=>'application/json'}).
      to_return(:status => 200, :body => "", :headers => {})
    stub_elastic_info
    create_ilm_policy("fluent-policy")

    assert_requested(:put, "http://localhost:9200/_ilm/policy/fluent-policy", times: 1)
  end
end
