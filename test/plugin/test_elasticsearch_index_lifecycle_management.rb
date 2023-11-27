require_relative '../helper'
require 'elasticsearch'
require 'fluent/plugin/elasticsearch_index_lifecycle_management'

class TestElasticsearchIndexLifecycleManagement < Test::Unit::TestCase
  include Fluent::Plugin::ElasticsearchIndexLifecycleManagement

  def setup
    if Gem::Version.new(Elasticsearch::VERSION) < Gem::Version.new("7.14.0")
      begin
        require "elasticsearch/xpack"
      rescue LoadError
        omit "ILM testcase needs elasticsearch-xpack gem."
      end
    end
    if Gem::Version.create(::TRANSPORT_CLASS::VERSION) < Gem::Version.create("7.4.0")
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

  def elasticsearch_version
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("8.0.0")
      TRANSPORT_CLASS::VERSION
    else
      '6.4.2'.freeze
    end
  end

  def ilm_existence_endpoint(policy_id)
    if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("8.0.0")
      "_ilm/policy/#{policy_id}"
    else
      "_ilm/policy/%7B:policy_id=%3E%22#{policy_id}%22%7D"
    end
  end

  def ilm_creation_endpoint(policy_id)
    "_ilm/policy/#{policy_id}"
  end

  def stub_elastic_info(url="http://localhost:9200/", version=elasticsearch_version)
    body ="{\"version\":{\"number\":\"#{version}\", \"build_flavor\":\"default\"},\"tagline\" : \"You Know, for Search\"}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
  end

  def test_xpack_info
    stub_request(:get, "http://localhost:9200/_xpack").
      to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'  })
    stub_elastic_info
    expected = {"features"=>{"ilm"=>{"available"=>true, "enabled"=>true}}}
    if xpack_info.is_a?(Elasticsearch::API::Response)
      assert_equal(expected, xpack_info.body)
    else
      assert_equal(expected, xpack_info)
    end
  end

  def test_verify_ilm_working
    stub_request(:get, "http://localhost:9200/_xpack").
      to_return(:status => 200, :body => '{"features":{"ilm":{"available":true,"enabled":true}}}', :headers => {"Content-Type"=> "application/json", 'x-elastic-product' => 'Elasticsearch'  })
    stub_elastic_info
    assert_nothing_raised { verify_ilm_working }
  end

  def test_ilm_policy_doesnt_exists
    stub_request(:get, "http://localhost:9200/#{ilm_existence_endpoint("fluentd-policy")}").
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info
    assert_false(ilm_policy_exists?("fluentd-policy"))
  end

  def test_ilm_policy_exists
    stub_request(:get, "http://localhost:9200/#{ilm_existence_endpoint("fluent-policy")}").
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info
    assert_true(ilm_policy_exists?("fluent-policy"))
  end

  def test_create_ilm_policy
    stub_request(:get, "http://localhost:9200/#{ilm_creation_endpoint("fluent-policy")}").
      to_return(:status => 404, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_request(:put, "http://localhost:9200/#{ilm_creation_endpoint("fluent-policy")}").
      with(:body => "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_size\":\"50gb\",\"max_age\":\"30d\"}}}}}}",
         :headers => {'Content-Type'=>'application/json'}).
      to_return(:status => 200, :body => "", :headers => {'x-elastic-product' => 'Elasticsearch'})
    stub_elastic_info
    create_ilm_policy("fluent-policy")

    assert_requested(:put, "http://localhost:9200/#{ilm_creation_endpoint("fluent-policy")}", times: 1)
  end
end
