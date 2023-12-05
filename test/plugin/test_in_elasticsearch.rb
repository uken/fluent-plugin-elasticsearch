require_relative '../helper'
require 'date'
require 'fluent/test/helpers'
require 'json'
require 'fluent/test/driver/input'
require 'flexmock/test_unit'
require 'fluent/plugin/in_elasticsearch'

class ElasticsearchInputTest < Test::Unit::TestCase
  include FlexMock::TestCase
  include Fluent::Test::Helpers

  CONFIG = %[
    tag raw.elasticsearch
    interval 2
  ]

  def setup
    Fluent::Test.setup
    @driver = nil
    log = Fluent::Engine.log
    log.out.logs.slice!(0, log.out.logs.length)
    @http_method = if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("7.9.0")
                     :post
                   else
                     :get
                   end
  end

  def driver(conf='')
    @driver ||= Fluent::Test::Driver::Input.new(Fluent::Plugin::ElasticsearchInput).configure(conf)
  end

  def elasticsearch_version
    if Gem::Version.new(TRANSPORT_CLASS::VERSION) >= Gem::Version.new("7.14.0")
      TRANSPORT_CLASS::VERSION
    else
      '7.9.0'.freeze
    end
  end

  def stub_elastic_info(url="http://localhost:9200/", version=elasticsearch_version)
    body ="{\"version\":{\"number\":\"#{version}\", \"build_flavor\":\"default\"},\"tagline\" : \"You Know, for Search\"}"
    stub_request(:get, url).to_return({:status => 200, :body => body, :headers => { 'Content-Type' => 'json', 'x-elastic-product' => 'Elasticsearch' } })
  end

  def sample_response(index_name="fluentd")
    {
      "took"=>4,
      "timed_out"=>false,
      "_shards"=>{
        "total"=>2,
        "successful"=>2,
        "skipped"=>0,
        "failed"=>0
      },
      "hits"=>{
        "total"=>{
          "value"=>1,
          "relation"=>"eq"
        },
        "max_score"=>1,
        "hits"=>[
          {
            "_index"=>"#{index_name}-2019.11.14",
            "_type"=>"_doc",
            "_id"=>"MJ_faG4B16RqUMOji_nH",
            "_score"=>1,
            "_source"=>{
              "message"=>"Hi from Fluentd!",
              "@timestamp"=>"2019-11-14T16:45:10.559841000+09:00"
            }
          }
        ]
      }
    }.to_json
  end

  def sample_scroll_response
    {
      "_scroll_id"=>"WomkoUKG0QPB679Ulo6TqQgh3pIGRUmrl9qXXGK3EeiQh9rbYNasTkspZQcJ01uz",
      "took"=>0,
      "timed_out"=>false,
      "_shards"=>{
        "total"=>1,
        "successful"=>1,
        "skipped"=>0,
        "failed"=>0
      },
      "hits"=>{
        "total"=>{
          "value"=>7,
          "relation"=>"eq"
        },
        "max_score"=>nil,
        "hits"=>[
          {
            "_index"=>"fluentd-2019.11.14",
            "_type"=>"_doc",
            "_id"=>"MJ_faG4B16RqUMOji_nH",
            "_score"=>1,
            "_source"=>{
              "message"=>"Hi from Fluentd!",
              "@timestamp"=>"2019-11-14T16:45:10.559841000+09:00"
            },
            "sort"=>[0]
          }
        ]
      }
    }.to_json
  end

  def sample_scroll_response_2
    {
      "_scroll_id"=>"WomkoUKG0QPB679Ulo6TqQgh3pIGRUmrl9qXXGK3EeiQh9rbYNasTkspZQcJ01uz",
      "took"=>0,
      "timed_out"=>false,
      "_shards"=>{
        "total"=>1,
        "successful"=>1,
        "skipped"=>0,
        "failed"=>0
      },
      "hits"=>{
        "total"=>{
          "value"=>7,
          "relation"=>"eq"
        },
        "max_score"=>nil,
        "hits"=>[
          {
            "_index"=>"fluentd-2019.11.14",
            "_type"=>"_doc",
            "_id"=>"L5-saG4B16RqUMOjw_kb",
            "_score"=>1,
            "_source"=>{
              "message"=>"Yaaaaaaay from Fluentd!",
              "@timestamp"=>"2019-11-14T15:49:41.112023000+09:00"
            },
            "sort"=>[1]
          }
        ]
      }
    }.to_json
  end

  def sample_scroll_response_terminate
    {
      "_scroll_id"=>"WomkoUKG0QPB679Ulo6TqQgh3pIGRUmrl9qXXGK3EeiQh9rbYNasTkspZQcJ01uz",
      "took"=>1,
      "timed_out"=>false,
      "terminated_early"=>true,
      "_shards"=>{
        "total"=>1,
        "successful"=>1,
        "skipped"=>0,
        "failed"=>0
      },
      "hits"=>{
        "total"=>{
          "value"=>7,
          "relation"=>"eq"
        },
        "max_score"=>nil,
        "hits"=>[]
      }
    }.to_json
  end

  def test_configure
    config = %{
      host     logs.google.com
      port     777
      scheme   https
      path     /es/
      user     john
      password doe
      tag      raw.elasticsearch
    }
    instance = driver(config).instance

    expected_query = { "sort" => [ "_doc" ]}
    assert_equal 'logs.google.com', instance.host
    assert_equal 777, instance.port
    assert_equal :https, instance.scheme
    assert_equal '/es/', instance.path
    assert_equal 'john', instance.user
    assert_equal 'doe', instance.password
    assert_equal 'raw.elasticsearch', instance.tag
    assert_equal :TLSv1_2, instance.ssl_version
    assert_equal 'fluentd', instance.index_name
    assert_equal expected_query, instance.query
    assert_equal '1m', instance.scroll
    assert_equal 1000, instance.size
    assert_equal 1, instance.num_slices
    assert_equal 5, instance.interval
    assert_true instance.repeat
    assert_nil instance.client_key
    assert_nil instance.client_cert
    assert_nil instance.client_key_pass
    assert_nil instance.ca_file
    assert_false instance.with_transporter_log
    assert_equal :excon, instance.http_backend
    assert_nil instance.sniffer_class_name
    assert_true instance.custom_headers.empty?
    assert_equal ['_index', '_type', '_id'], instance.docinfo_fields
    assert_equal '@metadata', instance.docinfo_target
    assert_false instance.docinfo
  end

  def test_single_host_params_and_defaults
    config = %{
      host     logs.google.com
      user     john
      password doe
      tag      raw.elasticsearch
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
    assert_equal 'raw.elasticsearch', instance.tag
  end

  def test_single_host_params_and_defaults_with_escape_placeholders
    config = %{
      host     logs.google.com
      user     %{j+hn}
      password %{d@e}
      tag      raw.elasticsearch
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
    assert_equal 'raw.elasticsearch', instance.tag
  end

  def test_legacy_hosts_list
    config = %{
      hosts    host1:50,host2:100,host3
      scheme   https
      path     /es/
      port     123
      tag      raw.elasticsearch
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
    assert_equal 'raw.elasticsearch', instance.tag
  end

  def test_hosts_list
    config = %{
      hosts    https://john:password@host1:443/elastic/,http://host2
      path     /default_path
      user     default_user
      password default_password
      tag      raw.elasticsearch
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
    assert_equal 'raw.elasticsearch', instance.tag
  end

  def test_hosts_list_with_escape_placeholders
    config = %{
      hosts    https://%{j+hn}:%{passw@rd}@host1:443/elastic/,http://host2
      path     /default_path
      user     default_user
      password default_password
      tag      raw.elasticsearch
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
    assert_equal 'raw.elasticsearch', instance.tag
  end

  def test_emit
    stub_request(@http_method, "http://localhost:9200/fluentd/_search?scroll=1m&size=1000").
      with(body: "{\"sort\":[\"_doc\"]}").
      to_return(status: 200, body: sample_response.to_s,
                headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    driver(CONFIG)
    driver.run(expect_emits: 1, timeout: 10)
    expected = {"message"    => "Hi from Fluentd!",
                "@timestamp" => "2019-11-14T16:45:10.559841000+09:00"}
    event = driver.events.map {|e| e.last}.last
    assert_equal expected, event
  end

  def test_emit_with_custom_index_name
    index_name = "logstash"
    stub_request(@http_method, "http://localhost:9200/#{index_name}/_search?scroll=1m&size=1000").
      with(body: "{\"sort\":[\"_doc\"]}").
      to_return(status: 200, body: sample_response(index_name).to_s,
                headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    driver(CONFIG + %[index_name #{index_name}])
    driver.run(expect_emits: 1, timeout: 10)
    expected = {"message"    => "Hi from Fluentd!",
                "@timestamp" => "2019-11-14T16:45:10.559841000+09:00"}
    event = driver.events.map {|e| e.last}.last
    assert_equal expected, event
  end

  def test_emit_with_parse_timestamp
    index_name = "fluentd"
    stub_request(@http_method, "http://localhost:9200/#{index_name}/_search?scroll=1m&size=1000").
      with(body: "{\"sort\":[\"_doc\"]}").
      to_return(status: 200, body: sample_response(index_name).to_s,
                headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    driver(CONFIG + %[parse_timestamp])
    driver.run(expect_emits: 1, timeout: 10)
    expected = {"message"    => "Hi from Fluentd!",
                "@timestamp" => "2019-11-14T16:45:10.559841000+09:00"}
    event = driver.events.map {|e| e.last}.last
    time = driver.events.map {|e| e[1]}.last
    expected_time = event_time("2019-11-14T16:45:10.559841000+09:00")
    assert_equal expected_time.to_time, time.to_time
    assert_equal expected, event
  end

  def test_emit_with_parse_timestamp_and_timstamp_format
    index_name = "fluentd"
    stub_request(@http_method, "http://localhost:9200/#{index_name}/_search?scroll=1m&size=1000").
      with(body: "{\"sort\":[\"_doc\"]}").
      to_return(status: 200, body: sample_response(index_name).to_s,
                headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    driver(CONFIG + %[parse_timestamp true
                      timestamp_key_format %Y-%m-%dT%H:%M:%S.%N%z
                      ])
    driver.run(expect_emits: 1, timeout: 10)
    expected = {"message"    => "Hi from Fluentd!",
                "@timestamp" => "2019-11-14T16:45:10.559841000+09:00"}
    event = driver.events.map {|e| e.last}.last
    time = driver.events.map {|e| e[1]}.last
    expected_time = event_time("2019-11-14T16:45:10.559841000+09:00")
    assert_equal expected_time.to_time, time.to_time
    assert_equal expected, event
  end

  def test_emit_with_docinfo
    stub_request(@http_method, "http://localhost:9200/fluentd/_search?scroll=1m&size=1000").
      with(body: "{\"sort\":[\"_doc\"]}").
      to_return(status: 200, body: sample_response.to_s,
                headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    driver(CONFIG + %[docinfo true])
    driver.run(expect_emits: 1, timeout: 10)
    expected = {"message"    => "Hi from Fluentd!",
                "@timestamp" => "2019-11-14T16:45:10.559841000+09:00"}
    expected.merge!({"@metadata"=>
                     {"_id"=>"MJ_faG4B16RqUMOji_nH",
                      "_index"=>"fluentd-2019.11.14",
                      "_type"=>"_doc"}
                    })
    event = driver.events.map {|e| e.last}.last
    assert_equal expected, event
  end

  def test_emit_with_slices
    stub_request(@http_method, "http://localhost:9200/fluentd/_search?scroll=1m&size=1000").
      with(body: "{\"sort\":[\"_doc\"],\"slice\":{\"id\":0,\"max\":2}}").
      to_return(status: 200, body: sample_response.to_s,
                headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'})
    stub_request(@http_method, "http://localhost:9200/fluentd/_search?scroll=1m&size=1000").
      with(body: "{\"sort\":[\"_doc\"],\"slice\":{\"id\":1,\"max\":2}}").
      to_return(status: 200, body: sample_response.to_s,
                headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'})
    stub_elastic_info

    driver(CONFIG + %[num_slices 2])
    driver.run(expect_emits: 1, timeout: 10)
    expected = [
      {"message"=>"Hi from Fluentd!", "@timestamp"=>"2019-11-14T16:45:10.559841000+09:00"},
      {"message"=>"Hi from Fluentd!", "@timestamp"=>"2019-11-14T16:45:10.559841000+09:00"},
    ]
    events = driver.events.map {|e| e.last}
    assert_equal expected, events
  end

  def test_emit_with_size
    stub_request(@http_method, "http://localhost:9200/fluentd/_search?scroll=1m&size=1").
      with(body: "{\"sort\":[\"_doc\"]}").
      to_return(status: 200, body: sample_scroll_response.to_s,
                headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'})
    connection = 0
    scroll_request = stub_request(@http_method, "http://localhost:9200/_search/scroll?scroll=1m").
      with(
        body: "{\"scroll_id\":\"WomkoUKG0QPB679Ulo6TqQgh3pIGRUmrl9qXXGK3EeiQh9rbYNasTkspZQcJ01uz\"}") do
      connection += 1
    end
    stub_elastic_info
    scroll_request.to_return(lambda do |req|
                               if connection <= 1
                                 {status: 200, body: sample_scroll_response_2.to_s,
                                  headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'}}
                               else
                                 {status: 200, body: sample_scroll_response_terminate.to_s,
                                  headers: {'Content-Type' => 'application/json', 'X-elastic-product' => 'Elasticsearch'}}
                               end
                             end)
    if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("7.0.0")
      stub_request(:delete, "http://localhost:9200/_search/scroll").
        with(body: "{\"scroll_id\":\"WomkoUKG0QPB679Ulo6TqQgh3pIGRUmrl9qXXGK3EeiQh9rbYNasTkspZQcJ01uz\"}").
      to_return(status: 200, body: "", headers: {})
    else
      stub_request(:delete, "http://localhost:9200/_search/scroll/WomkoUKG0QPB679Ulo6TqQgh3pIGRUmrl9qXXGK3EeiQh9rbYNasTkspZQcJ01uz").
        to_return(status: 200, body: "", headers: {})
    end
    driver(CONFIG + %[size 1])
    driver.run(expect_emits: 1, timeout: 10)
    expected = [
      {"message"=>"Hi from Fluentd!", "@timestamp"=>"2019-11-14T16:45:10.559841000+09:00"},
      {"message"=>"Yaaaaaaay from Fluentd!", "@timestamp"=>"2019-11-14T15:49:41.112023000+09:00"}
    ]
    events = driver.events.map{|e| e.last}
    assert_equal expected, events
  end

end
