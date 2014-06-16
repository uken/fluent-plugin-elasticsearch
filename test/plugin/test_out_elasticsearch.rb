require 'test/unit'

require 'fluent/test'
require 'fluent/plugin/out_elasticsearch'

require 'webmock/test_unit'
require 'date'

require 'helper'

$:.push File.expand_path("../lib", __FILE__)
$:.push File.dirname(__FILE__)

WebMock.disable_net_connect!

class ElasticsearchOutput < Test::Unit::TestCase
  attr_accessor :index_cmds, :index_command_counts

  def setup
    Fluent::Test.setup
    @driver = nil
  end

  def driver(tag='test', conf='')
    @driver ||= Fluent::Test::BufferedOutputTestDriver.new(Fluent::ElasticsearchOutput, tag).configure(conf)
  end

  def sample_record
    {'age' => 26, 'request_id' => '42', 'parent_id' => 'parent'}
  end

  def stub_elastic_ping(url="http://localhost:9200")
    stub_request(:head, url).with.to_return(:status => 200, :body => "", :headers => {})
  end

  def stub_elastic(url="http://localhost:9200/_bulk")
    stub_request(:post, url).with do |req|
      @index_cmds = req.body.split("\n").map {|r| JSON.parse(r) }
    end
  end

  def stub_elastic_unavailable(url="http://localhost:9200/_bulk")
    stub_request(:post, url).to_return(:status => [503, "Service Unavailable"])
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

  def test_writes_to_default_index
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert_equal('fluentd', index_cmds.first['index']['_index'])
  end

  def test_writes_to_default_type
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert_equal('fluentd', index_cmds.first['index']['_type'])
  end

  def test_writes_to_speficied_index
    driver.configure("index_name myindex\n")
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert_equal('myindex', index_cmds.first['index']['_index'])
  end

  def test_writes_to_speficied_type
    driver.configure("type_name mytype\n")
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert_equal('mytype', index_cmds.first['index']['_type'])
  end

  def test_writes_to_speficied_host
    driver.configure("host 192.168.33.50\n")
    stub_elastic_ping("http://192.168.33.50:9200")
    elastic_request = stub_elastic("http://192.168.33.50:9200/_bulk")
    driver.emit(sample_record)
    driver.run
    assert_requested(elastic_request)
  end

  def test_writes_to_speficied_port
    driver.configure("port 9201\n")
    stub_elastic_ping("http://localhost:9201")
    elastic_request = stub_elastic("http://localhost:9201/_bulk")
    driver.emit(sample_record)
    driver.run
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

    1000.times do
      driver.emit(sample_record.merge('age'=>rand(100)))
    end

    driver.run

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

  def test_makes_bulk_request
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.emit(sample_record.merge('age' => 27))
    driver.run
    assert_equal(4, index_cmds.count)
  end

  def test_all_records_are_preserved_in_bulk
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.emit(sample_record.merge('age' => 27))
    driver.run
    assert_equal(26, index_cmds[1]['age'])
    assert_equal(27, index_cmds[3]['age'])
  end

  def test_writes_to_logstash_index
    driver.configure("logstash_format true\n")
    time = Time.parse Date.today.to_s
    logstash_index = "logstash-#{time.getutc.strftime("%Y.%m.%d")}"
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record, time)
    driver.run
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  def test_writes_to_logstash_utc_index
    driver.configure("logstash_format true\nutc_index false\n")
    time = Time.parse Date.today.to_s
    utc_index = "logstash-#{time.strftime("%Y.%m.%d")}"
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record, time)
    driver.run
    assert_equal(utc_index, index_cmds.first['index']['_index'])
  end

  def test_writes_to_logstash_index_with_specified_prefix
    driver.configure("logstash_format true\nlogstash_prefix myprefix\n")
    time = Time.parse Date.today.to_s
    logstash_index = "myprefix-#{time.getutc.strftime("%Y.%m.%d")}"
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record, time)
    driver.run
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

    def test_writes_to_logstash_index_with_specified_dateformat
    driver.configure("logstash_format true\nlogstash_dateformat %Y.%m\n")
    time = Time.parse Date.today.to_s
    logstash_index = "logstash-#{time.getutc.strftime("%Y.%m")}"
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record, time)
    driver.run
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  def test_writes_to_logstash_index_with_specified_prefix_and_dateformat
    driver.configure("logstash_format true\nlogstash_prefix myprefix\nlogstash_dateformat %Y.%m\n")
    time = Time.parse Date.today.to_s
    logstash_index = "myprefix-#{time.getutc.strftime("%Y.%m")}"
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record, time)
    driver.run
    assert_equal(logstash_index, index_cmds.first['index']['_index'])
  end

  def test_doesnt_add_logstash_timestamp_by_default
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert_nil(index_cmds[1]['@timestamp'])
  end

  def test_adds_logstash_timestamp_when_configured
    driver.configure("logstash_format true\n")
    stub_elastic_ping
    stub_elastic
    ts = DateTime.now.to_s
    driver.emit(sample_record)
    driver.run
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end

  def test_uses_custom_timestamp_when_included_in_record
    driver.configure("logstash_format true\n")
    stub_elastic_ping
    stub_elastic
    ts = DateTime.new(2001,2,3).to_s
    driver.emit(sample_record.merge!('@timestamp' => ts))
    driver.run
    assert(index_cmds[1].has_key? '@timestamp')
    assert_equal(index_cmds[1]['@timestamp'], ts)
  end

  def test_doesnt_add_tag_key_by_default
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert_nil(index_cmds[1]['tag'])
  end

  def test_adds_tag_key_when_configured
    driver('mytag').configure("include_tag_key true\n")
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert(index_cmds[1].has_key?('tag'))
    assert_equal(index_cmds[1]['tag'], 'mytag')
  end

  def test_adds_id_key_when_configured
    driver.configure("id_key request_id\n")
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert_equal(index_cmds[0]['index']['_id'], '42')
  end

  def test_doesnt_add_id_key_if_missing_when_configured
    driver.configure("id_key another_request_id\n")
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert(!index_cmds[0]['index'].has_key?('_id'))
  end

  def test_adds_id_key_when_not_configured
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert(!index_cmds[0]['index'].has_key?('_id'))
  end

  def test_adds_parent_key_when_configured
    driver.configure("parent_key parent_id\n")
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert_equal(index_cmds[0]['index']['_parent'], 'parent')
  end

  def test_doesnt_add_parent_key_if_missing_when_configured
    driver.configure("parent_key another_parent_id\n")
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert(!index_cmds[0]['index'].has_key?('_parent'))
  end

  def test_adds_parent_key_when_not_configured
    stub_elastic_ping
    stub_elastic
    driver.emit(sample_record)
    driver.run
    assert(!index_cmds[0]['index'].has_key?('_parent'))
  end

  def test_request_error
    stub_elastic_ping
    stub_elastic_unavailable
    driver.emit(sample_record)
    assert_raise(Elasticsearch::Transport::Transport::Errors::ServiceUnavailable) {
      driver.run
    }
  end
end
