# encoding: UTF-8
require 'date'
require 'elasticsearch'

class Fluent::ElasticsearchOutput < Fluent::BufferedOutput
  Fluent::Plugin.register_output('elasticsearch', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :logstash_format, :bool, :default => false
  config_param :logstash_prefix, :string, :default => "logstash"
  config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"
  config_param :type_name, :string, :default => "fluentd"
  config_param :index_name, :string, :default => "fluentd"
  config_param :id_key, :string, :default => nil
  config_param :flush_size, :integer, :default => 1000

  include Fluent::SetTagKeyMixin
  config_set_default :include_tag_key, false

  def initialize
    super
  end

  def configure(conf)
    super
  end

  def start
    super
    @es = Elasticsearch::Client.new :hosts => ["#{@host}:#{@port}"], :reload_connections => true
    raise "Can not reach Elasticsearch cluster (#{@host}:#{@port})!" unless @es.ping
  end

  def format(tag, time, record)
    [tag, time, record].to_msgpack
  end

  def shutdown
    super
  end

  def write(chunk)
    bulk_message = []

    chunk.msgpack_each do |tag, time, record|
      if @logstash_format
        record.merge!({"@timestamp" => Time.at(time).to_datetime.to_s})
	target_index = "#{@logstash_prefix}-#{Time.at(time).strftime("#{@logstash_dateformat}")}"
      else
        target_index = @index_name
      end

      if @include_tag_key
        record.merge!(@tag_key => tag)
      end

      meta = { "index" => {"_index" => target_index, "_type" => type_name} }
      if @id_key && record[@id_key]
        meta['index']['_id'] = record[@id_key]
      end
      if bulk_message.size < @flush_size
        bulk_message << Yajl::Encoder.encode(meta)
        bulk_message << Yajl::Encoder.encode(record)
      else 
	send(bulk_message)
        bulk_message.clear
      end
    end
    send(bulk_message) unless bulk_message.empty?
    bulk_message.clear
  end
  
  def send(data)
    @es.bulk body: data
  end
end
