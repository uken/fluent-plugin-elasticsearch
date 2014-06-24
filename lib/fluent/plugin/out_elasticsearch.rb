# encoding: UTF-8
require 'date'
require 'patron'
require 'elasticsearch'

class Fluent::ElasticsearchOutput < Fluent::BufferedOutput
  Fluent::Plugin.register_output('elasticsearch', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :time_key, :string, :default => nil
  config_param :time_format, :string, :default => nil
  config_param :type_name, :string, :default => "fluentd"
  config_param :index_name, :string, :default => "fluentd"
  config_param :id_key, :string, :default => nil
  config_param :parent_key, :string, :default => nil
  config_param :hosts, :string, :default => nil

  # Allow automatic sharding of indexes
  config_param :shard, :bool, :default => false
  config_param :shard_format, :string, :default => "%{prefix}-%{date}"
  config_param :shard_prefix, :string, :default => nil
  config_param :shard_dateformat, :string, :default => "%Y.%m.%d"
  config_param :utc_index, :bool, :default => true

  # Logstash-specific commands to create pre-defined behavior
  config_param :logstash_format, :bool, :default => false
  config_param :logstash_prefix, :string, :default => "logstash"
  config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"

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
  end

  def client
    @_es ||= begin
      adapter_conf = lambda {|f| f.adapter :patron }
      transport = Elasticsearch::Transport::Transport::HTTP::Faraday.new({ hosts: get_hosts,
                                                                           options: {
                                                                             reload_connections: true,
                                                                             retry_on_failure: 5
                                                                          }}, &adapter_conf)
      Elasticsearch::Client.new transport: transport
    end
    raise "Can not reach Elasticsearch cluster (#{@host}:#{@port})!" unless @_es.ping
    @_es
  end

  def get_hosts
    if @hosts
        @hosts.split(',').map {|x| hp = x.split(':'); { host: hp[0], port: hp[1] || @port } }.compact
     else
       [{host: @host, port: @port }]
     end
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
      target_index = @index_name

      # Pre-defined logstash compatibility
      if @logstash_format
        @time_key = "@timestamp"
        @time_format = nil
        @shard = true
        @shard_prefix = @logstash_prefix
        @shard_dateformat = @logstash_dateformat
        @shard_format = "%{prefix}-%{date}"
      end

      # Merge in time key if required
      if @time_key
        if @time_format
          record.merge!({@time_key => Time.at(time).strftime("#{@time_format}")}) unless record.has_key?(@time_key)
        else
          record.merge!({@time_key => Time.at(time).to_datetime.to_s}) unless record.has_key?(@time_key)
        end
      end

      # Merge in tag key if required
      if @include_tag_key
        record.merge!(@tag_key => tag)
      end

      # Shard index key if required
      if @shard
        shard_time = Time.at(time)
        if @utc_index
          shard_time.getutc!
        end

        # If shard_prefix is nil, we inherit the index_name
        if @shard_prefix.nil?
          @shard_prefix = @index_name
        end

        shard_index_context = {
            prefix: @shard_prefix,
            date: shard_time.strftime("#{@shard_dateformat}"),
            index: @index_name,
            type: @type_name
        }
        target_index = @shard_format % shard_index_context
      end

      meta = { "index" => {"_index" => target_index, "_type" => type_name} }
      if @id_key && record[@id_key]
        meta['index']['_id'] = record[@id_key]
      end

      if @parent_key && record[@parent_key]
        meta['index']['_parent'] = record[@parent_key]
      end

      bulk_message << meta
      bulk_message << record
    end

    send(bulk_message) unless bulk_message.empty?
    bulk_message.clear
  end

  def send(data)
    client.bulk body: data
  end
end
