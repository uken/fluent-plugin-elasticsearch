# encoding: UTF-8
require 'date'
require 'patron'
require 'elasticsearch'

class Fluent::ElasticsearchOutput < Fluent::BufferedOutput
  Fluent::Plugin.register_output('elasticsearch', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :logstash_format, :bool, :default => false
  config_param :logstash_prefix, :string, :default => "logstash"
  config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"
  config_param :utc_index, :bool, :default => true
  config_param :type_name, :string, :default => "fluentd"
  config_param :index_name, :string, :default => "fluentd"
  config_param :id_key, :string, :default => nil
  config_param :parent_key, :string, :default => nil
  config_param :hosts, :string, :default => nil
  config_param :request_timeout, :time, :default => 5

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
                                                                             retry_on_failure: 5,
                                                                             transport_options: {
                                                                               request: { timeout: @request_timeout }
                                                                             }
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
      next unless record.is_a? Hash
      if @logstash_format
        record.merge!({"@timestamp" => Time.at(time).to_datetime.to_s}) unless record.has_key?("@timestamp")
        if @utc_index
          target_index = "#{@logstash_prefix}-#{Time.at(time).getutc.strftime("#{@logstash_dateformat}")}"
        else
          target_index = "#{@logstash_prefix}-#{Time.at(time).strftime("#{@logstash_dateformat}")}"
        end
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
