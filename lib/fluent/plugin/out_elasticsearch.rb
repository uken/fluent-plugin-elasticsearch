# encoding: UTF-8
require 'date'
require 'patron'
require 'elasticsearch'
require 'uri'

class Fluent::ElasticsearchOutput < Fluent::BufferedOutput
  class ConnectionFailure < StandardError; end

  Fluent::Plugin.register_output('elasticsearch', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :user, :string, :default => nil
  config_param :password, :string, :default => nil
  config_param :path, :string, :default => nil
  config_param :scheme, :string, :default => 'http'
  config_param :hosts, :string, :default => nil
  config_param :logstash_format, :bool, :default => false
  config_param :logstash_prefix, :string, :default => "logstash"
  config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"
  config_param :utc_index, :bool, :default => true
  config_param :type_name, :string, :default => "fluentd"
  config_param :index_name, :string, :default => "fluentd"
  config_param :id_key, :string, :default => nil
  config_param :parent_key, :string, :default => nil
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
      transport = Elasticsearch::Transport::Transport::HTTP::Faraday.new(get_connection_options.merge(
                                                                          options: {
                                                                            reload_connections: true,
                                                                            retry_on_failure: 5,
                                                                            transport_options: {
                                                                              request: { timeout: @request_timeout }
                                                                            }
                                                                          }), &adapter_conf)
      es = Elasticsearch::Client.new transport: transport

      begin
        raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})!" unless es.ping
      rescue Faraday::ConnectionFailed => e
        raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})! #{e.message}"
      end

      log.info "Connection opened to Elasticsearch cluster => #{connection_options_description}"
      es
    end
  end

  def get_connection_options
    raise "`password` must be present if `user` is present" if @user && !@password

    hosts = if @hosts
      @hosts.split(',').map do |host_str|
        # Support legacy hosts format host:port,host:port,host:port...
        if host_str.match(%r{^[^:]+\:\d+$})
          {
            host:   host_str.split(':')[0],
            port:   (host_str.split(':')[1] || @port).to_i,
            scheme: @scheme
          }
        else
          # New hosts format expects URLs such as http://logs.foo.com,https://john:pass@logs2.foo.com/elastic
          uri = URI(host_str)
          %w(user password path).inject(host: uri.host, port: uri.port, scheme: uri.scheme) do |hash, key|
            hash[key.to_sym] = uri.public_send(key) unless uri.public_send(key).nil? || uri.public_send(key) == ''
            hash
          end
        end
      end.compact
    else
      [{host: @host, port: @port, scheme: @scheme}]
    end.each do |host|
      host.merge!(user: @user, password: @password) if !host[:user] && @user
      host.merge!(path: @path) if !host[:path] && @path
    end

    {
      hosts: hosts
    }
  end

  def connection_options_description
    get_connection_options[:hosts].map do |host_info|
      attributes = host_info.dup
      attributes[:password] = 'obfuscated' if attributes.has_key?(:password)
      attributes.inspect
    end.join(', ')
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
    retries = 0
    begin
      client.bulk body: data
    rescue Faraday::ConnectionFailed, Faraday::TimeoutError => e
      if retries < 2
        retries += 1
        @_es = nil
        log.warn "Could not push logs to Elasticsearch, resetting connection and trying again. #{e.message}"
        sleep 2**retries
        retry
      end
      raise ConnectionFailure, "Could not push logs to Elasticsearch after #{retries} retries. #{e.message}"
    end
  end
end
