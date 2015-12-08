# encoding: UTF-8
require 'date'
require 'excon'
require 'elasticsearch'
require 'uri'

class Fluent::ElasticsearchOutput < Fluent::BufferedOutput
  ConnectionFailure = Class.new(StandardError)
  TIMESTAMP_KEY = '@timestamp'.freeze
  TRANSPORT_CLASS = Elasticsearch::Transport::Transport::HTTP::Faraday

  Fluent::Plugin.register_output('elasticsearch', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :user, :string, :default => nil
  config_param :password, :string, :default => nil, :secret => true
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
  config_param :reload_connections, :bool, :default => true
  config_param :reload_on_failure, :bool, :default => false
  config_param :resurrect_after, :time, :default => 60
  config_param :time_key, :string, :default => nil
  config_param :ssl_verify , :bool, :default => true
  config_param :client_key, :string, :default => nil
  config_param :client_cert, :string, :default => nil
  config_param :client_key_pass, :string, :default => nil
  config_param :ca_file, :string, :default => nil

  include Fluent::SetTagKeyMixin
  config_set_default :include_tag_key, false

  # def initialize
  #   super
  # end

  def configure(conf)
    super

    @_connection_options = {
      reload_connections: @reload_connections,
      reload_on_failure: @reload_on_failure,
      resurrect_after: @resurrect_after,
      retry_on_failure: 5,
      transport_options: {
        request: { timeout: @request_timeout },
        ssl: { verify: @ssl_verify, ca_file: @ca_file }
      }
    }
  end

  # def start
  #   super
  # end

  def client
    @_es ||= begin
      transport = TRANSPORT_CLASS.new(hosts: hosts, options: @_connection_options) do |f|
        f.adapter :excon, {
          client_key: @client_key,
          client_cert: @client_cert,
          client_key_pass: @client_key_pass
        }
      end
      es = Elasticsearch::Client.new transport: transport

      begin
        es.ping or raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})!"
      rescue *es.transport.host_unreachable_exceptions => e
        raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})! #{e.message}"
      end

      log.info "Connection opened to Elasticsearch cluster => #{connection_options_description}"
      es
    end
  end

  def hosts
    raise "`password` must be present if `user` is present" if @user && !@password

    @_hosts ||= begin
      hosts = if @hosts
        parse_hosts(@hosts, @port, @scheme)
      else
        [{host: @host, port: @port, scheme: @scheme}]
      end

      hosts.each do |host|
        if !host[:user] && @user
          host[:user] = @user
          host[:password] = @password
        end
        host[:path] = @path if !host[:path] && @path
      end

      hosts
    end
  end

  def parse_hosts(hosts, port, scheme)
    hosts.split(',').map do |host_str|
      # Support legacy hosts format host:port,host:port,host:port...
      if host_str.match(/^([^:]+)(:(\d+))?$/)
        {host: $1, port: ($3 || port).to_i, scheme: scheme}
      else
        # New hosts format expects URLs such as http://logs.foo.com,https://john:pass@logs2.foo.com/elastic
        uri = URI(host_str)
        %w(user password path).inject(host: uri.host, port: uri.port, scheme: uri.scheme) do |hash, key|
          hash[key.to_sym] = uri.public_send(key) unless uri.public_send(key).nil? || uri.public_send(key) == ''
          hash
        end
      end
    end
  end

  def connection_options_description
    hosts.map do |host_info|
      attributes = host_info.dup
      attributes[:password] = '[obfuscated]' if attributes.has_key?(:password)
      attributes.inspect
    end.join(', ')
  end

  def format(tag, time, record)
    [tag, time, record].to_msgpack
  end

  # def shutdown
  #   super
  # end

  def write(chunk)
    bulk_message = []

    chunk.msgpack_each do |tag, time, record|
      next unless record.is_a? Hash
      bulk_message += message(tag, time, record)
    end

    send(bulk_message) unless bulk_message.empty?
    bulk_message.clear
  end

  def message(tag, time, record)
    time = process_time(record, time) if @logstash_format

    if @include_tag_key
      record[@tag_key] = tag
    end

    meta = build_meta(time, record)

    [meta, record]
  end

  def build_meta(time, record)
    index = if @logstash_format
      "#{@logstash_prefix}-#{time.strftime("#{@logstash_dateformat}")}"
    else
      @index_name
    end

    meta = { "index" => {"_index" => index, "_type" => @type_name} }

    meta['index']['_id'] = record[@id_key] if @id_key && record[@id_key]
    meta['index']['_parent'] = record[@parent_key] if @parent_key && record[@parent_key]

    meta
  end

  def process_time(record, time)
    time = if record.has_key?(TIMESTAMP_KEY)
      Time.parse(record[TIMESTAMP_KEY])
    elsif record.has_key?(@time_key)
      record[TIMESTAMP_KEY] = record[@time_key]
      Time.parse(record[@time_key])
    else
      record[TIMESTAMP_KEY] = Time.at(time).to_datetime.to_s
      time
    end

    @utc_index ? Time.at(time).getutc : Time.at(time)
  end

  def send(data)
    retries = 0
    begin
      client.bulk body: data
    rescue *client.transport.host_unreachable_exceptions => e
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
