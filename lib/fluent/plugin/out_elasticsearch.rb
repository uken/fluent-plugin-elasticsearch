# encoding: UTF-8
require 'date'
require 'excon'
require 'elasticsearch'
require 'uri'
begin
  require 'strptime'
rescue LoadError
end

class Fluent::ElasticsearchOutput < Fluent::BufferedOutput
  class ConnectionFailure < StandardError; end

  Fluent::Plugin.register_output('elasticsearch', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :user, :string, :default => nil
  config_param :password, :string, :default => nil, :secret => true
  config_param :path, :string, :default => nil
  config_param :scheme, :string, :default => 'http'
  config_param :hosts, :string, :default => nil
  config_param :target_index_key, :string, :default => nil
  config_param :target_type_key, :string, :default => nil
  config_param :time_key_format, :string, :default => nil
  config_param :logstash_format, :bool, :default => false
  config_param :logstash_prefix, :string, :default => "logstash"
  config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"
  config_param :utc_index, :bool, :default => true
  config_param :type_name, :string, :default => "fluentd"
  config_param :index_name, :string, :default => "fluentd"
  config_param :id_key, :string, :default => nil
  config_param :write_operation, :string, :default => "index"
  config_param :parent_key, :string, :default => nil
  config_param :routing_key, :string, :default => nil
  config_param :request_timeout, :time, :default => 5
  config_param :reload_connections, :bool, :default => true
  config_param :reload_on_failure, :bool, :default => false
  config_param :resurrect_after, :time, :default => 60
  config_param :time_key, :string, :default => nil
  config_param :time_key_exclude_timestamp, :bool, :default => false
  config_param :ssl_verify , :bool, :default => true
  config_param :client_key, :string, :default => nil
  config_param :client_cert, :string, :default => nil
  config_param :client_key_pass, :string, :default => nil
  config_param :ca_file, :string, :default => nil
  config_param :remove_keys, :string, :default => nil
  config_param :flatten_hashes, :bool, :default => false
  config_param :flatten_hashes_separator, :string, :default => "_"

  include Fluent::SetTagKeyMixin
  config_set_default :include_tag_key, false

  def initialize
    super
    @time_parser = TimeParser.new(@time_key_format, @router)
  end

  def configure(conf)
    super
    @time_parser = TimeParser.new(@time_key_format, @router)

    if @remove_keys
      @remove_keys = @remove_keys.split(/\s*,\s*/)
    end

    if @target_index_key && @target_index_key.is_a?(String)
      @target_index_key = @target_index_key.split '.'
    end

    if @target_type_key && @target_type_key.is_a?(String)
      @target_type_key = @target_type_key.split '.'
    end
  end

  def start
    super
  end

  # once fluent v0.14 is released we might be able to use
  # Fluent::Parser::TimeParser, but it doesn't quite do what we want - if gives
  # [sec,nsec] where as we want something we can call `strftime` on...
  class TimeParser
    def initialize(time_key_format, router)
      @time_key_format = time_key_format
      @router = router
      @parser = if time_key_format
        begin
          # Strptime doesn't support all formats, but for those it does it's
          # blazingly fast.
          strptime = Strptime.new(time_key_format)
          Proc.new { |value| strptime.exec(value).to_datetime }
        rescue
          # Can happen if Strptime doesn't recognize the format; or
          # if strptime couldn't be required (because it's not installed -- it's
          # ruby 2 only)
          Proc.new { |value| DateTime.strptime(value, time_key_format) }
        end
      else
        Proc.new { |value| DateTime.parse(value) }
      end
    end

    def parse(value, event_time)
      @parser.call(value)
    rescue => e
      @router.emit_error_event("Fluent::ElasticsearchOutput::TimeParser.error", Fluent::Engine.now, {'time' => event_time, 'format' => @time_key_format, 'value' => value }, e)
      return Time.at(event_time).to_datetime
    end
  end

  def client
    @_es ||= begin
      excon_options = { client_key: @client_key, client_cert: @client_cert, client_key_pass: @client_key_pass }
      adapter_conf = lambda {|f| f.adapter :excon, excon_options }
      transport = Elasticsearch::Transport::Transport::HTTP::Faraday.new(get_connection_options.merge(
                                                                          options: {
                                                                            reload_connections: @reload_connections,
                                                                            reload_on_failure: @reload_on_failure,
                                                                            resurrect_after: @resurrect_after,
                                                                            retry_on_failure: 5,
                                                                            transport_options: {
                                                                              request: { timeout: @request_timeout },
                                                                              ssl: { verify: @ssl_verify, ca_file: @ca_file }
                                                                            }
                                                                          }), &adapter_conf)
      es = Elasticsearch::Client.new transport: transport

      begin
        raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description})!" unless es.ping
      rescue *es.transport.host_unreachable_exceptions => e
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
        if host_str.match(%r{^[^:]+(\:\d+)?$})
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

  def append_record_to_messages(op, meta, record, msgs)
    case op
    when "update", "upsert"
      if meta.has_key?("_id")
        msgs << { "update" => meta }
        msgs << { "doc" => record, "doc_as_upsert" => op == "upsert" }
      end
    when "create"
      if meta.has_key?("_id")
        msgs << { "create" => meta }
        msgs << record
      end
    when "index"
      msgs << { "index" => meta }
      msgs << record
    end
  end

  def flatten_record(record, prefix=[])
    ret = {}
    if record.is_a? Hash
      record.each { |key, value|
        ret.merge! flatten_record(value, prefix + [key.to_s])
      }
    elsif record.is_a? Array
      # Don't mess with arrays, leave them unprocessed
      ret.merge!({prefix.join(@flatten_hashes_separator) => record})
    else
      return {prefix.join(@flatten_hashes_separator) => record}
    end
    ret
  end

  def write(chunk)
    bulk_message = []

    chunk.msgpack_each do |tag, time, record|
      if @flatten_hashes
        record = flatten_record(record)
      end

      next unless record.is_a? Hash
      target_index_parent, target_index_child_key = get_parent_of(record, @target_index_key)
      if target_index_parent && target_index_parent[target_index_child_key]
        target_index = target_index_parent.delete(target_index_child_key)
      elsif @logstash_format
        if record.has_key?("@timestamp")
          dt = record["@timestamp"]
          dt = @time_parser.parse(record["@timestamp"], time)
        elsif record.has_key?(@time_key)
          dt = @time_parser.parse(record[@time_key], time)
          record['@timestamp'] = record[@time_key] unless time_key_exclude_timestamp
        else
          dt = Time.at(time).to_datetime
          record.merge!({"@timestamp" => dt.to_s})
        end
        dt = dt.new_offset(0) if @utc_index
        target_index = "#{@logstash_prefix}-#{dt.strftime(@logstash_dateformat)}"
      else
        target_index = @index_name
      end

      # Change target_index to lower-case since Elasticsearch doesn't
      # allow upper-case characters in index names.
      target_index = target_index.downcase
      if @include_tag_key
        record.merge!(@tag_key => tag)
      end

      target_type_parent, target_type_child_key = get_parent_of(record, @target_type_key)
      if target_type_parent && target_type_parent[target_type_child_key]
        target_type = target_type_parent.delete(target_type_child_key)
      else
        target_type = @type_name
      end

      meta = {"_index" => target_index, "_type" => target_type}

      @meta_config_map ||= { 'id_key' => '_id', 'parent_key' => '_parent', 'routing_key' => '_routing' }
      @meta_config_map.each_pair do |config_name, meta_key|
        record_key = self.instance_variable_get("@#{config_name}")
        meta[meta_key] = record[record_key] if record_key && record[record_key]
      end

      if @remove_keys
        @remove_keys.each { |key| record.delete(key) }
      end

      append_record_to_messages(@write_operation, meta, record, bulk_message)
    end

    send(bulk_message) unless bulk_message.empty?
    bulk_message.clear
  end

  # returns [parent, child_key] of child described by path array in record's tree
  # returns [nil, child_key] if path doesnt exist in record
  def get_parent_of(record, path)
    return [nil, nil] unless path

    parent_object = path[0..-2].reduce(record) { |a, e| a.is_a?(Hash) ? a[e] : nil }
    [parent_object, path[-1]]
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
