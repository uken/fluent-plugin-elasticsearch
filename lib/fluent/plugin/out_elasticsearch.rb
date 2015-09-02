# encoding: UTF-8
require 'date'
require 'excon'
require 'elasticsearch'
require 'uri'

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
  config_param :time_key, :string, :default => nil
  config_param :ssl_verify , :bool, :default => true
  config_param :client_key, :string, :default => nil
  config_param :client_cert, :string, :default => nil
  config_param :client_key_pass, :string, :default => nil
  config_param :ca_file, :string, :default => nil
  config_param :delimiter, :string, :default => "."

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
      excon_options = { client_key: config['client_key'], client_cert: config['client_cert'], client_key_pass: config['client_key_pass'] }
      adapter_conf = lambda {|f| f.adapter :excon, excon_options }
      transport = Elasticsearch::Transport::Transport::HTTP::Faraday.new(get_connection_options.merge(
                                                                          options: {
                                                                            reload_connections: config['reload_connections'],
                                                                            reload_on_failure: config['reload_on_failure'],
                                                                            retry_on_failure: 5,
                                                                            transport_options: {
                                                                              request: { timeout: config['request_timeout'] },
                                                                              ssl: { verify: config['ssl_verify'], ca_file: config['ca_file'] }
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
    raise "`password` must be present if `user` is present" if config['user'] && !config['password']

    hosts = if @hosts
      @hosts.split(',').map do |host_str|
        # Support legacy hosts format host:port,host:port,host:port...
        if host_str.match(%r{^[^:]+(\:\d+)?$})
          {
            host:   host_str.split(':')[0],
            port:   (host_str.split(':')[1] || config['port']).to_i,
            scheme: config['scheme']
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
      [{host: config['host'], port: config['port'], scheme: config['scheme']}]
    end.each do |host|
      host.merge!(user: config['user'], password: config['password']) if !host[:user] && config['user']
      host.merge!(path: config['path']) if !host[:path] && config['path']
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

      # evaluate all configurations here
      config = Hash.new
      self.instance_variables.each { |var|
        if self.instance_variable_get(var).is_a?(String) || self.instance_variable_get(var).is_a?(TrueClass) || self.instance_variable_get(var).is_a?(FalseClass) then
          value = expand_param(self.instance_variable_get(var), tag, record)

          var = var.to_s.gsub(/@(.+)/){ $1 }
          config[var] = value
        end
      }
      # end eval all configs

      if @logstash_format
        if record.has_key?("@timestamp")
          time = Time.parse record["@timestamp"]
        elsif record.has_key?(@time_key)
          time = Time.parse record[config['time_key']]
          record['@timestamp'] = record[config['time_key']]
        else
          record.merge!({"@timestamp" => Time.at(time).to_datetime.to_s})
        end

        if config['utc_index']
          target_index = "#{config['logstash_prefix']}-#{Time.at(time).getutc.strftime("#{config['logstash_dateformat']}")}"
        else
          target_index = "#{config['logstash_prefix']}-#{Time.at(time).strftime("#{config['logstash_dateformat']}")}"
        end
      else
        target_index = config['index_name']
      end

      if config['include_tag_key']
        record.merge!(config['tag_key'] => tag)
      end

      meta = { "index" => {"_index" => target_index, "_type" => config['type_name']} }
      if config['id_key'] && record[config['id_key']]
        meta['index']['_id'] = record[config['id_key']]
      end

      if config['parent_key'] && record[config['parent_key']]
        meta['index']['_parent'] = record[config['parent_key']]
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

  def expand_param(param, tag, record)

    # check for '${ ... }'
    #   yes => `eval`
    #   no  => return param
    return param if (param =~ /^\${.+}$/).nil?

    # check for 'tag_parts[]'
      # separated by a delimiter (default '.')
    tag_parts = tag.split(@delimiter) unless (param =~ /tag_parts\[.+\]/).nil?

    # pull out section between ${} then eval
    param.gsub(/^\${(.+)}$/) {
      eval( $1 )
    }
  end
end
