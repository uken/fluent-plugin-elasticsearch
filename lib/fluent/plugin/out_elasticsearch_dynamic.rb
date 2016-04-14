# encoding: UTF-8
require_relative 'out_elasticsearch'

class Fluent::ElasticsearchOutputDynamic < Fluent::ElasticsearchOutput

  Fluent::Plugin.register_output('elasticsearch_dynamic', self)

  config_param :delimiter, :string, :default => "."

  # params overloaded as strings
  config_param :port, :string, :default => "9200"
  config_param :logstash_format, :string, :default => "false"
  config_param :utc_index, :string, :default => "true"
  config_param :time_key_exclude_timestamp, :bool, :default => false
  config_param :reload_connections, :string, :default => "true"
  config_param :reload_on_failure, :string, :default => "false"
  config_param :resurrect_after, :string, :default => "60"
  config_param :ssl_verify, :string, :dfeault => "true"

  def configure(conf)
    super

    # evaluate all configurations here
    @dynamic_params = self.instance_variables.select { |var| is_valid_expand_param_type(var) }
    @dynamic_config = Hash.new
    @dynamic_params.each { |var|
      value = expand_param(self.instance_variable_get(var), nil, nil, nil)
      var = var[1..-1]
      @dynamic_config[var] = value
    }
    # end eval all configs
    @current_config = nil
  end

  def client(host)

    # check here to see if we already have a client connection for the given host
    connection_options = get_connection_options(host)

    @_es = nil unless is_existing_connection(connection_options[:hosts])

    @_es ||= begin
      @current_config = connection_options[:hosts].clone
      excon_options = { client_key: @dynamic_config['client_key'], client_cert: @dynamic_config['client_cert'], client_key_pass: @dynamic_config['client_key_pass'] }
      adapter_conf = lambda {|f| f.adapter :excon, excon_options }
      transport = Elasticsearch::Transport::Transport::HTTP::Faraday.new(connection_options.merge(
                                                                          options: {
                                                                            reload_connections: @dynamic_config['reload_connections'],
                                                                            reload_on_failure: @dynamic_config['reload_on_failure'],
                                                                            resurrect_after: @dynamic_config['resurrect_after'].to_i,
                                                                            retry_on_failure: 5,
                                                                            transport_options: {
                                                                              request: { timeout: @dynamic_config['request_timeout'] },
                                                                              ssl: { verify: @dynamic_config['ssl_verify'], ca_file: @dynamic_config['ca_file'] }
                                                                            }
                                                                          }), &adapter_conf)
      es = Elasticsearch::Client.new transport: transport

      begin
        raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description(host)})!" unless es.ping
      rescue *es.transport.host_unreachable_exceptions => e
        raise ConnectionFailure, "Can not reach Elasticsearch cluster (#{connection_options_description(host)})! #{e.message}"
      end

      log.info "Connection opened to Elasticsearch cluster => #{connection_options_description(host)}"
      es
    end
  end

  def get_connection_options(con_host)
    raise "`password` must be present if `user` is present" if @dynamic_config['user'] && !@dynamic_config['password']

    hosts = if con_host || @dynamic_config['hosts']
      (con_host || @dynamic_config['hosts']).split(',').map do |host_str|
        # Support legacy hosts format host:port,host:port,host:port...
        if host_str.match(%r{^[^:]+(\:\d+)?$})
          {
            host:   host_str.split(':')[0],
            port:   (host_str.split(':')[1] || @dynamic_config['port']).to_i,
            scheme: @dynamic_config['scheme']
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
      [{host: @dynamic_config['host'], port: @dynamic_config['port'].to_i, scheme: @dynamic_config['scheme']}]
    end.each do |host|
      host.merge!(user: @dynamic_config['user'], password: @dynamic_config['password']) if !host[:user] && @dynamic_config['user']
      host.merge!(path: @dynamic_config['path']) if !host[:path] && @dynamic_config['path']
    end

    {
      hosts: hosts
    }
  end

  def connection_options_description(host)
    get_connection_options(host)[:hosts].map do |host_info|
      attributes = host_info.dup
      attributes[:password] = 'obfuscated' if attributes.has_key?(:password)
      attributes.inspect
    end.join(', ')
  end

  def write(chunk)
    bulk_message = Hash.new { |h,k| h[k] = [] }
    dynamic_conf = @dynamic_config.clone

    chunk.msgpack_each do |tag, time, record|
      next unless record.is_a? Hash

      # evaluate all configurations here
      @dynamic_params.each { |var|
        k = var[1..-1]
        v = self.instance_variable_get(var)
        # check here to determine if we should evaluate
        if dynamic_conf[k] != v
          value = expand_param(v, tag, time, record)
          dynamic_conf[k] = value
        end
      }
      # end eval all configs

      if eval(dynamic_conf['logstash_format'])
        if record.has_key?("@timestamp")
          time = Time.parse record["@timestamp"]
        elsif record.has_key?(dynamic_conf['time_key'])
          time = Time.parse record[dynamic_conf['time_key']]
          record['@timestamp'] = record[dynamic_conf['time_key']] unless time_key_exclude_timestamp
        else
          record.merge!({"@timestamp" => Time.at(time).to_datetime.to_s})
        end

        if eval(dynamic_conf['utc_index'])
          target_index = "#{dynamic_conf['logstash_prefix']}-#{Time.at(time).getutc.strftime("#{dynamic_conf['logstash_dateformat']}")}"
        else
          target_index = "#{dynamic_conf['logstash_prefix']}-#{Time.at(time).strftime("#{dynamic_conf['logstash_dateformat']}")}"
        end
      else
        target_index = dynamic_conf['index_name']
      end
    
      # Change target_index to lower-case since Elasticsearch doesn't
      # allow upper-case characters in index names.
      target_index = target_index.downcase
       
      if @include_tag_key
        record.merge!(dynamic_conf['tag_key'] => tag)
      end

      meta = {"_index" => target_index, "_type" => dynamic_conf['type_name']}

      @meta_config_map ||= { 'id_key' => '_id', 'parent_key' => '_parent', 'routing_key' => '_routing' }
      @meta_config_map.each_pair do |config_name, meta_key|
        if dynamic_conf[config_name] && record[dynamic_conf[config_name]]
          meta[meta_key] = record[dynamic_conf[config_name]]
        end
      end

      if dynamic_conf['hosts']
        host = dynamic_conf['hosts']
      else
        host = "#{dynamic_conf['host']}:#{dynamic_conf['port']}"
      end

      if @remove_keys
        @remove_keys.each { |key| record.delete(key) }
      end

      append_record_to_messages(dynamic_conf["write_operation"], meta, record, bulk_message[host])
    end

    bulk_message.each do | hKey, array |
      send(array, hKey) unless array.empty?
      array.clear
    end
  end

  def send(data, host)
    retries = 0
    begin
      client(host).bulk body: data
    rescue *client(host).transport.host_unreachable_exceptions => e
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

  def expand_param(param, tag, time, record)
    # check for '${ ... }'
    #   yes => `eval`
    #   no  => return param
    return param if (param =~ /\${.+}/).nil?

    # check for 'tag_parts[]'
      # separated by a delimiter (default '.')
    tag_parts = tag.split(@delimiter) unless (param =~ /tag_parts\[.+\]/).nil? || tag.nil?

    # pull out section between ${} then eval
    inner = param.clone
    while inner.match(/\${.+}/)
      to_eval = inner.match(/\${(.+?)}/){$1}

      if !(to_eval =~ /record\[.+\]/).nil? && record.nil?
        return to_eval
      elsif !(to_eval =~/tag_parts\[.+\]/).nil? && tag_parts.nil?
        return to_eval
      elsif !(to_eval =~/time/).nil? && time.nil?
        return to_eval
      else
        inner.sub!(/\${.+?}/, eval( to_eval ))
      end
    end
    inner
  end

  def is_valid_expand_param_type(param)
    return false if [:@buffer_type].include?(param)
    return self.instance_variable_get(param).is_a?(String)
  end

  def is_existing_connection(host)
    # check if the host provided match the current connection
    return false if @_es.nil?
    return false if host.length != @current_config.length

    for i in 0...host.length
      if !host[i][:host].eql? @current_config[i][:host] || host[i][:port] != @current_config[i][:port]
        return false
      end
    end

    return true
  end
end
