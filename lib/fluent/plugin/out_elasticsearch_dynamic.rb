# encoding: UTF-8
require_relative 'out_elasticsearch'

class Fluent::ElasticsearchOutputDynamic < Fluent::ElasticsearchOutput

  Fluent::Plugin.register_output('elasticsearch_dynamic', self)

  config_param :delimiter, :string, :default => "."

  # params overloaded as strings
  config_param :port, :string, :default => "9200"
  config_param :logstash_format, :string, :default => "false"
  config_param :utc_index, :string, :default => "true"
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
    @_hosts = hosts(host)

    @_es = nil unless is_existing_connection(@_hosts)

    @_es ||= begin
      @current_config = @_hosts.clone
      transport = TRANSPORT_CLASS.new(hosts: @_hosts, options: {
        reload_connections: @dynamic_config['reload_connections'],
        reload_on_failure: @dynamic_config['reload_on_failure'],
        resurrect_after: @dynamic_config['resurrect_after'].to_i,
        retry_on_failure: 5,
        transport_options: {
          request: { timeout: @dynamic_config['request_timeout'] },
          ssl: { verify: @dynamic_config['ssl_verify'], ca_file: @dynamic_config['ca_file'] }
        }
      }) do |f|
        f.adapter :excon, {
          client_key: @dynamic_config['client_key'],
          client_cert: @dynamic_config['client_cert'],
          client_key_pass: @dynamic_config['client_key_pass']
        }
      end
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

  def hosts(con_host)
    raise "`password` must be present if `user` is present" if @dynamic_config['user'] && !@dynamic_config['password']

    hosts = if con_host || @dynamic_config['hosts']
      parse_hosts(con_host || @dynamic_config['hosts'], @dynamic_config['port'], @dynamic_config['scheme'])
    else
      [{host: @dynamic_config['host'], port: @dynamic_config['port'].to_i, scheme: @dynamic_config['scheme']}]
    end

    augment_hosts!(hosts, @dynamic_config['user'], @dynamic_config['password'], @dynamic_config['path'])

    hosts
  end

  def connection_options_description(host)
    hosts(host).map do |host_info|
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
          record['@timestamp'] = record[dynamic_conf['time_key']]
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

      if @include_tag_key
        record.merge!(dynamic_conf['tag_key'] => tag)
      end

      meta = { "index" => {"_index" => target_index, "_type" => dynamic_conf['type_name']} }
      if dynamic_conf['id_key'] && record[dynamic_conf['id_key']]
        meta['index']['_id'] = record[dynamic_conf['id_key']]
      end

      if dynamic_conf['parent_key'] && record[dynamic_conf['parent_key']]
        meta['index']['_parent'] = record[dynamic_conf['parent_key']]
      end

      if dynamic_conf['hosts']
        host = dynamic_conf['hosts']
      else
        host = "#{dynamic_conf['host']}:#{dynamic_conf['port']}"
      end

      bulk_message[host] << meta
      bulk_message[host] << record

    end

    bulk_message.each do | hKey, array |
      send(array, hKey) unless array.empty?
      array.clear
    end
  end

  def send(data, host)
    retriable(client(host).transport.host_unreachable_exceptions) do
      client(host).bulk body: data
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
