# encoding: UTF-8
require 'date'
require 'excon'
require 'elasticsearch'
require 'json'
require 'uri'
begin
  require 'strptime'
rescue LoadError
end

require 'fluent/plugin/output'
require 'fluent/event'
require 'fluent/error'
require_relative 'elasticsearch_constants'
require_relative 'elasticsearch_error_handler'
require_relative 'elasticsearch_index_template'
begin
  require_relative 'oj_serializer'
rescue LoadError
end

module Fluent::Plugin
  class ElasticsearchOutput < Output
    class ConnectionFailure < StandardError; end
    class ConnectionRetryFailure < Fluent::UnrecoverableError; end

    # MissingIdFieldError is raised for records that do not
    # include the field for the unique record identifier
    class MissingIdFieldError < StandardError; end

    # RetryStreamError privides a stream to be
    # put back in the pipeline for cases where a bulk request
    # failed (e.g some records succeed while others failed)
    class RetryStreamError < StandardError
      attr_reader :retry_stream
      def initialize(retry_stream)
        @retry_stream = retry_stream
      end
    end

    RequestInfo = Struct.new(:host, :index)

    helpers :event_emitter, :compat_parameters, :record_accessor

    Fluent::Plugin.register_output('elasticsearch', self)

    DEFAULT_BUFFER_TYPE = "memory"
    DEFAULT_ELASTICSEARCH_VERSION = 5 # For compatibility.
    DEFAULT_TYPE_NAME_ES_7x = "_doc".freeze
    DEFAULT_TYPE_NAME = "fluentd".freeze
    DEFAULT_RELOAD_AFTER = -1

    config_param :host, :string,  :default => 'localhost'
    config_param :port, :integer, :default => 9200
    config_param :user, :string, :default => nil
    config_param :password, :string, :default => nil, :secret => true
    config_param :path, :string, :default => nil
    config_param :scheme, :enum, :list => [:https, :http], :default => :http
    config_param :hosts, :string, :default => nil
    config_param :target_index_key, :string, :default => nil
    config_param :target_type_key, :string, :default => nil,
                 :deprecated => <<EOC
Elasticsearch 7.x or above will ignore this config. Please use fixed type_name instead.
EOC
    config_param :time_key_format, :string, :default => nil
    config_param :time_precision, :integer, :default => 9
    config_param :include_timestamp, :bool, :default => false
    config_param :logstash_format, :bool, :default => false
    config_param :logstash_prefix, :string, :default => "logstash"
    config_param :logstash_prefix_separator, :string, :default => '-'
    config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"
    config_param :utc_index, :bool, :default => true
    config_param :type_name, :string, :default => DEFAULT_TYPE_NAME
    config_param :index_name, :string, :default => "fluentd"
    config_param :id_key, :string, :default => nil
    config_param :write_operation, :string, :default => "index"
    config_param :parent_key, :string, :default => nil
    config_param :routing_key, :string, :default => nil
    config_param :request_timeout, :time, :default => 5
    config_param :reload_connections, :bool, :default => true
    config_param :reload_on_failure, :bool, :default => false
    config_param :retry_tag, :string, :default=>nil
    config_param :resurrect_after, :time, :default => 60
    config_param :time_key, :string, :default => nil
    config_param :time_key_exclude_timestamp, :bool, :default => false
    config_param :ssl_verify , :bool, :default => true
    config_param :client_key, :string, :default => nil
    config_param :client_cert, :string, :default => nil
    config_param :client_key_pass, :string, :default => nil
    config_param :ca_file, :string, :default => nil
    config_param :ssl_version, :enum, list: [:SSLv23, :TLSv1, :TLSv1_1, :TLSv1_2], :default => :TLSv1
    config_param :remove_keys, :string, :default => nil
    config_param :remove_keys_on_update, :string, :default => ""
    config_param :remove_keys_on_update_key, :string, :default => nil
    config_param :flatten_hashes, :bool, :default => false
    config_param :flatten_hashes_separator, :string, :default => "_"
    config_param :template_name, :string, :default => nil
    config_param :template_file, :string, :default => nil
    config_param :template_overwrite, :bool, :default => false
    config_param :customize_template, :hash, :default => nil
    config_param :rollover_index, :string, :default => false
    config_param :index_date_pattern, :string, :default => "now/d"
    config_param :deflector_alias, :string, :default => nil
    config_param :index_prefix, :string, :default => "logstash"
    config_param :application_name, :string, :default => "default"
    config_param :templates, :hash, :default => nil
    config_param :max_retry_putting_template, :integer, :default => 10
    config_param :include_tag_key, :bool, :default => false
    config_param :tag_key, :string, :default => 'tag'
    config_param :time_parse_error_tag, :string, :default => 'Fluent::ElasticsearchOutput::TimeParser.error'
    config_param :reconnect_on_error, :bool, :default => false
    config_param :pipeline, :string, :default => nil
    config_param :with_transporter_log, :bool, :default => false
    config_param :emit_error_for_missing_id, :bool, :default => false
    config_param :sniffer_class_name, :string, :default => nil
    config_param :reload_after, :integer, :default => DEFAULT_RELOAD_AFTER
    config_param :content_type, :enum, list: [:"application/json", :"application/x-ndjson"], :default => :"application/json",
                 :deprecated => <<EOC
elasticsearch gem v6.0.2 starts to use correct Content-Type. Please upgrade elasticserach gem and stop to use this option.
see: https://github.com/elastic/elasticsearch-ruby/pull/514
EOC
    config_param :include_index_in_url, :bool, :default => false
    config_param :http_backend, :enum, list: [:excon, :typhoeus], :default => :excon
    config_param :validate_client_version, :bool, :default => false
    config_param :prefer_oj_serializer, :bool, :default => false
    config_param :unrecoverable_error_types, :array, :default => ["out_of_memory_error", "es_rejected_execution_exception"]
    config_param :verify_es_version_at_startup, :bool, :default => true
    config_param :default_elasticsearch_version, :integer, :default => DEFAULT_ELASTICSEARCH_VERSION
    config_param :log_es_400_reason, :bool, :default => false

    config_section :buffer do
      config_set_default :@type, DEFAULT_BUFFER_TYPE
      config_set_default :chunk_keys, ['tag']
      config_set_default :timekey_use_utc, true
    end

    include Fluent::ElasticsearchIndexTemplate
    include Fluent::Plugin::ElasticsearchConstants

    def initialize
      super
    end

    def configure(conf)
      compat_parameters_convert(conf, :buffer)

      super
      raise Fluent::ConfigError, "'tag' in chunk_keys is required." if not @chunk_key_tag

      @time_parser = create_time_parser
      @backend_options = backend_options

      if @remove_keys
        @remove_keys = @remove_keys.split(/\s*,\s*/)
      end

      if @target_index_key && @target_index_key.is_a?(String)
        @target_index_key = @target_index_key.split '.'
      end

      if @target_type_key && @target_type_key.is_a?(String)
        @target_type_key = @target_type_key.split '.'
      end

      if @remove_keys_on_update && @remove_keys_on_update.is_a?(String)
        @remove_keys_on_update = @remove_keys_on_update.split ','
      end

      raise Fluent::ConfigError, "'max_retry_putting_template' must be positive number." if @max_retry_putting_template < 0

      if @template_name && @template_file
        retry_install(@max_retry_putting_template) do
          if @customize_template
            if @rollover_index
              raise Fluent::ConfigError, "'deflector_alias' must be provided if 'rollover_index' is set true ." if not @deflector_alias
            end
            template_custom_install(@template_name, @template_file, @template_overwrite, @customize_template, @index_prefix, @rollover_index, @deflector_alias, @application_name, @index_date_pattern)
          else
            template_install(@template_name, @template_file, @template_overwrite)
          end
        end
      elsif @templates
        retry_install(@max_retry_putting_template) do
          templates_hash_install(@templates, @template_overwrite)
        end
      end

      # Consider missing the prefix of "$." in nested key specifiers.
      @id_key = convert_compat_id_key(@id_key) if @id_key
      @parent_key = convert_compat_id_key(@parent_key) if @parent_key
      @routing_key = convert_compat_id_key(@routing_key) if @routing_key

      @meta_config_map = create_meta_config_map

      @serializer_class = nil
      begin
        require 'oj'
        @dump_proc = Oj.method(:dump)
        if @prefer_oj_serializer
          @serializer_class = Fluent::Plugin::Serializer::Oj
          Elasticsearch::API.settings[:serializer] = Fluent::Plugin::Serializer::Oj
        end
      rescue LoadError
        @dump_proc = Yajl.method(:dump)
      end

      if @user && m = @user.match(/%{(?<user>.*)}/)
        @user = URI.encode_www_form_component(m["user"])
      end
      if @password && m = @password.match(/%{(?<password>.*)}/)
        @password = URI.encode_www_form_component(m["password"])
      end

      @transport_logger = nil
      if @with_transporter_log
        @transport_logger = log
        log_level = conf['@log_level'] || conf['log_level']
        log.warn "Consider to specify log_level with @log_level." unless log_level
      end
      # Specify @sniffer_class before calling #client.
      # #detect_es_major_version uses #client.
      @sniffer_class = nil
      begin
        @sniffer_class = Object.const_get(@sniffer_class_name) if @sniffer_class_name
      rescue Exception => ex
        raise Fluent::ConfigError, "Could not load sniffer class #{@sniffer_class_name}: #{ex}"
      end

      @last_seen_major_version =
        if @verify_es_version_at_startup
          begin
            detect_es_major_version
          rescue
            log.warn "Could not connect Elasticsearch or obtain version. Assuming Elasticsearch #{@default_elasticsearch_version}."
            @default_elasticsearch_version
          end
        else
          @default_elasticsearch_version
        end
      if @last_seen_major_version == 6 && @type_name != DEFAULT_TYPE_NAME_ES_7x
        log.info "Detected ES 6.x: ES 7.x will only accept `_doc` in type_name."
      end
      if @last_seen_major_version >= 7 && @type_name != DEFAULT_TYPE_NAME_ES_7x
        log.warn "Detected ES 7.x or above: `_doc` will be used as the document `_type`."
        @type_name = '_doc'.freeze
      end

      if @validate_client_version
        if @last_seen_major_version != client_library_version.to_i
          raise Fluent::ConfigError, <<-EOC
            Detected ES #{@last_seen_major_version} but you use ES client #{client_library_version}.
            Please consider to use #{@last_seen_major_version}.x series ES client.
          EOC
        end
      end

      if @last_seen_major_version >= 6
        case @ssl_version
        when :SSLv23, :TLSv1, :TLSv1_1
          if @scheme == :https
            log.warn "Detected ES 6.x or above and enabled insecure security:
                      You might have to specify `ssl_version TLSv1_2` in configuration."
          end
        end
      end
    end

    def backend_options
      case @http_backend
      when :excon
        { client_key: @client_key, client_cert: @client_cert, client_key_pass: @client_key_pass }
      when :typhoeus
        require 'typhoeus'
        { sslkey: @client_key, sslcert: @client_cert, keypasswd: @client_key_pass }
      end
    rescue LoadError
      raise Fluent::ConfigError, "You must install #{@http_backend} gem."
    end

    def detect_es_major_version
      @_es_info ||= client.info
      @_es_info["version"]["number"].to_i
    end

    def client_library_version
      Elasticsearch::VERSION
    end

    def convert_compat_id_key(key)
      if key.include?('.') && !key.start_with?('$[')
        key = "$.#{key}" unless key.start_with?('$.')
      end
      key
    end

    def create_meta_config_map
      result = []
      result << [record_accessor_create(@id_key), '_id'] if @id_key
      result << [record_accessor_create(@parent_key), '_parent'] if @parent_key
      result << [record_accessor_create(@routing_key), '_routing'] if @routing_key
      result
    end

    # once fluent v0.14 is released we might be able to use
    # Fluent::Parser::TimeParser, but it doesn't quite do what we want - if gives
    # [sec,nsec] where as we want something we can call `strftime` on...
    def create_time_parser
      if @time_key_format
        begin
          # Strptime doesn't support all formats, but for those it does it's
          # blazingly fast.
          strptime = Strptime.new(@time_key_format)
          Proc.new { |value| strptime.exec(value).to_datetime }
        rescue
          # Can happen if Strptime doesn't recognize the format; or
          # if strptime couldn't be required (because it's not installed -- it's
          # ruby 2 only)
          Proc.new { |value| DateTime.strptime(value, @time_key_format) }
        end
      else
        Proc.new { |value| DateTime.parse(value) }
      end
    end

    def parse_time(value, event_time, tag)
      @time_parser.call(value)
    rescue => e
      router.emit_error_event(@time_parse_error_tag, Fluent::Engine.now, {'tag' => tag, 'time' => event_time, 'format' => @time_key_format, 'value' => value}, e)
      return Time.at(event_time).to_datetime
    end

    def client
      @_es ||= begin
        adapter_conf = lambda {|f| f.adapter @http_backend, @backend_options }
        local_reload_connections = @reload_connections
        if local_reload_connections && @reload_after > DEFAULT_RELOAD_AFTER
          local_reload_connections = @reload_after
        end
        transport = Elasticsearch::Transport::Transport::HTTP::Faraday.new(get_connection_options.merge(
                                                                            options: {
                                                                              reload_connections: local_reload_connections,
                                                                              reload_on_failure: @reload_on_failure,
                                                                              resurrect_after: @resurrect_after,
                                                                              retry_on_failure: 5,
                                                                              logger: @transport_logger,
                                                                              transport_options: {
                                                                                headers: { 'Content-Type' => @content_type.to_s },
                                                                                request: { timeout: @request_timeout },
                                                                                ssl: { verify: @ssl_verify, ca_file: @ca_file, version: @ssl_version }
                                                                              },
                                                                              http: {
                                                                                user: @user,
                                                                                password: @password
                                                                              },
                                                                              sniffer_class: @sniffer_class,
                                                                              serializer_class: @serializer_class,
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

    def get_escaped_userinfo(host_str)
      if m = host_str.match(/(?<scheme>.*)%{(?<user>.*)}:%{(?<password>.*)}(?<path>@.*)/)
        m["scheme"] +
          URI.encode_www_form_component(m["user"]) +
          ':' +
          URI.encode_www_form_component(m["password"]) +
          m["path"]
      else
        host_str
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
              scheme: @scheme.to_s
            }
          else
            # New hosts format expects URLs such as http://logs.foo.com,https://john:pass@logs2.foo.com/elastic
            uri = URI(get_escaped_userinfo(host_str))
            %w(user password path).inject(host: uri.host, port: uri.port, scheme: uri.scheme) do |hash, key|
              hash[key.to_sym] = uri.public_send(key) unless uri.public_send(key).nil? || uri.public_send(key) == ''
              hash
            end
          end
        end.compact
      else
        [{host: @host, port: @port, scheme: @scheme.to_s}]
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

    # append_record_to_messages adds a record to the bulk message
    # payload to be submitted to Elasticsearch.  Records that do
    # not include '_id' field are skipped when 'write_operation'
    # is configured for 'create' or 'update'
    #
    # returns 'true' if record was appended to the bulk message
    #         and 'false' otherwise
    def append_record_to_messages(op, meta, header, record, msgs)
      case op
      when UPDATE_OP, UPSERT_OP
        if meta.has_key?(ID_FIELD)
          header[UPDATE_OP] = meta
          msgs << @dump_proc.call(header) << BODY_DELIMITER
          msgs << @dump_proc.call(update_body(record, op)) << BODY_DELIMITER
          return true
        end
      when CREATE_OP
        if meta.has_key?(ID_FIELD)
          header[CREATE_OP] = meta
          msgs << @dump_proc.call(header) << BODY_DELIMITER
          msgs << @dump_proc.call(record) << BODY_DELIMITER
          return true
        end
      when INDEX_OP
        header[INDEX_OP] = meta
        msgs << @dump_proc.call(header) << BODY_DELIMITER
        msgs << @dump_proc.call(record) << BODY_DELIMITER
        return true
      end
      return false
    end

    def update_body(record, op)
      update = remove_keys(record)
      body = {"doc".freeze => update}
      if op == UPSERT_OP
        if update == record
          body["doc_as_upsert".freeze] = true
        else
          body[UPSERT_OP] = record
        end
      end
      body
    end

    def remove_keys(record)
      keys = record[@remove_keys_on_update_key] || @remove_keys_on_update || []
      record.delete(@remove_keys_on_update_key)
      return record unless keys.any?
      record = record.dup
      keys.each { |key| record.delete(key) }
      record
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

    def expand_placeholders(metadata)
      logstash_prefix = extract_placeholders(@logstash_prefix, metadata)
      index_name = extract_placeholders(@index_name, metadata)
      type_name = extract_placeholders(@type_name, metadata)
      return logstash_prefix, index_name, type_name
    end

    def multi_workers_ready?
      true
    end

    def write(chunk)
      bulk_message_count = Hash.new { |h,k| h[k] = 0 }
      bulk_message = Hash.new { |h,k| h[k] = '' }
      header = {}
      meta = {}

      tag = chunk.metadata.tag
      extracted_values = expand_placeholders(chunk.metadata)
      @last_seen_major_version = detect_es_major_version rescue @default_elasticsearch_version

      chunk.msgpack_each do |time, record|
        next unless record.is_a? Hash
        begin
          meta, header, record = process_message(tag, meta, header, time, record, extracted_values)
          info = if @include_index_in_url
                   RequestInfo.new(nil, meta.delete("_index".freeze))
                 else
                   RequestInfo.new(nil, nil)
                 end

          if append_record_to_messages(@write_operation, meta, header, record, bulk_message[info])
            bulk_message_count[info] += 1;
          else
            if @emit_error_for_missing_id
              raise MissingIdFieldError, "Missing '_id' field. Write operation is #{@write_operation}"
            else
              log.on_debug { log.debug("Dropping record because its missing an '_id' field and write_operation is #{@write_operation}: #{record}") }
            end
          end
        rescue => e
          router.emit_error_event(tag, time, record, e)
        end
      end


      bulk_message.each do |info, msgs|
        send_bulk(msgs, tag, chunk, bulk_message_count[info], extracted_values, info.index) unless msgs.empty?
        msgs.clear
      end
    end

    def process_message(tag, meta, header, time, record, extracted_values)
      logstash_prefix, index_name, type_name = extracted_values

      if @flatten_hashes
        record = flatten_record(record)
      end

      dt = nil
      if @logstash_format || @include_timestamp
        if record.has_key?(TIMESTAMP_FIELD)
          rts = record[TIMESTAMP_FIELD]
          dt = parse_time(rts, time, tag)
        elsif record.has_key?(@time_key)
          rts = record[@time_key]
          dt = parse_time(rts, time, tag)
          record[TIMESTAMP_FIELD] = dt.iso8601(@time_precision) unless @time_key_exclude_timestamp
        else
          dt = Time.at(time).to_datetime
          record[TIMESTAMP_FIELD] = dt.iso8601(@time_precision)
        end
      end

      target_index_parent, target_index_child_key = @target_index_key ? get_parent_of(record, @target_index_key) : nil
      if target_index_parent && target_index_parent[target_index_child_key]
        target_index = target_index_parent.delete(target_index_child_key)
      elsif @logstash_format
        dt = dt.new_offset(0) if @utc_index
        target_index = "#{logstash_prefix}#{@logstash_prefix_separator}#{dt.strftime(@logstash_dateformat)}"
      else
        target_index = index_name
      end

      # Change target_index to lower-case since Elasticsearch doesn't
      # allow upper-case characters in index names.
      target_index = target_index.downcase
      if @include_tag_key
        record[@tag_key] = tag
      end

      target_type_parent, target_type_child_key = @target_type_key ? get_parent_of(record, @target_type_key) : nil
      if target_type_parent && target_type_parent[target_type_child_key]
        target_type = target_type_parent.delete(target_type_child_key)
        if @last_seen_major_version == 6
          log.warn "Detected ES 6.x: `@type_name` will be used as the document `_type`."
          target_type = type_name
        elsif @last_seen_major_version >= 7
          log.warn "Detected ES 7.x or above: `_doc` will be used as the document `_type`."
          target_type = '_doc'.freeze
        end
      else
        if @last_seen_major_version >= 7 && target_type != DEFAULT_TYPE_NAME_ES_7x
          log.warn "Detected ES 7.x or above: `_doc` will be used as the document `_type`."
          target_type = '_doc'.freeze
        else
          target_type = type_name
        end
      end

      meta.clear
      meta["_index".freeze] = target_index
      meta["_type".freeze] = target_type

      if @pipeline
        meta["pipeline".freeze] = @pipeline
      end

      @meta_config_map.each do |record_accessor, meta_key|
        if raw_value = record_accessor.call(record)
          meta[meta_key] = raw_value
        end
      end

      if @remove_keys
        @remove_keys.each { |key| record.delete(key) }
      end

      return [meta, header, record]
    end

    # returns [parent, child_key] of child described by path array in record's tree
    # returns [nil, child_key] if path doesnt exist in record
    def get_parent_of(record, path)
      parent_object = path[0..-2].reduce(record) { |a, e| a.is_a?(Hash) ? a[e] : nil }
      [parent_object, path[-1]]
    end

    # send_bulk given a specific bulk request, the original tag,
    # chunk, and bulk_message_count
    def send_bulk(data, tag, chunk, bulk_message_count, extracted_values, index)
      retries = 0
      begin

        log.on_trace { log.trace "bulk request: #{data}" }
        response = client.bulk body: data, index: index
        log.on_trace { log.trace "bulk response: #{response}" }

        if response['errors']
          error = Fluent::Plugin::ElasticsearchErrorHandler.new(self)
          error.handle_error(response, tag, chunk, bulk_message_count, extracted_values)
        end
      rescue RetryStreamError => e
        emit_tag = @retry_tag ? @retry_tag : tag
        router.emit_stream(emit_tag, e.retry_stream)
      rescue *client.transport.host_unreachable_exceptions => e
        if retries < 2
          retries += 1
          @_es = nil
          @_es_info = nil
          log.warn "Could not push logs to Elasticsearch, resetting connection and trying again. #{e.message}"
          sleep 2**retries
          retry
        end
        raise ConnectionRetryFailure, "Could not push logs to Elasticsearch after #{retries} retries. #{e.message}"
      rescue Exception
        @_es = nil if @reconnect_on_error
        @_es_info = nil if @reconnect_on_error
        raise
      end
    end
  end
end
