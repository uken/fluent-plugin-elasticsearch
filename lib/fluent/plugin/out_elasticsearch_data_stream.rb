
require_relative 'out_elasticsearch'

module Fluent::Plugin
  class ElasticsearchOutputDataStream < ElasticsearchOutput

    Fluent::Plugin.register_output('elasticsearch_data_stream', self)

    helpers :event_emitter

    config_param :data_stream_name, :string
    config_param :data_stream_ilm_name, :string, :default => nil
    config_param :data_stream_template_name, :string, :default => nil
    config_param :data_stream_ilm_policy, :string, :default => nil
    config_param :data_stream_ilm_policy_overwrite, :bool, :default => false
    config_param :data_stream_template_use_index_patterns_wildcard, :bool, :default => true

    # Elasticsearch 7.9 or later always support new style of index template.
    config_set_default :use_legacy_template, false

    INVALID_START_CHRACTERS = ["-", "_", "+", "."]
    INVALID_CHARACTERS = ["\\", "/", "*", "?", "\"", "<", ">", "|", " ", ",", "#", ":"]

    def configure(conf)
      super

      if Gem::Version.new(TRANSPORT_CLASS::VERSION) < Gem::Version.new("8.0.0")
        begin
          require 'elasticsearch/api'
          require 'elasticsearch/xpack'
        rescue LoadError
          raise Fluent::ConfigError, "'elasticsearch/api', 'elasticsearch/xpack' are required for <@elasticsearch_data_stream>."
        end
      else
        begin
          require 'elasticsearch/api'
        rescue LoadError
          raise Fluent::ConfigError, "'elasticsearch/api is required for <@elasticsearch_data_stream>."
        end
      end

      @data_stream_ilm_name = "#{@data_stream_name}_policy" if @data_stream_ilm_name.nil?
      @data_stream_template_name = "#{@data_stream_name}_template" if @data_stream_template_name.nil?
      @data_stream_ilm_policy = File.read(File.join(File.dirname(__FILE__), "default-ilm-policy.json")) if @data_stream_ilm_policy.nil?

      # ref. https://www.elastic.co/guide/en/elasticsearch/reference/master/indices-create-data-stream.html
      unless placeholder?(:data_stream_name_placeholder, @data_stream_name)
        validate_data_stream_parameters
      else
        @use_placeholder = true
        @data_stream_names = []
      end

      unless @use_placeholder
        begin
          @data_stream_names = [@data_stream_name]
          retry_operate(@max_retry_putting_template,
                        @fail_on_putting_template_retry_exceed,
                        @catch_transport_exception_on_retry) do
            create_ilm_policy(@data_stream_name, @data_stream_template_name, @data_stream_ilm_name)
            create_index_template(@data_stream_name, @data_stream_template_name, @data_stream_ilm_name)
            create_data_stream(@data_stream_name)
          end
        rescue => e
          raise Fluent::ConfigError, "Failed to create data stream: <#{@data_stream_name}> #{e.message}"
        end
      end
    end

    def validate_data_stream_parameters
      {"data_stream_name" => @data_stream_name,
       "data_stream_template_name"=> @data_stream_template_name,
       "data_stream_ilm_name" => @data_stream_ilm_name}.each do |parameter, value|
        unless valid_data_stream_parameters?(value)
          unless start_with_valid_characters?(value)
            if not_dots?(value)
              raise Fluent::ConfigError, "'#{parameter}' must not start with #{INVALID_START_CHRACTERS.join(",")}: <#{value}>"
            else
              raise Fluent::ConfigError, "'#{parameter}' must not be . or ..: <#{value}>"
            end
          end
          unless valid_characters?(value)
            raise Fluent::ConfigError, "'#{parameter}' must not contain invalid characters #{INVALID_CHARACTERS.join(",")}: <#{value}>"
          end
          unless lowercase_only?(value)
            raise Fluent::ConfigError, "'#{parameter}' must be lowercase only: <#{value}>"
          end
          if value.bytes.size > 255
            raise Fluent::ConfigError, "'#{parameter}' must not be longer than 255 bytes: <#{value}>"
          end
        end
      end
    end

    def create_ilm_policy(datastream_name, template_name, ilm_name, host = nil)
      unless @data_stream_ilm_policy_overwrite
        return if data_stream_exist?(datastream_name, host) or template_exists?(template_name, host) or ilm_policy_exists?(ilm_name, host)
      end

      params = {
        body: @data_stream_ilm_policy
      }
      retry_operate(@max_retry_putting_template,
                    @fail_on_putting_template_retry_exceed,
                    @catch_transport_exception_on_retry) do
        if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("8.0.0")
          client(host).ilm.put_lifecycle(params.merge(policy: ilm_name))
        else
          client(host).xpack.ilm.put_policy(params.merge(policy_id: ilm_name))
        end
      end
    end

    def create_index_template(datastream_name, template_name, ilm_name, host = nil)
      return if data_stream_exist?(datastream_name, host) or template_exists?(template_name, host)
      wildcard = @data_stream_template_use_index_patterns_wildcard ? '*' : ''
      body = {
        "index_patterns" => ["#{datastream_name}#{wildcard}"],
        "data_stream" => {},
        "template" => {
          "settings" => {
            "index.lifecycle.name" => "#{ilm_name}"
          }
        }
      }
      params = {
        name: template_name,
        body: body
      }
      retry_operate(@max_retry_putting_template,
                    @fail_on_putting_template_retry_exceed,
                    @catch_transport_exception_on_retry) do
        client(host).indices.put_index_template(params)
      end
    end

    def data_stream_exist?(datastream_name, host = nil)
      params = {
        name: datastream_name
      }
      begin
        response = client(host).indices.get_data_stream(params)
        return (not response.is_a?(TRANSPORT_CLASS::Transport::Errors::NotFound))
      rescue TRANSPORT_CLASS::Transport::Errors::NotFound => e
        log.info "Specified data stream does not exist. Will be created: <#{e}>"
        return false
      end
    end

    def create_data_stream(datastream_name, host = nil)
      return if data_stream_exist?(datastream_name, host)
      params = {
        name: datastream_name
      }
      retry_operate(@max_retry_putting_template,
                    @fail_on_putting_template_retry_exceed,
                    @catch_transport_exception_on_retry) do
        client(host).indices.create_data_stream(params)
      end
    end

    def ilm_policy_exists?(policy_id, host = nil)
      begin
        if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("8.0.0")
          client(host).ilm.get_lifecycle(policy: policy_id)
        else
          client(host).ilm.get_policy(policy_id: policy_id)
        end
        true
      rescue
        false
      end
    end

    def template_exists?(name, host = nil)
      if @use_legacy_template
        client(host).indices.get_template(:name => name)
      else
        client(host).indices.get_index_template(:name => name)
      end
      return true
    rescue TRANSPORT_CLASS::Transport::Errors::NotFound
      return false
    end

    def valid_data_stream_parameters?(data_stream_parameter)
      lowercase_only?(data_stream_parameter) and
        valid_characters?(data_stream_parameter) and
        start_with_valid_characters?(data_stream_parameter) and
        not_dots?(data_stream_parameter) and
        data_stream_parameter.bytes.size <= 255
    end

    def lowercase_only?(data_stream_parameter)
      data_stream_parameter.downcase == data_stream_parameter
    end

    def valid_characters?(data_stream_parameter)
      not (INVALID_CHARACTERS.each.any? do |v| data_stream_parameter.include?(v) end)
    end

    def start_with_valid_characters?(data_stream_parameter)
      not (INVALID_START_CHRACTERS.each.any? do |v| data_stream_parameter.start_with?(v) end)
    end

    def not_dots?(data_stream_parameter)
      not (data_stream_parameter == "." or data_stream_parameter == "..")
    end

    def client_library_version
      Elasticsearch::VERSION
    end

    def multi_workers_ready?
      true
    end

    def write(chunk)
      data_stream_name = @data_stream_name
      data_stream_template_name = @data_stream_template_name
      data_stream_ilm_name = @data_stream_ilm_name
      host = nil
      if @use_placeholder
        host = if @hosts
                 extract_placeholders(@hosts, chunk)
               else
                 extract_placeholders(@host, chunk)
               end
        data_stream_name = extract_placeholders(@data_stream_name, chunk)
        data_stream_template_name = extract_placeholders(@data_stream_template_name, chunk)
        data_stream_ilm_name = extract_placeholders(@data_stream_ilm_name, chunk)
        unless @data_stream_names.include?(data_stream_name)
          begin
            create_ilm_policy(data_stream_name, data_stream_template_name, data_stream_ilm_name, host)
            create_index_template(data_stream_name, data_stream_template_name, data_stream_ilm_name, host)
            create_data_stream(data_stream_name)
            @data_stream_names << data_stream_name
          rescue => e
            raise Fluent::ConfigError, "Failed to create data stream: <#{data_stream_name}> #{e.message}"
          end
        end
      end

      bulk_message = ""
      headers = {
        CREATE_OP => {}
      }
      tag = chunk.metadata.tag
      chunk.msgpack_each do |time, record|
        next unless record.is_a? Hash

        if @include_tag_key
          record[@tag_key] = tag
        end

        begin
          unless record.has_key?("@timestamp")
            record.merge!({"@timestamp" => Time.at(time).iso8601(@time_precision)})
          end
          bulk_message = append_record_to_messages(CREATE_OP, {}, headers, record, bulk_message)
        rescue => e
          router.emit_error_event(tag, time, record, e)
        end
      end

      prepared_data = if compression
        gzip(bulk_message)
      else
        bulk_message
      end

      params = {
        index: data_stream_name,
        body: prepared_data
      }
      begin
        response = client(host, compression).bulk(params)
        if response['errors']
          log.error "Could not bulk insert to Data Stream: #{data_stream_name} #{response}"
          @num_errors_metrics.inc
        end
      rescue => e
        raise RecoverableRequestFailure, "could not push logs to Elasticsearch cluster (#{data_stream_name}): #{e.message}"
      end
    end

    def append_record_to_messages(op, meta, header, record, msgs)
      header[CREATE_OP] = meta
      msgs << @dump_proc.call(header) << BODY_DELIMITER
      msgs << @dump_proc.call(record) << BODY_DELIMITER
      msgs
    end

    def retry_stream_retryable?
      @buffer.storable?
    end
  end
end
