require_relative 'out_elasticsearch'

module Fluent::Plugin
  class ElasticsearchOutputDataStream < ElasticsearchOutput

    Fluent::Plugin.register_output('elasticsearch_data_stream', self)

    helpers :event_emitter

    config_param :data_stream_name, :string
    # Elasticsearch 7.9 or later always support new style of index template.
    config_set_default :use_legacy_template, false

    INVALID_START_CHRACTERS = ["-", "_", "+", "."]
    INVALID_CHARACTERS = ["\\", "/", "*", "?", "\"", "<", ">", "|", " ", ",", "#", ":"]

    def configure(conf)
      super

      begin
        require 'elasticsearch/api'
        require 'elasticsearch/xpack'
      rescue LoadError
        raise Fluent::ConfigError, "'elasticsearch/api', 'elasticsearch/xpack' are required for <@elasticsearch_data_stream>."
      end

      # ref. https://www.elastic.co/guide/en/elasticsearch/reference/master/indices-create-data-stream.html
      unless placeholder?(:data_stream_name_placeholder, @data_stream_name)
        validate_data_stream_name
      else
        @use_placeholder = true
        @data_stream_names = []
      end

      @client = client
      unless @use_placeholder
        begin
          @data_stream_names = [@data_stream_name]
          create_ilm_policy(@data_stream_name)
          create_index_template(@data_stream_name)
          create_data_stream(@data_stream_name)
        rescue => e
          raise Fluent::ConfigError, "Failed to create data stream: <#{@data_stream_name}> #{e.message}"
        end
      end
    end

    def validate_data_stream_name
      unless valid_data_stream_name?
        unless start_with_valid_characters?
          if not_dots?
            raise Fluent::ConfigError, "'data_stream_name' must not start with #{INVALID_START_CHRACTERS.join(",")}: <#{@data_stream_name}>"
          else
            raise Fluent::ConfigError, "'data_stream_name' must not be . or ..: <#{@data_stream_name}>"
          end
        end
        unless valid_characters?
          raise Fluent::ConfigError, "'data_stream_name' must not contain invalid characters #{INVALID_CHARACTERS.join(",")}: <#{@data_stream_name}>"
        end
        unless lowercase_only?
          raise Fluent::ConfigError, "'data_stream_name' must be lowercase only: <#{@data_stream_name}>"
        end
        if @data_stream_name.bytes.size > 255
          raise Fluent::ConfigError, "'data_stream_name' must not be longer than 255 bytes: <#{@data_stream_name}>"
        end
      end
    end

    def create_ilm_policy(name)
      return if data_stream_exist?(name)
      params = {
        policy_id: "#{name}_policy",
        body: File.read(File.join(File.dirname(__FILE__), "default-ilm-policy.json"))
      }
      retry_operate(@max_retry_putting_template,
                    @fail_on_putting_template_retry_exceed,
                    @catch_transport_exception_on_retry) do
        @client.xpack.ilm.put_policy(params)
      end
    end

    def create_index_template(name)
      return if data_stream_exist?(name)
      body = {
        "index_patterns" => ["#{name}*"],
        "data_stream" => {},
        "template" => {
          "settings" => {
            "index.lifecycle.name" => "#{name}_policy"
          }
        }
      }
      params = {
        name: name,
        body: body
      }
      retry_operate(@max_retry_putting_template,
                    @fail_on_putting_template_retry_exceed,
                    @catch_transport_exception_on_retry) do
        @client.indices.put_index_template(params)
      end
    end

    def data_stream_exist?(name)
      params = {
        "name": name
      }
      begin
        response = @client.indices.get_data_stream(params)
        return (not response.is_a?(Elasticsearch::Transport::Transport::Errors::NotFound))
      rescue Elasticsearch::Transport::Transport::Errors::NotFound => e
        log.info "Specified data stream does not exist. Will be created: <#{e}>"
        return false
      end
    end

    def create_data_stream(name)
      return if data_stream_exist?(name)
      params = {
        "name": name
      }
      retry_operate(@max_retry_putting_template,
                    @fail_on_putting_template_retry_exceed,
                    @catch_transport_exception_on_retry) do
        @client.indices.create_data_stream(params)
      end
    end

    def valid_data_stream_name?
      lowercase_only? and
        valid_characters? and
        start_with_valid_characters? and
        not_dots? and
        @data_stream_name.bytes.size <= 255
    end

    def lowercase_only?
      @data_stream_name.downcase == @data_stream_name
    end

    def valid_characters?
      not (INVALID_CHARACTERS.each.any? do |v| @data_stream_name.include?(v) end)
    end

    def start_with_valid_characters?
      not (INVALID_START_CHRACTERS.each.any? do |v| @data_stream_name.start_with?(v) end)
    end

    def not_dots?
      not (@data_stream_name == "." or @data_stream_name == "..")
    end

    def client_library_version
      Elasticsearch::VERSION
    end

    def multi_workers_ready?
      true
    end

    def write(chunk)
      data_stream_name = @data_stream_name
      if @use_placeholder
        data_stream_name = extract_placeholders(@data_stream_name, chunk)
        unless @data_stream_names.include?(data_stream_name)
          begin
            create_ilm_policy(data_stream_name)
            create_index_template(data_stream_name)
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

        begin
          record.merge!({"@timestamp" => Time.at(time).iso8601(@time_precision)})
          bulk_message = append_record_to_messages(CREATE_OP, {}, headers, record, bulk_message)
        rescue => e
          router.emit_error_event(tag, time, record, e)
        end
      end

      params = {
        index: data_stream_name,
        body: bulk_message
      }
      begin
        response = @client.bulk(params)
        if response['errors']
          log.error "Could not bulk insert to Data Stream: #{data_stream_name} #{response}"
        end
      rescue => e
        log.error "Could not bulk insert to Data Stream: #{data_stream_name} #{e.message}"
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
