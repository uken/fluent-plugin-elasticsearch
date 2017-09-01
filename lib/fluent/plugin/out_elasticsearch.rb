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

require 'fluent/output'
require_relative 'elasticsearch_index_template'

class Fluent::ElasticsearchOutput < Fluent::ObjectBufferedOutput
  class ConnectionFailure < StandardError; end
  class BulkIndexQueueFull < StandardError; end
  class ElasticsearchOutOfMemory < StandardError; end
  class ElasticsearchVersionMismatch < StandardError; end
  class UnrecognizedElasticsearchError < StandardError; end
  class ElasticsearchError < StandardError; end

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
  config_param :time_precision, :integer, :default => 0
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
  config_param :remove_keys_on_update, :string, :default => ""
  config_param :remove_keys_on_update_key, :string, :default => nil
  config_param :flatten_hashes, :bool, :default => false
  config_param :flatten_hashes_separator, :string, :default => "_"
  config_param :template_name, :string, :default => nil
  config_param :template_file, :string, :default => nil
  config_param :templates, :hash, :default => nil
  config_param :include_tag_key, :bool, :default => false
  config_param :tag_key, :string, :default => 'tag'
  config_param :time_parse_error_tag, :string, :default => 'Fluent::ElasticsearchOutput::TimeParser.error'
  config_param :reconnect_on_error, :bool, :default => false

  include Fluent::ElasticsearchIndexTemplate

  def initialize
    super
  end

  def configure(conf)
    super
    @time_parser = create_time_parser

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

    if @template_name && @template_file
      template_install(@template_name, @template_file)
    elsif @templates
      templates_hash_install (@templates)
    end

    @meta_config_map = create_meta_config_map

    begin
      require 'oj'
      @dump_proc = Oj.method(:dump)
    rescue LoadError
      @dump_proc = Yajl.method(:dump)
    end
  end

  def create_meta_config_map
    result = []
    result << [@id_key, '_id'] if @id_key
    result << [@parent_key, '_parent'] if @parent_key
    result << [@routing_key, '_routing'] if @routing_key
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
      excon_options = { client_key: @client_key, client_cert: @client_cert, client_key_pass: @client_key_pass }
      adapter_conf = lambda {|f| f.adapter :excon, excon_options }
      transport = Elasticsearch::Transport::Transport::HTTP::Faraday.new(get_connection_options.merge(
                                                                          options: {
                                                                            reload_connections: @reload_connections,
                                                                            reload_on_failure: @reload_on_failure,
                                                                            resurrect_after: @resurrect_after,
                                                                            retry_on_failure: 5,
                                                                            transport_options: {
                                                                              headers: { 'Content-Type' => 'application/json' },
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

  BODY_DELIMITER = "\n".freeze
  UPDATE_OP = "update".freeze
  UPSERT_OP = "upsert".freeze
  CREATE_OP = "create".freeze
  INDEX_OP = "index".freeze
  ID_FIELD = "_id".freeze
  TIMESTAMP_FIELD = "@timestamp".freeze

  def append_record_to_messages(op, meta, header, record, msgs)
    case op
    when UPDATE_OP, UPSERT_OP
      if meta.has_key?(ID_FIELD)
        header[UPDATE_OP] = meta
        msgs << @dump_proc.call(header) << BODY_DELIMITER
        msgs << @dump_proc.call(update_body(record, op)) << BODY_DELIMITER
      end
    when CREATE_OP
      if meta.has_key?(ID_FIELD)
        header[CREATE_OP] = meta
        msgs << @dump_proc.call(header) << BODY_DELIMITER
        msgs << @dump_proc.call(record) << BODY_DELIMITER
      end
    when INDEX_OP
      header[INDEX_OP] = meta
      msgs << @dump_proc.call(header) << BODY_DELIMITER
      msgs << @dump_proc.call(record) << BODY_DELIMITER
    end
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

  def write_objects(tag, chunk)
    bulk_message = ''
    header = {}
    meta = {}
    records = 0
    bulk_message_count = 0
    chunk.msgpack_each do |time, record|
      records += 1
      next unless record.is_a? Hash

      if @flatten_hashes
        record = flatten_record(record)
      end

      target_index_parent, target_index_child_key = @target_index_key ? get_parent_of(record, @target_index_key) : nil
      if target_index_parent && target_index_parent[target_index_child_key]
        target_index = target_index_parent.delete(target_index_child_key)
      elsif @logstash_format
        if record.has_key?(TIMESTAMP_FIELD)
          rts = record[TIMESTAMP_FIELD]
          dt = parse_time(rts, time, tag)
        elsif record.has_key?(@time_key)
          rts = record[@time_key]
          dt = parse_time(rts, time, tag)
          record[TIMESTAMP_FIELD] = rts unless @time_key_exclude_timestamp
        else
          dt = Time.at(time).to_datetime
          record[TIMESTAMP_FIELD] = dt.iso8601(@time_precision)
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
        record[@tag_key] = tag
      end

      target_type_parent, target_type_child_key = @target_type_key ? get_parent_of(record, @target_type_key) : nil
      if target_type_parent && target_type_parent[target_type_child_key]
        target_type = target_type_parent.delete(target_type_child_key)
      else
        target_type = @type_name
      end

      meta.clear
      meta["_index".freeze] = target_index
      meta["_type".freeze] = target_type

      @meta_config_map.each do |record_key, meta_key|
        meta[meta_key] = record[record_key] if record[record_key]
      end

      if @remove_keys
        @remove_keys.each { |key| record.delete(key) }
      end

      append_record_to_messages(@write_operation, meta, header, record, bulk_message)
      bulk_message_count += 1
    end

    send_bulk(bulk_message, bulk_message_count) unless bulk_message.empty?
    bulk_message.clear
  end

  # returns [parent, child_key] of child described by path array in record's tree
  # returns [nil, child_key] if path doesnt exist in record
  def get_parent_of(record, path)
    parent_object = path[0..-2].reduce(record) { |a, e| a.is_a?(Hash) ? a[e] : nil }
    [parent_object, path[-1]]
  end

  def send_bulk(data, count)
    retries = 0
    begin
      response = client.bulk body: data
      if response['errors']
        errors = Hash.new(0)
        errors_bad_resp = 0
        errors_unrecognized = 0
        successes = 0
        duplicates = 0
        bad_arguments = 0
        # Count up the individual error types returned for each item
        # Note: this appears to be an undocumented feature of Elasticsearch
        # https://www.elastic.co/guide/en/elasticsearch/reference/2.4/docs-bulk.html
        # When you submit an "index" write_operation, with no "_id" field in the
        # metadata header, Elasticsearch will turn this into a "create"
        # operation in the response.
        response['items'].each do |item|
          if item.has_key?(@write_operation)
            write_operation = @write_operation
          elsif INDEX_OP == @write_operation && item.has_key?(CREATE_OP)
            write_operation = CREATE_OP
          else
            # When we don't have an expected ops field, something changed in the API
            # expected return values (ES 2.x)
            errors_bad_resp += 1
            next
          end
          if item[write_operation].has_key?('status')
            status = item[write_operation]['status']
          else
            # When we don't have a status field, something changed in the API
            # expected return values (ES 2.x)
            errors_bad_resp += 1
            next
          end
          case
          when CREATE_OP == write_operation && 409 == status
            duplicates += 1
          when 400 == status
            bad_arguments += 1
            log.debug "Elasticsearch rejected document: #{item}"
          when [429, 500].include?(status)
            if item[write_operation].has_key?('error') && item[write_operation]['error'].has_key?('type')
              type = item[write_operation]['error']['type']
            else
              # When we don't have a type field, something changed in the API
              # expected return values (ES 2.x)
              errors_bad_resp += 1
              next
            end
            errors[type] += 1
          when [200, 201].include?(status)
            successes += 1
          else
            errors_unrecognized += 1
          end
        end
        if errors_bad_resp > 0
          msg = "Unable to parse error response from Elasticsearch, likely an API version mismatch  #{response}"
          log.error msg
          raise ElasticsearchVersionMismatch, msg
        end
        if bad_arguments > 0
          log.warn "Elasticsearch rejected #{bad_arguments} documents due to invalid field arguments"
        end
        if duplicates > 0
          log.info "Encountered #{duplicates} duplicate(s) of #{successes} indexing chunk, ignoring"
        end
        msg = "Indexed (op = #{@write_operation}) #{successes} successfully, #{duplicates} duplicate(s), #{bad_arguments} bad argument(s), #{errors_unrecognized} unrecognized error(s)"
        errors.each_key do |key|
          msg << ", #{errors[key]} #{key} error(s)"
        end
        log.debug msg
        if errors_unrecognized > 0
          raise UnrecognizedElasticsearchError, "Unrecognized elasticsearch errors returned, retrying  #{response}"
        end
        errors.each_key do |key|
          case key
          when 'out_of_memory_error'
            raise ElasticsearchOutOfMemory, "Elasticsearch has exhausted its heap, retrying"
          when 'es_rejected_execution_exception'
            raise BulkIndexQueueFull, "Bulk index queue is full, retrying"
          else
            raise ElasticsearchError, "Elasticsearch errors returned, retrying  #{response}"
          end
        end
      else
        log.debug "Successfully indexed (op = #{@write_operation}) #{count} documents"
      end
    rescue *client.transport.host_unreachable_exceptions => e
      if retries < 2
        retries += 1
        @_es = nil
        log.warn "Could not push logs to Elasticsearch, resetting connection and trying again. #{e.message}"
        sleep 2**retries
        retry
      end
      raise ConnectionFailure, "Could not push logs to Elasticsearch after #{retries} retries. #{e.message}"
    rescue Exception
      @_es = nil if @reconnect_on_error
      raise
    end
  end
end
