require 'elasticsearch'

require 'faraday/excon'
require 'fluent/log-ext'
require 'fluent/plugin/input'
require_relative 'elasticsearch_constants'
require_relative 'elasticsearch_compat'

module Fluent::Plugin
  class ElasticsearchInput < Input
    class UnrecoverableRequestFailure < Fluent::UnrecoverableError; end

    DEFAULT_RELOAD_AFTER = -1
    DEFAULT_STORAGE_TYPE = 'local'
    METADATA = "@metadata".freeze

    helpers :timer, :thread

    Fluent::Plugin.register_input('elasticsearch', self)

    config_param :tag, :string
    config_param :host, :string,  :default => 'localhost'
    config_param :port, :integer, :default => 9200
    config_param :user, :string, :default => nil
    config_param :password, :string, :default => nil, :secret => true
    config_param :path, :string, :default => nil
    config_param :scheme, :enum, :list => [:https, :http], :default => :http
    config_param :hosts, :string, :default => nil
    config_param :index_name, :string, :default => "fluentd"
    config_param :parse_timestamp, :bool, :default => false
    config_param :timestamp_key_format, :string, :default => nil
    config_param :timestamp_parse_error_tag, :string, :default => 'elasticsearch_plugin.input.time.error'
    config_param :query, :hash, :default => {"sort" => [ "_doc" ]}
    config_param :scroll, :string, :default => "1m"
    config_param :size, :integer, :default => 1000
    config_param :num_slices, :integer, :default => 1
    config_param :interval, :size, :default => 5
    config_param :repeat, :bool, :default => true
    config_param :http_backend, :enum, list: [:excon, :typhoeus], :default => :excon
    config_param :request_timeout, :time, :default => 5
    config_param :reload_connections, :bool, :default => true
    config_param :reload_on_failure, :bool, :default => false
    config_param :resurrect_after, :time, :default => 60
    config_param :reload_after, :integer, :default => DEFAULT_RELOAD_AFTER
    config_param :ssl_verify , :bool, :default => true
    config_param :client_key, :string, :default => nil
    config_param :client_cert, :string, :default => nil
    config_param :client_key_pass, :string, :default => nil, :secret => true
    config_param :ca_file, :string, :default => nil
    config_param :ssl_version, :enum, list: [:SSLv23, :TLSv1, :TLSv1_1, :TLSv1_2], :default => :TLSv1_2
    config_param :with_transporter_log, :bool, :default => false
    config_param :sniffer_class_name, :string, :default => nil
    config_param :custom_headers, :hash, :default => {}
    config_param :docinfo_fields, :array, :default => ['_index', '_type', '_id']
    config_param :docinfo_target, :string, :default => METADATA
    config_param :docinfo, :bool, :default => false

    include Fluent::Plugin::ElasticsearchConstants

    def initialize
      super
    end

    def configure(conf)
      super

      @timestamp_parser = create_time_parser
      @backend_options = backend_options

      raise Fluent::ConfigError, "`password` must be present if `user` is present" if @user && @password.nil?

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
      @current_config = nil
      # Specify @sniffer_class before calling #client.
      @sniffer_class = nil
      begin
        @sniffer_class = Object.const_get(@sniffer_class_name) if @sniffer_class_name
      rescue Exception => ex
        raise Fluent::ConfigError, "Could not load sniffer class #{@sniffer_class_name}: #{ex}"
      end

      @options = {
        :index => @index_name,
        :scroll => @scroll,
        :size => @size
      }
      @base_query = @query
    end

    def backend_options
      case @http_backend
      when :excon
        { client_key: @client_key, client_cert: @client_cert, client_key_pass: @client_key_pass }
      when :typhoeus
        require 'typhoeus'
        { sslkey: @client_key, sslcert: @client_cert, keypasswd: @client_key_pass }
      end
    rescue LoadError => ex
      log.error_backtrace(ex.backtrace)
      raise Fluent::ConfigError, "You must install #{@http_backend} gem. Exception: #{ex}"
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

    def get_connection_options(con_host=nil)

      hosts = if con_host || @hosts
        (con_host || @hosts).split(',').map do |host_str|
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

    def start
      super

      timer_execute(:in_elasticsearch_timer, @interval, repeat: @repeat, &method(:run))
    end

    # once fluent v0.14 is released we might be able to use
    # Fluent::Parser::TimeParser, but it doesn't quite do what we want - if gives
    # [sec,nsec] where as we want something we can call `strftime` on...
    def create_time_parser
      if @timestamp_key_format
        begin
          # Strptime doesn't support all formats, but for those it does it's
          # blazingly fast.
          strptime = Strptime.new(@timestamp_key_format)
          Proc.new { |value|
            value = convert_numeric_time_into_string(value, @timestamp_key_format) if value.is_a?(Numeric)
            strptime.exec(value).to_time
          }
        rescue
          # Can happen if Strptime doesn't recognize the format; or
          # if strptime couldn't be required (because it's not installed -- it's
          # ruby 2 only)
          Proc.new { |value|
            value = convert_numeric_time_into_string(value, @timestamp_key_format) if value.is_a?(Numeric)
            DateTime.strptime(value, @timestamp_key_format).to_time
          }
        end
      else
        Proc.new { |value|
          value = convert_numeric_time_into_string(value) if value.is_a?(Numeric)
          DateTime.parse(value).to_time
        }
      end
    end

    def convert_numeric_time_into_string(numeric_time, timestamp_key_format = "%Y-%m-%dT%H:%M:%S.%N%z")
      numeric_time_parser = Fluent::NumericTimeParser.new(:float)
      Time.at(numeric_time_parser.parse(numeric_time).to_r).strftime(timestamp_key_format)
    end

    def parse_time(value, event_time, tag)
      @timestamp_parser.call(value)
    rescue => e
      router.emit_error_event(@timestamp_parse_error_tag, Fluent::Engine.now, {'tag' => tag, 'time' => event_time, 'format' => @timestamp_key_format, 'value' => value}, e)
      return Time.at(event_time).to_time
    end

    def client(host = nil)
      # check here to see if we already have a client connection for the given host
      connection_options = get_connection_options(host)

      @_es = nil unless is_existing_connection(connection_options[:hosts])

      @_es ||= begin
        @current_config = connection_options[:hosts].clone
        adapter_conf = lambda {|f| f.adapter @http_backend, @backend_options }
        local_reload_connections = @reload_connections
        if local_reload_connections && @reload_after > DEFAULT_RELOAD_AFTER
          local_reload_connections = @reload_after
        end

        headers = { 'Content-Type' => "application/json" }.merge(@custom_headers)

        transport = TRANSPORT_CLASS::Transport::HTTP::Faraday.new(
          connection_options.merge(
            options: {
              reload_connections: local_reload_connections,
              reload_on_failure: @reload_on_failure,
              resurrect_after: @resurrect_after,
              logger: @transport_logger,
              transport_options: {
                headers: headers,
                request: { timeout: @request_timeout },
                ssl: { verify: @ssl_verify, ca_file: @ca_file, version: @ssl_version }
              },
              http: {
                user: @user,
                password: @password
              },
              sniffer_class: @sniffer_class,
            }), &adapter_conf)
        Elasticsearch::Client.new transport: transport
      end
    end

    def is_existing_connection(host)
      # check if the host provided match the current connection
      return false if @_es.nil?
      return false if @current_config.nil?
      return false if host.length != @current_config.length

      for i in 0...host.length
        if !host[i][:host].eql? @current_config[i][:host] || host[i][:port] != @current_config[i][:port]
          return false
        end
      end

      return true
    end

    def run
      return run_slice if @num_slices <= 1

      log.warn("Large slice number is specified:(#{@num_slices}). Consider reducing num_slices") if @num_slices > 8

      @num_slices.times.map do |slice_id|
        thread_create(:"in_elasticsearch_thread_#{slice_id}") do
          run_slice(slice_id)
        end
      end
    end

    def run_slice(slice_id=nil)
      slice_query = @base_query
      slice_query = slice_query.merge('slice' => { 'id' => slice_id, 'max' => @num_slices}) unless slice_id.nil?
      result = client.search(@options.merge(:body => Yajl.dump(slice_query) ))
      es = Fluent::MultiEventStream.new

      result["hits"]["hits"].each {|hit| process_events(hit, es)}
      has_hits = result['hits']['hits'].any?
      scroll_id = result['_scroll_id']

      while has_hits && scroll_id
        result = process_next_scroll_request(es, scroll_id)
        has_hits = result['has_hits']
        scroll_id = result['_scroll_id']
      end

      router.emit_stream(@tag, es)
      if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("7.0.0")
        client.clear_scroll(body: {scroll_id: scroll_id}) if scroll_id
      else
        client.clear_scroll(scroll_id: scroll_id) if scroll_id
      end
    end

    def process_scroll_request(scroll_id)
      client.scroll(:body => { :scroll_id => scroll_id }, :scroll => @scroll)
    end

    def process_next_scroll_request(es, scroll_id)
      result = process_scroll_request(scroll_id)
      result['hits']['hits'].each { |hit| process_events(hit, es) }
      {'has_hits' => result['hits']['hits'].any?, '_scroll_id' => result['_scroll_id']}
    end

    def process_events(hit, es)
      event = hit["_source"]
      time = Fluent::Engine.now
      if @parse_timestamp
        if event.has_key?(TIMESTAMP_FIELD)
          rts = event[TIMESTAMP_FIELD]
          time = parse_time(rts, time, @tag)
        end
      end
      if @docinfo
        docinfo_target = event[@docinfo_target] || {}

        unless docinfo_target.is_a?(Hash)
          raise UnrecoverableError, "incompatible type for the docinfo_target=#{@docinfo_target} field in the `_source` document, expected a hash got:", :type => docinfo_target.class, :event => event
        end

        @docinfo_fields.each do |field|
          docinfo_target[field] = hit[field]
        end

        event[@docinfo_target] = docinfo_target
      end
      es.add(time, event)
    end
  end
end
