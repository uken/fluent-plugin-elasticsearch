# encoding: UTF-8

require 'retryable'

module Fluent
  class ElasticsearchOutput < Fluent::BufferedOutput

    include Retryable

    Plugin.register_output('elasticsearch', self)
    attr_reader :nodes

    # Left here to be backwards compatible
    config_param :host, :string,  :default => 'localhost'
    config_param :port, :integer, :default => 9200

    config_param :logstash_format, :bool, :default => false
    config_param :logstash_prefix, :string, :default => "logstash"
    config_param :type_name, :string, :default => "fluentd"
    config_param :index_name, :string, :default => "fluentd"
    config_param :id_key, :string, :default => nil
    config_param :check_nodes_interval, :integer, :default => 10

    include Fluent::SetTagKeyMixin
    config_set_default :include_tag_key, false

    def initialize
      super
      require 'net/http'
      require 'date'
      @nodes = []
      @last_check = Time.now
    end

    def configure(conf)
      super
      if host = conf['host']
        $log.warn "'host' option in elastcisearch output is obsoleted. Use '<server> host xxx </server>' instead."
        port = conf['port']
        port = port ? port.to_i : 9200
        e = conf.add_element('server')
        e['host'] = host
        e['port'] = port.to_s
      end

      conf.elements.each {|e|
        # Ignore anything that is not a server
        next if e.name != "server"
        host = e['host']
        port = e.fetch('port', 9200)
        port = port ? port.to_i : 9200
        check_avaliability = e.fetch("check_avaliability", 300)
        name = e.fetch('name', "#{host}:#{port}")

        @nodes << Node.new(name, host, port, check_avaliability)
        $log.info "Adding backup elasticsearch node '#{name}'", :host=>host, :port=>port
      }
    end

    def start
      super
    end

    def format(tag, time, record)
      [tag, time, record].to_msgpack
    end

    def shutdown
      super
    end

    # Very rudimentary, we just re-enable the host if its been disable
    # longer than the check_availability setting states. The #write method
    # should disable it again if the node can't be reached
    def check_nodes
      return unless (Time.now - @last_check) > @check_nodes_interval
      @nodes.select { |x| x.available? == false }.each do |node|
        if (Time.now - node.disabled_since) > node.check_avaliability
          node.enable
        end
      end
    end

    def write(chunk)
      bulk_message = []

      check_nodes

      chunk.msgpack_each do |tag, time, record|
        if @logstash_format
          record.merge!({"@timestamp" => Time.at(time).to_datetime.to_s})
          target_index = "#{@logstash_prefix}-#{Time.at(time).getutc.strftime("%Y.%m.%d")}"
        else
          target_index = @index_name
        end

        if @include_tag_key
          record.merge!(@tag_key => tag)
        end

        meta = { "index" => {"_index" => target_index, "_type" => type_name} }
        if @id_key && record[@id_key]
          meta['index']['_id'] = record[@id_key]
        end
        bulk_message << meta.to_json
        bulk_message << record.to_json
      end
      bulk_message << ""

      retryable :on => [Timeout::Error, Errno::ECONNRESET, Errno::ECONNREFUSED], :times => 3, :sleep => false do
        # Select the first available node
        begin
          node = @nodes.select { |n| n.available? }.first
          # Raise an Error if there are no nodes available
          raise 'No more ElasticSearch servers to try' unless node
          $log.debug "Sending log to #{node.name}"
          http = Net::HTTP.new(node.host, node.port.to_i)
          request = Net::HTTP::Post.new("/_bulk")
          request.body = bulk_message.join("\n")
          http.request(request).value
          # We rescue the exception so we can mark the node as unavailable
          # then we rethrow the same exeption so retryable does its job
        rescue Timeout::Error, Errno::ECONNRESET, Errno::ECONNREFUSED => e
          node.disable
          raise e
        end

      end

    end
  end

  class Node
    attr_reader :name, :host, :port, :check_avaliability, :disabled_since
    attr_writer :available
    def initialize(name, host, port, check_avaliability)
      @name = name
      @host = host
      @port = port
      @available = true
      @check_avaliability = check_avaliability
      @disabled_since = nil
    end

    def disable
      @available = false
      @disabled_since = Time.now
      $log.info "Disabling '#{name}' (#{@host}:#{@port}) it will be automatically reenabled in #{@check_avaliability} seconds"
    end

    def enable
      @available = true
      @disabled_since = nil
      $log.info "Enabling '#{name}' (#{@host}:#{@port})"
    end

    def available?
      @available
    end
  end

end
