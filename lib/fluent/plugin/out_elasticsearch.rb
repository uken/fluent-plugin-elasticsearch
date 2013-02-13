# encoding: UTF-8
require 'net/http'
require 'date'

class Fluent::ElasticsearchOutput < Fluent::BufferedOutput
  Fluent::Plugin.register_output('elasticsearch', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :logstash_format, :bool, :default => false
  config_param :type_name, :string, :default => "fluentd"
  config_param :index_name, :string, :default => "fluentd"

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

  def format(tag, time, record)
    [tag, time, record].to_msgpack
  end

  def shutdown
    super
  end

  def write(chunk)
    bulk_message = []

    chunk.msgpack_each do |tag, time, record|
      if @logstash_format
        record.merge!({"@timestamp" => Time.at(time).to_datetime.to_s})
        target_index = "logstash-#{Time.now.strftime("%Y.%m.%d")}"
      else
        target_index = @index_name
      end

      if @include_tag_key
        record.merge!(@tag_key => tag)
      end

      bulk_message << { "index" => {"_index" => target_index, "_type" => type_name} }.to_json
      bulk_message << record.to_json
    end
    bulk_message << ""

    http = Net::HTTP.new(@host, @port.to_i)
    request = Net::HTTP::Post.new("/_bulk")
    request.body = bulk_message.join("\n")
    http.request(request)
  end
end
