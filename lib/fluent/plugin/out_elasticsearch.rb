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
  config_param :id_key, :string, :default => nil
  config_param :map, :string, :default => "{}"

  include Fluent::SetTagKeyMixin
  config_set_default :include_tag_key, false

  def initialize
    super
  end

  def configure(conf)
    super
    @index_map = eval(@map)
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
        mapped_index = @index_map[tag] || "logstash"
        record.merge!({"@timestamp" => Time.at(time).to_datetime.to_s})
        target_index = "#{mapped_index}-#{Time.at(time).getutc.strftime("%Y.%m.%d")}"
      else
        target_index = @index_map[tag] || @index_name
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

    http = Net::HTTP.new(@host, @port.to_i)
    request = Net::HTTP::Post.new("/_bulk")
    request.body = bulk_message.join("\n")
    http.request(request).value
  end
end
