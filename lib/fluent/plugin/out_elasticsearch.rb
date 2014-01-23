# encoding: UTF-8
require 'net/http'
require 'date'

class Fluent::ElasticsearchOutput < Fluent::BufferedOutput
  Fluent::Plugin.register_output('elasticsearch', self)

  config_param :host, :string,  :default => 'localhost'
  config_param :port, :integer, :default => 9200
  config_param :logstash_format, :bool, :default => false
  config_param :logstash_prefix, :string, :default => "logstash"
  config_param :logstash_dateformat, :string, :default => "%Y.%m.%d"
  config_param :type_name, :string, :default => "fluentd"
  config_param :index_name, :string, :default => "fluentd"
  config_param :id_key, :string, :default => nil
  config_param :tag_format, :string, :default => nil

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
      if @tag_format
        if @tag_format[0] == ?/ && @tag_format[@tag_format.length-1] == ?/
          # regexp
          begin
            regexp = Regexp.new(@tag_format[1..-2])
            if regexp.named_captures.empty?
              raise "No named captures"
            end
          rescue
            raise ConfigError, "Invalid regexp '#{@tag_format[1..-2]}': #{$!}"
          end
        end

        @parser = Fluent::TextParser::RegexpParser.new(regexp)

        @regexp = @parser.call(tag)

        if @index_name && @index_name[0..2] == "$[:" && @index_name[@index_name.length-1] == "]"
          index_key = @index_name[3..-2]
          index     = @regexp[1][index_key]
          @index_name = index if index
        end
        if @type_name && @type_name[0..2] == "$[:" && @type_name[@type_name.length-1] == "]"
          type_key  = @type_name[3..-2]
          type      = @regexp[1][type_key]
          @type_name = type if type
        end
        if @logstash_format && @logstash_prefix && @logstash_prefix[0..2] == "$[:" && @logstash_prefix[@logstash_prefix.length-1] == "]"
          prefix_key = @logstash_prefix[3..-2]
          prefix     = @regexp[1][prefix_key]
          @logstash_prefix = prefix if prefix
        end
      end

      if @logstash_format
        record.merge!({"@timestamp" => Time.at(time).to_datetime.to_s})
        target_index = "#{@logstash_prefix}-#{Time.at(time).getutc.strftime("#{@logstash_dateformat}")}"
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
      bulk_message << Yajl::Encoder.encode(meta)
      bulk_message << Yajl::Encoder.encode(record)
    end
    bulk_message << ""

    http = Net::HTTP.new(@host, @port.to_i)
    request = Net::HTTP::Post.new('/_bulk', {'content-type' => 'application/json; charset=utf-8'})
    request.body = bulk_message.join("\n")
    http.request(request).value
  end
end
