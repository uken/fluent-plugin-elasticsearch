require 'securerandom'
require 'base64'
require 'fluent/filter'

module Fluent
  class ElasticsearchGenidFilter < Filter
    Fluent::Plugin.register_filter('elasticsearch_genid', self)

    config_param :hash_id_key, :string, :default => '_hash'

    def initialize
      super
    end

    def configure(conf)
      super
    end

    def filter(tag, time, record)
      record[@hash_id_key] = Base64.strict_encode64(SecureRandom.uuid)
      record
    end

  end
end
