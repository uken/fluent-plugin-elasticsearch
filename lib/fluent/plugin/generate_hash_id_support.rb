require 'securerandom'
require 'base64'

module Fluent
  module GenerateHashIdSupport
    def self.included(klass)
      klass.instance_eval {
        config_section :hash, param_name: :hash_config, required: false, multi: false do
          config_param :hash_id_key, :string, default: '_hash',
                       obsoleted: "Use bundled filer-elasticsearch-genid instead."

        end
      }
    end

    def generate_hash_id_key(record)
      s = ""
      s += Base64.strict_encode64(SecureRandom.uuid)
      record[@hash_config.hash_id_key] = s
      record
    end
  end
end
