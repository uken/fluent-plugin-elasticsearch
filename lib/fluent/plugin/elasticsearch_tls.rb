require 'openssl'
require 'fluent/configurable'
require 'fluent/config/error'

module Fluent::Plugin
  module ElasticsearchTLS
    SUPPORTED_TLS_VERSIONS = if defined?(OpenSSL::SSL::TLS1_3_VERSION)
                               [:TLSv1, :TLSv1_1, :TLSv1_2, :TLSv1_3].freeze
                             else
                               [:SSLv23, :TLSv1, :TLSv1_1, :TLSv1_2].freeze
                             end

    DEFAULT_VERSION = :TLSv1_2
    METHODS_MAP = begin
                    # When openssl supports OpenSSL::SSL::TLSXXX constants representations, we use them.
                    map = {
                      TLSv1: OpenSSL::SSL::TLS1_VERSION,
                      TLSv1_1: OpenSSL::SSL::TLS1_1_VERSION,
                      TLSv1_2: OpenSSL::SSL::TLS1_2_VERSION
                    }
                    map[:TLSv1_3] = OpenSSL::SSL::TLS1_3_VERSION if defined?(OpenSSL::SSL::TLS1_3_VERSION)
                    USE_TLS_MINMAX_VERSION = true
                    map.freeze
                  rescue NameError
                    map = {
                      SSLv23: :SSLv23,
                      TLSv1: :TLSv1,
                      TLSv1_1: :TLSv1_1,
                      TLSv1_2: :TLSv1_2,
                    }
                    USE_TLS_MINMAX_VERSION = false
                  end
    private_constant :METHODS_MAP

    module ElasticsearchTLSParams
      include Fluent::Configurable

      config_param :ssl_version, :enum, list: Fluent::Plugin::ElasticsearchTLS::SUPPORTED_TLS_VERSIONS, default: Fluent::Plugin::ElasticsearchTLS::DEFAULT_VERSION
      config_param :ssl_min_version, :enum, list: Fluent::Plugin::ElasticsearchTLS::SUPPORTED_TLS_VERSIONS, default: nil
      config_param :ssl_max_version, :enum, list: Fluent::Plugin::ElasticsearchTLS::SUPPORTED_TLS_VERSIONS, default: nil
    end

    def self.included(mod)
      mod.include ElasticsearchTLSParams
    end

    def set_tls_minmax_version_config(ssl_version, ssl_max_version, ssl_min_version)
      if USE_TLS_MINMAX_VERSION
        case
        when ssl_min_version.nil? && ssl_max_version.nil?
          ssl_min_version = METHODS_MAP[:TLSv1_2]
          ssl_max_version = METHODS_MAP[:TLSv1_3]
        when ssl_min_version && ssl_max_version.nil?
          raise Fluent::ConfigError, "When you set 'ssl_min_version', must set 'ssl_max_version' together."
        when ssl_min_version.nil? && ssl_max_version
          raise Fluent::ConfigError, "When you set 'ssl_max_version', must set 'ssl_min_version' together."
        else
          ssl_min_version = METHODS_MAP[ssl_min_version]
          ssl_max_version = METHODS_MAP[ssl_max_version]
        end

        {max_version: ssl_max_version, min_version: ssl_min_version}
      else
        log.warn "'ssl_min_version' does not have any effect in this environment. Use 'ssl_version' instead." unless ssl_min_version.nil?
        log.warn "'ssl_max_version' does not have any effect in this environment. Use 'ssl_version' instead." unless ssl_max_version.nil?
        {version: ssl_version}
      end
    end
  end
end
