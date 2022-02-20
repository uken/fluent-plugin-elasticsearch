require 'oj'
require_relative 'elasticsearch_compat'

module Fluent::Plugin
  module Serializer

    class Oj
      include TRANSPORT_CLASS::Transport::Serializer::Base

      # De-serialize a Hash from JSON string
      #
      def load(string, options={})
        ::Oj.load(string, options)
      end

      # Serialize a Hash to JSON string
      #
      def dump(object, options={})
        ::Oj.dump(object, options)
      end
    end
  end
end
