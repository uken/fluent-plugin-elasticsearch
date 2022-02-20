require_relative 'elasticsearch_compat'

class Fluent::Plugin::ElasticseatchFallbackSelector
  include SELECTOR_CLASS::Base

  def select(options={})
    connections.first
  end
end
