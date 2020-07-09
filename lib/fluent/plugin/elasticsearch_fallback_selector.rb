require 'elasticsearch/transport/transport/connections/selector'

class Fluent::Plugin::ElasticseatchFallbackSelector
  include Elasticsearch::Transport::Transport::Connections::Selector::Base

  def select(options={})
    connections.first
  end
end
