require 'elastic/transport/transport/connections/selector'

class Fluent::Plugin::ElasticseatchFallbackSelector
  include Elastic::Transport::Transport::Connections::Selector::Base

  def select(options={})
    connections.first
  end
end
