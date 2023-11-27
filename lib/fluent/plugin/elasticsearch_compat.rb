begin
  require 'elastic/transport'
  ::TRANSPORT_CLASS = Elastic::Transport
rescue LoadError
end
begin
  require 'elasticsearch/transport'
  ::TRANSPORT_CLASS = Elasticsearch::Transport
rescue LoadError
end
if Gem::Version.new(Elasticsearch::VERSION) < Gem::Version.new("8.0.0")
  begin
    require 'elasticsearch/xpack'
  rescue LoadError
    require 'elasticsearch/api' # For elasticsearch-ruby 8 or later
  end
end

begin
  require 'elastic/transport/transport/connections/selector'
  ::SELECTOR_CLASS = Elastic::Transport::Transport::Connections::Selector
rescue LoadError
end
begin
  require 'elasticsearch/transport/transport/connections/selector'
  ::SELECTOR_CLASS = Elasticsearch::Transport::Transport::Connections::Selector
rescue LoadError
end
unless defined?(::Elasticsearch::UnsupportedProductError)
  class ::Elasticsearch::UnsupportedProductError < StandardError; end
end
