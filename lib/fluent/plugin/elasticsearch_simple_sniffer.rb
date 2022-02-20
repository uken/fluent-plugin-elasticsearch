require 'elasticsearch'
require_relative 'elasticsearch_compat'

class Fluent::Plugin::ElasticsearchSimpleSniffer < TRANSPORT_CLASS::Transport::Sniffer

  def hosts
    @transport.logger.debug "In Fluent::Plugin::ElasticsearchSimpleSniffer hosts #{@transport.hosts}" if @transport.logger
    @transport.hosts
  end

end
