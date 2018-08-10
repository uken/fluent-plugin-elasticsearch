require 'elasticsearch'

class Fluent::ElasticsearchSimpleSniffer < Elasticsearch::Transport::Transport::Sniffer

  def hosts
    @transport.logger.debug "In Fluent::ElasticsearchSimpleSniffer hosts #{@transport.hosts}" if @transport.logger
    @transport.hosts
  end

end
