require 'elasticsearch'

class Fluent::Plugin::ElasticsearchSimpleSniffer < Elastic::Transport::Transport::Sniffer

  def hosts
    @transport.logger.debug "In Fluent::Plugin::ElasticsearchSimpleSniffer hosts #{@transport.hosts}" if @transport.logger
    @transport.hosts
  end

end
