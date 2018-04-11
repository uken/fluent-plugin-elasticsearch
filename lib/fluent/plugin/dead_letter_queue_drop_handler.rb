
module Fluent::DeadLetterQueueDropHandler
  def handle_chunk_error(out_plugin, tag, error, time, record)
    begin
      log.error("Dropping record from '#{tag}': error:#{error} time:#{time} record:#{record}")
    rescue=>e
      log.error("Error while trying to log and drop message from chunk '#{tag}' #{e.message}")
    end
  end
end
