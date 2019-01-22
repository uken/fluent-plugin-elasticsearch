require 'fluent/error'

class Fluent::Plugin::ElasticsearchError
  class RetryableOperationExhaustedFailure < Fluent::UnrecoverableError; end
end
