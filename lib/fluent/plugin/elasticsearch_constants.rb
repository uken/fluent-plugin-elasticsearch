module Fluent
  module ElasticsearchConstants
    BODY_DELIMITER = "\n".freeze
    UPDATE_OP = "update".freeze
    UPSERT_OP = "upsert".freeze
    CREATE_OP = "create".freeze
    INDEX_OP = "index".freeze
    ID_FIELD = "_id".freeze
    TIMESTAMP_FIELD = "@timestamp".freeze
  end
end
