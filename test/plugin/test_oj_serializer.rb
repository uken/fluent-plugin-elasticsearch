require_relative '../helper'
require 'elasticsearch'

class OjSerializerTest < Test::Unit::TestCase
  def setup
    begin
      require 'fluent/plugin/oj_serializer'
    rescue LoadError
      omit "OjSerializer testcase needs oj gem."
    end
    @serializer = Fluent::Plugin::Serializer::Oj.new
  end

  def test_serializer
    data = {"message" => "Hi"}
    assert_equal data.to_json, @serializer.dump(data)
    assert_equal data, @serializer.load(data.to_json)
  end
end
