require 'helper'
require 'date'
require 'json'
require 'flexmock/test_unit'
require 'fluent/plugin/filter_elasticsearch_genid'

class ElasticsearchGenidFilterTest < Test::Unit::TestCase
  include FlexMock::TestCase

  def setup
    Fluent::Test.setup
  end

  def create_driver(conf='')
    Fluent::Test::FilterTestDriver.new(Fluent::ElasticsearchGenidFilter).configure(conf)
  end

  def sample_record
    {'age' => 26, 'request_id' => '42', 'parent_id' => 'parent', 'routing_id' => 'routing'}
  end

  def test_configure
    d = create_driver
    assert_equal '_hash', d.instance.hash_id_key
  end

  data("default" => {"hash_id_key" => "_hash"},
       "custom_key" => {"hash_id_key" => "_edited"},
      )
  def test_filter(data)
    d = create_driver("hash_id_key #{data["hash_id_key"]}")
    flexmock(SecureRandom).should_receive(:uuid)
      .and_return("13a0c028-bf7c-4ae2-ad03-ec09a40006df")
    d.run do
      d.filter(sample_record)
    end
    assert_equal(Base64.strict_encode64(SecureRandom.uuid),
                 d.filtered_as_array.map {|e| e.last}.first[d.instance.hash_id_key])
  end
end
