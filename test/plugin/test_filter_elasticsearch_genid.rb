require 'helper'
require 'date'
require 'fluent/test/helpers'
require 'json'
require 'fluent/test/driver/filter'
require 'flexmock/test_unit'
require 'fluent/plugin/filter_elasticsearch_genid'

class ElasticsearchGenidFilterTest < Test::Unit::TestCase
  include FlexMock::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
  end

  def create_driver(conf='')
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::ElasticsearchGenidFilter).configure(conf)
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
    time = event_time("2017-10-15 15:00:23.34567890 UTC")
    d.run(default_tag: 'test') do
      d.feed(time, sample_record)
    end
    assert_equal(Base64.strict_encode64(SecureRandom.uuid),
                 d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
  end
end
