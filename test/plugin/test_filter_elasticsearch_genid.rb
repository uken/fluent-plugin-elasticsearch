require_relative '../helper'
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

  test "invalid configuration" do
    assert_raise(Fluent::ConfigError) do
      create_driver("use_record_as_seed true")
    end
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

  class UseRecordAsSeedTest < self
    data("md5" => ["md5", "PPg+zmH1ASUCpNzMUcTzqw=="],
         "sha1" => ["sha1", "JKfCrEAxeAyRSdcKqkw4unC9xZ8="],
         "sha256" => ["sha256", "9Z9i+897bGivSItD/6i0vye9uRwq/sLwWkxOwydtTJY="],
         "sha512" => ["sha512", "KWI5OdZPaCFW9/CEY3NoGrvueMtjZJdmGdqIVGJP8vgI4uW+0gHExZVaHerw+RhbtIdLCtVZ43xBgMKH+KliQg=="],
        )
    def test_simple(data)
      hash_type, expected = data
      d = create_driver(%[
        use_record_as_seed true
        record_keys age,parent_id,routing_id,custom_key
        hash_type #{hash_type}
      ])
      time = event_time("2017-10-15 15:00:23.34567890 UTC")
      d.run(default_tag: 'test') do
        d.feed(time, sample_record.merge("custom_key" => "This is also encoded value."))
      end
      assert_equal(expected,
                   d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
    end

    data("md5" => ["md5", "qUO/xqWiOJq4D0ApdoHVEQ=="],
         "sha1" => ["sha1", "v3UWYr90zIH2veGQBVwUH586TuI="],
         "sha256" => ["sha256", "4hwh10qfw9B24NtNFoEFF8wCiImvgIy1Vk4gzcKt5Pw="],
         "sha512" => ["sha512", "TY3arcmC8mhYClDIjQxH8ePRLnHK01Cj5QQL8FxbwNtPQBY3IZ4qJY9CpOusmdWBYwm1golRVQCmURiAhlnWIQ=="],)
    def test_record_with_tag(data)
      hash_type, expected = data
      d = create_driver(%[
        use_record_as_seed true
        record_keys age,parent_id,routing_id,custom_key
        hash_type #{hash_type}
        include_tag_in_seed true
      ])
      time = event_time("2017-10-15 15:00:23.34567890 UTC")
      d.run(default_tag: 'test.fluentd') do
        d.feed(time, sample_record.merge("custom_key" => "This is also encoded value."))
      end
      assert_equal(expected,
                   d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
    end

    data("md5" => ["md5", "oHo+PoC5I4KC+XCfXvyf9w=="],
         "sha1" => ["sha1", "50Nwarm2225gLy1ka8d9i+W6cKA="],
         "sha256" => ["sha256", "ReX1XgizcrHjBc0sQwx9Sjuf2QBFll2njYf4ee+XSIc="],
         "sha512" => ["sha512", "8bcpZrqNUQIz6opdoVZz0MwxP8r9SCqOEPkWF6xGLlFwPCJVqk2SQp99m8rPufr0xPIgvZyOMejA5slBV9xrdg=="],)
    def test_record_with_time(data)
      hash_type, expected = data
      d = create_driver(%[
        use_record_as_seed true
        record_keys age,parent_id,routing_id,custom_key
        hash_type #{hash_type}
        include_time_in_seed true
      ])
      time = event_time("2017-10-15 15:00:23.34567890 UTC")
      d.run(default_tag: 'test.fluentd') do
        d.feed(time, sample_record.merge("custom_key" => "This is also encoded value."))
      end
      assert_equal(expected,
                   d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
    end

    data("md5" => ["md5", "u7/hr09gDC9CM5DI7tLc2Q=="],
         "sha1" => ["sha1", "1WgptcTnVSHtTAlNUwNcoiaY3oM="],
         "sha256" => ["sha256", "1iWZHI19m/A1VH8iFK7H2KFoyLdszpJRiVeKBv1Ndis="],
         "sha512" => ["sha512", "NM+ui0lUmeDaEJsT7c9EyTc+lQBbRf1x6MQXXYdxp21CX3jZvHy3IT8Xp9ZdIKevZwhoo3Suo/tIBlfyLFXJXw=="],)
    def test_record_with_tag_and_time
      hash_type, expected = data
      d = create_driver(%[
        use_record_as_seed true
        record_keys age,parent_id,routing_id,custom_key
        hash_type #{hash_type}
        include_tag_in_seed true
        include_time_in_seed true
      ])
      time = event_time("2017-10-15 15:00:23.34567890 UTC")
      d.run(default_tag: 'test.fluentd') do
        d.feed(time, sample_record.merge("custom_key" => "This is also encoded value."))
      end
      assert_equal(expected,
                   d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
    end
  end

  class UseEntireRecordAsSeedTest < self
    data("md5" => ["md5", "OAod7J0DR9s9/rOQnkeSFw=="],
         "sha1" => ["sha1", "0CT4aMJ4gxMT3TKaYPCYApiVsq8="],
         "sha256" => ["sha256", "mbAuKF5can0TTj/JBk71AXtOyoVqw5W5gMPUxx6pxLk="],
         "sha512" => ["sha512", "f7kz5KVuDy+riENePDzqBjGQfbuRNpRBSQMzT2/6hrljXbYtBy3YFmxB86ofIf3zz4ZBao2QM2W7YvcwbRtK1w=="],)
    def test_record
      hash_type, expected = data
      d = create_driver(%[
        use_record_as_seed true
        use_entire_record true
        hash_type #{hash_type}
      ])
      time = event_time("2017-10-15 15:00:23.34567890 UTC")
      d.run(default_tag: 'test.fluentd') do
        d.feed(time, sample_record.merge("custom_key" => "This is also encoded value."))
      end
      assert_equal(expected,
                   d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
    end

    data("md5" => ["md5", "Hb0jwxofNQP+ufQTKK1U4g=="],
         "sha1" => ["sha1", "BakTtlotl/u+yOON6YcViTz6nms="],
         "sha256" => ["sha256", "eLuTCsFqDlk6PfABNyD39r36+yNIBeDTHyNKfJ8fZQw="],
         "sha512" => ["sha512", "PhPCNGalM4H4xT19DnCBnpwr56lbvCo8wJGyCiH9dWcyhn1nA5l1diYSZlF2fNiq1+wzMqfGvJILIjgQrlAPcg=="],)
    def test_record_with_tag
      hash_type, expected = data
      d = create_driver(%[
        use_record_as_seed true
        use_entire_record true
        hash_type #{hash_type}
        include_tag_in_seed true
      ])
      time = event_time("2017-10-15 15:00:23.34567890 UTC")
      d.run(default_tag: 'test.fluentd') do
        d.feed(time, sample_record.merge("custom_key" => "This is also encoded value."))
      end
      assert_equal(expected,
                   d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
    end

    data("md5" => ["md5", "C8vfhC4kecNCNutFCuC6MA=="],
         "sha1" => ["sha1", "+YWVqUEL90wpKJRrionUJwNgXHg="],
         "sha256" => ["sha256", "eSqGZqjnO6Uum/4CNfJaolX49+2XKogiGMHGNHiO91Q="],
         "sha512" => ["sha512", "iVmuD0D+i/WtBwNza09ZXSIW8Xg8/yrUwK/M/EZaCMjz/x5FyyCiVkb1VVKsgNnJy0SYt4w21dhHewu1aXM6HA=="],)
    def test_record_with_time
      hash_type, expected = data
      d = create_driver(%[
        use_record_as_seed true
        use_entire_record true
        hash_type #{hash_type}
        include_time_in_seed true
      ])
      time = event_time("2017-10-15 15:00:23.34567890 UTC")
      d.run(default_tag: 'test.fluentd') do
        d.feed(time, sample_record.merge("custom_key" => "This is also encoded value."))
      end
      assert_equal(expected,
                   d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
    end

    data("md5" => ["md5", "lU7d4EiF+2M1zxWcsmBbjg=="],
         "sha1" => ["sha1", "nghmz1y3KTEFxalfS2/Oe4n4yfQ="],
         "sha256" => ["sha256", "d0le9UOnUeuGPF/2yEBRM1YzOYeHtxYOE1UU6JgJrvU="],
         "sha512" => ["sha512", "n7rhisGHUBne6c4Cs9DRMbPror8O5Y/vYajDqAtOaiUTys/Z1EKBMnZQA0iVNFw7joX33cenBW3Yyccct3xSew=="],)
    def test_record_with_tag_and_time
      hash_type, expected = data
      d = create_driver(%[
        use_record_as_seed true
        use_entire_record true
        hash_type #{hash_type}
        include_tag_in_seed true
        include_time_in_seed true
      ])
      time = event_time("2017-10-15 15:00:23.34567890 UTC")
      d.run(default_tag: 'test.fluentd') do
        d.feed(time, sample_record.merge("custom_key" => "This is also encoded value."))
      end
      assert_equal(expected,
                   d.filtered.map {|e| e.last}.first[d.instance.hash_id_key])
    end
  end
end
