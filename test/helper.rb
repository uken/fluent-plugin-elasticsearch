require 'simplecov'
SimpleCov.start do
  add_filter do |src|
    !(src.filename =~ /^#{SimpleCov.root}\/lib/)
  end
end

require 'coveralls'
Coveralls.wear!

# needs to be after simplecov but before test/unit, because fluentd sets default
# encoding to ASCII-8BIT, but coverall might load git data which could contain a
# UTF-8 character
at_exit do
  Encoding.default_internal = 'UTF-8' if defined?(Encoding) && Encoding.respond_to?(:default_internal)
  Encoding.default_external = 'UTF-8' if defined?(Encoding) && Encoding.respond_to?(:default_external)
end

require 'test/unit'
require 'fluent/test'
require 'minitest/pride'

require 'webmock/test_unit'
WebMock.disable_net_connect!
