require 'simplecov'
SimpleCov.start do
  add_filter do |src|
    !(src.filename =~ /^#{SimpleCov.root}\/lib/)
  end
end

require 'coveralls'
Coveralls.wear!

require 'test/unit'
require 'fluent/test'
require 'minitest/pride'

require 'webmock/test_unit'
WebMock.disable_net_connect!
