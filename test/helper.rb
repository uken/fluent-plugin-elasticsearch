require 'rubygems'
require 'bundler'

require 'test/unit'
require 'fluent/test'
require 'fluent/plugin/out_elasticsearch'
require 'webmock/test_unit'
require 'date'


$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))

WebMock.disable_net_connect!

