require 'rubygems'
require 'bundler'

require 'test/unit'
require 'fluent/test'
require 'fluent/plugin/out_elasticsearch'
require 'webmock/test_unit'
require 'date'

$:.push File.expand_path("../lib", __FILE__)
$:.push File.dirname(__FILE__)

WebMock.disable_net_connect!
