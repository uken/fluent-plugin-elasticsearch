require 'helper'
require 'fluent/log-ext'

class TestFluentLogExtHandler < Test::Unit::TestCase
  def setup
    @log = Fluent::Test::TestLogger.new
    @log.level = "info"
  end

  def test_trace?
    assert_false @log.respond_to?(:trace?)
  end

  def test_debug?
    assert_true @log.respond_to?(:debug?)
  end

  def test_info?
    assert_true @log.respond_to?(:info?)
  end

  def test_warn?
    assert_true @log.respond_to?(:warn?)
  end

  def test_error?
    assert_true @log.respond_to?(:error?)
  end

  def test_fatal?
    assert_true @log.respond_to?(:fatal?)
  end
end
