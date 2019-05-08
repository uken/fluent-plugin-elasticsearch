require 'helper'
require 'fluent/log-ext'

class TestFluentLogExtHandler < Test::Unit::TestCase
  def setup
    @log_device = Fluent::Test::DummyLogDevice.new
    dl_opts = {:log_level => ServerEngine::DaemonLogger::INFO}
    logger = ServerEngine::DaemonLogger.new(@log_device, dl_opts)
    @log = Fluent::Log.new(logger)
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
