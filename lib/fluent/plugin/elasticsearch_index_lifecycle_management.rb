require_relative 'elasticsearch_compat'

module Fluent::Plugin::ElasticsearchIndexLifecycleManagement
  ILM_DEFAULT_POLICY_PATH = "default-ilm-policy.json"

  def setup_ilm(enable_ilm, policy_id, ilm_policy = default_policy_payload, overwrite = false)
    return unless enable_ilm

    create_ilm_policy(policy_id, ilm_policy, overwrite)
  end

  def verify_ilm_working
    # Check the Elasticsearch instance for ILM readiness - this means that the version has to be a non-OSS release, with ILM feature
    # available and enabled.
    begin
      xpack = xpack_info
      if xpack.nil?
        raise Fluent::ConfigError, "xpack endpoint does not work"
      end
      features = xpack["features"]
      ilm = features.nil? ? nil : features["ilm"]
      raise Fluent::ConfigError, "Index Lifecycle management is enabled in Fluentd, but not installed on your Elasticsearch" if features.nil? || ilm.nil?
      raise Fluent::ConfigError, "Index Lifecycle management is enabled in Fluentd, but not available in your Elasticsearch" unless ilm['available']
      raise Fluent::ConfigError, "Index Lifecycle management is enabled in Fluentd, but not enabled in your Elasticsearch" unless ilm['enabled']

    rescue ::TRANSPORT_CLASS::Transport::Error => e
      raise Fluent::ConfigError, "Index Lifecycle management is enabled in Fluentd, but not installed on your Elasticsearch", error: e
    end
  end

  def create_ilm_policy(policy_id, ilm_policy = default_policy_payload, overwrite = false)
    if overwrite || !ilm_policy_exists?(policy_id)
      ilm_policy_put(policy_id, ilm_policy)
    end
  end

  def xpack_info
    begin
      client.xpack.info
    rescue NoMethodError
      raise RuntimeError, "elasticsearch-xpack gem is not installed."
    rescue
      nil
    end
  end

  def get_ilm_policy
    if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("8.0.0")
      client.ilm.get_lifecycle
    else
      client.ilm.get_policy
    end
  end

  def ilm_policy_exists?(policy_id)
    begin
      if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("8.0.0")
        client.ilm.get_lifecycle(policy: policy_id)
      else
        client.ilm.get_policy(policy_id: policy_id)
      end
      true
    rescue
      false
    end
  end

  def ilm_policy_put(policy_id, policy)
    log.info("Installing ILM policy: #{policy}")
    if Gem::Version.new(Elasticsearch::VERSION) >= Gem::Version.new("8.0.0")
      client.ilm.put_lifecycle(policy: policy_id, body: policy)
    else
      client.ilm.put_policy(policy_id: policy_id, body: policy)
    end
  end

  def default_policy_payload
    default_policy_path = File.join(__dir__, ILM_DEFAULT_POLICY_PATH)
    Yajl.load(::IO.read(default_policy_path))
  end
end
