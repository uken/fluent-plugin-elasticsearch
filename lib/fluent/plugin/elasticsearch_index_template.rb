require 'fluent/error'
require_relative './elasticsearch_error'

module Fluent::ElasticsearchIndexTemplate
  def get_template(template_file)
    if !File.exists?(template_file)
      raise "If you specify a template_name you must specify a valid template file (checked '#{template_file}')!"
    end
    file_contents = IO.read(template_file).gsub(/\n/,'')
    JSON.parse(file_contents)
  end

  def get_custom_template(template_file, customize_template)
    if !File.exists?(template_file)
      raise "If you specify a template_name you must specify a valid template file (checked '#{template_file}')!"
    end
    file_contents = IO.read(template_file).gsub(/\n/,'')
    customize_template.each do |key, value|
      file_contents = file_contents.gsub(key,value.downcase)
    end
    JSON.parse(file_contents)
  end

  def template_exists?(name, host = nil)
    client(host).indices.get_template(:name => name)
    return true
  rescue Elasticsearch::Transport::Transport::Errors::NotFound
    return false
  end

  def retry_operate(max_retries, fail_on_retry_exceed = true)
    return unless block_given?
    retries = 0
    begin
      yield
    rescue *client.transport.host_unreachable_exceptions, Timeout::Error => e
      @_es = nil
      @_es_info = nil
      if retries < max_retries
        retries += 1
        wait_seconds = 2**retries
        sleep wait_seconds
        log.warn "Could not communicate to Elasticsearch, resetting connection and trying again. #{e.message}"
        log.warn "Remaining retry: #{max_retries - retries}. Retry to communicate after #{wait_seconds} second(s)."
        retry
      end
      message = "Could not communicate to Elasticsearch after #{retries} retries. #{e.message}"
      log.warn message
      raise Fluent::Plugin::ElasticsearchError::RetryableOperationExhaustedFailure,
            message if fail_on_retry_exceed
    end
  end

  def template_put(name, template, host = nil)
    client(host).indices.put_template(:name => name, :body => template)
  end

  def indexcreation(index_name, host = nil)
    client(host).indices.create(:index => index_name)
  rescue Elasticsearch::Transport::Transport::Error => e
    if e.message =~ /"already exists"/
      log.debug("Index #{index_name} already exists")
    else
      log.error("Error while index creation - #{index_name}: #{e.inspect}")
    end
  end

  def template_install(name, template_file, overwrite, enable_ilm = false, deflector_alias_name = nil, ilm_policy_id = nil, host = nil)
    inject_template_name = get_template_name(enable_ilm, name, deflector_alias_name)
    if overwrite
      template_put(inject_template_name,
                   enable_ilm ? inject_ilm_settings_to_template(deflector_alias_name,
                                                                ilm_policy_id,
                                                                get_template(template_file)) :
                     get_template(template_file), host)

      log.info("Template '#{inject_template_name}' overwritten with #{template_file}.")
      return
    end
    if !template_exists?(inject_template_name, host)
      template_put(inject_template_name,
                   enable_ilm ? inject_ilm_settings_to_template(deflector_alias_name,
                                                                ilm_policy_id,
                                                                get_template(template_file)) :
                     get_template(template_file), host)
      log.info("Template configured, but no template installed. Installed '#{inject_template_name}' from #{template_file}.")
    else
      log.debug("Template '#{inject_template_name}' configured and already installed.")
    end
  end

  def template_custom_install(template_name, template_file, overwrite, customize_template, enable_ilm, deflector_alias_name, ilm_policy_id, host)
    template_custom_name = get_template_name(enable_ilm, template_name, deflector_alias_name)
    custom_template = if enable_ilm
                        inject_ilm_settings_to_template(deflector_alias_name, ilm_policy_id,
                                                        get_custom_template(template_file,
                                                                            customize_template))
                      else
                        get_custom_template(template_file, customize_template)
                      end
    if overwrite
      template_put(template_custom_name, custom_template, host)
      log.info("Template '#{template_custom_name}' overwritten with #{template_file}.")
    else
      if !template_exists?(template_custom_name, host)
        template_put(template_custom_name, custom_template, host)
        log.info("Template configured, but no template installed. Installed '#{template_custom_name}' from #{template_file}.")
      else
        log.debug("Template '#{template_custom_name}' configured and already installed.")
      end
    end
  end

  def get_template_name(enable_ilm, template_name, deflector_alias_name)
    enable_ilm ? deflector_alias_name : template_name
  end

  def inject_ilm_settings_to_template(deflector_alias_name, ilm_policy_id, template)
    log.debug("Overwriting index patterns when Index Lifecycle Management is enabled.")
    template.delete('template') if template.include?('template')
    template['index_patterns'] = "#{deflector_alias_name}-*"
    template['order'] = template['order'] ? template['order'] + deflector_alias_name.split('-').length : 50 + deflector_alias_name.split('-').length
    if template['settings'] && (template['settings']['index.lifecycle.name'] || template['settings']['index.lifecycle.rollover_alias'])
      log.debug("Overwriting index lifecycle name and rollover alias when Index Lifecycle Management is enabled.")
    end
    template['settings'].update({ 'index.lifecycle.name' => ilm_policy_id, 'index.lifecycle.rollover_alias' => deflector_alias_name})
    template
  end

  def create_rollover_alias(index_prefix, rollover_index, deflector_alias_name, app_name, index_date_pattern, index_separator, enable_ilm, ilm_policy_id, ilm_policy, host)
    if rollover_index
      if !client.indices.exists_alias(:name => deflector_alias_name)
        if index_date_pattern.empty?
          index_name_temp='<'+index_prefix.downcase+index_separator+app_name.downcase+'-000001>'
        else
          index_name_temp='<'+index_prefix.downcase+index_separator+app_name.downcase+'-{'+index_date_pattern+'}-000001>'
        end
        indexcreation(index_name_temp, host)
        body = {}
        body = rollover_alias_payload(deflector_alias_name) if enable_ilm
        client.indices.put_alias(:index => index_name_temp, :name => deflector_alias_name,
                                 :body => body)
        log.info("The alias '#{deflector_alias_name}' is created for the index '#{index_name_temp}'")
        if enable_ilm
          if ilm_policy.empty?
            setup_ilm(enable_ilm, ilm_policy_id)
          else
            setup_ilm(enable_ilm, ilm_policy_id, ilm_policy)
          end
        end
      else
        log.debug("The alias '#{deflector_alias_name}' is already present")
      end
    else
      log.info("No index and alias creation action performed because rollover_index is set to '#{rollover_index}'")
    end
  end

  def templates_hash_install(templates, overwrite)
    templates.each do |key, value|
      template_install(key, value, overwrite)
    end
  end

  def rollover_alias_payload(rollover_alias)
    {
      'aliases' => {
        rollover_alias => {
          'is_write_index' =>  true
        }
      }
    }
  end
end
