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

  def template_exists?(name)
    client.indices.get_template(:name => name)
    return true
  rescue Elasticsearch::Transport::Transport::Errors::NotFound
    return false
  end

  def retry_install(max_retries)
    return unless block_given?
    retries = 0
    begin
      yield
    rescue Fluent::Plugin::ElasticsearchOutput::ConnectionFailure, Timeout::Error => e
      @_es = nil
      @_es_info = nil
      if retries < max_retries
        retries += 1
        sleep 2**retries
        log.warn "Could not push template(s) to Elasticsearch, resetting connection and trying again. #{e.message}"
        retry
      end
      raise Fluent::Plugin::ElasticsearchOutput::ConnectionFailure, "Could not push template(s) to Elasticsearch after #{retries} retries. #{e.message}"
    end
  end

  def template_put(name, template)
    client.indices.put_template(:name => name, :body => template)
  end

  def indexcreation(index_name)
    client.indices.create(:index => index_name)
    rescue Elasticsearch::Transport::Transport::Error => e
      log.error("Error while index creation - #{index_name}: #{e.inspect}")
  end

  def template_install(name, template_file, overwrite)
    if overwrite
      template_put(name, get_template(template_file))
      log.info("Template '#{name}' overwritten with #{template_file}.")
      return
    end
    if !template_exists?(name)
      template_put(name, get_template(template_file))
      log.info("Template configured, but no template installed. Installed '#{name}' from #{template_file}.")
    else
      log.info("Template configured and already installed.")
    end
  end

  def template_custom_install(template_name, template_file, overwrite, customize_template, index_prefix, rollover_index, deflector_alias_name, app_name, index_date_pattern)
    template_custom_name=template_name.downcase
    if overwrite
      template_put(template_custom_name, get_custom_template(template_file, customize_template))
      log.info("Template '#{template_custom_name}' overwritten with #{template_file}.")
    else
      if !template_exists?(template_custom_name)
        template_put(template_custom_name, get_custom_template(template_file, customize_template))
        log.info("Template configured, but no template installed. Installed '#{template_custom_name}' from #{template_file}.")
      else
        log.info("Template configured and already installed.")
      end
    end

    if rollover_index
      if !client.indices.exists_alias(:name => deflector_alias_name)
        index_name_temp='<'+index_prefix.downcase+'-'+app_name.downcase+'-{'+index_date_pattern+'}-000001>'
        indexcreation(index_name_temp)
        client.indices.put_alias(:index => index_name_temp, :name => deflector_alias_name)
        log.info("The alias '#{deflector_alias_name}' is created for the index '#{index_name_temp}'")
      else
        log.info("The alias '#{deflector_alias_name}' is already present")
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

end
