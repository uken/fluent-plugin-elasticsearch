module Fluent::ElasticsearchIndexTemplate

  def get_template(template_file)
    if !File.exists?(template_file)
      raise "If you specify a template_name you must specify a valid template file (checked '#{template_file}')!"
    end
    file_contents = IO.read(template_file).gsub(/\n/,'').gsub(/##alias_name##/,name)
    JSON.parse(file_contents)
  end

  def get_custom_template(template_file, customize_template)
    if !File.exists?(template_file)
      raise "If you specify a template_name you must specify a valid template file (checked '#{template_file}')!"
    end
    file_contents = IO.read(template_file).gsub(/\n/,'')
    customize_template.each do |key, value|
      file_contents = file_contents.gsub(/key/,value)
    end
    JSON.parse(file_contents)
  end

  def template_exists?(name)
    client.indices.get_template(:name => name)
    return true
  rescue Elasticsearch::Transport::Transport::Errors::NotFound
    return false
  end

  def template_put(name, template)
    client.indices.put_template(:name => name, :body => template)
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

  def template_custom_install(name, template_file, overwrite, customize_template)
    if overwrite
      template_put(name, get_custom_template(template_file, customize_template))
      log.info("Template '#{name}' overwritten with #{template_file}.")
      return
    end
    if !template_exists?(name)
      template_put(name, get_custom_template(template_file, customize_template))
      log.info("Template configured, but no template installed. Installed '#{name}' from #{template_file}.")
    else
      log.info("Template configured and already installed.")
    end
  end

  def templates_hash_install(templates, overwrite)
    templates.each do |key, value|
      template_install(key, value, overwrite)
    end
  end

end
