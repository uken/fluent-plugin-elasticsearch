# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)

Gem::Specification.new do |s|
  s.name          = 'fluent-plugin-elasticsearch'
  s.version       = '0.3.0'
  s.authors       = ['diogo', 'pitr']
  s.email         = ['team@uken.com']
  s.description   = %q{ElasticSearch output plugin for Fluent event collector}
  s.summary       = s.description
  s.homepage      = 'https://github.com/uken/fluent-plugin-elasticsearch'
  s.license       = 'MIT'

  s.files         = `git ls-files`.split($/)
  s.executables   = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.test_files    = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths = ['lib']

  s.add_runtime_dependency 'fluentd', '~> 0'
  s.add_runtime_dependency 'patron', '~> 0'
  s.add_runtime_dependency 'elasticsearch', '~> 0'

  s.add_development_dependency 'rake', '~> 0'
  s.add_development_dependency 'webmock', '~> 1'
end
