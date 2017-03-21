# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)

Gem::Specification.new do |s|
  s.name          = 'fluent-plugin-elasticsearch'
  s.version       = '1.9.2'
  s.authors       = ['diogo', 'pitr']
  s.email         = ['pitr.vern@gmail.com', 'me@diogoterror.com']
  s.description   = %q{ElasticSearch output plugin for Fluent event collector}
  s.summary       = s.description
  s.homepage      = 'https://github.com/uken/fluent-plugin-elasticsearch'
  s.license       = 'MIT'

  s.files         = `git ls-files`.split($/)
  s.executables   = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.test_files    = s.files.grep(%r{^(test|spec|features)/})
  s.require_paths = ['lib']

  s.required_ruby_version = Gem::Requirement.new(">= 2.0".freeze)

  s.add_runtime_dependency 'fluentd', '>= 0.10.43'
  s.add_runtime_dependency 'excon', '>= 0'
  s.add_runtime_dependency 'elasticsearch'


  s.add_development_dependency 'rake', '>= 0'
  s.add_development_dependency 'webmock', '~> 1'
  s.add_development_dependency 'test-unit', '~> 3.1.0'
  s.add_development_dependency 'minitest', '~> 5.8'
end
