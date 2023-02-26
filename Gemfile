source 'https://rubygems.org'

# Specify your gem's dependencies in fluent-plugin-elasticsearch.gemspec
gemspec

gem 'simplecov', require: false
gem 'strptime', require: false if RUBY_ENGINE == "ruby" && RUBY_VERSION =~ /^2/
gem "irb" if RUBY_ENGINE == "ruby" && RUBY_VERSION >= "2.6"
gem "elasticsearch-xpack" if ENV["USE_XPACK"]
gem "oj"
