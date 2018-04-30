# encoding: utf-8

Gem::Specification.new do |s|
  s.name          = 'logstash-filter-cipher_kms'
  s.version       = '0.1.1'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = 'This is a Logstash plugin to allow data
                      encryption/decryption using AWS KMS.'
  s.description   = 'This is a Logstash plugin to allow data
                      encryption/decryption using AWS KMS.'
  s.homepage      = 'https://github.com/onfido/logstash-filter-cipher_kms'
  s.authors       = ['Onfido']
  s.email         = 'engineering@onfido.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*', 'spec/**/*', 'vendor/**/*', '*.gemspec', '*.md',
                'CONTRIBUTORS', 'Gemfile', 'LICENSE', 'NOTICE.TXT']
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.1.1"
  s.add_development_dependency 'logstash-devutils'
  s.add_dependency('activesupport')
  s.add_dependency('aws-sdk', '~> 2')
  s.add_development_dependency('vcr', '~> 4.0.0')
  s.add_development_dependency('webmock', '~> 3.1.1')
end
