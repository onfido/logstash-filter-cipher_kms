# encoding: utf-8

require 'logstash/devutils/rspec/spec_helper'
require 'vcr'

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into :webmock
end