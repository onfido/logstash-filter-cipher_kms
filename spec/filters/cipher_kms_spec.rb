# encoding: utf-8

require_relative '../spec_helper'
require 'logstash/filters/cipher_kms'

describe LogStash::Filters::CipherKms do

  describe 'configuration validations' do

    it 'should pass validation with encrypt mode' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'AES_128',
        'iv_random_length' => 16,
        'mode' => 'encrypt'
      )
      expect(config.validate_config).to eq(true)
    end

    it 'should pass validation with decrypt mode' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'AES_128',
        'iv_random_length' => 16,
        'mode' => 'decrypt'
      )
      expect(config.validate_config).to eq(true)
    end

    it 'should fail validation with invalid crypt mode' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'AES_128',
        'iv_random_length' => 16,
        'mode' => 'foo'
      )
      expect {config.validate_config}.to raise_error(LogStash::ConfigurationError)
    end

    it 'should pass validation with AES_128 algorithm' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'AES_128',
        'iv_random_length' => 16,
        'mode' => 'encrypt'
      )
      expect(config.validate_config).to eq(true)
    end

    it 'should pass validation with AES_256 algorithm' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'AES_256',
        'iv_random_length' => 16,
        'mode' => 'encrypt'
      )
      expect(config.validate_config).to eq(true)
    end

    it 'should fail validation with invalid algorithm' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'foo',
        'iv_random_length' => 16,
        'mode' => 'encrypt'
      )
      expect {config.validate_config}.to raise_error(LogStash::ConfigurationError)
    end

    it 'should pass validation with valid encryption context' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'AES_128',
        'iv_random_length' => 16,
        'mode' => 'encrypt',
        'encryption_context' => {'foo' => 'bar'}
      )
      expect(config.validate_config).to eq(true)
    end

    it 'should pass validation with a missing encryption context param' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'AES_128',
        'iv_random_length' => 16,
        'mode' => 'encrypt'
      )
      expect(config.validate_config).to eq(true)
    end

    it 'should fail validation with an invalid encryption context' do
      config = described_class.new(
        'key_id' => 'id',
        'region' => 'us-west-1',
        'algorithm' => 'AES_128',
        'iv_random_length' => 16,
        'mode' => 'encrypt',
        'encryption_context' => {'foo' => {'bar' => 'foobar'}}
      )
      expect {config.validate_config}.to raise_error(LogStash::ConfigurationError)
    end
  end

  describe 'decryption' do
    it 'returns a plain text version of the input' do
      encrypter = described_class.new(
        'algorithm' => 'AES_256',
        'mode' => 'encrypt',
        'base64' => true,
        'key_id' => 'arn:aws:kms:eu-west-1:666666666666:alias/kms-key',
        'iv_random_length' => 16,
        'region' => 'eu-west-1',
        'access_key_id' => 'fake_aws_key',
        'secret_access_key' => 'fake_aws_secret_key',
        'encryption_context' => {
            'kms_cmk_id' => 'arn:aws:kms:eu-west-1:666666666666:alias/kms-key'
        }
      )
      decrypter = described_class.new(
        'algorithm' => 'AES_256',
        'mode' => 'decrypt',
        'base64' => true,
        'key_id' => 'arn:aws:kms:eu-west-1:666666666666:alias/kms-key',
        'iv_random_length' => 16,
        'region' => 'eu-west-1',
        'access_key_id' => 'fake_aws_key',
        'secret_access_key' => 'fake_aws_secret_key',
        'encryption_context' => {
            'kms_cmk_id' => 'arn:aws:kms:eu-west-1:666666666666:alias/kms-key'
        }
      )
      plain_text = 'foo'
      event = LogStash::Event.new(LogStash::Json.load("{\"message\":\"#{plain_text}\"}"))
      encrypter.register
      decrypter.register

      VCR.use_cassette('aws_kms_communication') do
        encrypter.filter(event)
        decrypter.filter(event)
      end

      expect(event.get('message')).to eq(plain_text)
    end
  end
end
