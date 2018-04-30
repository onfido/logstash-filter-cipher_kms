# encoding: utf-8

require 'aws-sdk'
require 'json'
require 'logstash/filters/base'
require 'logstash/namespace'
require 'openssl'

# This filter parses a source and apply a cipher or decipher before
# storing it in the target.
# It uses AWS KMS to generate the envelope key for ciphering/deciphering.
class LogStash::Filters::CipherKms < LogStash::Filters::Base
  config_name 'cipher_kms'

  # The field to perform filter
  #
  # Example, to use the @message field (default):
  # [source,ruby]
  #     filter { cipher_kms { source => "message" } }
  config :source, validate: :string, default: 'message'

  # The name of the container to put the result
  #
  # Example, to place the result into crypt :
  # [source,ruby]
  #     filter { cipher_kms { target => "crypt" } }
  config :target, validate: :string, default: 'message'

  # The name of the container to put the crypt metadata
  #
  # Example, to place the crypt metadata into crypt_metadata :
  # [source,ruby]
  #     filter { cipher_kms { crypt_metadata => "crypt_metadata" } }
  config :crypt_metadata, validate: :string, default: 'crypt_metadata'

  # Do we have to perform a `base64` decode or encode?
  #
  # If we are decrypting, `base64` decode will be done before.
  # If we are encrypting, `base64` will be done after.
  #
  config :base64, validate: :boolean, default: true

  # The AWS KMS key id to use
  #
  config :key_id, validate: :string, required: true

  # The AWS region for KMS (e.g. eu-west-1)
  # See http://docs.aws.amazon.com/general/latest/gr/rande.html#kms_region
  config :region, validate: :string, required: true

  # An optional aws access key id to use for AWS.
  #
  config :access_key_id, validate: :string, default: nil

  # An optional secret access key to use for AWS.
  #
  config :secret_access_key, validate: :string, default: nil

  # An optional AWS profile to use.
  # See http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-multiple-profiles
  config :aws_profile, validate: :string, default: nil

  # An optional path for the shared credentials file.
  # See http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
  config :aws_shared_credentials_path, validate: :string, default: nil

  # An optional setting whether to use AWS instance profile.
  # See http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html
  config :aws_instance_profile, validate: :boolean, default: false

  # An optional setting whether to use AWS ECS credentials.
  # See http://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
  config :aws_ecs_credentials, validate: :boolean, default: false

  # An encryption context to use to encrypting and decrypting data.
  # When encrypting, the encryption context is sent as a part of the payload.
  # When decrypting, if any of the key-value pairs specified in encryption_context
  # fails to match the payload's encryption context, then decryption will fail.
  # Nested hashes are not supported. This is just a flat map of key value pairs.
  # See: http://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html
  config :encryption_context, validate: :hash, default: {}

  # The cipher algorithm
  #
  # Due to AWS KMS restrictions the available algorithms are: AES_128, AES_256
  # The mapping for the equivalent Ruby ciphers are as follows:
  # {AES_128 => AES-128-cbc, AES_256 => AES-256-cbc}
  config :algorithm, validate: :string, required: true

  # Encrypting or decrypting some data
  #
  # Valid values are encrypt or decrypt
  config :mode, validate: :string, required: true

  # Force a random IV to be used per encryption invocation and specify
  # the length of the random IV that will be generated via:
  #
  #       OpenSSL::Random.random_bytes(int_length)
  #
  # Enabling this will force the plugin to generate a unique
  # random IV for each encryption call. This random IV will be prepended to the
  # encrypted result bytes and then base64 encoded.
  # On decryption "iv_random_length" must also be set to utilize this feature.
  # Random IV's are better than statically hardcoded IVs.
  #
  # For AES algorithms you can set this to a 16
  # [source,ruby]
  #     filter { cipher { iv_random_length => 16 }}
  config :iv_random_length, validate: :number, required: true

  # If this is set, the internal Cipher instance will be
  # re-used up to @max_cipher_reuse times before being
  # reset() and re-created from scratch. This is an option
  # for efficiency where lots of data is being encrypted
  # and decrypted using this filter. This lets the filter
  # avoid creating new Cipher instances over and over
  # for each encrypt/decrypt operation.
  #
  # This is optional, the default is no re-use of the Cipher
  # instance and max_cipher_reuse = 1 by default
  # [source,ruby]
  #     filter { cipher { max_cipher_reuse => 1000 }}
  config :max_cipher_reuse, validate: :number, default: 1

  # Mapping between AWS KMS available ciphers and correlated Ruby ciphers
  KMS_RUBY_CIPHER_MAP = {"AES_128" => "AES-128-cbc", "AES_256" => "AES-256-cbc"}.freeze

  def register
    require 'base64' if @base64
    validate_config
    init_cipher
  end

  def filter(event)
    # If decrypt or encrypt fails, we keep it it intact.
    begin
      if blank?(event.get(@source))
        @logger.debug("Event to filter, event 'source' field: " + @source + ' was nil or empty, doing nothing.')
        return
      end

      @logger.debug('Event to filter', event: event)
      data = event.get(@source)

      if @mode == 'encrypt'
        result, metadata = encrypt(data)
        event.set(@crypt_metadata, metadata)
      elsif @mode == 'decrypt'
        result = decrypt(data, event.get(@crypt_metadata))
        event.remove(@crypt_metadata)
      end

      @total_cipher_uses += 1
      unless result.nil?
        event.set(@target, result)
        filter_matched(event)
      end
    rescue => e
      handle_unexpected_error(event, e)
    ensure
      rotate_cipher_if_needed
    end
  end

  def handle_unexpected_error(event, error)
    @logger.warn('Exception caught on cipher filter', event: event, error: error)
    # force a re-initialize on error to be safe
    init_cipher
  end

  def encrypt(data)
    @random_iv = OpenSSL::Random.random_bytes(@iv_random_length)
    kms_response = @kms.generate_data_key(key_id: @key_id, key_spec: @algorithm,
                                          encryption_context: @encryption_context) # => returns a ciphertext and a plaintext key

    begin
      data = JSON.generate(data)
    rescue JSON::GeneratorError
      # ignored, use as is
    end
    result = cipher_process(kms_response.plaintext, data)

    # Prepend padding and base64 encoding if configured
    result = @random_iv + result unless @random_iv.nil?
    result = Base64.strict_encode64(result).encode('utf-8') if @base64
    metadata = Base64.strict_encode64(kms_response.ciphertext_blob).encode('utf-8')
    [result, metadata]
  end

  def decrypt(data, metadata)
    kms_response = @kms.decrypt(ciphertext_blob: Base64.strict_decode64(metadata),
                                encryption_context: @encryption_context)

    data = Base64.strict_decode64(data) if @base64
    @random_iv = data.byteslice(0, @iv_random_length)
    data = data.byteslice(@iv_random_length..data.length)

    result = cipher_process(kms_response.plaintext, data)
    result.force_encoding('utf-8')
    begin
      result = JSON.parse(result)
    rescue JSON::ParserError
      # ignored, return as is
    end

    result
  end

  def cipher_set_required_params(key)
    @cipher.key = key
    @cipher.iv = @random_iv
  end

  def cipher_process(key, data)
    cipher_set_required_params(key)
    result = @cipher.update(data) + @cipher.final
    result
  end

  def rotate_cipher_if_needed
    if !@max_cipher_reuse.nil? && @total_cipher_uses >= @max_cipher_reuse
      @logger.debug('max_cipher_reuse[' + @max_cipher_reuse.to_s + '] reached, total_cipher_uses = ' + @total_cipher_uses.to_s)
      init_cipher
    end
  end

  def init_cipher
    @logger.debug('Encryption Context: ' + @encryption_context.to_s, plugin: self.class.name)

    credentials = nil
    if !blank?(@access_key_id) && !blank?(@secret_access_key)
      credentials = Aws::Credentials.new(@access_key_id, @secret_access_key)
      @logger.debug('Using Static Credentials', plugin: self.class.name)
    elsif !blank?(@aws_shared_credentials_path) || !blank?(@aws_profile.blank)
      credentials = Aws::SharedCredentials.new(path: @aws_shared_credentials_path, profile_name: @aws_profile)
      @logger.debug('Using Shared Credentials', plugin: self.class.name)
    elsif @aws_instance_profile
      credentials = Aws::InstanceProfileCredentials.new
      @logger.debug('Using Instance Profile Credentials', plugin: self.class.name)
    elsif @aws_ecs_credentials
      credentials = Aws::ECSCredentials.new
      @logger.debug('Using ECS Credentials', plugin: self.class.name)
    end

    @kms = Aws::KMS::Client.new(region: @region, credentials: credentials)

    @total_cipher_uses = 0
    @cipher = OpenSSL::Cipher.new(KMS_RUBY_CIPHER_MAP[@algorithm])
    set_cipher_crypt_mode

    @logger.debug('Cipher initialisation done', mode: @mode, iv_random_length: @iv_random_length,
                                                algorithm: @algorithm, base64: @base64,
                                                max_cipher_reuse: @max_cipher_reuse)
  end

  def set_cipher_crypt_mode
    if @mode == 'encrypt'
      @cipher.encrypt
    elsif @mode == 'decrypt'
      @cipher.decrypt
    end
  end

  def validate_config
    @encryption_context.each do |_, value|
      unless value.is_a?(String)
        raise LogStash::ConfigurationError, 'Values in encryption_context must be strings, aborting.'
      end
    end

    unless KMS_RUBY_CIPHER_MAP.key?(@algorithm)
      raise LogStash::ConfigurationError, 'You can only use one of the following algorithms: ' + KMS_RUBY_CIPHER_MAP.keys.to_s + ', aborting.'
    end

    unless @mode == 'encrypt' || @mode == 'decrypt'
      @logger.error('Invalid cipher mode. Valid values are \"encrypt\" or \"decrypt\"', mode: @mode)
      raise LogStash::ConfigurationError, 'Invalid cipher mode. Valid values are \"encrypt\" or \"decrypt\", aborting.'
    end

    true
  end

  private

  def blank?(data)
    data.nil? || data.empty?
  end
end
