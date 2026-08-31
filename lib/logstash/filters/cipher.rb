# encoding: utf-8
require "logstash/filters/base"
require "openssl"
require "concurrent/atomic/thread_local_var"

# This filter parses a source and apply a cipher or decipher before
# storing it in the target.
#
class LogStash::Filters::Cipher < LogStash::Filters::Base
  config_name "cipher"

  # The field to perform filter
  #
  # Example, to use the @message field (default) :
  # [source,ruby]
  #     filter { cipher { source => "message" } }
  config :source, :validate => :string, :default => "message"

  # The name of the container to put the result
  #
  # Example, to place the result into crypt :
  # [source,ruby]
  #     filter { cipher { target => "crypt" } }
  config :target, :validate => :string, :default => "message"

  # Do we have to perform a `base64` decode or encode?
  #
  # If we are decrypting, `base64` decode will be done before.
  # If we are encrypting, `base64` will be done after.
  #
  config :base64, :validate => :boolean, :default => true

  # The key to use
  #
  # NOTE: If you encounter an error message at runtime containing the following:
  #
  # "java.security.InvalidKeyException: Illegal key size: possibly you need to install 
  # Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files for your JRE"
  #
  # Please read the following: https://github.com/jruby/jruby/wiki/UnlimitedStrengthCrypto
  #
  config :key, :validate => :password

  # Key is base64
  #
  # boolean (true or false)
  # default is false
  config :key_base64, :validate => :boolean, :default => false

  # The key size to pad
  #
  # It depends of the cipher algorithm. If your key doesn't need
  # padding, don't set this parameter
  #
  # Example, for AES-128, we must have 16 char long key. AES-256 = 32 chars 
  # [source,ruby]
  #     filter { cipher { key_size => 16 }
  #
  config :key_size, :validate => :number, :default => 16

  # The character used to pad the key
  config :key_pad, :default => "\0"

  # The cipher algorithm
  #
  # A list of supported algorithms can be obtained by
  # [source,ruby]
  #     puts OpenSSL::Cipher.ciphers
  config :algorithm, :validate => OpenSSL::Cipher.ciphers, :required => true

  # Encrypting or decrypting some data
  #
  # Valid values are encrypt or decrypt
  config :mode, :validate => %w(encrypt decrypt), :required => true

  # Cipher padding to use. Enables or disables padding.
  #
  # By default encryption operations are padded using standard block padding
  # and the padding is checked and removed when decrypting. If the pad
  # parameter is zero then no padding is performed, the total amount of data
  # encrypted or decrypted must then be a multiple of the block size or an
  # error will occur.
  #
  # See EVP_CIPHER_CTX_set_padding for further information.
  #
  # We are using Openssl jRuby which uses default padding to PKCS5Padding
  # If you want to change it, set this parameter. If you want to disable
  # it, Set this parameter to 0
  # [source,ruby]
  #     filter { cipher { cipher_padding => 0 }}
  config :cipher_padding, :validate => :string

  # Force an random IV to be used per encryption invocation and specify
  # the length of the random IV that will be generated via:
  #
  #       OpenSSL::Random.random_bytes(int_length)
  #
  # Enabling this will force the plugin to generate a unique
  # random IV for each encryption call. This random IV will be prepended to the
  # encrypted result bytes and then base64 encoded. On decryption "iv_random_length" must
  # also be set to utilize this feature. Random IV's are better than statically
  # hardcoded IVs
  #
  # For AES algorithms you can set this to a 16
  # [source,ruby]
  #     filter { cipher { iv_random_length => 16 }}
  config :iv_random_length, :validate => :number, :required => true

  # If this is set the internal Cipher instance will be
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
  config :max_cipher_reuse, :validate => :number, :default => 1

  def register
    require 'base64' if @base64
    if cipher_reuse_enabled?
      @reusable_cipher = Concurrent::ThreadLocalVar.new
      @cipher_reuse_count = Concurrent::ThreadLocalVar.new
    end

    if @key.value.length != @key_size
      @logger.debug("key length is " + @key.value.length.to_s + ", padding it to " + @key_size.to_s + " with '" + @key_pad.to_s + "'")
      @key = @key.class.new(@key.value[0,@key_size].ljust(@key_size,@key_pad))
    end
  end # def register

  def filter(event)
    source = event.get(@source)
    if (source.nil? || source.empty?)
      @logger.debug("Event to filter, event 'source' field: " + @source + " was null(nil) or blank, doing nothing")
      return
    end

    result = case(@mode)
             when "encrypt" then do_encrypt(source)
             when "decrypt" then do_decrypt(source)
             else
               @logger.error("Invalid cipher mode. Valid values are \"encrypt\" or \"decrypt\"", :mode => @mode)
               raise "Internal Error, aborting."
             end

    event.set(@target, result)
    filter_matched(event) unless result.nil?
  rescue => e
    @logger.error("An error occurred while #{@mode}ing.", :exception => e.message)
    event.tag("_cipherfiltererror")
  end

  private

  def cipher_reuse_enabled?
    @max_cipher_reuse > 1
  end

  ##
  # @param plaintext [String]
  # @return [String]: ciphertext
  def do_encrypt(plaintext)
    with_cipher do |cipher|
      random_iv = OpenSSL::Random.random_bytes(@iv_random_length)
      cipher.iv = random_iv

      ciphertext = random_iv + cipher.update(plaintext) + cipher.final

      ciphertext = Base64.strict_encode64(ciphertext).encode("utf-8") if @base64 == true

      ciphertext
    end
  end

  ##
  # @param ciphertext_with_iv [String]
  # @return [String] plaintext
  def do_decrypt(ciphertext_with_iv)
    ciphertext_with_iv = Base64.strict_decode64(ciphertext_with_iv) if @base64 == true
    encoded_iv =  ""
    case(@iv_random_length)
    when 0
      ciphertext = ciphertext_with_iv
    else
      encoded_iv = ciphertext_with_iv.byteslice(0..@iv_random_length)
      ciphertext = ciphertext_with_iv.byteslice(@iv_random_length..-1)
    end
    with_cipher do |cipher|
      unless encoded_iv.empty? 
        cipher.iv = encoded_iv
      end
      plaintext = cipher.update(ciphertext)
      plaintext << cipher.final
      plaintext.force_encoding("UTF-8")
      plaintext
    end
  end
  ##
  # Returns a new or freshly-reset cipher, bypassing cipher reuse if it is not enabled
  #
  # @yieldparam [OpenSSL::Cipher]
  # @yieldreturn [Object]: the object that this method should return
  # @return [Object]: the object that was returned by the yielded block
  def with_cipher
    return yield(init_cipher) unless cipher_reuse_enabled?

    with_reusable_cipher do |reusable_cipher|
      yield reusable_cipher
    end
  end

  ##
  # Returns a new or freshly-reset cipher.
  #
  # @yieldparam [OpenSSL::Cipher]
  # @yieldreturn [Object]: the object that this method should return
  # @return [Object]: the object that was returned by the yielded block
  def with_reusable_cipher
    cipher = get_or_init_reusable_cipher

    result = yield(cipher)

    cleanup_reusable_cipher

    return result
  rescue => e
    # when an error is encountered, we cannot trust the state of the cipher object.
    @logger.debug("shared cipher: removing because an exception was raised in #{Thread.current}", :exception => e.message)
    destroy_reusable_cipher
    raise
  end

  def get_or_init_reusable_cipher
    if @reusable_cipher.value.nil?
      @logger.debug("shared cipher: initializing for #{Thread.current}")
      @reusable_cipher.value = init_cipher
      @cipher_reuse_count.value = 0
    end

    @cipher_reuse_count.value += 1
    @reusable_cipher.value
  end

  def cleanup_reusable_cipher
    if @cipher_reuse_count.value >= @max_cipher_reuse
      @logger.debug("shared cipher: max_cipher_reuse[#{@max_cipher_reuse}] reached for #{Thread.current}, total_cipher_uses = #{@cipher_reuse_count.value}") if @logger.debug?
      destroy_reusable_cipher
    else
      @logger.debug("shared cipher: resetting for #{Thread.current}")
      @reusable_cipher.value.reset
    end
  end

  def destroy_reusable_cipher
    @reusable_cipher.value = nil
    @cipher_reuse_count.value = 0
  end

  ##
  # @return [OpenSSL::Cipher]
  def init_cipher
    cipher = OpenSSL::Cipher.new(@algorithm)

    cipher.public_send(@mode)
    
    if @key_base64 == true
      key = Base64.strict_decode64(@key.value) 
    else 
      key = @key.value
    end
    logger.info("Base64: #{@key_base64} Key: #{key}")
    cipher.key = key

    cipher.padding = @cipher_padding if @cipher_padding

    if @logger.trace?
      @logger.trace("Cipher initialisation done", :mode => @mode,
                                                  :key => key,
                                                  :iv_random_length => @iv_random_length,
                                                  :iv_random => @iv_random,
                                                  :cipher_padding => @cipher_padding)
    end

    cipher
  end # def init_cipher


end # class LogStash::Filters::Cipher
