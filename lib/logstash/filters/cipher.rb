# encoding: utf-8
require "logstash/filters/base"
require "openssl"

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
  config :key, :validate => :string

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
  config :algorithm, :validate => :string, :required => true

  # Encrypting or decrypting some data
  #
  # Valid values are encrypt or decrypt
  config :mode, :validate => :string, :required => true

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

  config :iv, :validate => :string, :obsolete => "Please use 'iv_random_length'"

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
    init_cipher
  end # def register


  def filter(event)
    


    #If decrypt or encrypt fails, we keep it it intact.
    begin

      if (event.get(@source).nil? || event.get(@source).empty?)
        @logger.debug("Event to filter, event 'source' field: " + @source + " was null(nil) or blank, doing nothing")
        return
      end

      #@logger.debug("Event to filter", :event => event)
      data = event.get(@source)
      if @mode == "decrypt"
        data =  Base64.strict_decode64(data) if @base64 == true
        @random_iv = data.byteslice(0,@iv_random_length)
        data = data.byteslice(@iv_random_length..data.length)
      end

      if @mode == "encrypt"
        @random_iv = OpenSSL::Random.random_bytes(@iv_random_length)
      end

      @cipher.iv = @random_iv

      result = @cipher.update(data) + @cipher.final

      if @mode == "encrypt"

        # if we have a random_iv, prepend that to the crypted result
        if !@random_iv.nil?
          result = @random_iv + result
        end

        result =  Base64.strict_encode64(result).encode("utf-8") if @base64 == true
      end

    rescue => e
      @logger.warn("Exception catch on cipher filter", :event => event, :error => e)

      # force a re-initialize on error to be safe
      init_cipher

    else
      @total_cipher_uses += 1

      result = result.force_encoding("utf-8") if @mode == "decrypt"

      event.set(@target, result)

      #Is it necessary to add 'if !result.nil?' ? exception have been already catched.
      #In doubt, I keep it.
      filter_matched(event) if !result.nil?

      if !@max_cipher_reuse.nil? and @total_cipher_uses >= @max_cipher_reuse
        @logger.debug("max_cipher_reuse["+@max_cipher_reuse.to_s+"] reached, total_cipher_uses = "+@total_cipher_uses.to_s)
        init_cipher
      end

    end
  end # def filter

  def init_cipher

    if !@cipher.nil?
      @cipher.reset
      @cipher = nil
    end

    @cipher = OpenSSL::Cipher.new(@algorithm)

    @total_cipher_uses = 0

    if @mode == "encrypt"
      @cipher.encrypt
    elsif @mode == "decrypt"
      @cipher.decrypt
    else
      @logger.error("Invalid cipher mode. Valid values are \"encrypt\" or \"decrypt\"", :mode => @mode)
      raise "Bad configuration, aborting."
    end

    if @key.length != @key_size
      @logger.debug("key length is " + @key.length.to_s + ", padding it to " + @key_size.to_s + " with '" + @key_pad.to_s + "'")
      @key = @key[0,@key_size].ljust(@key_size,@key_pad)
    end

    @cipher.key = @key

    @cipher.padding = @cipher_padding if @cipher_padding

    @logger.debug("Cipher initialisation done", :mode => @mode, :key => @key, :iv_random_length => @iv_random_length, :iv_random => @iv_random, :cipher_padding => @cipher_padding)
  end # def init_cipher


end # class LogStash::Filters::Cipher
