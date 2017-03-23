# encoding: ASCII-8BIT
require "logstash/filters/base"
require "logstash/namespace"
require "logstash/json"
require "openssl"
require "thread"
require "json"
require "pry"
require "ostruct"
require "concurrent"






# This filter parses a source and apply a cipher or decipher before
# storing it in the target.

class LogStash::Filters::Cipher < LogStash::Filters::Base
  config_name "cipher"

  config :field_to_crypt, :validate => :string, :default  => ""
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

  # The initialization vector to use (statically hard-coded). For
  # a random IV see the iv_random_length property
  #
  # NOTE: If iv_random_length is set, it takes precedence over any value set for "iv"
  #
  # The cipher modes CBC, CFB, OFB and CTR all need an "initialization
  # vector", or short, IV. ECB mode is the only mode that does not require
  # an IV, but there is almost no legitimate use case for this mode
  # because of the fact that it does not sufficiently hide plaintext patterns.
  #
  # For AES algorithms set this to a 16 byte string.
  # [source,ruby]
  #     filter { cipher { iv => "1234567890123456" }}
  #
  # Deprecated: Please use `iv_random_length` instead
  config :iv, :validate => :string, :deprecated => "Please use 'iv_random_length'"

  # Force an random IV to be used per encryption invocation and specify
  # the length of the random IV that will be generated via:
  #
  #       OpenSSL::Random.random_bytes(int_length)
  #
  # If iv_random_length is set, it takes precedence over any value set for "iv"
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
  config :iv_random_length, :validate => :number

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


  def crypto(event, key, value)
    printf("sono dentro crypto\n")
    printf("il value che mi sono portato dal json per la criptazione è : #{value}\n")
    printf("riesco a vedere event? : #{event.get(@source)}")
    if (event.get(@source).nil? || event.get(@source).empty?)
      @logger.debug("Event to filter, event 'source' field: " + @source + " was null(nil) or blank, doing nothing")
      return
    end
    data = value #cambio la source, cambiarlo ciclicamente
    printf("data is (deve essere uguale a value) : #{data}\n")
    if @mode == "decrypt"
      data =  Base64.strict_decode64(data) if @base64 == true

      if !@iv_random_length.nil?
        @random_iv = data.byteslice(0,@iv_random_length)
        data = data.byteslice(@iv_random_length..data.length)
      end

    end

    if !@iv_random_length.nil? and @mode == "encrypt"
      @random_iv = OpenSSL::Random.random_bytes(@iv_random_length)
    end

    # if iv_random_length is specified, generate a new one
    # and force the cipher's IV = to the random value
    if !@iv_random_length.nil?
      @cipher.iv = @random_iv
    end

    result = @cipher.update(data) + @cipher.final
    printf("questo è il result dopo cipher.update + cipher final : #{result}\n")
    if @mode == "encrypt"
      printf("sono in encrypt\n")
      # if we have a random_iv, prepend that to the crypted result
      if !@random_iv.nil?
        result = @random_iv + result
      end
      printf("questo è result prima di fare encode: #{result}\n")
      result =  Base64.strict_encode64(result).encode("utf-8") if @base64 == true
      printf("questo è result se mode == encrypt: #{result}\n")
    end

  rescue => e
    @logger.warn("Exception catch on cipher filter", :event => event, :error => e)

    # force a re-initialize on error to be safe
    init_cipher

  else
    @total_cipher_uses += 1
    printf("sono dentro else?\n")
    result = result.force_encoding("utf-8") if @mode == "decrypt"


    #event.set(key,result)

    printf("ho saltato tutto?")
    #Is it necessary to add 'if !result.nil?' ? exception have been already catched.
    #In doubt, I keep it.
    filter_matched(event) if !result.nil?

    if !@max_cipher_reuse.nil? and @total_cipher_uses >= @max_cipher_reuse
      @logger.debug("max_cipher_reuse["+@max_cipher_reuse.to_s+"] reached, total_cipher_uses = "+@total_cipher_uses.to_s)
      init_cipher
    end

    return result
  end #def crypto


  def visit_json(event,parent, myHash)
    #print("sono dentro visit_json")
    myHash.each do |key, value|
      #print("sono dentro il primo ciclo")
      value.is_a?(Hash) ? visit_json(event,key, value) :
          if "#{key}" == "#{@field_to_crypt}"
            printf("the key is #{key}:#{value}\n")
            crypto(event,"#{key}","#{value}")
            p = Concurrent::Promise.new{10}
            event.set(value, result )
            # else
            #   printf("#{key}!=#{@field_to_crypt}\n")
          end
    end
  end



  def register
    require 'base64' if @base64
    @semaphore = Mutex.new
     @semaphore.synchronize {
       init_cipher
     }
  end # def register

#  def crypto_regex(hash)
#    regex = '^.*iban":\s"(.*)",$'


  def filter(event)

@semaphore.synchronize {


    #If decrypt or encrypt fails, we keep it it intact.
    begin



      my_source = event.get(@source)
      parsed = LogStash::Json.load(my_source)

      # puts "Let's talk about #{parsed}.\n"
      # puts "field to crypt #{@field_to_crypt}\n"


      visit_json(event,nil, parsed)

    end
  }
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

    if !@iv.nil? and !@iv.empty? and @iv_random_length.nil?
      @cipher.iv = @iv if @iv

    elsif !@iv_random_length.nil?
      @logger.debug("iv_random_length is configured, ignoring any statically defined value for 'iv'", :iv_random_length => @iv_random_length)
    else
      raise "cipher plugin: either 'iv' or 'iv_random_length' must be configured, but not both; aborting"
    end

    @cipher.padding = @cipher_padding if @cipher_padding

    @logger.debug("Cipher initialisation done", :mode => @mode, :key => @key, :iv => @iv, :iv_random => @iv_random, :cipher_padding => @cipher_padding)
  end # def init_cipher

end # class LogStash::Filters::Cipher
