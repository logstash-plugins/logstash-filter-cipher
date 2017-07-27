# encoding: utf-8
require 'logstash-core'
require "logstash/codecs/base"
require 'logstash/filters/cipher'

describe LogStash::Filters::Cipher do

  let(:cleartext) do
    'شسيبشن٤٤ت٥ت داھدساققبمر фывапролдзщшгнекутцйячсмить asdfghjklqpoiuztreyxcvbnm,.-öäü+ä123ß´yö.,;LÖÜ*O 來少精清皆人址法田手扌打表氵開日大木裝 1234567890#$%^&*()!@#;:\'?.>,<testAESEn+=_-~`}]'
  end

  describe 'single event, encrypt/decrypt aes-128-cbc, 16b RANDOM IV, 16b key, b64 encode' do
    let(:event) do
      LogStash::Event.new(LogStash::Json.load("{\"message\":\"#{cleartext}\"}"))
    end

    let(:encrypter) do
      described_class.new(
        "algorithm" => "aes-128-cbc",
        "cipher_padding" => 1,
        "iv_random_length" => 16,
        "key" => "1234567890123456",
        "key_size" => 16,
        "mode" => "encrypt",
        "source" => "message",
        "target" => "message_crypted",
        "base64" => true,
        "max_cipher_reuse" => 1)
    end

    let(:decrypter) do
      described_class.new(
        "algorithm" => "aes-128-cbc",
        "cipher_padding" => 1,
        "iv_random_length" => 16,
        "key" => "1234567890123456",
        "key_size" => 16,
        "mode" => "decrypt",
        "source" => "message_crypted",
        "target" => "message_decrypted",
        "base64" => true,
        "max_cipher_reuse" => 1)
    end

    before(:each) do
      encrypter.register
      decrypter.register
    end

    let(:result) do
      encrypter.filter(event)
      decrypter.filter(event)
      event
    end

    it 'validate initial cleartext message' do
      expect(result.get("message")).to eq(cleartext)
    end

    it 'validate decrypted message' do
      expect(result.get("message_decrypted")).to eq(result.get("message"))
    end

    it 'validate encrypted message is not equal to message' do
      expect(result.get("message")).not_to eq(result.get("message_crypted"))
    end

  end

  describe '1000 events, 11 re-use, encrypt/decrypt aes-128-cbc, 16b RANDOM IV, 16b key, b64 encode' do

    total_events = 1000

    let(:events) do
      (1..total_events).map do |i|
        LogStash::Event.new(LogStash::Json.load("{\"message\":\"#{cleartext}\"}"))
      end
    end

    let(:encrypter) do
      described_class.new(
        "algorithm" => "aes-128-cbc",
        "cipher_padding" => 1,
        "iv_random_length" => 16,
        "key" => "1234567890123456",
        "key_size" => 16,
        "mode" => "encrypt",
        "source" => "message",
        "target" => "message_crypted",
        "base64" => true,
        "max_cipher_reuse" => 11)
    end

    let(:decrypter) do
      described_class.new(
        "algorithm" => "aes-128-cbc",
        "cipher_padding" => 1,
        "iv_random_length" => 16,
        "key" => "1234567890123456",
        "key_size" => 16,
        "mode" => "decrypt",
        "source" => "message_crypted",
        "target" => "message_decrypted",
        "base64" => true,
        "max_cipher_reuse" => 11)
    end

    before(:each) do
      encrypter.register
      decrypter.register
    end

    let(:results) do
      events.each do |e|
        encrypter.filter(e)
        decrypter.filter(e)
      end
      events
    end

    it 'validate total events' do
      expect(results.length).to eq(total_events)
    end

    it 'validate initial cleartext message' do
      results.each do |result|
        expect(result.get("message")).to eq(cleartext)
      end
    end

    it 'validate decrypted message' do
      results.each do |result|
        expect(result.get("message_decrypted")).to eq(result.get("message"))
      end
    end

    it 'validate encrypted message is not equal to message' do
      results.each do |result|
        expect(result.get("message")).not_to eq(result.get("message_crypted"))
      end
    end
  end
end
