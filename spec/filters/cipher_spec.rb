# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require 'logstash/filters/cipher'

describe LogStash::Filters::Cipher do

  let(:cleartext) do
    'شسيبشن٤٤ت٥ت داھدساققبمر фывапролдзщшгнекутцйячсмить asdfghjklqpoiuztreyxcvbnm,.-öäü+ä123ß´yö.,;LÖÜ*O 來少精清皆人址法田手扌打表氵開日大木裝 1234567890#$%^&*()!@#;:\'?.>,<testAESEn+=_-~`}]'
  end

  let(:pipeline) { LogStash::Pipeline.new(config) }

  let(:events) do
    arr = event.is_a?(Array) ? event : [event]
    arr.map do |evt|
      LogStash::Event.new(evt.is_a?(String) ? LogStash::Json.load(evt) : evt)
    end
  end

  let(:results) do
    pipeline.instance_eval { @filters.each(&:register) }
    results  = []
    events.each do |evt|
      # filter call the block on all filtered events, included new events added by the filter
      pipeline.filter(evt) do |filtered_event|
        results.push(filtered_event)
      end
    end
    pipeline.flush_filters(:final => true) { |flushed_event| results << flushed_event }

    results.select { |e| !e.cancelled? }
  end

  describe 'encrypt aes-256-cbc, 16b random IV, 32b key, b64 encode' do

    let(:event) do
      "{\"message\":\"#{cleartext}\"}"
    end

    let(:config) do
      <<-CONFIG
filter {

    cipher {
        algorithm => "aes-256-cbc"
        cipher_padding => 1
        iv_random_length => 16
        key => "12345678901234567890123456789012"
        key_size => 32
        mode => "encrypt"
        source => "message"
        target => "message_crypted"
        base64 => true
        max_cipher_reuse => 1
    }

    cipher {
        algorithm => "aes-256-cbc"
        cipher_padding => 1
        iv_random_length => 16
        key => "12345678901234567890123456789012"
        key_size => 32
        mode => "decrypt"
        source => "message_crypted"
        target => "message_decrypted"
        base64 => true
        max_cipher_reuse => 1
    }
}
CONFIG
    end

    it 'validate initial cleartext message' do
      result = results.first
      expect(result["message"]).to eq(cleartext)
    end

    it 'validate decrypted message' do
      result = results.first
      expect(result["message_decrypted"]).to eq(result["message"])
    end

    it 'validate encrypted message is not equal to message' do
      result = results.first
      expect(result["message"]).not_to eq(result["message_crypted"])
    end

  end

end

