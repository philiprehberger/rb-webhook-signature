# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Philiprehberger::WebhookSignature do
  let(:secret) { 'test_secret_key_12345' }
  let(:payload) { '{"event":"test","data":{"id":1}}' }
  let(:timestamp) { 1_710_000_000 }

  it 'has a version number' do
    expect(Philiprehberger::WebhookSignature::VERSION).not_to be_nil
  end

  describe '.sign and .verify' do
    it 'signs and verifies a payload' do
      result = described_class.sign(payload, secret: secret, timestamp: timestamp)

      valid = described_class.verify(
        payload,
        secret: secret,
        timestamp: result[:timestamp],
        signature: result[:signature],
        tolerance: nil
      )

      expect(valid).to be true
    end

    it 'rejects a tampered payload' do
      result = described_class.sign(payload, secret: secret, timestamp: timestamp)

      valid = described_class.verify(
        'tampered',
        secret: secret,
        timestamp: result[:timestamp],
        signature: result[:signature],
        tolerance: nil
      )

      expect(valid).to be false
    end

    it 'rejects a wrong secret' do
      result = described_class.sign(payload, secret: secret, timestamp: timestamp)

      valid = described_class.verify(
        payload,
        secret: 'wrong_secret',
        timestamp: result[:timestamp],
        signature: result[:signature],
        tolerance: nil
      )

      expect(valid).to be false
    end
  end
end

RSpec.describe Philiprehberger::WebhookSignature::Signer do
  let(:secret) { 'test_secret' }
  let(:signer) { described_class.new(secret) }
  let(:payload) { 'test payload' }
  let(:timestamp) { 1_710_000_000 }

  it 'raises on empty secret' do
    expect { described_class.new('') }.to raise_error(ArgumentError)
    expect { described_class.new(nil) }.to raise_error(ArgumentError)
  end

  describe '#sign' do
    it 'returns timestamp and signature' do
      result = signer.sign(payload, timestamp: timestamp)
      expect(result[:timestamp]).to eq(timestamp)
      expect(result[:signature]).to be_a(String)
      expect(result[:signature].length).to eq(64) # SHA256 hex digest
    end

    it 'produces deterministic signatures' do
      sig1 = signer.sign(payload, timestamp: timestamp)[:signature]
      sig2 = signer.sign(payload, timestamp: timestamp)[:signature]
      expect(sig1).to eq(sig2)
    end

    it 'produces different signatures for different timestamps' do
      sig1 = signer.sign(payload, timestamp: 1000)[:signature]
      sig2 = signer.sign(payload, timestamp: 2000)[:signature]
      expect(sig1).not_to eq(sig2)
    end
  end

  describe '#sign_header' do
    it 'returns a formatted header string' do
      header = signer.sign_header(payload, timestamp: timestamp)
      expect(header).to match(/\At=\d+,v1=[a-f0-9]{64}\z/)
    end
  end
end

RSpec.describe Philiprehberger::WebhookSignature::Verifier do
  let(:secret) { 'test_secret' }
  let(:signer) { Philiprehberger::WebhookSignature::Signer.new(secret) }
  let(:verifier) { described_class.new(secret) }
  let(:payload) { 'test payload' }

  it 'raises on empty secret' do
    expect { described_class.new('') }.to raise_error(ArgumentError)
  end

  describe '#verify' do
    it 'returns true for valid signatures' do
      result = signer.sign(payload, timestamp: Time.now.to_i)
      expect(verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature])).to be true
    end

    it 'returns false for invalid signatures' do
      expect(verifier.verify(payload, timestamp: Time.now.to_i, signature: 'invalid')).to be false
    end

    it 'returns false for stale timestamps' do
      old_time = Time.now.to_i - 600
      result = signer.sign(payload, timestamp: old_time)
      expect(verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature],
                                      tolerance: 300)).to be false
    end

    it 'skips replay check when tolerance is nil' do
      old_time = Time.now.to_i - 99_999
      result = signer.sign(payload, timestamp: old_time)
      expect(verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature],
                                      tolerance: nil)).to be true
    end
  end

  describe '#verify_header' do
    it 'verifies a valid header' do
      header = signer.sign_header(payload, timestamp: Time.now.to_i)
      expect(verifier.verify_header(payload, header: header)).to be true
    end

    it 'rejects an invalid header' do
      expect(verifier.verify_header(payload, header: 't=0,v1=invalid')).to be false
    end

    it 'rejects a malformed header' do
      expect(verifier.verify_header(payload, header: 'garbage')).to be false
    end
  end

  describe '#verify_header!' do
    it 'returns true for a valid header' do
      header = signer.sign_header(payload, timestamp: Time.now.to_i)
      expect(verifier.verify_header!(payload, header: header)).to be true
    end

    it 'raises VerificationError for an invalid header signature' do
      expect do
        verifier.verify_header!(payload, header: "t=#{Time.now.to_i},v1=invalid")
      end.to raise_error(Philiprehberger::WebhookSignature::VerificationError, /mismatch/)
    end

    it 'raises VerificationError for a malformed header' do
      expect do
        verifier.verify_header!(payload, header: 'garbage')
      end.to raise_error(Philiprehberger::WebhookSignature::VerificationError, /Invalid header format/)
    end
  end

  describe '#valid?' do
    it 'returns true for valid signatures' do
      result = signer.sign(payload, timestamp: Time.now.to_i)
      expect(verifier.valid?(payload, timestamp: result[:timestamp], signature: result[:signature])).to be true
    end

    it 'returns false for invalid signatures' do
      expect(verifier.valid?(payload, timestamp: Time.now.to_i, signature: 'invalid')).to be false
    end

    it 'returns false for stale timestamps' do
      old_time = Time.now.to_i - 600
      result = signer.sign(payload, timestamp: old_time)
      expect(verifier.valid?(payload, timestamp: result[:timestamp], signature: result[:signature],
                                      tolerance: 300)).to be false
    end
  end

  describe '#valid_header?' do
    it 'returns true for a valid header' do
      header = signer.sign_header(payload, timestamp: Time.now.to_i)
      expect(verifier.valid_header?(payload, header: header)).to be true
    end

    it 'returns false for an invalid header' do
      expect(verifier.valid_header?(payload, header: 't=0,v1=invalid')).to be false
    end

    it 'returns false for a malformed header' do
      expect(verifier.valid_header?(payload, header: 'garbage')).to be false
    end
  end

  describe '#verify!' do
    it 'returns true for valid signatures' do
      result = signer.sign(payload, timestamp: Time.now.to_i)
      expect(verifier.verify!(payload, timestamp: result[:timestamp], signature: result[:signature])).to be true
    end

    it 'raises VerificationError for invalid signatures' do
      expect do
        verifier.verify!(payload, timestamp: Time.now.to_i, signature: 'invalid')
      end.to raise_error(Philiprehberger::WebhookSignature::VerificationError, /mismatch/)
    end

    it 'raises VerificationError for stale timestamps' do
      old_time = Time.now.to_i - 600
      result = signer.sign(payload, timestamp: old_time)
      expect do
        verifier.verify!(payload, timestamp: result[:timestamp], signature: result[:signature])
      end.to raise_error(Philiprehberger::WebhookSignature::VerificationError, /too old/)
    end
  end

  describe '#verify with empty payload' do
    it 'signs and verifies an empty payload' do
      result = signer.sign('', timestamp: Time.now.to_i)
      expect(verifier.verify('', timestamp: result[:timestamp], signature: result[:signature])).to be true
    end
  end

  describe '#verify with different tolerance windows' do
    it 'accepts signature within custom tolerance' do
      ts = Time.now.to_i - 50
      result = signer.sign(payload, timestamp: ts)
      expect(verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature],
                                      tolerance: 60)).to be true
    end

    it 'rejects signature outside custom tolerance' do
      ts = Time.now.to_i - 120
      result = signer.sign(payload, timestamp: ts)
      expect(verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature],
                                      tolerance: 60)).to be false
    end

    it 'accepts with tolerance of 1 second when timestamp is current' do
      ts = Time.now.to_i
      result = signer.sign(payload, timestamp: ts)
      expect(verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature],
                                      tolerance: 1)).to be true
    end
  end

  describe '#verify with tampered signature' do
    it 'rejects a signature with one character changed' do
      result = signer.sign(payload, timestamp: Time.now.to_i)
      tampered = result[:signature].chars
      tampered[0] = tampered[0] == 'a' ? 'b' : 'a'
      expect(verifier.verify(payload, timestamp: result[:timestamp], signature: tampered.join)).to be false
    end

    it 'rejects a truncated signature' do
      result = signer.sign(payload, timestamp: Time.now.to_i)
      truncated = result[:signature][0..31]
      expect(verifier.verify(payload, timestamp: result[:timestamp], signature: truncated)).to be false
    end
  end

  describe '#verify with different secrets' do
    it 'fails verification when verifier uses different secret' do
      other_verifier = described_class.new('different_secret')
      result = signer.sign(payload, timestamp: Time.now.to_i)
      expect(other_verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature],
                                            tolerance: nil)).to be false
    end
  end

  describe '#verify_header with extra fields' do
    it 'handles header with extra key-value pairs' do
      header = signer.sign_header(payload, timestamp: Time.now.to_i)
      header_with_extra = "#{header},extra=value"
      expect(verifier.verify_header(payload, header: header_with_extra)).to be true
    end
  end

  describe '#verify_header with missing parts' do
    it 'returns false when timestamp is missing' do
      expect(verifier.verify_header(payload, header: 'v1=abc123')).to be false
    end

    it 'returns false when signature is missing' do
      expect(verifier.verify_header(payload, header: 't=12345')).to be false
    end

    it 'returns false for empty header' do
      expect(verifier.verify_header(payload, header: '')).to be false
    end
  end

  describe 'with multiple secrets' do
    let(:first_secret) { 'new_secret_v2' }
    let(:second_secret) { 'old_secret_v1' }
    let(:rotation_verifier) { described_class.new(secrets: [first_secret, second_secret]) }

    it 'verifies a signature created with the first secret' do
      result = Philiprehberger::WebhookSignature::Signer.new(first_secret)
                                                        .sign(payload, timestamp: Time.now.to_i)
      expect(
        rotation_verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature])
      ).to be true
    end

    it 'verifies a signature created with the second secret (key rotation case)' do
      result = Philiprehberger::WebhookSignature::Signer.new(second_secret)
                                                        .sign(payload, timestamp: Time.now.to_i)
      expect(
        rotation_verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature])
      ).to be true
    end

    it 'rejects a signature created with an unrelated secret' do
      result = Philiprehberger::WebhookSignature::Signer.new('unrelated_secret')
                                                        .sign(payload, timestamp: Time.now.to_i)
      expect(
        rotation_verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature])
      ).to be false
    end

    it 'raises ArgumentError when both secret: and secrets: are provided' do
      expect do
        described_class.new('a', secrets: %w[b c])
      end.to raise_error(ArgumentError, /both/)
    end

    it 'raises ArgumentError when neither secret: nor secrets: is provided' do
      expect { described_class.new }.to raise_error(ArgumentError)
    end
  end
end

RSpec.describe 'Algorithm selection' do
  let(:secret) { 'test_secret' }
  let(:payload) { 'hello payload' }
  let(:timestamp) { 1_710_000_000 }

  describe 'default algorithm (:sha256)' do
    it 'produces a 64-char hex signature unchanged from prior releases' do
      signer = Philiprehberger::WebhookSignature::Signer.new(secret)
      result = signer.sign(payload, timestamp: timestamp)
      expect(result[:signature].length).to eq(64)
    end

    it 'matches the explicit :sha256 signer byte-for-byte' do
      default_sig = Philiprehberger::WebhookSignature::Signer.new(secret)
                                                             .sign(payload, timestamp: timestamp)[:signature]
      explicit_sig = Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :sha256)
                                                              .sign(payload, timestamp: timestamp)[:signature]
      expect(default_sig).to eq(explicit_sig)
    end
  end

  describe ':sha512 round-trip' do
    it 'produces a 128-char hex signature and verifies successfully' do
      signer = Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :sha512)
      verifier = Philiprehberger::WebhookSignature::Verifier.new(secret, algorithm: :sha512)

      result = signer.sign(payload, timestamp: timestamp)
      expect(result[:signature].length).to eq(128)
      expect(
        verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature], tolerance: nil)
      ).to be true
    end

    it 'round-trips through module-level helpers' do
      result = Philiprehberger::WebhookSignature.sign(
        payload, secret: secret, timestamp: timestamp, algorithm: :sha512
      )
      valid = Philiprehberger::WebhookSignature.verify(
        payload,
        secret: secret,
        timestamp: result[:timestamp],
        signature: result[:signature],
        tolerance: nil,
        algorithm: :sha512
      )
      expect(valid).to be true
    end
  end

  describe 'cross-algorithm rejection' do
    it 'rejects a :sha512 signature when verifier is :sha256' do
      signer = Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :sha512)
      verifier = Philiprehberger::WebhookSignature::Verifier.new(secret, algorithm: :sha256)

      result = signer.sign(payload, timestamp: timestamp)
      expect(
        verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature], tolerance: nil)
      ).to be false
    end

    it 'rejects a :sha256 signature when verifier is :sha512' do
      signer = Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :sha256)
      verifier = Philiprehberger::WebhookSignature::Verifier.new(secret, algorithm: :sha512)

      result = signer.sign(payload, timestamp: timestamp)
      expect(
        verifier.verify(payload, timestamp: result[:timestamp], signature: result[:signature], tolerance: nil)
      ).to be false
    end

    it 'produces different digest bytes across algorithms' do
      sha256 = Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :sha256)
                                                        .sign(payload, timestamp: timestamp)[:signature]
      sha512 = Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :sha512)
                                                        .sign(payload, timestamp: timestamp)[:signature]
      expect(sha256).not_to eq(sha512)
      expect(sha256.length).not_to eq(sha512.length)
    end
  end

  describe 'invalid algorithm' do
    it 'raises ArgumentError from Signer' do
      expect do
        Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :md5)
      end.to raise_error(ArgumentError, /Unsupported algorithm.*sha256.*sha512/m)
    end

    it 'raises ArgumentError from Verifier' do
      expect do
        Philiprehberger::WebhookSignature::Verifier.new(secret, algorithm: :sha1)
      end.to raise_error(ArgumentError, /Unsupported algorithm.*sha256.*sha512/m)
    end

    it 'raises ArgumentError from module-level sign' do
      expect do
        Philiprehberger::WebhookSignature.sign(payload, secret: secret, algorithm: :bogus)
      end.to raise_error(ArgumentError, /Unsupported algorithm/)
    end

    it 'raises ArgumentError from module-level verify' do
      expect do
        Philiprehberger::WebhookSignature.verify(
          payload, secret: secret, timestamp: timestamp, signature: 'x', algorithm: :bogus
        )
      end.to raise_error(ArgumentError, /Unsupported algorithm/)
    end
  end
end
