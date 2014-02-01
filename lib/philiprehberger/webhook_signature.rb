# frozen_string_literal: true

require_relative "webhook_signature/version"
require_relative "webhook_signature/signer"
require_relative "webhook_signature/verifier"

module Philiprehberger
  module WebhookSignature
    class Error < StandardError; end

    # Raised when signature verification fails.
    class VerificationError < Error; end

    # Convenience: sign a payload.
    #
    # @param payload [String] the raw payload body
    # @param secret [String] the shared secret
    # @param timestamp [Integer] Unix timestamp
    # @return [Hash] { timestamp:, signature: }
    def self.sign(payload, secret:, timestamp: Time.now.to_i)
      Signer.new(secret).sign(payload, timestamp: timestamp)
    end

    # Convenience: verify a payload.
    #
    # @param payload [String] the raw payload body
    # @param secret [String] the shared secret
    # @param timestamp [Integer] the timestamp
    # @param signature [String] the signature
    # @param tolerance [Integer, nil] max age in seconds
    # @return [Boolean]
    def self.verify(payload, secret:, timestamp:, signature:, tolerance: 300)
      Verifier.new(secret).verify(payload, timestamp: timestamp, signature: signature, tolerance: tolerance)
    end
  end
end
