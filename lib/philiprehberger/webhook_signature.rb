# frozen_string_literal: true

require_relative 'webhook_signature/version'
require_relative 'webhook_signature/signer'
require_relative 'webhook_signature/verifier'

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
    # @param algorithm [Symbol] HMAC digest algorithm (:sha256 or :sha512)
    # @return [Hash] { timestamp:, signature: }
    def self.sign(payload, secret:, timestamp: Time.now.to_i, algorithm: :sha256)
      Signer.new(secret, algorithm: algorithm).sign(payload, timestamp: timestamp)
    end

    # Convenience: verify a payload.
    #
    # @param payload [String] the raw payload body
    # @param secret [String, nil] the shared secret (single-secret form)
    # @param secrets [Array<String>, nil] an Array of shared secrets to support key rotation
    # @param timestamp [Integer] the timestamp
    # @param signature [String] the signature
    # @param tolerance [Integer, nil] max age in seconds
    # @param algorithm [Symbol] HMAC digest algorithm (:sha256 or :sha512)
    # @return [Boolean]
    def self.verify(payload, timestamp:, signature:, secret: nil, secrets: nil, tolerance: 300, algorithm: :sha256)
      raise ArgumentError, 'Provide either secret: or secrets:, not both' if !secret.nil? && !secrets.nil?
      raise ArgumentError, 'Must provide secret: or secrets:' if secret.nil? && secrets.nil?

      list = secrets.nil? ? [secret] : secrets
      Verifier.new(secrets: list, algorithm: algorithm)
              .verify(payload, timestamp: timestamp, signature: signature, tolerance: tolerance)
    end
  end
end
