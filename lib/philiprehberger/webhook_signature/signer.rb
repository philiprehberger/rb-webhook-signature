# frozen_string_literal: true

require 'openssl'
require 'time'

module Philiprehberger
  module WebhookSignature
    # Signs payloads with HMAC and a timestamp for replay prevention.
    class Signer
      SUPPORTED_ALGORITHMS = {
        sha256: 'SHA256',
        sha512: 'SHA512'
      }.freeze

      # @param secret [String] the shared secret key
      # @param algorithm [Symbol] HMAC digest algorithm (:sha256 or :sha512)
      def initialize(secret, algorithm: :sha256)
        raise ArgumentError, 'Secret must be a non-empty string' if secret.nil? || secret.empty?

        unless SUPPORTED_ALGORITHMS.key?(algorithm)
          raise ArgumentError,
                "Unsupported algorithm: #{algorithm.inspect}. Supported algorithms: #{SUPPORTED_ALGORITHMS.keys.map(&:inspect).join(', ')}"
        end

        @secret = secret
        @algorithm = algorithm
        @digest_name = SUPPORTED_ALGORITHMS.fetch(algorithm)
      end

      # Sign a payload.
      #
      # @param payload [String] the raw payload body
      # @param timestamp [Integer] Unix timestamp (default: current time)
      # @return [Hash] signature components { timestamp:, signature: }
      def sign(payload, timestamp: Time.now.to_i)
        signature = compute_signature(payload, timestamp)
        { timestamp: timestamp, signature: signature }
      end

      # Build a signature header value.
      #
      # @param payload [String] the raw payload body
      # @param timestamp [Integer] Unix timestamp (default: current time)
      # @return [String] header value in "t=TIMESTAMP,v1=SIGNATURE" format
      def sign_header(payload, timestamp: Time.now.to_i)
        signature = compute_signature(payload, timestamp)
        "t=#{timestamp},v1=#{signature}"
      end

      private

      def compute_signature(payload, timestamp)
        message = "#{timestamp}.#{payload}"
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new(@digest_name), @secret, message)
      end
    end
  end
end
