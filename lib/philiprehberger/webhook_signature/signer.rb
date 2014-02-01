# frozen_string_literal: true

require "openssl"
require "time"

module Philiprehberger
  module WebhookSignature
    # Signs payloads with HMAC-SHA256 and a timestamp for replay prevention.
    class Signer
      # @param secret [String] the shared secret key
      def initialize(secret)
        raise ArgumentError, "Secret must be a non-empty string" if secret.nil? || secret.empty?

        @secret = secret
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
        OpenSSL::HMAC.hexdigest("SHA256", @secret, message)
      end
    end
  end
end
