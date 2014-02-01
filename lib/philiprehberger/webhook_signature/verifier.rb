# frozen_string_literal: true

require "openssl"

module Philiprehberger
  module WebhookSignature
    # Verifies HMAC-SHA256 webhook signatures with replay prevention.
    class Verifier
      DEFAULT_TOLERANCE = 300 # 5 minutes

      # @param secret [String] the shared secret key
      def initialize(secret)
        raise ArgumentError, "Secret must be a non-empty string" if secret.nil? || secret.empty?

        @secret = secret
      end

      # Verify a payload against a signature.
      #
      # @param payload [String] the raw payload body
      # @param timestamp [Integer] the timestamp from the signature
      # @param signature [String] the hex-encoded HMAC signature
      # @param tolerance [Integer, nil] max age in seconds (nil to skip replay check)
      # @return [Boolean] true if valid
      def verify(payload, timestamp:, signature:, tolerance: DEFAULT_TOLERANCE)
        return false if tolerance && stale?(timestamp, tolerance)

        expected = compute_signature(payload, timestamp)
        secure_compare(expected, signature)
      end

      # Verify a signature header string.
      #
      # @param payload [String] the raw payload body
      # @param header [String] the header value in "t=TIMESTAMP,v1=SIGNATURE" format
      # @param tolerance [Integer, nil] max age in seconds
      # @return [Boolean] true if valid
      def verify_header(payload, header:, tolerance: DEFAULT_TOLERANCE)
        parsed = parse_header(header)
        return false unless parsed

        verify(payload, timestamp: parsed[:timestamp], signature: parsed[:signature], tolerance: tolerance)
      end

      # Verify and raise on failure.
      #
      # @param (see #verify)
      # @raise [VerificationError] if verification fails
      # @return [true]
      def verify!(payload, timestamp:, signature:, tolerance: DEFAULT_TOLERANCE)
        if tolerance && stale?(timestamp, tolerance)
          raise VerificationError, "Signature timestamp is too old (tolerance: #{tolerance}s)"
        end

        expected = compute_signature(payload, timestamp)
        raise VerificationError, "Signature mismatch" unless secure_compare(expected, signature)

        true
      end

      private

      def compute_signature(payload, timestamp)
        message = "#{timestamp}.#{payload}"
        OpenSSL::HMAC.hexdigest("SHA256", @secret, message)
      end

      def stale?(timestamp, tolerance)
        (Time.now.to_i - timestamp).abs > tolerance
      end

      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        OpenSSL.fixed_length_secure_compare(a, b)
      end

      def parse_header(header)
        parts = header.split(",").to_h { |part| part.split("=", 2) }
        timestamp = parts["t"]&.to_i
        signature = parts["v1"]

        return nil unless timestamp && signature

        { timestamp: timestamp, signature: signature }
      end
    end
  end
end
