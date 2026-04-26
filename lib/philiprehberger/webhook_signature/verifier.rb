# frozen_string_literal: true

require 'openssl'

module Philiprehberger
  module WebhookSignature
    # Verifies HMAC webhook signatures with replay prevention.
    class Verifier
      DEFAULT_TOLERANCE = 300 # 5 minutes

      SUPPORTED_ALGORITHMS = {
        sha256: 'SHA256',
        sha512: 'SHA512'
      }.freeze

      # @param secret [String, nil] the shared secret key (single-secret form)
      # @param algorithm [Symbol] HMAC digest algorithm (:sha256 or :sha512)
      # @param secrets [Array<String>, nil] an Array of shared secrets to support key rotation
      def initialize(secret = nil, algorithm: :sha256, secrets: nil)
        if !secret.nil? && !secrets.nil?
          raise ArgumentError, 'Provide either secret: or secrets:, not both'
        end

        resolved = if secrets.nil?
                     raise ArgumentError, 'Secret must be a non-empty string' if secret.nil? || secret.empty?

                     [secret]
                   else
                     unless secrets.is_a?(Array) && !secrets.empty?
                       raise ArgumentError, 'secrets must be a non-empty Array of strings'
                     end
                     if secrets.any? { |s| s.nil? || s.empty? }
                       raise ArgumentError, 'Each secret must be a non-empty string'
                     end

                     secrets
                   end

        unless SUPPORTED_ALGORITHMS.key?(algorithm)
          raise ArgumentError,
                "Unsupported algorithm: #{algorithm.inspect}. Supported algorithms: #{SUPPORTED_ALGORITHMS.keys.map(&:inspect).join(', ')}"
        end

        @secrets = resolved
        @algorithm = algorithm
        @digest_name = SUPPORTED_ALGORITHMS.fetch(algorithm)
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

        @secrets.any? { |s| signature_matches?(payload, timestamp, signature, s) }
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

        unless @secrets.any? { |s| signature_matches?(payload, timestamp, signature, s) }
          raise VerificationError, 'Signature mismatch'
        end

        true
      end

      # Verify a header string or raise on failure.
      #
      # @param payload [String] the raw payload body
      # @param header [String] the header value in "t=TIMESTAMP,v1=SIGNATURE" format
      # @param tolerance [Integer, nil] max age in seconds
      # @raise [VerificationError] if verification fails
      # @return [true]
      def verify_header!(payload, header:, tolerance: DEFAULT_TOLERANCE)
        parsed = parse_header(header)
        raise VerificationError, 'Invalid header format' unless parsed

        verify!(payload, timestamp: parsed[:timestamp], signature: parsed[:signature], tolerance: tolerance)
      end

      # Boolean wrapper around verify!.
      #
      # @param (see #verify)
      # @return [Boolean]
      def valid?(payload, timestamp:, signature:, tolerance: DEFAULT_TOLERANCE)
        verify!(payload, timestamp: timestamp, signature: signature, tolerance: tolerance)
      rescue VerificationError
        false
      end

      # Boolean wrapper around verify_header!.
      #
      # @param payload [String] the raw payload body
      # @param header [String] the header value in "t=TIMESTAMP,v1=SIGNATURE" format
      # @param tolerance [Integer, nil] max age in seconds
      # @return [Boolean]
      def valid_header?(payload, header:, tolerance: DEFAULT_TOLERANCE)
        verify_header!(payload, header: header, tolerance: tolerance)
      rescue VerificationError
        false
      end

      private

      def signature_matches?(payload, timestamp, signature, secret)
        expected = compute_signature(payload, timestamp, secret)
        secure_compare(expected, signature)
      end

      def compute_signature(payload, timestamp, secret)
        message = "#{timestamp}.#{payload}"
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new(@digest_name), secret, message)
      end

      def stale?(timestamp, tolerance)
        (Time.now.to_i - timestamp).abs > tolerance
      end

      def secure_compare(expected, actual)
        return false unless expected.bytesize == actual.bytesize

        OpenSSL.fixed_length_secure_compare(expected, actual)
      end

      def parse_header(header)
        parts = {}
        header.split(',').each do |part|
          key, value = part.split('=', 2)
          next unless value

          parts[key] = value
        end

        timestamp = parts['t']&.to_i
        signature = parts['v1']

        return nil unless timestamp && signature

        { timestamp: timestamp, signature: signature }
      end
    end
  end
end
