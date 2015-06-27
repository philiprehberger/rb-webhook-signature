# frozen_string_literal: true

require_relative "lib/philiprehberger/webhook_signature/version"

Gem::Specification.new do |spec|
  spec.name = "philiprehberger-webhook_signature"
  spec.version = Philiprehberger::WebhookSignature::VERSION
  spec.authors = ["Philip Rehberger"]
  spec.email = ["me@philiprehberger.com"]

  spec.summary = "HMAC-SHA256 webhook signing and verification with replay prevention"
  spec.description = "Sign and verify webhook payloads using HMAC-SHA256 with timestamp-based " \
                     "replay prevention. Provides both object-oriented and convenience APIs."
  spec.homepage = "https://github.com/philiprehberger/rb-webhook-signature"
  spec.license = "MIT"

  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir["lib/**/*.rb", "LICENSE", "README.md", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
end
