# philiprehberger-webhook_signature

[![Tests](https://github.com/philiprehberger/rb-webhook-signature/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-webhook-signature/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-webhook_signature.svg)](https://rubygems.org/gems/philiprehberger-webhook_signature)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rb-webhook-signature)](https://github.com/philiprehberger/rb-webhook-signature/commits/main)

HMAC-SHA256 webhook signing and verification with replay prevention

## Requirements

- Ruby >= 3.1

## Installation

Add to your Gemfile:

```ruby
gem "philiprehberger-webhook_signature"
```

Or install directly:

```bash
gem install philiprehberger-webhook_signature
```

## Usage

### Signing (sender side)

```ruby
require "philiprehberger/webhook_signature"

secret = "whsec_your_secret_key"
payload = '{"event":"order.created","data":{"id":123}}'

# Quick sign
result = Philiprehberger::WebhookSignature.sign(payload, secret: secret)
# => { timestamp: 1710000000, signature: "a1b2c3..." }

# Or use a Signer instance
signer = Philiprehberger::WebhookSignature::Signer.new(secret)
header = signer.sign_header(payload)
# => "t=1710000000,v1=a1b2c3..."
```

### Verification (receiver side)

```ruby
secret = "whsec_your_secret_key"

# Quick verify
valid = Philiprehberger::WebhookSignature.verify(
  payload,
  secret: secret,
  timestamp: params[:timestamp],
  signature: params[:signature]
)

# Or use a Verifier instance
verifier = Philiprehberger::WebhookSignature::Verifier.new(secret)

# Verify from components
verifier.verify(payload, timestamp: ts, signature: sig)

# Verify from header string
verifier.verify_header(payload, header: "t=1710000000,v1=a1b2c3...")

# Verify and raise on failure
verifier.verify!(payload, timestamp: ts, signature: sig)
# raises VerificationError on failure

# Verify header and raise on failure
verifier.verify_header!(payload, header: "t=1710000000,v1=a1b2c3...")
# raises VerificationError on failure

# Boolean helpers (return true/false, never raise)
verifier.valid?(payload, timestamp: ts, signature: sig)
verifier.valid_header?(payload, header: "t=1710000000,v1=a1b2c3...")
```

### Choosing an HMAC Algorithm

```ruby
# Default is :sha256 — existing code is unaffected
signer = Philiprehberger::WebhookSignature::Signer.new(secret)

# Opt in to SHA-512 for a longer digest
signer = Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :sha512)
verifier = Philiprehberger::WebhookSignature::Verifier.new(secret, algorithm: :sha512)

# Or via the module-level helpers
Philiprehberger::WebhookSignature.sign(payload, secret: secret, algorithm: :sha512)
Philiprehberger::WebhookSignature.verify(
  payload, secret: secret, timestamp: ts, signature: sig, algorithm: :sha512
)

# Unsupported values raise ArgumentError listing the supported symbols
Philiprehberger::WebhookSignature::Signer.new(secret, algorithm: :md5)
# => ArgumentError: Unsupported algorithm: :md5. Supported algorithms: :sha256, :sha512
```

### Replay Prevention

```ruby
verifier = Philiprehberger::WebhookSignature::Verifier.new(secret)

# Default: 300 seconds (5 minutes) tolerance
verifier.verify(payload, timestamp: old_ts, signature: sig)
# => false (if timestamp is too old)

# Custom tolerance
verifier.verify(payload, timestamp: ts, signature: sig, tolerance: 600)

# Disable replay check
verifier.verify(payload, timestamp: ts, signature: sig, tolerance: nil)
```

## API

| Method / Class | Description |
|----------------|-------------|
| `WebhookSignature.sign(payload, secret:, timestamp:, algorithm:)` | Sign a payload |
| `WebhookSignature.verify(payload, secret:, timestamp:, signature:, tolerance:, algorithm:)` | Verify a payload |
| `Signer.new(secret, algorithm:)` | Create a signer (algorithm defaults to `:sha256`; `:sha512` also supported) |
| `Signer#sign(payload, timestamp:)` | Sign, returns hash |
| `Signer#sign_header(payload, timestamp:)` | Sign, returns header string |
| `Verifier.new(secret, algorithm:)` | Create a verifier (algorithm defaults to `:sha256`; `:sha512` also supported) |
| `Verifier#verify(payload, timestamp:, signature:, tolerance:)` | Verify, returns boolean |
| `Verifier#verify_header(payload, header:, tolerance:)` | Verify a header string |
| `Verifier#verify!(payload, timestamp:, signature:, tolerance:)` | Verify or raise |
| `Verifier#verify_header!(payload, header:, tolerance:)` | Verify a header string or raise |
| `Verifier#valid?(payload, timestamp:, signature:, tolerance:)` | Boolean verify (never raises) |
| `Verifier#valid_header?(payload, header:, tolerance:)` | Boolean header verify (never raises) |

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/rb-webhook-signature)

🐛 [Report issues](https://github.com/philiprehberger/rb-webhook-signature/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/rb-webhook-signature/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
