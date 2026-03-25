# philiprehberger-webhook_signature

[![Tests](https://github.com/philiprehberger/rb-webhook-signature/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rb-webhook-signature/actions/workflows/ci.yml)
[![Gem Version](https://badge.fury.io/rb/philiprehberger-webhook_signature.svg)](https://rubygems.org/gems/philiprehberger-webhook_signature)
[![License](https://img.shields.io/github/license/philiprehberger/rb-webhook-signature)](LICENSE)

HMAC-SHA256 webhook signing and verification with replay prevention for Ruby.

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
| `WebhookSignature.sign(payload, secret:, timestamp:)` | Sign a payload |
| `WebhookSignature.verify(payload, secret:, timestamp:, signature:, tolerance:)` | Verify a payload |
| `Signer.new(secret)` | Create a signer |
| `Signer#sign(payload, timestamp:)` | Sign, returns hash |
| `Signer#sign_header(payload, timestamp:)` | Sign, returns header string |
| `Verifier.new(secret)` | Create a verifier |
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

## License

MIT
