# Changelog

## 0.2.1

- Add License badge to README
- Add bug_tracker_uri to gemspec

All notable changes to this gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-03-13

### Added
- `Verifier#verify_header!` — parses and verifies header strings, raises `VerificationError` on failure
- `Verifier#valid?` — boolean wrapper around `verify!` (returns true/false, never raises)
- `Verifier#valid_header?` — boolean wrapper around `verify_header!` (returns true/false, never raises)

## [0.1.0] - 2026-03-10

### Added
- Initial release
- HMAC-SHA256 payload signing with timestamps
- Signature verification with constant-time comparison
- Replay prevention with configurable tolerance window
- Header format support (`t=TIMESTAMP,v1=SIGNATURE`)
- Convenience class methods and OO API
