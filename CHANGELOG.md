# Changelog

All notable changes to this gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-10

### Added
- Initial release
- HMAC-SHA256 payload signing with timestamps
- Signature verification with constant-time comparison
- Replay prevention with configurable tolerance window
- Header format support (`t=TIMESTAMP,v1=SIGNATURE`)
- Convenience class methods and OO API
