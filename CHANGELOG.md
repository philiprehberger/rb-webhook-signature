# Changelog

All notable changes to this gem will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.7] - 2026-03-31

### Changed
- Standardize README badges, support section, and license format

## [0.2.6] - 2026-03-26

### Changed

- Add Sponsor badge and fix License link format in README

## [0.2.5] - 2026-03-24

### Fixed
- Fix README one-liner to remove trailing period and match gemspec summary

## [0.2.4] - 2026-03-24

### Fixed
- Remove inline comments from Development section to match template

## [0.2.3] - 2026-03-22

### Changed
- Expand test coverage with tolerance windows, tampered signatures, header edge cases, and error paths

## [0.2.2] - 2026-03-22

### Changed
- Update rubocop configuration for Windows compatibility

## [0.2.2] - 2026-03-21

### Fixed
- Standardize Installation section in README

## [0.2.1] - 2026-03-16

### Added
- Add License badge to README
- Add bug_tracker_uri to gemspec

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
