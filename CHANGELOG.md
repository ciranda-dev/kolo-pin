# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Breaking: a pinning peer serves an add only when the key the connection proved is the capability's owner. A requester
  with another key, even with a valid capability, now gets `ErrUnauthorized`, before the capability's expiry or
  revocation is checked. Add with the owner's identity.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-pin.
