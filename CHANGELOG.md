# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

## [0.6.0] - 2026-07-31

### Added

- Added validated parameter and reconstruction-set APIs.
- Added owned DKG results and opaque, transport-aware protocol messages.
- Added serialization support for participant state, with explicit guidance for
  protecting secret key material.
- Added BLS12-381 support through the `bls12_381_plus` and `blstrs_plus`
  backends.

### Changed

- Upgraded to `vsss-rs` 6.0.1 and RustCrypto's elliptic-curve 0.14 APIs.
- Updated the supported group features to `bls12_381_plus`, `blstrs_plus`,
  `curve25519-dalek`, `ed448`, `k256`, `p256`, and `p384`.
- Raised the minimum supported Rust version to 1.87 and adopted Rust edition
  2024.
- Strengthened protocol input validation and transcript handling.

### Removed

- Removed the `bls`, `curve25519`, and `jubjub` features and their legacy
  backends.
