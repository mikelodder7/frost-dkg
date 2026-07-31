# FROST DKG

This crate implements the FROST Distributed Key Generation (DKG) protocol
described in the [FROST paper](https://eprint.iacr.org/2020/852.pdf).

The protocol is a variant of
[Pedersen verifiable secret sharing](https://link.springer.com/content/pdf/10.1007%2F3-540-46766-1_9.pdf)
that also requires each participant to prove knowledge of its secret with a
Schnorr proof, mitigating rogue-key attacks.

The crate can publicly verify a DKG result using only the round 1 broadcast
information and the DKG parameters.

## Supported groups

All supported group features are enabled by default:

- BLS12-381 through `bls12_381_plus` or `blstrs_plus`
- Curve25519 through `curve25519-dalek`
- Ed448 through `ed448`
- secp256k1 through `k256`
- NIST P-256 through `p256`
- NIST P-384 through `p384`

Default features can be disabled to select only the required group backends.

## Security notes

This implementation has never been independently audited. Use it at your own
risk.

Serialized participant state contains plaintext secret key material. Store or
transport it only with authenticated encryption or an equivalently protected
mechanism, and do not deserialize unauthenticated participant state.

## Minimum supported Rust version

This crate requires Rust **1.87** or newer.

The minimum supported Rust version may change in a future minor release.

## License

Licensed under either of the following, at your option:

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](https://opensource.org/licenses/MIT)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work, as defined in the Apache-2.0 license, is
dual-licensed as described above, without any additional terms or conditions.
