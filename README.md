Frost-DKG
=========

The Frost Distributed Key Generation Algorithm as described [here](https://eprint.iacr.org/2020/852.pdf).

This protocol is a variant of [PedersenVSS](https://link.springer.com/content/pdf/10.1007%2F3-540-46766-1_9.pdf)
that also requires participants to prove their secret with a schnorr proof to mitigate rogue-key attacks.

# Security Notes
The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

# Minimum Supported Rust Version
This crate requires Rust **1.82** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor version bump.

# License
Licensed under

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)
at your option.

# Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
