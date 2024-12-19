/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Frost Distributed Key Generation Algorithm.
//!
//! The full paper can be found [here](https://eprint.iacr.org/2020/852.pdf).

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    clippy::mod_module_files
)]
#![deny(clippy::unwrap_used)]

mod data;
mod error;
mod parameters;
mod participant;
mod traits;

pub use data::*;
pub use error::*;
pub use parameters::*;
pub use participant::*;
pub use traits::*;

pub use elliptic_curve;
pub use elliptic_curve_tools;
pub use rand_core;
pub use vsss_rs;
