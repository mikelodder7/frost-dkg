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

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::group::GroupEncoding;
    use elliptic_curve_tools::SumOfProducts;
    use std::num::NonZeroUsize;
    use vsss_rs::{IdentifierPrimeField, ReadableShareSet};

    #[test]
    fn works() {
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 3;

        let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
        let limit = NonZeroUsize::new(LIMIT).unwrap();

        let parameters = Parameters::<k256::ProjectivePoint>::new(threshold, limit, None, None);

        let mut participants = (1..=3)
            .map(|id| {
                let id = IdentifierPrimeField(k256::Scalar::from(id as u64));
                SecretParticipant::<k256::ProjectivePoint>::new_secret(id, &parameters).unwrap()
            })
            .collect::<Vec<_>>();

        for _ in [Round::One, Round::Two, Round::Three] {
            let generators = next_round(&mut participants);
            receive(&mut participants, generators);
        }

        let shares = participants
            .iter()
            .map(|p| p.get_secret_share().unwrap())
            .collect::<Vec<_>>();

        let res = shares.combine();
        assert!(res.is_ok());
        let secret = res.unwrap();

        let expected_pk = k256::ProjectivePoint::GENERATOR * *secret;

        assert_eq!(participants[1].get_public_key().unwrap(), expected_pk);
    }

    fn next_round<G>(participants: &mut [SecretParticipant<G>]) -> Vec<RoundOutputGenerator<G>>
    where
        G: SumOfProducts + GroupEncoding + Default,
        G::Scalar: ScalarHash,
    {
        let mut round_generators = Vec::with_capacity(participants.len());
        for participant in participants {
            let generator = participant.run().unwrap();
            round_generators.push(generator);
        }
        round_generators
    }

    fn receive<G>(
        participants: &mut [SecretParticipant<G>],
        round_generators: Vec<RoundOutputGenerator<G>>,
    ) where
        G: SumOfProducts + GroupEncoding + Default,
        G::Scalar: ScalarHash,
    {
        for round_generator in &round_generators {
            for ParticipantRoundOutput {
                dst_ordinal: ordinal,
                dst_id: id,
                data,
                ..
            } in round_generator.iter()
            {
                if let Some(participant) = participants.get_mut(ordinal) {
                    assert_eq!(participant.ordinal, ordinal);
                    assert_eq!(participant.id, id);
                    let res = participant.receive(data.as_slice());
                    assert!(res.is_ok());
                }
            }
        }
    }
}
