/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Frost Distributed Key Generation Algorithm.
//!
//! The full paper can be found [here](https://eprint.iacr.org/2020/852.pdf).

#![cfg_attr(docsrs, feature(doc_cfg))]
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

use elliptic_curve::{
    Field, Group, PrimeField,
    group::GroupEncoding,
    subtle::{Choice, ConditionallySelectable},
};
use elliptic_curve_tools::SumOfProducts;
use std::collections::{BTreeMap, BTreeSet};
use vsss_rs::{IdentifierPrimeField, ParticipantIdGeneratorCollection, ShareVerifierGroup};

/// Round1 data represent all the broadcast information. Using this
/// anyone can publicly verify the output of the DKG.
pub fn publicly_verify_dkg_results<G>(
    round1_data: &[Round1Data<G>],
    parameters: &Parameters<G>,
    public_key: G,
) -> DkgResult<()>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    // This is essentially performing the same checks as round1::Participant::receive_round1data
    // but also checks that the computed public matches from the commitments
    if round1_data.len() < parameters.threshold {
        return Err(Error::Pvss(format!(
            "Not enough round 1 records. Expected at least {}, found {}",
            parameters.threshold,
            round1_data.len()
        )));
    }
    if round1_data.len() > parameters.limit {
        return Err(Error::Pvss(format!(
            "Too many round 1 records. Expected at most {}, found {}",
            parameters.limit,
            round1_data.len()
        )));
    }

    let all_participant_ids: BTreeMap<usize, IdentifierPrimeField<G::Scalar>> =
        ParticipantIdGeneratorCollection::from(&parameters.participant_number_generators)
            .iter()
            .take(parameters.limit)
            .enumerate()
            .collect();
    if all_participant_ids.len() != parameters.limit {
        return Err(Error::Pvss(format!(
            "Participant ID generators produced {} identifiers, expected {}",
            all_participant_ids.len(),
            parameters.limit
        )));
    }

    let mut computed_public_key = G::default();
    let mut all_refresh = true;
    let mut sender_ordinals = BTreeSet::new();

    for (i, round1_data) in round1_data.iter().enumerate() {
        if !sender_ordinals.insert(round1_data.sender_ordinal) {
            return Err(Error::Pvss(format!(
                "Data at {} duplicates sender ordinal {}",
                i + 1,
                round1_data.sender_ordinal
            )));
        }
        let Some(id) = all_participant_ids.get(&round1_data.sender_ordinal) else {
            return Err(Error::Pvss(format!(
                "Data at {} doesn't exist in the set of participants",
                i + 1
            )));
        };
        if *id != round1_data.sender_id {
            return Err(Error::Pvss(format!(
                "Data at {} doesn't match the expected sender id",
                i + 1
            )));
        }
        if id.is_zero().into() {
            return Err(Error::Pvss(format!(
                "Data at {} contains an id that is zero",
                i + 1
            )));
        }
        if round1_data.feldman_commitments.is_empty() {
            return Err(Error::Pvss(format!(
                "Data at {} has no Feldman commitments",
                i + 1
            )));
        }
        if round1_data.feldman_commitments.len() != parameters.threshold {
            return Err(Error::Pvss(format!(
                "Data at {} has commitments that do not match the expected threshold. Expected {}, found {}",
                i + 1,
                parameters.threshold,
                round1_data.feldman_commitments.len()
            )));
        }
        if round1_data.feldman_commitments[1..]
            .iter()
            .fold(Choice::from(0u8), |acc, c| acc | c.is_identity())
            .into()
        {
            return Err(Error::Pvss(format!(
                "Data at {} has an feldman commitment that are the identity element which is not allowed",
                i + 1
            )));
        }

        let feldman_valid = match round1_data.sender_type {
            ParticipantType::Secret => {
                SecretParticipantImpl::check_feldman_verifier(*round1_data.feldman_commitments[0])
                    && round1_data.feldman_commitments[0].0 == round1_data.verifying_share
            }
            ParticipantType::Refresh => {
                RefreshParticipantImpl::check_feldman_verifier(*round1_data.feldman_commitments[0])
                    && round1_data.feldman_commitments[0].0 != round1_data.verifying_share
            }
        };

        if !feldman_valid {
            return Err(Error::Pvss(format!(
                "Data at {} has an invalid feldman commitment for its participant type",
                i + 1
            )));
        }

        verify_signature(
            SchnorrContext {
                ordinal: round1_data.sender_ordinal,
                id: &round1_data.sender_id,
                participant_type: &round1_data.sender_type,
                threshold: parameters.threshold,
                limit: parameters.limit,
                message_generator: &parameters.message_generator,
                feldman_verifiers: &round1_data.feldman_commitments,
                verifying_share: &round1_data.verifying_share,
                all_participant_ids: &all_participant_ids,
            },
            &round1_data.signature,
        )
        .map_err(|_e| Error::Pvss(format!("Data at {} failed signature verification", i + 1)))?;

        all_refresh &= matches!(round1_data.sender_type, ParticipantType::Refresh);
        computed_public_key += round1_data.feldman_commitments[0].0;
    }

    let public_key_identity = bool::from(computed_public_key.is_identity());
    if all_refresh && !public_key_identity || !all_refresh && public_key_identity {
        return Err(Error::Pvss(
            "The computed public key is not valid for the given participants".to_string(),
        ));
    }

    if computed_public_key != public_key {
        return Err(Error::Pvss(format!(
            "The public keys do not match: Expected {}, computed {}",
            hex::encode(public_key.to_bytes()),
            hex::encode(computed_public_key.to_bytes())
        )));
    }

    Ok(())
}

struct SchnorrContext<'a, G>
where
    G: Group + GroupEncoding + Default,
{
    ordinal: usize,
    id: &'a IdentifierPrimeField<G::Scalar>,
    participant_type: &'a ParticipantType,
    threshold: usize,
    limit: usize,
    message_generator: &'a G,
    feldman_verifiers: &'a [ShareVerifierGroup<G>],
    verifying_share: &'a G,
    all_participant_ids: &'a BTreeMap<usize, IdentifierPrimeField<G::Scalar>>,
}

pub(crate) fn verify_signature<G>(
    context: SchnorrContext<'_, G>,
    signature: &Signature<G>,
) -> DkgResult<()>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    let bytes = bytes_for_schnorr(&context, &signature.r);
    let challenge = G::Scalar::hash_to_scalar(&bytes);

    let computed_r =
        *context.message_generator * signature.s - *context.verifying_share * challenge;
    if signature.r != computed_r {
        return Err(Error::Round(format!(
            "Round {}: Received invalid round 1 signature proof from ordinal: '{}', id: '{:?}'",
            Round::One,
            context.ordinal,
            context.id,
        )));
    }
    Ok(())
}

pub(crate) fn bytes_for_schnorr<G>(context: &SchnorrContext<'_, G>, r_i: &G) -> Vec<u8>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    let mut bytes = Vec::with_capacity(512);
    // ID
    bytes.extend_from_slice(context.id.0.to_repr().as_ref());
    // Add these for domain separation to prevent replay attacks
    bytes.extend_from_slice(&(context.ordinal as u16).to_be_bytes());
    bytes.extend_from_slice(&u16::from(*context.participant_type).to_be_bytes());
    bytes.extend_from_slice(&(context.threshold as u16).to_be_bytes());
    bytes.extend_from_slice(&(context.limit as u16).to_be_bytes());
    bytes.extend_from_slice(context.message_generator.to_bytes().as_ref());
    for id in context.all_participant_ids.values() {
        bytes.extend_from_slice(id.0.to_repr().as_ref());
    }
    // Add the R_i
    bytes.extend_from_slice(r_i.to_bytes().as_ref());
    // Add the verifying share
    bytes.extend_from_slice(context.verifying_share.to_bytes().as_ref());
    // Add the verifiers
    for vf in context.feldman_verifiers {
        bytes.extend_from_slice(vf.0.to_bytes().as_ref());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::{Field, group::GroupEncoding, subtle::ConditionallySelectable};
    use elliptic_curve_tools::SumOfProducts;
    use rand_core::SeedableRng;
    use std::num::NonZeroUsize;
    use vsss_rs::{
        DefaultShare, IdentifierPrimeField, ParticipantIdGenerator, ReadableShareSet,
        ValuePrimeField, shamir,
    };

    #[test]
    fn works() {
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 3;

        let threshold = NonZeroUsize::new(THRESHOLD).expect("threshold is non-zero");
        let limit = NonZeroUsize::new(LIMIT).expect("limit is non-zero");

        let parameters = Parameters::<k256::ProjectivePoint>::new(threshold, limit, None, None);

        let mut participants = (1..=3)
            .map(|id| {
                let id = IdentifierPrimeField(k256::Scalar::from(id as u64));
                SecretParticipant::<k256::ProjectivePoint>::new_secret(id, &parameters)
                    .expect("create secret participant")
            })
            .collect::<Vec<_>>();

        for _ in [Round::One, Round::Two, Round::Three] {
            let generators = next_round(&mut participants);
            receive(&mut participants, generators);
        }

        let shares = participants
            .iter()
            .map(|p| p.secret_share().expect("participant has a secret share"))
            .collect::<Vec<_>>();

        let res = shares.combine();
        assert!(res.is_ok());
        let secret = res.expect("combine shares");

        let expected_pk = k256::ProjectivePoint::GENERATOR * *secret;

        assert_eq!(
            participants[1]
                .public_key()
                .expect("participant has public key"),
            expected_pk
        );

        let participant: Box<dyn AnyParticipant<k256::ProjectivePoint>> =
            Box::new(participants.pop().expect("participant exists"));
        let output = participant.into_output().expect("completed DKG output");
        assert_eq!(output.public_key(), expected_pk);
        assert_eq!(output.participant_ids().len(), LIMIT);
        assert_eq!(output.feldman_verifiers().len(), THRESHOLD);
        assert_eq!(*output.secret_share().identifier, k256::Scalar::from(3u64));
        assert!(!format!("{output:?}").contains("secret_share"));
    }

    #[test]
    fn public_verification_rejects_invalid_record_sets() {
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 3;

        let parameters = Parameters::<k256::ProjectivePoint>::new(
            NonZeroUsize::new(THRESHOLD).expect("threshold is non-zero"),
            NonZeroUsize::new(LIMIT).expect("limit is non-zero"),
            None,
            None,
        );
        let mut participants = (1..=LIMIT)
            .map(|id| {
                SecretParticipant::<k256::ProjectivePoint>::new_secret(
                    IdentifierPrimeField(k256::Scalar::from(id as u64)),
                    &parameters,
                )
                .expect("create secret participant")
            })
            .collect::<Vec<_>>();

        for _ in [Round::One, Round::Two, Round::Three] {
            let generators = next_round(&mut participants);
            receive(&mut participants, generators);
        }

        let round1_data = participants[0]
            .received_round1_data()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let public_key = participants[0]
            .public_key()
            .expect("participant has public key");
        assert!(publicly_verify_dkg_results(&round1_data, &parameters, public_key).is_ok());

        let threshold_records = &round1_data[..THRESHOLD];
        let threshold_public_key = threshold_records
            .iter()
            .map(|data| data.feldman_commitments[0].0)
            .sum();
        assert!(
            publicly_verify_dkg_results(threshold_records, &parameters, threshold_public_key)
                .is_ok()
        );

        let too_few =
            publicly_verify_dkg_results(&round1_data[..THRESHOLD - 1], &parameters, public_key);
        assert!(matches!(too_few, Err(Error::Pvss(message)) if message.contains("Not enough")));

        let duplicate_records = vec![round1_data[0].clone(), round1_data[0].clone()];
        let duplicate = publicly_verify_dkg_results(&duplicate_records, &parameters, public_key);
        assert!(
            matches!(duplicate, Err(Error::Pvss(message)) if message.contains("duplicates sender ordinal"))
        );

        let mut empty_commitments = round1_data[..THRESHOLD].to_vec();
        empty_commitments[0].feldman_commitments.clear();
        let empty =
            publicly_verify_dkg_results(&empty_commitments, &parameters, threshold_public_key);
        assert!(
            matches!(empty, Err(Error::Pvss(message)) if message.contains("no Feldman commitments"))
        );

        let mut too_many_records = round1_data.clone();
        too_many_records.push(round1_data[0].clone());
        let too_many = publicly_verify_dkg_results(&too_many_records, &parameters, public_key);
        assert!(matches!(too_many, Err(Error::Pvss(message)) if message.contains("Too many")));
    }

    #[test]
    fn advance_produces_opaque_transport_messages() {
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 3;

        let parameters = Parameters::<k256::ProjectivePoint>::new(
            NonZeroUsize::new(THRESHOLD).expect("threshold is non-zero"),
            NonZeroUsize::new(LIMIT).expect("limit is non-zero"),
            None,
            None,
        );
        let mut participants = (1..=LIMIT)
            .map(|id| {
                SecretParticipant::<k256::ProjectivePoint>::new_secret(
                    IdentifierPrimeField(k256::Scalar::from(id as u64)),
                    &parameters,
                )
                .expect("create secret participant")
            })
            .collect::<Vec<_>>();

        for round in [Round::One, Round::Two] {
            let batches = participants
                .iter_mut()
                .map(
                    |participant| match participant.advance().expect("advance participant") {
                        AdvanceResult::Messages(messages) => messages,
                        AdvanceResult::Complete => panic!("protocol completed too early"),
                    },
                )
                .collect::<Vec<_>>();

            for batch in batches {
                match round {
                    Round::One => {
                        assert_eq!(batch.messages().len(), 1);
                        assert!(matches!(
                            batch.messages()[0].destination(),
                            MessageDestination::Broadcast
                        ));
                    }
                    Round::Two => {
                        assert_eq!(batch.messages().len(), LIMIT - 1);
                        assert!(batch.messages().iter().all(|message| matches!(
                            message.destination(),
                            MessageDestination::Direct { .. }
                        )));
                    }
                    _ => unreachable!("only messaging rounds are tested here"),
                }

                for output in batch.into_per_recipient() {
                    let recipient = &mut participants[output.dst_ordinal];
                    assert_eq!(recipient.id(), output.dst_id);
                    recipient
                        .receive(&output.data)
                        .expect("receive opaque protocol message");
                }
            }
        }

        for participant in &mut participants {
            assert!(matches!(
                participant.advance().expect("complete participant"),
                AdvanceResult::Complete
            ));
        }
        assert!(participants.iter().all(Participant::completed));
    }

    #[test]
    fn recovery() {
        type SecretShare =
            DefaultShare<IdentifierPrimeField<k256::Scalar>, ValuePrimeField<k256::Scalar>>;
        const THRESHOLD: usize = 2;
        const LIMIT: usize = 3;

        let threshold = NonZeroUsize::new(THRESHOLD).expect("threshold is non-zero");
        let limit = NonZeroUsize::new(LIMIT).expect("limit is non-zero");
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0);

        let original_secret = k256::Scalar::random(&mut rng);
        let public_key = k256::ProjectivePoint::GENERATOR * original_secret;

        let original_peer_ids = (1..=LIMIT)
            .map(|_| IdentifierPrimeField(k256::Scalar::random(&mut rng)))
            .collect::<Vec<_>>();
        let original_peer_id_list = ParticipantIdGenerator::list(&original_peer_ids);
        let original_shares = shamir::split_secret_with_participant_generators::<SecretShare>(
            THRESHOLD,
            LIMIT,
            &IdentifierPrimeField(original_secret),
            &mut rng,
            &[original_peer_id_list],
        )
        .expect("split original secret");

        let new_peer_ids = (1..=LIMIT)
            .map(|_| IdentifierPrimeField(k256::Scalar::random(&mut rng)))
            .collect::<Vec<_>>();

        let parameters = Parameters::<k256::ProjectivePoint>::new(
            threshold,
            limit,
            None,
            Some(vec![ParticipantIdGenerator::list(&new_peer_ids)]),
        );
        let mut participants = Vec::with_capacity(LIMIT);
        for i in 0..LIMIT {
            let participant = SecretParticipant::<k256::ProjectivePoint>::with_secret(
                new_peer_ids[i],
                &original_shares[i],
                &parameters,
                &original_peer_ids,
            )
            .expect("create participant from existing share");
            participants.push(participant);
        }

        for _ in [Round::One, Round::Two, Round::Three] {
            let generators = next_round(&mut participants);
            receive(&mut participants, generators);
        }

        let shares = participants
            .iter()
            .map(|p| p.secret_share().expect("participant has a secret share"))
            .collect::<Vec<_>>();

        let res = shares.combine();
        assert!(res.is_ok());
        let secret = res.expect("combine shares");

        assert_eq!(secret.0, original_secret);
        assert_eq!(
            participants[1]
                .public_key()
                .expect("participant has public key"),
            public_key
        );
    }

    fn next_round<G>(participants: &mut [SecretParticipant<G>]) -> Vec<RoundOutputGenerator<G>>
    where
        G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
        G::Scalar: ScalarHash,
    {
        let mut round_generators = Vec::with_capacity(participants.len());
        for participant in participants {
            let generator = participant.run().expect("run participant round");
            round_generators.push(generator);
        }
        round_generators
    }

    fn receive<G>(
        participants: &mut [SecretParticipant<G>],
        round_generators: Vec<RoundOutputGenerator<G>>,
    ) where
        G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
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
