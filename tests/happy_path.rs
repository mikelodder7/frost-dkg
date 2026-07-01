use elliptic_curve::{Field, subtle::ConditionallySelectable};
use elliptic_curve_tools::SumOfProducts;
use frost_dkg::*;
use rand_chacha::ChaCha8Rng;
use rand_core::{Rng, SeedableRng};
use rstest::*;
use std::num::NonZeroUsize;
use vsss_rs::{
    IdentifierPrimeField, ParticipantIdGeneratorCollection, ParticipantIdGeneratorType,
    ReadableShareSet,
    elliptic_curve::{Group, group::GroupEncoding},
};

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY)]
#[case::p256(p256::ProjectivePoint::IDENTITY)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY)]
fn static_init_dkg<G>(#[case] _g: G)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    let rng = ChaCha8Rng::from_seed([0u8; 32]);
    static_numbering_init_dkg::<G>(rng);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY)]
#[case::p256(p256::ProjectivePoint::IDENTITY)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY)]
fn static_add_participant_same_threshold<G>(#[case] _g: G)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const THRESHOLD: usize = 3;
    static_five_participants_add_participant::<G>(THRESHOLD);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY)]
#[case::p256(p256::ProjectivePoint::IDENTITY)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY)]
fn static_add_participant_increase_threshold<G>(#[case] _g: G)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const THRESHOLD: usize = 5;
    static_five_participants_add_participant::<G>(THRESHOLD)
}

#[rstest]
#[case::k256(k256::ProjectivePoint::default())]
#[case::p256(p256::ProjectivePoint::default())]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY)]
fn static_remove_participant_same_threshold<G>(#[case] _g: G)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const THRESHOLD: usize = 3;
    static_five_participants_remove_participant::<G>(THRESHOLD);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::default())]
#[case::p256(p256::ProjectivePoint::default())]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::default())]
fn static_remove_participant_decrease_threshold<G>(#[case] _g: G)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const THRESHOLD: usize = 2;
    static_five_participants_remove_participant::<G>(THRESHOLD);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 5)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 5)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY, 5)]
fn static_add_and_remove_participant_increase_participant<G>(
    #[case] _g: G,
    #[case] threshold: usize,
) where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    static_five_participants_add_and_remove_increase_participant::<G>(threshold);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 3)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 4)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY, 3)]
fn static_add_and_remove_participant_decrease_participant<G>(
    #[case] _g: G,
    #[case] threshold: usize,
) where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    static_five_participants_add_and_remove_decrease_participant::<G>(threshold);
}

fn static_five_participants_add_participant<G>(threshold: usize)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const LIMIT: usize = 5;
    const INCREMENT: usize = 2;

    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
    let (participants, secret) = static_numbering_init_dkg::<G>(&mut rng);

    let threshold = NonZeroUsize::new(threshold).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let mut pids = participants.iter().map(|p| p.get_id()).collect::<Vec<_>>();
    pids.push(IdentifierPrimeField(G::Scalar::random(&mut rng)));
    pids.push(IdentifierPrimeField(G::Scalar::random(&mut rng)));
    let seq = vec![ParticipantIdGeneratorType::list(&pids)];
    let parameters = Parameters::<G>::new(threshold, limit, None, Some(seq));

    let mut participants: [Box<dyn AnyParticipant<G>>; 7] = [
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[0].get_id(),
                &participants[0].get_secret_share().unwrap(),
                &parameters,
                &pids[..participants.len()],
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[1].get_id(),
                &participants[1].get_secret_share().unwrap(),
                &parameters,
                &pids[..participants.len()],
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[2].get_id(),
                &participants[2].get_secret_share().unwrap(),
                &parameters,
                &pids[..participants.len()],
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[3].get_id(),
                &participants[3].get_secret_share().unwrap(),
                &parameters,
                &pids[..participants.len()],
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[4].get_id(),
                &participants[4].get_secret_share().unwrap(),
                &parameters,
                &pids[..participants.len()],
            )
            .unwrap(),
        ),
        Box::new(RefreshParticipant::<G>::new_refresh(pids[5], None, &parameters).unwrap()),
        Box::new(RefreshParticipant::<G>::new_refresh(pids[6], None, &parameters).unwrap()),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();

    let res = (&shares[..threshold.get()]).combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    let actual_pk = G::generator() * *new_secret;

    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    // Old shared secret remains unchanged
    assert_eq!(secret, *new_secret);
}

fn static_five_participants_remove_participant<G>(threshold: usize)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const LIMIT: usize = 3;
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
    let (participants, secret) = static_numbering_init_dkg::<G>(&mut rng);

    let threshold = NonZeroUsize::new(threshold).unwrap();
    let limit = NonZeroUsize::new(LIMIT).unwrap();
    let share_ids = [
        participants[0].get_id(),
        participants[2].get_id(),
        participants[4].get_id(),
    ];
    let seq = vec![ParticipantIdGeneratorType::list(share_ids.as_slice())];
    let parameters = Parameters::<G>::new(threshold, limit, None, Some(seq));

    let mut participants: [Box<dyn AnyParticipant<G>>; 3] = [
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[0],
                &participants[0].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[1],
                &participants[2].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[2],
                &participants[4].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();

    let res = shares.combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    let actual_pk = G::generator() * *new_secret;

    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    // Old shared secret remains unchanged
    assert_eq!(secret, *new_secret);
}

fn static_five_participants_add_and_remove_decrease_participant<G>(threshold: usize)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const LIMIT: usize = 3;
    const INCREMENT: usize = 1;
    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
    let (participants, secret) = static_numbering_init_dkg::<G>(&mut rng);

    let threshold = NonZeroUsize::new(threshold).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let share_ids = [
        participants[1].get_id(),
        participants[2].get_id(),
        participants[3].get_id(),
        IdentifierPrimeField(G::Scalar::random(&mut rng)),
    ];

    let seq = vec![ParticipantIdGeneratorType::list(&share_ids)];
    let parameters = Parameters::<G>::new(threshold, limit, None, Some(seq));

    let mut participants: [Box<dyn AnyParticipant<G>>; 4] = [
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[0],
                &participants[1].get_secret_share().unwrap(),
                &parameters,
                &share_ids[..3],
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[1],
                &participants[2].get_secret_share().unwrap(),
                &parameters,
                &share_ids[..3],
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[2],
                &participants[3].get_secret_share().unwrap(),
                &parameters,
                &share_ids[..3],
            )
            .unwrap(),
        ),
        Box::new(RefreshParticipant::<G>::new_refresh(share_ids[3], None, &parameters).unwrap()),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();
    let res = shares.combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();
    let actual_pk = G::generator() * *new_secret;

    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    // Old shared secret remains unchanged
    assert_eq!(secret, *new_secret);
}

fn static_five_participants_add_and_remove_increase_participant<G>(threshold: usize)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const LIMIT: usize = 3;
    const INCREMENT: usize = 3;

    let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
    let (participants, secret) = static_numbering_init_dkg::<G>(&mut rng);

    let threshold = NonZeroUsize::new(threshold).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let share_ids = [
        participants[1].get_id(),
        participants[2].get_id(),
        participants[4].get_id(),
        IdentifierPrimeField(G::Scalar::random(&mut rng)),
        IdentifierPrimeField(G::Scalar::random(&mut rng)),
        IdentifierPrimeField(G::Scalar::random(&mut rng)),
    ];
    let seq = vec![ParticipantIdGeneratorType::list(&share_ids)];
    let parameters = Parameters::<G>::new(threshold, limit, None, Some(seq));

    let mut participants: [Box<dyn AnyParticipant<G>>; 6] = [
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[0],
                &participants[1].get_secret_share().unwrap(),
                &parameters,
                &share_ids[..3],
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[1],
                &participants[2].get_secret_share().unwrap(),
                &parameters,
                &share_ids[..3],
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                share_ids[2],
                &participants[4].get_secret_share().unwrap(),
                &parameters,
                &share_ids[..3],
            )
            .unwrap(),
        ),
        Box::new(RefreshParticipant::<G>::new_refresh(share_ids[3], None, &parameters).unwrap()),
        Box::new(RefreshParticipant::<G>::new_refresh(share_ids[4], None, &parameters).unwrap()),
        Box::new(RefreshParticipant::<G>::new_refresh(share_ids[5], None, &parameters).unwrap()),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();
    let res = shares.combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();
    let actual_pk = G::generator() * *new_secret;
    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    // Old shared secret remains unchanged
    assert_eq!(secret, *new_secret);
}

fn static_numbering_init_dkg<G>(
    mut rng: impl Rng,
) -> (Vec<Box<dyn AnyParticipant<G>>>, <G as Group>::Scalar)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const THRESHOLD: usize = 3;
    const LIMIT: usize = 5;

    let ids = (0..LIMIT)
        .map(|_| IdentifierPrimeField(G::Scalar::random(&mut rng)))
        .collect::<Vec<_>>();

    let seq =
        vec![ParticipantIdGeneratorType::<IdentifierPrimeField<G::Scalar>>::list(ids.as_slice())];
    let parameters = Parameters::<G>::new(
        NonZeroUsize::new(THRESHOLD).unwrap(),
        NonZeroUsize::new(LIMIT).unwrap(),
        None,
        Some(seq.clone()),
    );

    let mut participants = ParticipantIdGeneratorCollection::from(&seq)
        .iter()
        .map(|id| {
            let p = Box::new(SecretParticipant::<G>::new_secret(id, &parameters).unwrap());
            p as Box<dyn AnyParticipant<G>>
        })
        .collect::<Vec<Box<dyn AnyParticipant<G>>>>();

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..LIMIT {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();

    let res = shares.combine();
    assert!(res.is_ok());
    let secret = res.unwrap();

    assert_eq!(
        participants[1].get_public_key().unwrap(),
        G::generator() * *secret
    );

    (participants, *secret)
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY)]
#[case::p256(p256::ProjectivePoint::IDENTITY)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY)]
fn init_dkg<G>(#[case] _g: G)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    five_participants_init::<G>();
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY)]
#[case::p256(p256::ProjectivePoint::IDENTITY)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY)]
fn refresh<G>(#[case] _g: G)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const THRESHOLD: usize = 3;
    const LIMIT: usize = 5;

    let (participants, secret) = five_participants_init::<G>();

    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT).unwrap();
    let pids = participants.iter().map(|p| p.get_id()).collect::<Vec<_>>();
    let seq = vec![ParticipantIdGeneratorType::list(&pids)];
    let parameters = Parameters::<G>::new(threshold, limit, None, Some(seq));

    let mut participants: [Box<dyn AnyParticipant<G>>; 5] = [
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                participants[0].get_id(),
                participants[0].get_secret_share().map(|s| s.value.0),
                &parameters,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                participants[1].get_id(),
                participants[1].get_secret_share().map(|s| s.value.0),
                &parameters,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                participants[2].get_id(),
                participants[2].get_secret_share().map(|s| s.value.0),
                &parameters,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                participants[3].get_id(),
                participants[3].get_secret_share().map(|s| s.value.0),
                &parameters,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                participants[4].get_id(),
                participants[4].get_secret_share().map(|s| s.value.0),
                &parameters,
            )
            .unwrap(),
        ),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();

    let res = shares.combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    assert_eq!(new_secret.0.is_zero().unwrap_u8(), 1);

    let actual_pk = G::generator() * *new_secret;

    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    assert_eq!(
        participants[0]
            .get_public_key()
            .unwrap()
            .is_identity()
            .unwrap_u8(),
        1u8
    );

    // Old shared secret remains unchanged
    assert_eq!(secret + *new_secret, secret);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 3)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 3)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY, 3)]
fn add_participant_same_threshold<G>(#[case] _g: G, #[case] threshold: usize)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    five_participants_add_participant::<G>(threshold);
}

// Previous threshold was 3, new threshold is 5
#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 5)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 5)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY, 5)]
fn add_participant_increase_threshold<G>(#[case] _g: G, #[case] threshold: usize)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    five_participants_add_participant::<G>(threshold);
}

// Previous threshold was 3
#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 3)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 3)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY, 3)]
fn remove_participant_same_threshold<G>(#[case] _g: G, #[case] threshold: usize)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    five_participants_remove_participant::<G>(threshold);
}

// Previous threshold was 3, new threshold is 2
#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 2)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 2)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY, 2)]
fn remove_participant_decrease_threshold<G>(#[case] _g: G, #[case] threshold: usize)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    five_participants_remove_participant::<G>(threshold);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 5)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 5)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY, 5)]
fn add_and_remove_participant_increase_participant<G>(#[case] _g: G, #[case] threshold: usize)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    five_participants_add_and_remove_increase_participant::<G>(threshold);
}

#[rstest]
#[case::k256(k256::ProjectivePoint::IDENTITY, 3)]
#[case::p256(p256::ProjectivePoint::IDENTITY, 4)]
#[case::ed448(ed448_goldilocks_plus::EdwardsPoint::IDENTITY, 3)]
fn add_and_remove_participant_decrease_participant<G>(#[case] _g: G, #[case] threshold: usize)
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    five_participants_add_and_remove_decrease_participant::<G>(threshold);
}

fn five_participants_init<G>() -> (Vec<Box<dyn AnyParticipant<G>>>, <G as Group>::Scalar)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    const THRESHOLD: usize = 3;
    const LIMIT: usize = 5;

    let threshold = NonZeroUsize::new(THRESHOLD).unwrap();
    let limit = NonZeroUsize::new(LIMIT).unwrap();
    let seq = vec![
        ParticipantIdGeneratorType::<IdentifierPrimeField<G::Scalar>>::sequential(
            None, None, limit,
        ),
    ];
    let parameters = Parameters::<G>::new(threshold, limit, None, Some(seq.clone()));
    let mut participants = ParticipantIdGeneratorCollection::from(&seq)
        .iter()
        .map(|id| {
            let p = Box::new(SecretParticipant::<G>::new_secret(id, &parameters).unwrap());
            p as Box<dyn AnyParticipant<G>>
        })
        .collect::<Vec<Box<dyn AnyParticipant<G>>>>();

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..LIMIT {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();

    let res = shares.combine();
    assert!(res.is_ok());
    let secret = res.unwrap();

    assert_eq!(
        participants[1].get_public_key().unwrap(),
        G::generator() * *secret
    );

    // publicly verify secret sharing DKG result
    for participant in participants.iter() {
        let round1_data: Vec<Round1Data<G>> = participant
            .get_received_round1_data()
            .values()
            .cloned()
            .collect();
        assert!(
            publicly_verify_dkg_results(
                &round1_data,
                &parameters,
                participant.get_public_key().unwrap(),
            )
            .is_ok()
        );
    }

    (participants, *secret)
}

fn five_participants_add_participant<G>(threshold: usize)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    let (participants, secret) = five_participants_init::<G>();

    // Next epoch
    const LIMIT: usize = 5;
    const INCREMENT: usize = 2;

    let threshold = NonZeroUsize::new(threshold).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let pids = participants.iter().map(|p| p.get_id()).collect::<Vec<_>>();
    let seq = vec![
        ParticipantIdGeneratorType::list(&pids),
        ParticipantIdGeneratorType::sequential(
            Some(IdentifierPrimeField(G::Scalar::from(6))),
            None,
            NonZeroUsize::new(2).unwrap(),
        ),
    ];
    let parameters = Parameters::<G>::new(threshold, limit, None, Some(seq));

    let mut participants: [Box<dyn AnyParticipant<G>>; 7] = [
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[0].get_id(),
                &participants[0].get_secret_share().unwrap(),
                &parameters,
                &pids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[1].get_id(),
                &participants[1].get_secret_share().unwrap(),
                &parameters,
                &pids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[2].get_id(),
                &participants[2].get_secret_share().unwrap(),
                &parameters,
                &pids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[3].get_id(),
                &participants[3].get_secret_share().unwrap(),
                &parameters,
                &pids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                participants[4].get_id(),
                &participants[4].get_secret_share().unwrap(),
                &parameters,
                &pids,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                IdentifierPrimeField(G::Scalar::from(6)),
                None,
                &parameters,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                IdentifierPrimeField(G::Scalar::from(7)),
                None,
                &parameters,
            )
            .unwrap(),
        ),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();

    let res = shares.combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    let actual_pk = G::generator() * *new_secret;

    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    // Old shared secret remains unchanged
    assert_eq!(secret, *new_secret);
}

fn five_participants_remove_participant<G>(threshold: usize)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    let (participants, secret) = five_participants_init::<G>();

    // Next epoch
    const LIMIT: usize = 3;

    let threshold = NonZeroUsize::new(threshold).unwrap();
    let limit = NonZeroUsize::new(LIMIT).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit, None, None);

    let share_ids = [
        IdentifierPrimeField(G::Scalar::from(1)),
        IdentifierPrimeField(G::Scalar::from(3)),
        IdentifierPrimeField(G::Scalar::from(4)),
    ];

    let mut participants: [Box<dyn AnyParticipant<G>>; 3] = [
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(1)),
                &participants[0].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(2)),
                &participants[2].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(3)),
                &participants[3].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();

    let res = shares.combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();

    let actual_pk = G::generator() * *new_secret;

    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    // Old shared secret remains unchanged
    assert_eq!(secret, *new_secret);
}

fn five_participants_add_and_remove_decrease_participant<G>(threshold: usize)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    let (participants, secret) = five_participants_init::<G>();

    // Next epoch
    const LIMIT: usize = 3;
    const INCREMENT: usize = 1;

    let threshold = NonZeroUsize::new(threshold).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let parameters = Parameters::<G>::new(threshold, limit, None, None);

    let share_ids = [
        participants[1].get_id(),
        participants[2].get_id(),
        participants[3].get_id(),
    ];

    let mut participants: [Box<dyn AnyParticipant<G>>; 4] = [
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(1)),
                &participants[1].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(2)),
                &participants[2].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(3)),
                &participants[3].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                IdentifierPrimeField(G::Scalar::from(4)),
                None,
                &parameters,
            )
            .unwrap(),
        ),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();
    let res = shares.combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();
    let actual_pk = G::generator() * *new_secret;

    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    // Old shared secret remains unchanged
    assert_eq!(secret, *new_secret);
}

fn five_participants_add_and_remove_increase_participant<G>(threshold: usize)
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    let (participants, secret) = five_participants_init::<G>();

    // Next epoch
    const LIMIT: usize = 3;
    const INCREMENT: usize = 3;

    let threshold = NonZeroUsize::new(threshold).unwrap();
    let limit = NonZeroUsize::new(LIMIT + INCREMENT).unwrap();
    let share_ids = [
        participants[1].get_id(),
        participants[2].get_id(),
        participants[4].get_id(),
    ];
    let parameters = Parameters::<G>::new(threshold, limit, None, None);

    let mut participants: [Box<dyn AnyParticipant<G>>; 6] = [
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(1)),
                &participants[1].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(2)),
                &participants[2].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            SecretParticipant::<G>::with_secret(
                IdentifierPrimeField(G::Scalar::from(3)),
                &participants[4].get_secret_share().unwrap(),
                &parameters,
                &share_ids,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                IdentifierPrimeField(G::Scalar::from(4)),
                None,
                &parameters,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                IdentifierPrimeField(G::Scalar::from(5)),
                None,
                &parameters,
            )
            .unwrap(),
        ),
        Box::new(
            RefreshParticipant::<G>::new_refresh(
                IdentifierPrimeField(G::Scalar::from(6)),
                None,
                &parameters,
            )
            .unwrap(),
        ),
    ];

    for _ in [Round::One, Round::Two, Round::Three] {
        let round_generators = next_round(&mut participants);
        receive(&mut participants, &round_generators);
    }

    for i in 1..participants.len() {
        assert_eq!(
            participants[i - 1].get_public_key().unwrap(),
            participants[i].get_public_key().unwrap()
        );
    }

    let shares = participants
        .iter()
        .map(|p| p.get_secret_share().unwrap())
        .collect::<Vec<_>>();
    let res = shares.combine();
    assert!(res.is_ok());
    let new_secret = res.unwrap();
    let actual_pk = G::generator() * *new_secret;
    assert_eq!(participants[0].get_public_key().unwrap(), actual_pk);

    // Old shared secret remains unchanged
    assert_eq!(secret, *new_secret);

    let transcript_hash = participants[0].get_final_transcript_hash();
    for participant in participants.iter().skip(1) {
        assert_eq!(participant.get_final_transcript_hash(), transcript_hash);
    }
}

fn next_round<G>(participants: &mut [Box<dyn AnyParticipant<G>>]) -> Vec<RoundOutputGenerator<G>>
where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
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
    participants: &mut [Box<dyn AnyParticipant<G>>],
    round_generators: &[RoundOutputGenerator<G>],
) where
    G: GroupEncoding + SumOfProducts + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    for round_generator in round_generators {
        for ParticipantRoundOutput {
            dst_ordinal: ordinal,
            dst_id: id,
            data,
            ..
        } in round_generator.iter()
        {
            if let Some(participant) = participants.get_mut(ordinal) {
                assert_eq!(participant.get_ordinal(), ordinal);
                assert_eq!(participant.get_id(), id);
                let res = participant.receive(data.as_slice());
                assert!(res.is_ok());
            }
        }
    }
}
