mod round1;
mod round2;
mod round3;

use super::*;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::{Field, Group};
use elliptic_curve_tools::SumOfProducts;
use rand_core::{CryptoRngCore, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use vsss_rs::{
    subtle::ConstantTimeEq, DefaultShare, IdentifierPrimeField, ShareElement, ShareVerifierGroup,
    ValueGroup, ValuePrimeField,
};

/// The inner share representation
pub type SecretShare<F> = DefaultShare<IdentifierPrimeField<F>, IdentifierPrimeField<F>>;

/// The inner feldman share verifiers
pub type FeldmanShareVerifier<G> = ShareVerifierGroup<G>;

/// Participant implementation
pub trait ParticipantImpl<G>
where
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    /// Get the participant type
    fn get_type(&self) -> ParticipantType;
    /// Get the participants secret
    fn random_value(rng: impl CryptoRngCore) -> G::Scalar;
    /// Check the feldman verifier at position 0.
    /// During a new or update key gen, this value is not the identity
    /// during a refresh, it must be identity
    fn check_feldman_verifier(verifier: G) -> bool;
}

/// A DKG participant FSM
#[derive(Clone)]
pub struct Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    pub(crate) ordinal: usize,
    pub(crate) id: IdentifierPrimeField<G::Scalar>,
    pub(crate) threshold: usize,
    pub(crate) limit: usize,
    pub(crate) round: Round,
    pub(crate) completed: bool,
    pub(crate) secret_shares: BTreeMap<usize, SecretShare<G::Scalar>>,
    pub(crate) feldman_verifiers: Vec<ValueGroup<G>>,
    pub(crate) secret_share: SecretShare<G::Scalar>,
    pub(crate) message_generator: G,
    pub(crate) public_key: ValueGroup<G>,
    pub(crate) powers_of_i: Vec<G::Scalar>,
    pub(crate) received_round1_data: BTreeMap<usize, Round1Data<G>>,
    pub(crate) received_round2_data: BTreeMap<usize, Round2Data<G::Scalar>>,
    pub(crate) all_participant_ids: BTreeMap<usize, IdentifierPrimeField<G::Scalar>>,
    pub(crate) valid_participant_ids: BTreeMap<usize, IdentifierPrimeField<G::Scalar>>,
    pub(crate) participant_impl: I,
}

unsafe impl<I, G> Send for Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
}

unsafe impl<I, G> Sync for Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
}

impl<I, G> Debug for Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Participant")
            .field("ordinal", &self.ordinal)
            .field("id", &self.id)
            .field("threshold", &self.threshold)
            .field("limit", &self.limit)
            .field("round", &self.round)
            .field("feldman_verifiers", &self.feldman_verifiers)
            .field("secret_share", &self.secret_share)
            .field("public_key", &self.public_key)
            .field("powers_of_i", &self.powers_of_i)
            .field("received_round1_data", &self.received_round1_data)
            .field("received_round2_data", &self.received_round2_data)
            .finish()
    }
}

impl<G> Participant<SecretParticipantImpl<G>, G>
where
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    /// Create a new participant with an existing secret.
    ///
    /// This allows the polynomial to be updated versus refreshing the shares.
    pub fn with_secret(
        new_identifier: IdentifierPrimeField<G::Scalar>,
        old_share: &SecretShare<G::Scalar>,
        parameters: &Parameters<G>,
        shares_ids: &[IdentifierPrimeField<G::Scalar>],
    ) -> DkgResult<Self> {
        let secret = *old_share.value * *Self::lagrange(old_share, shares_ids);
        Self::initialize(new_identifier, parameters, IdentifierPrimeField(secret))
    }
}

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    /// Create a new participant to generate a new key share
    pub fn new(id: IdentifierPrimeField<G::Scalar>, parameters: &Parameters<G>) -> DkgResult<Self> {
        let rng = rand_core::OsRng;
        let secret = I::random_value(rng);
        Self::initialize(id, parameters, IdentifierPrimeField(secret))
    }

    fn initialize(
        id: IdentifierPrimeField<G::Scalar>,
        parameters: &Parameters<G>,
        secret: ValuePrimeField<G::Scalar>,
    ) -> DkgResult<Self> {
        let rng = rand_core::OsRng;

        if parameters.threshold > parameters.limit {
            return Err(Error::InitializationError(
                "Threshold greater than limit".to_string(),
            ));
        }
        if parameters.threshold < 1 {
            return Err(Error::InitializationError(
                "Threshold less than 1".to_string(),
            ));
        }
        if parameters.message_generator.is_identity().into() {
            return Err(Error::InitializationError(
                "Invalid message generator".to_string(),
            ));
        }

        let mut powers_of_i = vec![G::Scalar::ONE; parameters.threshold];
        powers_of_i[1] = *id;
        for i in 2..parameters.threshold {
            powers_of_i[i] = powers_of_i[i - 1] * *id;
        }

        let (shares, verifiers) = vsss_rs::feldman::split_secret_with_participant_generator::<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        >(
            parameters.threshold,
            parameters.limit,
            &secret,
            Some(ValueGroup(parameters.message_generator)),
            rng,
            &parameters.participant_number_generators,
        )?;

        if verifiers.iter().skip(1).any(|c| c.is_identity().into())
            || !I::check_feldman_verifier(*verifiers[0])
        {
            return Err(Error::InitializationError(
                "Invalid feldman verifier".to_string(),
            ));
        }

        let ordinal = shares
            .iter()
            .position(|s| s.identifier == id)
            .ok_or_else(|| {
                Error::InitializationError(format!(
                    "Invalid participant id '{}'. Not in generated set of shares",
                    id
                ))
            })?;

        let all_participant_ids = shares
            .iter()
            .enumerate()
            .map(|(i, s)| (i, s.identifier))
            .collect();
        Ok(Self {
            ordinal,
            id,
            threshold: parameters.threshold,
            limit: parameters.limit,
            completed: false,
            round: Round::One,
            secret_shares: shares
                .iter()
                .enumerate()
                .map(|(ordinal, share)| (ordinal, *share))
                .collect(),
            feldman_verifiers: verifiers,
            secret_share: SecretShare::<G::Scalar>::default(),
            message_generator: parameters.message_generator,
            public_key: ValueGroup::<G>::identity(),
            powers_of_i,
            received_round1_data: BTreeMap::new(),
            received_round2_data: BTreeMap::new(),
            all_participant_ids,
            valid_participant_ids: BTreeMap::new(),
            participant_impl: Default::default(),
        })
    }

    /// The ordinal index of this participant
    pub fn get_ordinal(&self) -> usize {
        self.ordinal
    }

    /// The identifier associated with this secret_participant
    pub fn get_id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id
    }

    /// Returns true if this secret_participant is complete
    pub fn completed(&self) -> bool {
        self.completed
    }

    /// Return the current round
    pub fn get_round(&self) -> Round {
        self.round
    }

    /// Return the set threshold
    pub fn get_threshold(&self) -> usize {
        self.threshold
    }

    /// Return the set limit
    pub fn get_limit(&self) -> usize {
        self.limit
    }

    /// Computed secret share.
    /// This value is useless until at least 2 rounds have been run
    /// so [`None`] is returned until completion
    pub fn get_secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        if self.completed {
            Some(self.secret_share)
        } else {
            None
        }
    }

    /// Computed public key
    /// This value is useless until all rounds have been run
    /// so [`None`] is returned until completion
    pub fn get_public_key(&self) -> Option<G> {
        if self.completed {
            Some(*self.public_key)
        } else {
            None
        }
    }

    /// Return the list of all participants that started the protocol
    pub fn get_all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.all_participant_ids
    }

    /// Return the list of valid participant ids
    pub fn get_valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.valid_participant_ids
    }

    /// Return the feldman verifiers
    pub fn get_feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.feldman_verifiers.clone()
    }

    /// Receive data from another participant
    pub fn receive(&mut self, data: &[u8]) -> DkgResult<()> {
        let round = Round::try_from(data[0]).map_err(Error::InitializationError)?;
        match round {
            Round::One => {
                let round1_payload = postcard::from_bytes::<Round1Data<G>>(&data[1..])?;
                self.receive_round1data(round1_payload)
            }
            Round::Two => {
                let round2_payload = postcard::from_bytes::<Round2Data<G::Scalar>>(&data[1..])?;
                self.receive_round2data(round2_payload)
            }
            _ => Err(Error::RoundError("Protocol is complete".to_string())),
        }
    }

    /// Run the next step in the protocol
    pub fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        match self.round {
            Round::One => self.round1(),
            Round::Two => self.round2(),
            Round::Three => self.round3(),
            Round::Four => Err(Error::RoundError("Protocol is complete".to_string())),
        }
    }

    pub(crate) fn check_sending_participant_id(
        &self,
        round: Round,
        sender_ordinal: usize,
        sender_id: IdentifierPrimeField<G::Scalar>,
    ) -> DkgResult<()> {
        let id = self
            .all_participant_ids
            .get(&sender_ordinal)
            .ok_or_else(|| {
                Error::RoundError(format!(
                    "Round {}: Unknown sender ordinal, {}",
                    round, sender_ordinal
                ))
            })?;
        if *id != sender_id {
            return Err(Error::RoundError(format!(
                "Round {}: Sender id mismatch, expected '{}', got '{}'",
                round, id, sender_id
            )));
        }
        if sender_id.is_zero().into() {
            return Err(Error::RoundError(format!(
                "Round {}: Sender id is zero",
                round
            )));
        }
        if self.id.ct_eq(&sender_id).into() {
            return Err(Error::RoundError(format!(
                "Round {}: Sender id is equal to our id",
                round
            )));
        }
        Ok(())
    }

    pub(crate) fn lagrange(
        share: &SecretShare<G::Scalar>,
        shares_ids: &[IdentifierPrimeField<G::Scalar>],
    ) -> ValuePrimeField<G::Scalar> {
        let mut num = G::Scalar::ONE;
        let mut den = G::Scalar::ONE;
        for &x_j in shares_ids.iter() {
            if x_j == share.identifier {
                continue;
            }
            num *= *x_j;
            den *= *x_j - *share.identifier;
        }

        IdentifierPrimeField(num * den.invert().expect("Denominator should not be zero"))
    }
}

/// Secret Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SecretParticipantImpl<G>(PhantomData<G>);

unsafe impl<G> Send for SecretParticipantImpl<G> {}
unsafe impl<G> Sync for SecretParticipantImpl<G> {}

impl<G> ParticipantImpl<G> for SecretParticipantImpl<G>
where
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    fn get_type(&self) -> ParticipantType {
        ParticipantType::Secret
    }

    fn random_value(mut rng: impl RngCore) -> <G as Group>::Scalar {
        G::Scalar::random(&mut rng)
    }

    fn check_feldman_verifier(verifier: G) -> bool {
        verifier.is_identity().unwrap_u8() == 0u8
    }
}

/// Refresh Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RefreshParticipantImpl<G>(PhantomData<G>);

unsafe impl<G> Send for RefreshParticipantImpl<G> {}
unsafe impl<G> Sync for RefreshParticipantImpl<G> {}

impl<G> ParticipantImpl<G> for RefreshParticipantImpl<G>
where
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    fn get_type(&self) -> ParticipantType {
        ParticipantType::Refresh
    }

    fn random_value(_rng: impl RngCore) -> <G as Group>::Scalar {
        G::Scalar::ZERO
    }

    fn check_feldman_verifier(verifier: G) -> bool {
        verifier.is_identity().into()
    }
}
