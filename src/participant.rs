mod round1;
mod round2;
mod round3;

use super::*;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::subtle::ConditionallySelectable;
use elliptic_curve::{Field, Group};
use elliptic_curve_tools::SumOfProducts;
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use vsss_rs::{
    DefaultShare, IdentifierPrimeField, ShareElement, ShareVerifierGroup, ValueGroup,
    ValuePrimeField, subtle::ConstantTimeEq,
};

/// Secret Participant type
pub type SecretParticipant<G> = Participant<SecretParticipantImpl<G>, G>;

/// Refresh Participant type
pub type RefreshParticipant<G> = Participant<RefreshParticipantImpl<G>, G>;

/// The inner share representation
pub type SecretShare<F> = DefaultShare<IdentifierPrimeField<F>, IdentifierPrimeField<F>>;

/// The inner feldman share verifiers
pub type FeldmanShareVerifier<G> = ShareVerifierGroup<G>;

/// Participant implementation
pub trait ParticipantImpl<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// Get the participant type
    fn get_type(&self) -> ParticipantType;
    /// Get the participants secret
    fn random_value(rng: impl CryptoRng) -> G::Scalar;
    /// Check the feldman verifier at position 0.
    /// During a new or update key gen, this value is not the identity
    /// during a refresh, it must be identity
    fn check_feldman_verifier(verifier: G) -> bool;
}

/// A DKG participant FSM
pub struct Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
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
    pub(crate) original_secret: G::Scalar,
    pub(crate) verifying_share: G,
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

impl<I, G> Debug for Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Participant")
            .field("ordinal", &self.ordinal)
            .field("id", &self.id)
            .field("threshold", &self.threshold)
            .field("limit", &self.limit)
            .field("round", &self.round)
            .field("completed", &self.completed)
            .field("feldman_verifiers", &self.feldman_verifiers)
            .field("public_key", &self.public_key)
            .field("powers_of_i", &self.powers_of_i)
            .finish()
    }
}

impl<G> Participant<SecretParticipantImpl<G>, G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// Create a new participant to generate a new key share
    pub fn new_secret(
        id: IdentifierPrimeField<G::Scalar>,
        parameters: &Parameters<G>,
    ) -> DkgResult<Self> {
        let rng = rand::rng();
        let secret = SecretParticipantImpl::<G>::random_value(rng);
        Self::initialize(id, parameters, IdentifierPrimeField(secret), None)
    }

    /// Create a new participant with an existing secret.
    ///
    /// This allows the polynomial to be updated versus refreshing the shares.
    pub fn with_secret(
        new_identifier: IdentifierPrimeField<G::Scalar>,
        old_share: &SecretShare<G::Scalar>,
        parameters: &Parameters<G>,
        shares_ids: &[IdentifierPrimeField<G::Scalar>],
    ) -> DkgResult<Self> {
        let secret = *old_share.value * *Self::lagrange(old_share, shares_ids)?;
        Self::initialize(
            new_identifier,
            parameters,
            IdentifierPrimeField(secret),
            None,
        )
    }
}

impl<G> Participant<RefreshParticipantImpl<G>, G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// Create a new participant to refresh an existing key share if it exists.
    ///
    /// If the share does not exist, assumes there are other participants
    /// that do possess a valid share of the original secret
    pub fn new_refresh(
        id: IdentifierPrimeField<G::Scalar>,
        existing_share: Option<G::Scalar>,
        parameters: &Parameters<G>,
    ) -> DkgResult<Self> {
        let secret = existing_share.unwrap_or_else(|| G::Scalar::random(&mut rand::rng()));
        Self::initialize(
            id,
            parameters,
            IdentifierPrimeField(secret),
            Some(parameters.message_generator * secret),
        )
    }
}

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    fn initialize(
        id: IdentifierPrimeField<G::Scalar>,
        parameters: &Parameters<G>,
        secret: ValuePrimeField<G::Scalar>,
        verifying_share: Option<G>,
    ) -> DkgResult<Self> {
        let rng = rand::rng();

        if parameters.threshold > parameters.limit {
            return Err(Error::Initialization(
                "Threshold greater than limit".to_string(),
            ));
        }
        if parameters.threshold < 2 {
            return Err(Error::Initialization("Threshold less than 1".to_string()));
        }
        if parameters.message_generator.is_identity().into() {
            return Err(Error::Initialization(
                "Invalid message generator".to_string(),
            ));
        }

        let mut powers_of_i = vec![G::Scalar::ONE; parameters.threshold];
        powers_of_i[1] = *id;
        for i in 2..parameters.threshold {
            powers_of_i[i] = powers_of_i[i - 1] * *id;
        }

        let participant_type = I::default().get_type();
        let secret_to_split = match participant_type {
            ParticipantType::Secret => secret,
            ParticipantType::Refresh => IdentifierPrimeField(G::Scalar::ZERO),
        };

        let (shares, verifiers) = vsss_rs::feldman::split_secret_with_participant_generators::<
            SecretShare<G::Scalar>,
            ShareVerifierGroup<G>,
        >(
            parameters.threshold,
            parameters.limit,
            &secret_to_split,
            Some(ValueGroup(parameters.message_generator)),
            rng,
            &parameters.participant_number_generators,
        )?;
        let verifiers = verifiers.iter().skip(1).copied().collect::<Vec<_>>();

        let verifying_share = match participant_type {
            ParticipantType::Secret => verifiers[0].0,
            ParticipantType::Refresh => verifying_share.ok_or(Error::Initialization(
                "Verifying share is required for refresh".to_string(),
            ))?,
        };

        if verifiers.iter().skip(1).any(|c| c.is_identity().into())
            || !I::check_feldman_verifier(*verifiers[0])
        {
            return Err(Error::Initialization(
                "Invalid feldman verifier".to_string(),
            ));
        }

        let ordinal = shares
            .iter()
            .position(|s| s.identifier == id)
            .ok_or_else(|| {
                Error::Initialization(format!(
                    "Invalid participant id '{id}'. Not in generated set of shares"
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
            original_secret: secret.0,
            verifying_share,
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
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }

    /// The identifier associated with this participant
    pub fn id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id
    }

    /// Returns true if this secret_participant is complete
    pub fn completed(&self) -> bool {
        self.completed
    }

    /// Return the current round
    pub fn round(&self) -> Round {
        self.round
    }

    /// Return the set threshold
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Return the set limit
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Computed secret share.
    /// This value is useless until at least 2 rounds have been run
    /// so [`None`] is returned until completion
    pub fn secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        if self.completed {
            Some(self.secret_share)
        } else {
            None
        }
    }

    /// Computed public key
    /// This value is useless until all rounds have been run
    /// so [`None`] is returned until completion
    pub fn public_key(&self) -> Option<G> {
        if self.completed {
            Some(*self.public_key)
        } else {
            None
        }
    }

    /// Return the list of all participants that started the protocol
    pub fn all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.all_participant_ids
    }

    /// Return the list of valid participant ids
    pub fn valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.valid_participant_ids
    }

    /// Return the feldman verifiers
    pub fn feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.feldman_verifiers.clone()
    }

    /// Get the received round 1 data so far
    pub fn received_round1_data(&self) -> &BTreeMap<usize, Round1Data<G>> {
        &self.received_round1_data
    }

    /// Get the received round 2 data so far
    pub fn received_round2_data(&self) -> &BTreeMap<usize, Round2Data<G::Scalar>> {
        &self.received_round2_data
    }

    /// The verifying share used by this participant.
    pub fn verifying_share(&self) -> G {
        self.verifying_share
    }

    /// The final transcript hash over received protocol messages.
    pub fn final_transcript_hash(&self) -> [u8; 32] {
        get_final_transcript_hash(&self.received_round1_data, &self.received_round2_data)
    }

    /// Consume a completed participant and return its final DKG output.
    ///
    /// Consuming the participant avoids cloning its secret share.
    pub fn into_output(self) -> DkgResult<DkgOutput<G>> {
        if !self.completed {
            return Err(Error::Round(
                "Protocol is not complete; no output is available".to_string(),
            ));
        }

        let transcript_hash =
            get_final_transcript_hash(&self.received_round1_data, &self.received_round2_data);
        Ok(DkgOutput {
            secret_share: self.secret_share,
            public_key: self.public_key.0,
            feldman_verifiers: self.feldman_verifiers,
            participant_ids: self.valid_participant_ids,
            transcript_hash,
        })
    }

    /// The ordinal index of this participant.
    #[deprecated(since = "0.6.0", note = "use `ordinal` instead")]
    pub fn get_ordinal(&self) -> usize {
        self.ordinal()
    }

    /// The identifier associated with this participant.
    #[deprecated(since = "0.6.0", note = "use `id` instead")]
    pub fn get_id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id()
    }

    /// Return the current round.
    #[deprecated(since = "0.6.0", note = "use `round` instead")]
    pub fn get_round(&self) -> Round {
        self.round()
    }

    /// Return the set threshold.
    #[deprecated(since = "0.6.0", note = "use `threshold` instead")]
    pub fn get_threshold(&self) -> usize {
        self.threshold()
    }

    /// Return the set limit.
    #[deprecated(since = "0.6.0", note = "use `limit` instead")]
    pub fn get_limit(&self) -> usize {
        self.limit()
    }

    /// Computed secret share, if the protocol is complete.
    #[deprecated(since = "0.6.0", note = "use `secret_share` instead")]
    pub fn get_secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        self.secret_share()
    }

    /// Computed public key, if the protocol is complete.
    #[deprecated(since = "0.6.0", note = "use `public_key` instead")]
    pub fn get_public_key(&self) -> Option<G> {
        self.public_key()
    }

    /// Return the list of all participants that started the protocol.
    #[deprecated(since = "0.6.0", note = "use `all_participant_ids` instead")]
    pub fn get_all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        self.all_participant_ids()
    }

    /// Return the list of valid participant IDs.
    #[deprecated(since = "0.6.0", note = "use `valid_participant_ids` instead")]
    pub fn get_valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        self.valid_participant_ids()
    }

    /// Return the Feldman verifiers.
    #[deprecated(since = "0.6.0", note = "use `feldman_verifiers` instead")]
    pub fn get_feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.feldman_verifiers()
    }

    /// Get the received round 1 data so far.
    #[deprecated(since = "0.6.0", note = "use `received_round1_data` instead")]
    pub fn get_received_round1_data(&self) -> &BTreeMap<usize, Round1Data<G>> {
        self.received_round1_data()
    }

    /// Get the received round 2 data so far.
    #[deprecated(since = "0.6.0", note = "use `received_round2_data` instead")]
    pub fn get_received_round2_data(&self) -> &BTreeMap<usize, Round2Data<G::Scalar>> {
        self.received_round2_data()
    }

    /// Receive data from another participant
    pub fn receive(&mut self, data: &[u8]) -> DkgResult<()> {
        let (&round, payload) = data
            .split_first()
            .ok_or_else(|| Error::InvalidMessage("message is empty".to_string()))?;
        let round = Round::try_from(round).map_err(Error::InvalidMessage)?;
        match round {
            Round::One => {
                let round1_payload = postcard::from_bytes::<Round1Data<G>>(payload)?;
                self.receive_round1data(round1_payload)
            }
            Round::Two => {
                let round2_payload = postcard::from_bytes::<Round2Data<G::Scalar>>(payload)?;
                self.receive_round2data(round2_payload)
            }
            _ => Err(Error::Round("Protocol is complete".to_string())),
        }
    }

    /// Run the next step in the protocol
    pub fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        match self.round {
            Round::One => self.round1(),
            Round::Two => self.round2(),
            Round::Three => self.round3(),
            Round::Four => Err(Error::Round("Protocol is complete".to_string())),
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
                Error::Round(format!(
                    "Round {round}: Unknown sender ordinal, {sender_ordinal}"
                ))
            })?;
        if *id != sender_id {
            return Err(Error::Round(format!(
                "Round {round}: Sender id mismatch, expected '{id}', got '{sender_id}'"
            )));
        }
        if sender_id.is_zero().into() {
            return Err(Error::Round(format!("Round {round}: Sender id is zero")));
        }
        if self.id.ct_eq(&sender_id).into() {
            return Err(Error::Round(format!(
                "Round {round}: Sender id is equal to our id",
            )));
        }
        Ok(())
    }

    pub(crate) fn lagrange(
        share: &SecretShare<G::Scalar>,
        shares_ids: &[IdentifierPrimeField<G::Scalar>],
    ) -> DkgResult<ValuePrimeField<G::Scalar>> {
        if shares_ids
            .iter()
            .map(|id| id.0.to_repr().as_ref().to_vec())
            .collect::<BTreeSet<_>>()
            .len()
            != shares_ids.len()
        {
            return Err(Error::Initialization(
                "participant identifiers must be unique".to_string(),
            ));
        }

        let mut num = G::Scalar::ONE;
        let mut den = G::Scalar::ONE;
        for &x_j in shares_ids.iter() {
            if x_j == share.identifier {
                continue;
            }
            num *= *x_j;
            den *= *x_j - *share.identifier;
        }

        let den_inverse = Option::<G::Scalar>::from(den.invert()).ok_or_else(|| {
            Error::Initialization("participant identifiers must be unique".to_string())
        })?;
        Ok(IdentifierPrimeField(num * den_inverse))
    }
}

/// Secret Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SecretParticipantImpl<G>(PhantomData<G>);

impl<G> ParticipantImpl<G> for SecretParticipantImpl<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    fn get_type(&self) -> ParticipantType {
        ParticipantType::Secret
    }

    fn random_value(mut rng: impl CryptoRng) -> <G as Group>::Scalar {
        G::Scalar::random(&mut rng)
    }

    fn check_feldman_verifier(verifier: G) -> bool {
        verifier.is_identity().unwrap_u8() == 0u8
    }
}

/// Refresh Participant Implementation
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RefreshParticipantImpl<G>(PhantomData<G>);

impl<G> ParticipantImpl<G> for RefreshParticipantImpl<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    fn get_type(&self) -> ParticipantType {
        ParticipantType::Refresh
    }

    fn random_value(_rng: impl CryptoRng) -> <G as Group>::Scalar {
        G::Scalar::ZERO
    }

    fn check_feldman_verifier(verifier: G) -> bool {
        verifier.is_identity().into()
    }
}

/// A trait to allow for dynamic dispatch of the participant
pub trait AnyParticipant<G>: Send + Sync + Debug
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// The ordinal index of this participant.
    fn ordinal(&self) -> usize;
    /// The identifier associated with this participant.
    fn id(&self) -> IdentifierPrimeField<G::Scalar>;
    /// The threshold.
    fn threshold(&self) -> usize;
    /// The participant limit.
    fn limit(&self) -> usize;
    /// The current round.
    fn round(&self) -> Round;
    /// The secret share, if the protocol is complete.
    fn secret_share(&self) -> Option<SecretShare<G::Scalar>>;
    /// The public key, if the protocol is complete.
    fn public_key(&self) -> Option<G>;
    /// The valid participant IDs from the last round.
    fn valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>>;
    /// All participant IDs that started the protocol.
    fn all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>>;
    /// The Feldman verifiers.
    fn feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>>;
    /// The received round 1 data so far.
    fn received_round1_data(&self) -> &BTreeMap<usize, Round1Data<G>>;
    /// The received round 2 data so far.
    fn received_round2_data(&self) -> &BTreeMap<usize, Round2Data<G::Scalar>>;
    /// The verifying share.
    fn verifying_share(&self) -> G;
    /// The final transcript hash.
    fn final_transcript_hash(&self) -> [u8; 32];
    /// Check if the participant is completed
    fn completed(&self) -> bool;
    /// Receive data from another participant
    fn receive(&mut self, data: &[u8]) -> DkgResult<()>;
    /// Run the next round in the protocol after receiving data from other participants
    fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>>;
    /// Consume a completed participant and return its final DKG output.
    fn into_output(self: Box<Self>) -> DkgResult<DkgOutput<G>>;

    /// Get the ordinal index of this participant.
    #[deprecated(since = "0.6.0", note = "use `ordinal` instead")]
    fn get_ordinal(&self) -> usize {
        self.ordinal()
    }

    /// Get the identifier associated with this participant.
    #[deprecated(since = "0.6.0", note = "use `id` instead")]
    fn get_id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id()
    }

    /// Get the threshold.
    #[deprecated(since = "0.6.0", note = "use `threshold` instead")]
    fn get_threshold(&self) -> usize {
        self.threshold()
    }

    /// Get the limit.
    #[deprecated(since = "0.6.0", note = "use `limit` instead")]
    fn get_limit(&self) -> usize {
        self.limit()
    }

    /// Get the current round.
    #[deprecated(since = "0.6.0", note = "use `round` instead")]
    fn get_round(&self) -> Round {
        self.round()
    }

    /// Get the secret share if completed.
    #[deprecated(since = "0.6.0", note = "use `secret_share` instead")]
    fn get_secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        self.secret_share()
    }

    /// Get the public key if completed.
    #[deprecated(since = "0.6.0", note = "use `public_key` instead")]
    fn get_public_key(&self) -> Option<G> {
        self.public_key()
    }

    /// Get the valid participant IDs from the last round.
    #[deprecated(since = "0.6.0", note = "use `valid_participant_ids` instead")]
    fn get_valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        self.valid_participant_ids()
    }

    /// Get all participant IDs that started the protocol.
    #[deprecated(since = "0.6.0", note = "use `all_participant_ids` instead")]
    fn get_all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        self.all_participant_ids()
    }

    /// Return the Feldman verifiers.
    #[deprecated(since = "0.6.0", note = "use `feldman_verifiers` instead")]
    fn get_feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.feldman_verifiers()
    }

    /// Get the received round 1 data so far.
    #[deprecated(since = "0.6.0", note = "use `received_round1_data` instead")]
    fn get_received_round1_data(&self) -> &BTreeMap<usize, Round1Data<G>> {
        self.received_round1_data()
    }

    /// Get the received round 2 data so far.
    #[deprecated(since = "0.6.0", note = "use `received_round2_data` instead")]
    fn get_received_round2_data(&self) -> &BTreeMap<usize, Round2Data<G::Scalar>> {
        self.received_round2_data()
    }

    /// Get the verifying share.
    #[deprecated(since = "0.6.0", note = "use `verifying_share` instead")]
    fn get_verifying_share(&self) -> G {
        self.verifying_share()
    }

    /// Get the final transcript hash.
    #[deprecated(since = "0.6.0", note = "use `final_transcript_hash` instead")]
    fn get_final_transcript_hash(&self) -> [u8; 32] {
        self.final_transcript_hash()
    }
}

impl<G> AnyParticipant<G> for Participant<SecretParticipantImpl<G>, G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    fn ordinal(&self) -> usize {
        self.ordinal
    }

    fn id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id
    }

    fn threshold(&self) -> usize {
        self.threshold
    }

    fn limit(&self) -> usize {
        self.limit
    }

    fn round(&self) -> Round {
        self.round
    }

    fn secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        self.secret_share()
    }

    fn public_key(&self) -> Option<G> {
        self.public_key()
    }

    fn valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.valid_participant_ids
    }

    fn all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.all_participant_ids
    }

    fn feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.feldman_verifiers()
    }

    fn received_round1_data(&self) -> &BTreeMap<usize, Round1Data<G>> {
        &self.received_round1_data
    }

    fn received_round2_data(&self) -> &BTreeMap<usize, Round2Data<G::Scalar>> {
        &self.received_round2_data
    }

    fn verifying_share(&self) -> G {
        self.verifying_share
    }

    fn final_transcript_hash(&self) -> [u8; 32] {
        get_final_transcript_hash(&self.received_round1_data, &self.received_round2_data)
    }

    fn completed(&self) -> bool {
        self.completed()
    }

    fn receive(&mut self, data: &[u8]) -> DkgResult<()> {
        self.receive(data)
    }

    fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        self.run()
    }

    fn into_output(self: Box<Self>) -> DkgResult<DkgOutput<G>> {
        (*self).into_output()
    }
}

impl<G> AnyParticipant<G> for Participant<RefreshParticipantImpl<G>, G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    fn ordinal(&self) -> usize {
        self.ordinal
    }

    fn id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.id
    }

    fn threshold(&self) -> usize {
        self.threshold
    }

    fn limit(&self) -> usize {
        self.limit
    }

    fn round(&self) -> Round {
        self.round
    }

    fn secret_share(&self) -> Option<SecretShare<G::Scalar>> {
        self.secret_share()
    }

    fn public_key(&self) -> Option<G> {
        self.public_key()
    }

    fn valid_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.valid_participant_ids
    }

    fn all_participant_ids(&self) -> &BTreeMap<usize, IdentifierPrimeField<G::Scalar>> {
        &self.all_participant_ids
    }

    fn feldman_verifiers(&self) -> Vec<ShareVerifierGroup<G>> {
        self.feldman_verifiers()
    }

    fn received_round1_data(&self) -> &BTreeMap<usize, Round1Data<G>> {
        &self.received_round1_data
    }

    fn received_round2_data(&self) -> &BTreeMap<usize, Round2Data<G::Scalar>> {
        &self.received_round2_data
    }

    fn verifying_share(&self) -> G {
        self.verifying_share
    }

    fn final_transcript_hash(&self) -> [u8; 32] {
        get_final_transcript_hash(&self.received_round1_data, &self.received_round2_data)
    }

    fn completed(&self) -> bool {
        self.completed()
    }

    fn receive(&mut self, data: &[u8]) -> DkgResult<()> {
        self.receive(data)
    }

    fn run(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        self.run()
    }

    fn into_output(self: Box<Self>) -> DkgResult<DkgOutput<G>> {
        (*self).into_output()
    }
}

fn get_final_transcript_hash<G>(
    received_round1_data: &BTreeMap<usize, Round1Data<G>>,
    received_round2_data: &BTreeMap<usize, Round2Data<G::Scalar>>,
) -> [u8; 32]
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    let mut transcript = merlin::Transcript::new(b"Frost DKG - Final Transcript");
    for round1data in received_round1_data.values() {
        round1data.add_to_transcript(&mut transcript);
    }
    for round2data in received_round2_data.values() {
        round2data.add_to_transcript(&mut transcript);
    }
    let mut transcript_hash = [0u8; 32];
    transcript.challenge_bytes(b"final result", &mut transcript_hash);
    transcript_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, Scalar};
    use std::num::NonZeroUsize;
    use vsss_rs::Share;

    #[test]
    fn receive_rejects_empty_message() {
        let parameters = Parameters::new(
            NonZeroUsize::new(2).expect("threshold is non-zero"),
            NonZeroUsize::new(2).expect("limit is non-zero"),
            None,
            None,
        );
        let mut participant = SecretParticipant::<ProjectivePoint>::new_secret(
            IdentifierPrimeField::ONE,
            &parameters,
        )
        .expect("create participant");

        let result = participant.receive(&[]);

        assert!(
            matches!(result, Err(Error::InvalidMessage(message)) if message == "message is empty")
        );
    }

    #[test]
    fn debug_redacts_secret_state() {
        let parameters = Parameters::new(
            NonZeroUsize::new(2).expect("threshold is non-zero"),
            NonZeroUsize::new(2).expect("limit is non-zero"),
            None,
            None,
        );
        let participant = SecretParticipant::<ProjectivePoint>::new_secret(
            IdentifierPrimeField::ONE,
            &parameters,
        )
        .expect("create participant");

        let debug = format!("{participant:?}");

        assert!(!debug.contains("original_secret"));
        assert!(!debug.contains("secret_share"));
        assert!(!debug.contains("secret_shares"));
        assert!(!debug.contains("received_round2_data"));
    }

    #[test]
    fn output_is_unavailable_before_completion() {
        let parameters = Parameters::new(
            NonZeroUsize::new(2).expect("threshold is non-zero"),
            NonZeroUsize::new(2).expect("limit is non-zero"),
            None,
            None,
        );
        let participant = SecretParticipant::<ProjectivePoint>::new_secret(
            IdentifierPrimeField::ONE,
            &parameters,
        )
        .expect("create participant");

        let result = participant.into_output();

        assert!(matches!(result, Err(Error::Round(message)) if message.contains("not complete")));
    }

    #[test]
    fn lagrange_rejects_duplicate_identifiers() {
        let identifier = IdentifierPrimeField(Scalar::ONE);
        let share =
            SecretShare::with_identifier_and_value(identifier, IdentifierPrimeField(Scalar::ONE));
        let identifiers = [identifier, identifier];

        let result =
            Participant::<SecretParticipantImpl<ProjectivePoint>, ProjectivePoint>::lagrange(
                &share,
                &identifiers,
            );

        assert!(matches!(result, Err(Error::Initialization(_))));
    }
}
