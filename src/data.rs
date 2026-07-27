use super::*;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::subtle::ConditionallySelectable;
use elliptic_curve::{Group, PrimeField};
use elliptic_curve_tools::{SumOfProducts, group, prime_field};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use vsss_rs::{IdentifierPrimeField, ShareVerifierGroup};

/// Valid rounds
#[derive(Copy, Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Round {
    /// First round
    One,
    /// Second round
    Two,
    /// Third round
    Three,
    /// Fourth round
    Four,
}

impl Display for Round {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::One => write!(f, "1"),
            Self::Two => write!(f, "2"),
            Self::Three => write!(f, "3"),
            Self::Four => write!(f, "4"),
        }
    }
}

macro_rules! impl_round_to_int {
    ($($ident:ident),+$(,)*) => {
        $(
            impl From<Round> for $ident {
                fn from(value: Round) -> Self {
                    match value {
                        Round::One => 1,
                        Round::Two => 2,
                        Round::Three => 3,
                        Round::Four => 4,
                    }
                }
            }

            impl TryFrom<$ident> for Round {
                type Error = String;

                fn try_from(value: $ident) -> Result<Self, Self::Error> {
                    match value {
                        1 => Ok(Round::One),
                        2 => Ok(Round::Two),
                        3 => Ok(Round::Three),
                        4 => Ok(Round::Four),
                        _ => Err(format!("Invalid round: {}", value)),
                    }
                }
            }
        )+
    };
}

impl_round_to_int!(u8, u16, u32, u128, usize);

/// The participant type
#[derive(Debug, Copy, Clone, Default, Deserialize, Serialize)]
pub enum ParticipantType {
    /// Secret participant
    #[default]
    Secret,
    /// Refresh participant
    Refresh,
}

macro_rules! impl_participant_to_int {
    ($($ident:ident),+$(,)*) => {
        $(
            impl From<ParticipantType> for $ident {
                fn from(value: ParticipantType) -> Self {
                    match value {
                        ParticipantType::Secret => 1,
                        ParticipantType::Refresh => 2,
                    }
                }
            }

            impl TryFrom<$ident> for ParticipantType {
                type Error = String;

                fn try_from(value: $ident) -> Result<Self, Self::Error> {
                    match value {
                        1 => Ok(ParticipantType::Secret),
                        2 => Ok(ParticipantType::Refresh),
                        _ => Err(format!("Invalid participant type: {}", value)),
                    }
                }
            }
        )+
    };
}

impl_participant_to_int!(u8, u16, u32, u128, usize);

/// The schnorr signature
#[derive(Debug, Default, Copy, Clone, Deserialize, Serialize)]
pub struct Signature<G: Group<Scalar: ScalarHash> + GroupEncoding + Default> {
    #[serde(with = "group")]
    pub(crate) r: G,
    #[serde(with = "prime_field")]
    pub(crate) s: G::Scalar,
}

/// The round output for a participant
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ParticipantRoundOutput<F: ScalarHash> {
    /// The participant ordinal to where the data should be sent
    pub dst_ordinal: usize,
    /// The participant ID to where the data should be sent
    #[serde(bound(
        serialize = "IdentifierPrimeField<F>: Serialize",
        deserialize = "IdentifierPrimeField<F>: Deserialize<'de>"
    ))]
    pub dst_id: IdentifierPrimeField<F>,
    /// The data to send
    pub data: WireMessage,
}

impl<F> ParticipantRoundOutput<F>
where
    F: ScalarHash,
{
    /// Create a new participant round output
    pub fn new(dst_ordinal: usize, dst_id: IdentifierPrimeField<F>, data: WireMessage) -> Self {
        Self {
            dst_ordinal,
            dst_id,
            data,
        }
    }
}

/// The completed output of a DKG participant.
///
/// This type owns the participant's final result and intentionally does not
/// implement [`Clone`] to avoid accidentally duplicating secret share material.
pub struct DkgOutput<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    pub(crate) secret_share: SecretShare<G::Scalar>,
    pub(crate) public_key: G,
    pub(crate) feldman_verifiers: Vec<ShareVerifierGroup<G>>,
    pub(crate) participant_ids: Vec<Option<IdentifierPrimeField<G::Scalar>>>,
    pub(crate) transcript_hash: [u8; 32],
}

impl<G> fmt::Debug for DkgOutput<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkgOutput")
            .field("public_key", &self.public_key)
            .field("feldman_verifiers", &self.feldman_verifiers)
            .field("participant_ids", &self.participant_ids)
            .field("transcript_hash", &self.transcript_hash)
            .finish_non_exhaustive()
    }
}

impl<G> DkgOutput<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// The participant's final secret share.
    pub fn secret_share(&self) -> SecretShare<G::Scalar> {
        self.secret_share
    }

    /// The public key produced by the DKG.
    pub fn public_key(&self) -> G {
        self.public_key
    }

    /// The participant's Feldman verifiers.
    pub fn feldman_verifiers(&self) -> &[ShareVerifierGroup<G>] {
        &self.feldman_verifiers
    }

    /// The participants included in the completed DKG.
    pub fn participant_ids(&self) -> &[Option<IdentifierPrimeField<G::Scalar>>] {
        &self.participant_ids
    }

    /// The final protocol transcript hash.
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }
}

/// An opaque, serialized protocol message.
#[derive(Clone)]
pub struct WireMessage(Arc<[u8]>);

impl WireMessage {
    /// Borrow the serialized message.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow the serialized message as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Vec<u8>> for WireMessage {
    fn from(value: Vec<u8>) -> Self {
        Self(Arc::from(value))
    }
}

impl Serialize for WireMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for WireMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer).map(Self::from)
    }
}

impl AsRef<[u8]> for WireMessage {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for WireMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireMessage")
            .field("len", &self.0.len())
            .finish()
    }
}

fn serialize_round_message<T>(round: Round, value: &T) -> DkgResult<WireMessage>
where
    T: Serialize + ?Sized,
{
    Ok(postcard::to_extend(value, vec![u8::from(round)])?.into())
}

/// The transport destination for an opaque protocol message.
#[derive(Clone, Debug)]
pub enum MessageDestination<F: ScalarHash> {
    /// Send the message through the application's broadcast channel.
    Broadcast,
    /// Send the message only to the specified participant.
    Direct {
        /// The recipient's ordinal index.
        ordinal: usize,
        /// The recipient's identifier.
        id: IdentifierPrimeField<F>,
    },
}

/// An opaque outbound protocol message and its transport destination.
#[derive(Clone, Debug)]
pub struct OutboundMessage<F: ScalarHash> {
    destination: MessageDestination<F>,
    message: WireMessage,
}

impl<F: ScalarHash> OutboundMessage<F> {
    /// The transport destination for this message.
    pub fn destination(&self) -> &MessageDestination<F> {
        &self.destination
    }

    /// The opaque bytes to send.
    pub fn message(&self) -> &WireMessage {
        &self.message
    }
}

/// The outbound messages produced by one protocol round.
#[derive(Clone, Debug)]
pub struct OutboundMessages<F: ScalarHash> {
    messages: Vec<OutboundMessage<F>>,
    broadcast_recipients: Vec<Option<IdentifierPrimeField<F>>>,
}

impl<F: ScalarHash> OutboundMessages<F> {
    /// The transport-aware messages produced by the round.
    pub fn messages(&self) -> &[OutboundMessage<F>] {
        &self.messages
    }

    /// The number of transport-aware messages in this batch.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether this batch contains no messages.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Iterate over the transport-aware messages in this batch.
    pub fn iter(&self) -> std::slice::Iter<'_, OutboundMessage<F>> {
        self.messages.iter()
    }

    /// Expand broadcasts into participant-targeted messages.
    ///
    /// This is useful for transports that do not provide native broadcast.
    pub fn into_per_recipient(self) -> Vec<ParticipantRoundOutput<F>> {
        let mut outputs = Vec::new();
        for message in self.messages {
            match message.destination {
                MessageDestination::Broadcast => {
                    outputs.extend(self.broadcast_recipients.iter().enumerate().filter_map(
                        |(ordinal, id)| {
                            id.map(|id| {
                                ParticipantRoundOutput::new(ordinal, id, message.message.clone())
                            })
                        },
                    ));
                }
                MessageDestination::Direct { ordinal, id } => {
                    outputs.push(ParticipantRoundOutput::new(ordinal, id, message.message));
                }
            }
        }
        outputs
    }
}

impl<F: ScalarHash> IntoIterator for OutboundMessages<F> {
    type Item = OutboundMessage<F>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.messages.into_iter()
    }
}

impl<'a, F: ScalarHash> IntoIterator for &'a OutboundMessages<F> {
    type Item = &'a OutboundMessage<F>;
    type IntoIter = std::slice::Iter<'a, OutboundMessage<F>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The result of advancing a participant by one protocol round.
#[derive(Clone, Debug)]
pub enum AdvanceResult<F: ScalarHash> {
    /// Messages that must be delivered before advancing again.
    Messages(OutboundMessages<F>),
    /// The participant has completed the protocol and can be converted into
    /// [`DkgOutput`] with `Participant::into_output`.
    Complete,
}

/// The round output generator
#[derive(Debug, Clone)]
pub enum RoundOutputGenerator<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// The round 1 output generator
    Round1(Round1OutputGenerator<G>),
    /// The round 2 output generator
    Round2(Round2OutputGenerator<G>),
    /// The round 3 output generator
    Round3,
}

impl<G> RoundOutputGenerator<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// Serialize the round output into opaque, transport-aware messages.
    pub fn into_messages(self) -> DkgResult<OutboundMessages<G::Scalar>> {
        match self {
            Self::Round1(data) => {
                let round1_output_data = Round1Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    sender_type: data.sender_type,
                    feldman_commitments: data.feldman_commitments,
                    verifying_share: data.verifying_share,
                    signature: data.signature,
                };
                let mut broadcast_recipients = data
                    .participant_ids
                    .into_iter()
                    .map(Some)
                    .collect::<Vec<_>>();
                broadcast_recipients[data.sender_ordinal] = None;
                Ok(OutboundMessages {
                    messages: vec![OutboundMessage {
                        destination: MessageDestination::Broadcast,
                        message: serialize_round_message(Round::One, &round1_output_data)?,
                    }],
                    broadcast_recipients,
                })
            }
            Self::Round2(data) => {
                let mut messages = Vec::with_capacity(data.participant_ids.len().saturating_sub(1));
                for (ordinal, id) in data.participant_ids.into_iter().enumerate() {
                    if ordinal == data.sender_ordinal {
                        continue;
                    }
                    let Some(id) = id else {
                        continue;
                    };
                    debug_assert_eq!(data.secret_shares[ordinal].identifier, id);
                    let round2_output_data = Round2Data {
                        sender_ordinal: data.sender_ordinal,
                        sender_id: data.sender_id,
                        sender_type: data.sender_type,
                        secret_share: data.secret_shares[ordinal],
                        transcript_hash: data.transcript_hash,
                    };
                    messages.push(OutboundMessage {
                        destination: MessageDestination::Direct { ordinal, id },
                        message: serialize_round_message(Round::Two, &round2_output_data)?,
                    });
                }
                Ok(OutboundMessages {
                    messages,
                    broadcast_recipients: Vec::new(),
                })
            }
            Self::Round3 => Ok(OutboundMessages {
                messages: Vec::new(),
                broadcast_recipients: Vec::new(),
            }),
        }
    }

    /// Iterate over the data to send to other participants
    /// The output is data that the caller sends the data to participant
    /// at ordinal index with id.
    pub fn iter(&self) -> DkgResult<std::vec::IntoIter<ParticipantRoundOutput<G::Scalar>>> {
        let outputs = match self {
            Self::Round1(data) => {
                let round1_output_data = Round1Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    sender_type: data.sender_type,
                    feldman_commitments: data.feldman_commitments.clone(),
                    verifying_share: data.verifying_share,
                    signature: data.signature,
                };
                let output = serialize_round_message(Round::One, &round1_output_data)?;
                data.participant_ids
                    .iter()
                    .enumerate()
                    .filter_map(|(index, id)| {
                        if index == data.sender_ordinal {
                            None
                        } else {
                            Some(ParticipantRoundOutput::new(index, *id, output.clone()))
                        }
                    })
                    .collect()
            }
            Self::Round2(data) => {
                let mut round2_output_data = Round2Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    sender_type: data.sender_type,
                    secret_share: SecretShare::<G::Scalar>::default(),
                    transcript_hash: data.transcript_hash,
                };
                let mut outputs = Vec::with_capacity(data.participant_ids.len().saturating_sub(1));
                for (index, id) in data.participant_ids.iter().enumerate() {
                    if index == data.sender_ordinal {
                        continue;
                    }
                    let Some(id) = id else {
                        continue;
                    };
                    debug_assert_eq!(data.secret_shares[index].identifier, *id);
                    round2_output_data.secret_share = data.secret_shares[index];
                    let output = serialize_round_message(Round::Two, &round2_output_data)?;
                    outputs.push(ParticipantRoundOutput::new(index, *id, output));
                }
                outputs
            }
            Self::Round3 => Vec::new(),
        };
        Ok(outputs.into_iter())
    }
}

/// The output generator for round 0
#[derive(Debug, Clone)]
pub struct Round1OutputGenerator<G>
where
    G: GroupEncoding + Default + SumOfProducts + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// The participant IDs to send to
    pub(crate) participant_ids: Vec<IdentifierPrimeField<G::Scalar>>,
    /// The sender's participant type
    pub(crate) sender_type: ParticipantType,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: IdentifierPrimeField<G::Scalar>,
    /// The feldman verifier set
    pub(crate) feldman_commitments: Vec<ShareVerifierGroup<G>>,
    /// The verifying share
    pub(crate) verifying_share: G,
    /// The schnorr signature
    pub(crate) signature: Signature<G>,
}

/// The round 1 data
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Round1Data<G>
where
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    #[serde(bound(
        serialize = "IdentifierPrimeField<G::Scalar>: Serialize",
        deserialize = "IdentifierPrimeField<G::Scalar>: Deserialize<'de>"
    ))]
    pub(crate) sender_id: IdentifierPrimeField<G::Scalar>,
    /// The sender's participant type
    pub(crate) sender_type: ParticipantType,
    /// The feldman commitments
    #[serde(bound(
        serialize = "ShareVerifierGroup<G>: Serialize",
        deserialize = "ShareVerifierGroup<G>: Deserialize<'de>"
    ))]
    pub(crate) feldman_commitments: Vec<ShareVerifierGroup<G>>,
    /// The verifying share
    #[serde(with = "group")]
    pub(crate) verifying_share: G,
    /// The schnorr signature
    #[serde(bound(
        serialize = "Signature<G>: Serialize",
        deserialize = "Signature<G>: Deserialize<'de>"
    ))]
    pub(crate) signature: Signature<G>,
}

impl<G> Round1Data<G>
where
    G: GroupEncoding + Default + SumOfProducts + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    pub(crate) fn add_to_transcript(&self, transcript: &mut merlin::Transcript) {
        transcript.append_message(
            b"sender_ordinal",
            &(self.sender_ordinal as u16).to_be_bytes(),
        );
        transcript.append_message(b"sender_id", self.sender_id.0.to_repr().as_ref());
        transcript.append_message(b"sender_type", &u16::from(self.sender_type).to_be_bytes());
        transcript.append_message(b"signature.r", self.signature.r.to_bytes().as_ref());
        transcript.append_message(b"signature.s", self.signature.s.to_repr().as_ref());
        transcript.append_message(
            b"feldman_commitments.len()",
            &(self.feldman_commitments.len() as u16).to_be_bytes(),
        );
        for (i, commitment) in self.feldman_commitments.iter().enumerate() {
            transcript.append_u64(b"feldman_commitments_index", i as u64);
            transcript.append_message(b"feldman_commitment", commitment.to_bytes().as_ref());
        }
    }

    /// Get the sender's ordinal index during the DKG
    pub fn sender_ordinal(&self) -> usize {
        self.sender_ordinal
    }

    /// Get the sender's ID during the DKG
    pub fn sender_id(&self) -> IdentifierPrimeField<G::Scalar> {
        self.sender_id
    }

    /// Get the sender's participant type during the DKG
    pub fn sender_type(&self) -> ParticipantType {
        self.sender_type
    }

    /// Get the feldman commitments used by the DKG
    pub fn feldman_commitments(&self) -> &[ShareVerifierGroup<G>] {
        &self.feldman_commitments
    }

    /// Get the signature verifying share used by the DKG
    pub fn verifying_share(&self) -> G {
        self.verifying_share
    }

    /// Get the schnorr signature used by the DKG
    pub fn signature(&self) -> Signature<G> {
        self.signature
    }
}

/// The output generator for round 2
#[derive(Debug, Clone)]
pub struct Round2OutputGenerator<G>
where
    G: GroupEncoding + Default + SumOfProducts + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// The participant IDs to send to
    pub(crate) participant_ids: Vec<Option<IdentifierPrimeField<G::Scalar>>>,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: IdentifierPrimeField<G::Scalar>,
    /// The sender's participant type
    pub(crate) sender_type: ParticipantType,
    /// The peer 2 peer data based on the participant ordinal index
    pub(crate) secret_shares: Vec<SecretShare<G::Scalar>>,
    /// The transcript hash
    pub(crate) transcript_hash: [u8; 32],
}

/// The round 2 data
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Round2Data<F: ScalarHash> {
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    #[serde(bound(
        serialize = "IdentifierPrimeField<F>: Serialize",
        deserialize = "IdentifierPrimeField<F>: Deserialize<'de>"
    ))]
    pub(crate) sender_id: IdentifierPrimeField<F>,
    /// The sender's participant type
    pub(crate) sender_type: ParticipantType,
    /// The peer 2 peer data
    #[serde(bound(
        serialize = "SecretShare<F>: Serialize",
        deserialize = "SecretShare<F>: Deserialize<'de>"
    ))]
    pub(crate) secret_share: SecretShare<F>,
    /// The transcript of all messages received
    pub(crate) transcript_hash: [u8; 32],
}

impl<F: ScalarHash> Round2Data<F> {
    pub(crate) fn add_to_transcript(&self, transcript: &mut merlin::Transcript) {
        transcript.append_message(
            b"sender_ordinal",
            &(self.sender_ordinal as u16).to_be_bytes(),
        );
        transcript.append_message(b"sender_id", self.sender_id.0.to_repr().as_ref());
        transcript.append_message(b"sender_type", &u16::from(self.sender_type).to_be_bytes());
        transcript.append_message(b"transcript_hash", &self.transcript_hash);
    }

    /// Get the sender's ordinal index during the DKG
    pub fn sender_ordinal(&self) -> usize {
        self.sender_ordinal
    }

    /// Get the sender's ID during the DKG
    pub fn sender_id(&self) -> IdentifierPrimeField<F> {
        self.sender_id
    }

    /// Get the sender's participant type during the DKG
    pub fn sender_type(&self) -> ParticipantType {
        self.sender_type
    }

    /// Get the secret share used by the DKG
    pub fn secret_share(&self) -> SecretShare<F> {
        self.secret_share
    }

    /// Get the transcript hash used by the DKG
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_round_message_prefixes_payload_without_changing_it() {
        let message =
            serialize_round_message(Round::Two, &42_u16).expect("serialize framed payload");

        assert_eq!(message.as_bytes().first(), Some(&u8::from(Round::Two)));
        assert_eq!(
            postcard::from_bytes::<u16>(&message.as_bytes()[1..]).expect("deserialize payload"),
            42
        );
    }

    #[test]
    fn participant_round_output_postcard_round_trip() {
        let output = ParticipantRoundOutput::<k256::Scalar>::new(
            1,
            IdentifierPrimeField(k256::Scalar::ONE),
            vec![1, 2, 3].into(),
        );

        let encoded = postcard::to_stdvec(&output).expect("serialize round output");
        let decoded = postcard::from_bytes::<ParticipantRoundOutput<k256::Scalar>>(&encoded)
            .expect("deserialize round output");

        assert_eq!(decoded.dst_ordinal, output.dst_ordinal);
        assert_eq!(decoded.dst_id, output.dst_id);
        assert_eq!(decoded.data.as_bytes(), output.data.as_bytes());
    }
}
