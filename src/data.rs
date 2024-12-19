use super::*;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::{Group, PrimeField};
use elliptic_curve_tools::{group, prime_field, SumOfProducts};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
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
    pub dst_id: IdentifierPrimeField<F>,
    /// The data to send
    pub data: Vec<u8>,
}

impl<F> ParticipantRoundOutput<F>
where
    F: ScalarHash,
{
    /// Create a new participant round output
    pub fn new(dst_ordinal: usize, dst_id: IdentifierPrimeField<F>, data: Vec<u8>) -> Self {
        Self {
            dst_ordinal,
            dst_id,
            data,
        }
    }
}

/// The round output generator
#[derive(Debug, Clone)]
pub enum RoundOutputGenerator<G>
where
    G: SumOfProducts + GroupEncoding + Default,
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
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    /// Iterate over the data to send to other participants
    /// The output is data that the caller sends the data to participant
    /// at ordinal index with id.
    pub fn iter(&self) -> Box<dyn Iterator<Item = ParticipantRoundOutput<G::Scalar>> + '_> {
        match self {
            Self::Round1(data) => {
                let round1_output_data = Round1Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    sender_type: data.sender_type,
                    feldman_commitments: data.feldman_commitments.clone(),
                    signature: data.signature,
                };
                let mut output =
                    postcard::to_stdvec(&round1_output_data).expect("to serialize into bytes");
                output.insert(0, u8::from(Round::One));
                Box::new(data.participant_ids.iter().filter_map(move |(index, id)| {
                    if *index == data.sender_ordinal {
                        None
                    } else {
                        Some(ParticipantRoundOutput::new(*index, *id, output.clone()))
                    }
                }))
            }
            Self::Round2(data) => {
                let mut round2_output_data = Round2Data {
                    sender_ordinal: data.sender_ordinal,
                    sender_id: data.sender_id,
                    sender_type: data.sender_type,
                    secret_share: SecretShare::<G::Scalar>::default(),
                    transcript_hash: data.transcript_hash,
                };
                Box::new(data.participant_ids.iter().filter_map(move |(index, &id)| {
                    if *index == data.sender_ordinal {
                        return None;
                    }
                    debug_assert_eq!(data.secret_shares[index].identifier, id);
                    round2_output_data.secret_share = data.secret_shares[index];
                    let mut output =
                        postcard::to_stdvec(&round2_output_data).expect("to serialize into bytes");
                    output.insert(0, u8::from(Round::Two));
                    Some(ParticipantRoundOutput::new(*index, id, output))
                }))
            }
            Self::Round3 => Box::new(std::iter::empty()),
        }
    }
}

/// The output generator for round 0
#[derive(Debug, Clone)]
pub struct Round1OutputGenerator<G>
where
    G: GroupEncoding + Default + SumOfProducts,
    G::Scalar: ScalarHash,
{
    /// The participant IDs to send to
    pub(crate) participant_ids: BTreeMap<usize, IdentifierPrimeField<G::Scalar>>,
    /// The sender's participant type
    pub(crate) sender_type: ParticipantType,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: IdentifierPrimeField<G::Scalar>,
    /// The feldman verifier set
    pub(crate) feldman_commitments: Vec<ShareVerifierGroup<G>>,
    /// The schnorr signature
    pub(crate) signature: Signature<G>,
}

/// The round 1 data
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Round1Data<G>
where
    G: SumOfProducts + GroupEncoding + Default,
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
    /// The schnorr signature
    #[serde(bound(
        serialize = "Signature<G>: Serialize",
        deserialize = "Signature<G>: Deserialize<'de>"
    ))]
    pub(crate) signature: Signature<G>,
}

impl<G> Round1Data<G>
where
    G: GroupEncoding + Default + SumOfProducts,
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
}

/// The output generator for round 2
#[derive(Debug, Clone)]
pub struct Round2OutputGenerator<G>
where
    G: GroupEncoding + Default + SumOfProducts,
    G::Scalar: ScalarHash,
{
    /// The participant IDs to send to
    pub(crate) participant_ids: BTreeMap<usize, IdentifierPrimeField<G::Scalar>>,
    /// The sender's ordinal index
    pub(crate) sender_ordinal: usize,
    /// The sender's ID
    pub(crate) sender_id: IdentifierPrimeField<G::Scalar>,
    /// The sender's participant type
    pub(crate) sender_type: ParticipantType,
    /// The peer 2 peer data based on the participant ordinal index
    pub(crate) secret_shares: BTreeMap<usize, SecretShare<G::Scalar>>,
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
    pub secret_share: SecretShare<F>,
    /// The transcript of all messages received
    pub transcript_hash: [u8; 32],
}
