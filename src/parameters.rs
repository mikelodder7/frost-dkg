use super::*;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve_tools::SumOfProducts;
use std::num::NonZeroUsize;
use vsss_rs::{IdentifierPrimeField, ParticipantIdGeneratorType};

/// The parameters used by the DKG participants.
/// This must be the same for all of them otherwise the protocol
/// will abort.
#[derive(Debug, Default, Clone)]
pub struct Parameters<'a, G>
where
    G: GroupEncoding + Default + SumOfProducts,
    G::Scalar: ScalarHash,
{
    pub(crate) threshold: usize,
    pub(crate) limit: usize,
    pub(crate) message_generator: G,
    pub(crate) participant_number_generators:
        Vec<ParticipantIdGeneratorType<'a, IdentifierPrimeField<G::Scalar>>>,
}

impl<'a, G> Parameters<'a, G>
where
    G: GroupEncoding + Default + SumOfProducts,
    G::Scalar: ScalarHash,
{
    /// Create regular parameters with the message_generator as the default generator
    /// and a random blinder_generator
    pub fn new(
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
        message_generator: Option<G>,
        participant_number_generator: Option<
            Vec<ParticipantIdGeneratorType<'a, IdentifierPrimeField<G::Scalar>>>,
        >,
    ) -> Self {
        let message_generator = message_generator.unwrap_or_else(G::generator);
        let participant_number_generator = participant_number_generator.unwrap_or_else(|| {
            vec![ParticipantIdGeneratorType::Sequential {
                start: IdentifierPrimeField::ONE,
                increment: IdentifierPrimeField::ONE,
                count: limit.get(),
            }]
        });
        Self {
            threshold: threshold.get(),
            limit: limit.get(),
            message_generator,
            participant_number_generators: participant_number_generator,
        }
    }

    /// The threshold parameter
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The limit parameter
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Get the message generator
    pub fn message_generator(&self) -> G {
        self.message_generator
    }

    /// Get the participant number generator
    pub fn participant_number_generator(
        &self,
    ) -> &[ParticipantIdGeneratorType<'a, IdentifierPrimeField<G::Scalar>>] {
        &self.participant_number_generators
    }
}
