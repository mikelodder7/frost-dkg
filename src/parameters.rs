use super::*;
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::subtle::ConditionallySelectable;
use elliptic_curve_tools::SumOfProducts;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use vsss_rs::{IdentifierPrimeField, ParticipantIdGenerator, ParticipantIdGeneratorCollection};

/// The parameters used by the DKG participants.
/// This must be the same for all of them otherwise the protocol
/// will abort.
#[derive(Debug, Clone)]
pub struct Parameters<'a, G>
where
    G: GroupEncoding + Default + SumOfProducts + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    pub(crate) threshold: usize,
    pub(crate) limit: usize,
    pub(crate) message_generator: G,
    pub(crate) participant_number_generators:
        Vec<ParticipantIdGenerator<'a, IdentifierPrimeField<G::Scalar>>>,
}

impl<'a, G> Parameters<'a, G>
where
    G: GroupEncoding + Default + SumOfProducts + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    /// Create validated parameters using the group's default generator and
    /// sequential participant identifiers.
    pub fn new(threshold: NonZeroUsize, limit: NonZeroUsize) -> DkgResult<Self> {
        let parameters = Self {
            threshold: threshold.get(),
            limit: limit.get(),
            message_generator: G::generator(),
            participant_number_generators: vec![ParticipantIdGenerator::Sequential {
                start: IdentifierPrimeField::ONE,
                increment: IdentifierPrimeField::ONE,
                count: limit.get(),
            }],
        };
        parameters.validate()?;
        Ok(parameters)
    }

    /// Use a custom message generator.
    pub fn with_message_generator(mut self, message_generator: G) -> DkgResult<Self> {
        self.message_generator = message_generator;
        self.validate()?;
        Ok(self)
    }

    /// Use custom participant identifier generators.
    pub fn with_participant_number_generators(
        mut self,
        participant_number_generators: Vec<
            ParticipantIdGenerator<'a, IdentifierPrimeField<G::Scalar>>,
        >,
    ) -> DkgResult<Self> {
        self.participant_number_generators = participant_number_generators;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> DkgResult<()> {
        if self.threshold < 2 {
            return Err(Error::Initialization(
                "Threshold must be at least 2".to_string(),
            ));
        }
        if self.threshold > self.limit {
            return Err(Error::Initialization(
                "Threshold cannot exceed the participant limit".to_string(),
            ));
        }
        if self.message_generator.is_identity().into() {
            return Err(Error::Initialization(
                "Message generator cannot be the identity".to_string(),
            ));
        }

        let participant_ids =
            ParticipantIdGeneratorCollection::from(&self.participant_number_generators)
                .iter()
                .take(self.limit)
                .collect::<Vec<_>>();
        if participant_ids.len() != self.limit {
            return Err(Error::Initialization(format!(
                "Participant ID generators produced {} identifiers, expected {}",
                participant_ids.len(),
                self.limit
            )));
        }
        let unique_ids = participant_ids.iter().copied().collect::<HashSet<_>>();
        if unique_ids.len() != participant_ids.len() {
            return Err(Error::Initialization(
                "Participant identifiers must be unique".to_string(),
            ));
        }
        Ok(())
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

    /// Get the participant number generators.
    pub fn participant_number_generators(
        &self,
    ) -> &[ParticipantIdGenerator<'a, IdentifierPrimeField<G::Scalar>>] {
        &self.participant_number_generators
    }

    /// Get the participant number generators.
    #[deprecated(since = "0.6.0", note = "use `participant_number_generators` instead")]
    pub fn participant_number_generator(
        &self,
    ) -> &[ParticipantIdGenerator<'a, IdentifierPrimeField<G::Scalar>>] {
        self.participant_number_generators()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn new_creates_valid_default_parameters() {
        let parameters = Parameters::<ProjectivePoint>::new(
            NonZeroUsize::new(2).expect("threshold is non-zero"),
            NonZeroUsize::new(3).expect("limit is non-zero"),
        )
        .expect("valid parameters");

        assert_eq!(parameters.threshold(), 2);
        assert_eq!(parameters.limit(), 3);
        assert_eq!(parameters.message_generator(), ProjectivePoint::GENERATOR);
        assert_eq!(parameters.participant_number_generators().len(), 1);
    }

    #[test]
    fn new_rejects_invalid_thresholds() {
        let below_minimum = Parameters::<ProjectivePoint>::new(
            NonZeroUsize::new(1).expect("threshold is non-zero"),
            NonZeroUsize::new(2).expect("limit is non-zero"),
        );
        assert!(
            matches!(below_minimum, Err(Error::Initialization(message)) if message.contains("at least 2"))
        );

        let above_limit = Parameters::<ProjectivePoint>::new(
            NonZeroUsize::new(3).expect("threshold is non-zero"),
            NonZeroUsize::new(2).expect("limit is non-zero"),
        );
        assert!(
            matches!(above_limit, Err(Error::Initialization(message)) if message.contains("cannot exceed"))
        );
    }

    #[test]
    fn custom_message_generator_is_validated() {
        let parameters = Parameters::<ProjectivePoint>::new(
            NonZeroUsize::new(2).expect("threshold is non-zero"),
            NonZeroUsize::new(3).expect("limit is non-zero"),
        )
        .expect("valid parameters");

        let result = parameters.with_message_generator(ProjectivePoint::IDENTITY);

        assert!(
            matches!(result, Err(Error::Initialization(message)) if message.contains("identity"))
        );
    }

    #[test]
    fn custom_participant_identifiers_are_validated() {
        let ids = [
            IdentifierPrimeField(Scalar::ONE),
            IdentifierPrimeField(Scalar::from(2u64)),
            IdentifierPrimeField(Scalar::from(3u64)),
        ];
        let parameters = Parameters::<ProjectivePoint>::new(
            NonZeroUsize::new(2).expect("threshold is non-zero"),
            NonZeroUsize::new(3).expect("limit is non-zero"),
        )
        .expect("valid parameters")
        .with_participant_number_generators(vec![ParticipantIdGenerator::list(&ids)])
        .expect("valid participant identifiers");
        assert_eq!(parameters.participant_number_generators().len(), 1);

        let duplicate_ids = [ids[0], ids[0], ids[2]];
        let duplicate_result = Parameters::<ProjectivePoint>::new(
            NonZeroUsize::new(2).expect("threshold is non-zero"),
            NonZeroUsize::new(3).expect("limit is non-zero"),
        )
        .expect("valid parameters")
        .with_participant_number_generators(vec![ParticipantIdGenerator::list(&duplicate_ids)]);
        assert!(
            matches!(duplicate_result, Err(Error::Initialization(message)) if message.contains("unique"))
        );
    }
}
