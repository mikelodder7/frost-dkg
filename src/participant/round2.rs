use crate::{
    DkgResult, Error, Participant, ParticipantImpl, Round, Round2Data, Round2OutputGenerator,
    RoundOutputGenerator, ScalarHash,
};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::subtle::ConditionallySelectable;
use elliptic_curve_tools::SumOfProducts;

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default + ConditionallySelectable,
    G::Scalar: ScalarHash,
{
    pub(crate) fn round2_ready(&self) -> bool {
        self.round == Round::Two
            && self.received_round1_data.iter().flatten().count() >= self.threshold
    }

    pub(crate) fn round2(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round2_ready() {
            return Err(Error::Round(format!(
                "Round 2 is not ready: not enough data has been received from other participants; need {} more",
                self.threshold - self.received_round1_data.iter().flatten().count()
            )));
        }

        let mut valid_participant_ids = vec![None; self.limit];
        let mut transcript = merlin::Transcript::new(b"Frost DKG - Round 2 Transcript");
        for round1data in self.received_round1_data.iter().flatten() {
            round1data.add_to_transcript(&mut transcript);
            valid_participant_ids[round1data.sender_ordinal] = Some(round1data.sender_id);
        }
        self.valid_participant_ids = valid_participant_ids.clone();
        let mut transcript_hash = [0u8; 32];
        transcript.challenge_bytes(b"round 2 result", &mut transcript_hash);
        self.received_round2_data[self.ordinal] = Some(Round2Data {
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            sender_type: self.participant_impl.get_type(),
            secret_share: self.secret_shares[self.ordinal],
            transcript_hash,
        });

        self.round = Round::Three;
        Ok(RoundOutputGenerator::Round2(Round2OutputGenerator {
            participant_ids: valid_participant_ids,
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            sender_type: self.participant_impl.get_type(),
            secret_shares: std::mem::take(&mut self.secret_shares),
            transcript_hash,
        }))
    }

    pub(crate) fn receive_round2data(&mut self, data: Round2Data<G::Scalar>) -> DkgResult<()> {
        if self.round > Round::Three {
            return Err(Error::Round(format!(
                "Round {}: invalid round payload received",
                Round::Two
            )));
        }
        self.check_sending_participant_id(Round::Two, data.sender_ordinal, data.sender_id)?;
        if !self
            .valid_participant_ids
            .get(data.sender_ordinal)
            .is_some_and(Option::is_some)
        {
            return Err(Error::Round(format!(
                "Round {}: sender is not a valid participant",
                Round::Two
            )));
        }
        if self
            .received_round2_data
            .get(data.sender_ordinal)
            .is_some_and(Option::is_some)
        {
            return Err(Error::Round(format!(
                "Round {}: sender has already sent data",
                Round::Two
            )));
        }
        let self_data = self
            .received_round2_data
            .get(self.ordinal)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                Error::Round(format!(
                    "Round {}: participant does not have its own round 2 data",
                    Round::Two
                ))
            })?;
        if data.transcript_hash != self_data.transcript_hash {
            return Err(Error::Round(format!(
                "Round {}: transcript hash does not match",
                Round::Two
            )));
        }

        let round1_data = self
            .received_round1_data
            .get(data.sender_ordinal)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                Error::Round(format!(
                    "Round {}: sender has not sent round 1 data",
                    Round::Two
                ))
            })?;

        // Verify the share.
        let rhs = <G as SumOfProducts>::sum_of_products_iter(
            self.powers_of_i
                .iter()
                .copied()
                .zip(round1_data.feldman_commitments.iter().map(|g| **g)),
        );
        let lhs = self.message_generator * data.secret_share.value.0;
        if !bool::from((lhs - rhs).is_identity()) {
            return Err(Error::Round(format!(
                "Round {}: The share does not verify with the given commitments",
                Round::Three
            )));
        }
        let sender_ordinal = data.sender_ordinal;
        self.received_round2_data[sender_ordinal] = Some(data);
        Ok(())
    }
}
