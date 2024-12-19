use crate::{
    DkgResult, Error, Participant, ParticipantImpl, Round, Round2Data, Round2OutputGenerator,
    RoundOutputGenerator, ScalarHash,
};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve_tools::SumOfProducts;
use std::collections::BTreeMap;

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    pub(crate) fn round2_ready(&self) -> bool {
        self.round == Round::Two && self.received_round1_data.len() >= self.threshold
    }

    pub(crate) fn round2(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round2_ready() {
            return Err(Error::RoundError(format!("Round 2 is not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round1_data.len())));
        }

        let mut valid_participant_ids = BTreeMap::new();
        let mut transcript = merlin::Transcript::new(b"Frost DKG - Round 2 Transcript");
        for round1data in self.received_round1_data.values() {
            round1data.add_to_transcript(&mut transcript);
            valid_participant_ids.insert(round1data.sender_ordinal, round1data.sender_id);
        }
        let mut transcript_hash = [0u8; 32];
        transcript.challenge_bytes(b"round 2 result", &mut transcript_hash);
        self.received_round2_data.insert(
            self.ordinal,
            Round2Data {
                sender_ordinal: self.ordinal,
                sender_id: self.id,
                sender_type: self.participant_impl.get_type(),
                secret_share: self.secret_share,
                transcript_hash,
            },
        );

        self.round = Round::Three;
        Ok(RoundOutputGenerator::Round2(Round2OutputGenerator {
            participant_ids: valid_participant_ids,
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            sender_type: self.participant_impl.get_type(),
            secret_shares: self.secret_shares.clone(),
            transcript_hash,
        }))
    }

    pub(crate) fn receive_round2data(&mut self, data: Round2Data<G::Scalar>) -> DkgResult<()> {
        if self.round > Round::Three {
            return Err(Error::RoundError(format!(
                "Round {}: Invalid round payload received",
                Round::Two
            )));
        }
        self.check_sending_participant_id(Round::Two, data.sender_ordinal, data.sender_id)?;
        if !self
            .valid_participant_ids
            .contains_key(&data.sender_ordinal)
        {
            return Err(Error::RoundError(format!(
                "Round {}: Not a valid participant",
                Round::Two
            )));
        }
        if self.received_round2_data.contains_key(&data.sender_ordinal) {
            return Err(Error::RoundError(format!(
                "Round {}: Sender has already sent data",
                Round::Two
            )));
        }
        let self_data = self
            .received_round2_data
            .get(&self.ordinal)
            .ok_or_else(|| {
                Error::RoundError(format!(
                    "Round {}: Self doesn't have round 2 data",
                    Round::Two
                ))
            })?;
        if data.transcript_hash != self_data.transcript_hash {
            return Err(Error::RoundError(format!(
                "Round {}: Transcript hash does not match",
                Round::Two
            )));
        }

        let round1_data = self
            .received_round1_data
            .get(&data.sender_ordinal)
            .ok_or_else(|| {
                Error::RoundError(format!(
                    "Round {}: Sender has not sent round 1 data",
                    Round::Two
                ))
            })?;

        // verify the share
        let input = self
            .powers_of_i
            .iter()
            .copied()
            .zip(round1_data.feldman_commitments.iter().map(|g| **g))
            .collect::<Vec<(G::Scalar, G)>>();
        let rhs = <G as SumOfProducts>::sum_of_products(&input);
        let lhs = self.message_generator * data.secret_share.value.0;
        if !bool::from((lhs - rhs).is_identity()) {
            return Err(Error::RoundError(format!(
                "Round {}: The share does not verify with the given commitments",
                Round::Three
            )));
        }
        self.received_round2_data.insert(data.sender_ordinal, data);
        Ok(())
    }
}
