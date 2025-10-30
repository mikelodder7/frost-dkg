use crate::{
    DkgResult, Error, Participant, ParticipantImpl, ParticipantType, RefreshParticipantImpl, Round,
    Round1Data, Round1OutputGenerator, RoundOutputGenerator, ScalarHash, SecretParticipantImpl,
    Signature,
};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::subtle::Choice;
use elliptic_curve_tools::SumOfProducts;

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    pub(crate) fn round1(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        let k = I::random_value(rand_core::OsRng);
        let r_i = self.message_generator * k;
        let signature = self.compute_signature(k, r_i);

        let self_round1_data = Round1Data {
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            sender_type: self.participant_impl.get_type(),
            feldman_commitments: self.feldman_verifiers.clone(),
            verifying_share: self.verifying_share,
            signature,
        };
        self.received_round1_data
            .insert(self.ordinal, self_round1_data);
        self.round = Round::Two;
        Ok(RoundOutputGenerator::Round1(Round1OutputGenerator {
            participant_ids: self.all_participant_ids.clone(),
            sender_type: self.participant_impl.get_type(),
            sender_ordinal: self.ordinal,
            sender_id: self.id,
            feldman_commitments: self.feldman_verifiers.clone(),
            verifying_share: self.verifying_share,
            signature,
        }))
    }

    pub(crate) fn compute_signature(&self, k: G::Scalar, r_i: G) -> Signature<G> {
        let bytes = crate::bytes_for_schnorr(
            self.ordinal,
            &self.id,
            &self.participant_impl.get_type(),
            self.threshold,
            self.limit,
            &self.message_generator,
            &self.feldman_verifiers,
            &self.verifying_share,
            &r_i,
            &self.all_participant_ids,
        );
        let challenge = G::Scalar::hash_to_scalar(&bytes);
        let s = k + challenge * self.original_secret;
        Signature { r: r_i, s }
    }

    pub(crate) fn verify_signature(&self, round1data: &Round1Data<G>) -> DkgResult<()> {
        crate::verify_signature(
            round1data.sender_ordinal,
            &round1data.sender_id,
            &round1data.sender_type,
            self.threshold,
            self.limit,
            &self.message_generator,
            &round1data.feldman_commitments,
            &round1data.verifying_share,
            &self.all_participant_ids,
            &round1data.signature,
        )
    }

    pub(crate) fn receive_round1data(&mut self, data: Round1Data<G>) -> DkgResult<()> {
        if self.round > Round::Two {
            return Err(Error::Round(format!(
                "Round {}: Invalid round payload received",
                Round::One
            )));
        }
        if self.received_round1_data.contains_key(&data.sender_ordinal) {
            return Err(Error::Round(format!(
                "Round: {}, Sender has already sent data",
                Round::One
            )));
        }
        self.check_sending_participant_id(Round::One, data.sender_ordinal, data.sender_id)?;
        if data.feldman_commitments.is_empty() {
            return Err(Error::Round(format!(
                "Round: {}, Feldman commitments are empty",
                Round::One
            )));
        }
        if data.feldman_commitments.len() != self.threshold {
            return Err(Error::Round(format!(
                "Round: {}, Feldman commitments length is not equal to threshold",
                Round::One
            )));
        }
        if data.feldman_commitments[1..]
            .iter()
            .fold(Choice::from(0u8), |acc, c| acc | c.is_identity())
            .into()
        {
            return Err(Error::Round(format!(
                "Round: {}, Feldman commitments contain the identity point",
                Round::One
            )));
        }
        let feldman_valid = match data.sender_type {
            ParticipantType::Secret => {
                SecretParticipantImpl::check_feldman_verifier(*data.feldman_commitments[0])
                    && data.feldman_commitments[0].0 == data.verifying_share
            }
            ParticipantType::Refresh => {
                RefreshParticipantImpl::check_feldman_verifier(*data.feldman_commitments[0])
                    && data.feldman_commitments[0].0 != data.verifying_share
            }
        };
        if !feldman_valid {
            return Err(Error::Round(format!(
                "Round: {}, Feldman commitment is not a valid verifier",
                Round::One
            )));
        }
        self.verify_signature(&data)?;

        self.received_round1_data.insert(data.sender_ordinal, data);
        Ok(())
    }
}
