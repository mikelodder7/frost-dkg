use crate::{
    DkgResult, Error, Participant, ParticipantImpl, ParticipantType, Round, RoundOutputGenerator,
    ScalarHash, SecretShare,
};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Field;
use elliptic_curve_tools::SumOfProducts;
use vsss_rs::{IdentifierPrimeField, Share, ValueGroup};

impl<I, G> Participant<I, G>
where
    I: ParticipantImpl<G> + Default,
    G: SumOfProducts + GroupEncoding + Default,
    G::Scalar: ScalarHash,
{
    pub(crate) fn round3_ready(&self) -> bool {
        self.round == Round::Three && self.received_round2_data.len() >= self.threshold
    }

    pub(crate) fn round3(&mut self) -> DkgResult<RoundOutputGenerator<G>> {
        if !self.round3_ready() {
            return Err(Error::RoundError(format!("Round 3 is not ready, haven't received enough data from other participants. Need {} more", self.threshold - self.received_round2_data.len())));
        }

        let mut secret_share = SecretShare::<G::Scalar>::with_identifier_and_value(
            self.id,
            IdentifierPrimeField(G::Scalar::ZERO),
        );
        let mut public_key = ValueGroup::<G>::default();
        let og_secret = self.secret_shares[&self.ordinal];

        let mut all_refresh = true;

        for (ordinal, round2data) in self.received_round2_data.iter() {
            let participant_type = self.received_round1_data[ordinal].sender_type;
            all_refresh &= matches!(participant_type, ParticipantType::Refresh);

            public_key.0 += self.received_round1_data[ordinal].feldman_commitments[0].0;
            secret_share.value.0 += round2data.secret_share.value.0;
        }

        let public_key_identity = bool::from(public_key.is_identity());
        if all_refresh && !public_key_identity || !all_refresh && public_key_identity {
            return Err(Error::RoundError(
                "Round 3: The resulting public key is invalid".to_string(),
            ));
        }

        if secret_share.value == og_secret.value {
            return Err(Error::RoundError(format!(
                "Round {}: The resulting secret key share is invalid",
                Round::Three
            )));
        }
        self.round = Round::Four;
        self.completed = true;
        self.public_key = public_key;
        self.secret_share = secret_share;
        Ok(RoundOutputGenerator::Round3)
    }
}
