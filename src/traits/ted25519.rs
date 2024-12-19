use super::*;
use vsss_rs::{curve25519::WrappedScalar, curve25519_dalek::Scalar};

impl ScalarHash for WrappedScalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        Self(Scalar::hash_from_bytes::<sha2::Sha512>(bytes))
    }
}

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        Self::hash_from_bytes::<sha2::Sha512>(bytes)
    }
}
