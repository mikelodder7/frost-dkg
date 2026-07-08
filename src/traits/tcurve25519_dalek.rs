use super::*;
use curve25519_dalek::Scalar;
use sha2::Digest;

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        let mut hash = sha2::Sha512::new();
        hash.update(bytes);
        Scalar::from_hash(hash)
    }
}
