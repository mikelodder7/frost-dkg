use super::*;
use elliptic_curve::array::typenum::U48;
use hash2curve::ExpandMsgXmd;
use k256::{Scalar, Secp256k1};

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        const DST: &[u8] = b"secp256k1_XMD:SHA-256_RO_NUL_";
        hash2curve::hash_to_scalar::<Secp256k1, ExpandMsgXmd<sha2::Sha256>, U48>(&[bytes], &[DST])
            .expect("hash_to_scalar failed")
    }
}
