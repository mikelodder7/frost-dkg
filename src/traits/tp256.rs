use super::*;
use elliptic_curve::array::typenum::U48;
use hash2curve::ExpandMsgXmd;
use p256::{NistP256, Scalar};

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        const DST: &[u8] = b"P256_XMD:SHA-256_RO_NUL_";
        hash2curve::hash_to_scalar::<NistP256, ExpandMsgXmd<sha2::Sha256>, U48>(&[bytes], &[DST])
            .expect("hash_to_scalar failed")
    }
}
