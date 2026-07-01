use super::*;
use elliptic_curve::array::typenum::U72;
use hash2curve::ExpandMsgXmd;
use p384::{NistP384, Scalar};

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        const DST: &[u8] = b"P384_XMD:SHA-384_RO_NUL_";
        hash2curve::hash_to_scalar::<NistP384, ExpandMsgXmd<sha2::Sha384>, U72>(&[bytes], &[DST])
            .expect("hash_to_scalar failed")
    }
}
