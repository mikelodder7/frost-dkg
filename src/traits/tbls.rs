use super::*;
use blsful::inner_types::Scalar;
use elliptic_curve::hash2curve::ExpandMsgXmd;

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(bytes, b"BLS12381_XMD:SHA-256_RO_NUL_")
    }
}
