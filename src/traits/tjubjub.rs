use super::*;
use elliptic_curve::hash2curve::ExpandMsgXmd;
use jubjub_plus::Scalar;

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXmd<blake2::Blake2b512>>(bytes, b"jubjub_XMD:BLAKE2b512_RO_NUL_")
    }
}
