use super::*;
use blstrs_plus::Scalar;
use blstrs_plus::elliptic_curve_013::hash2curve::ExpandMsgXmd;

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        Scalar::hash::<ExpandMsgXmd<sha2_010::Sha256>>(bytes, b"BLS12381_XMD:SHA-256_RO_NUL_")
    }
}
