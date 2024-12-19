use super::*;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::{Scalar, Secp256k1};

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        const DST: &[u8] = b"secp256k1_XMD:SHA-256_RO_NUL_";
        <Secp256k1 as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&[bytes], &[DST])
            .expect("hash_to_scalar failed")
    }
}
