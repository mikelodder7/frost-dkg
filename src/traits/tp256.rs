use super::*;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::{NistP256, Scalar};

impl ScalarHash for Scalar {
    fn hash_to_scalar(bytes: &[u8]) -> Self {
        const DST: &[u8] = b"P256_XMD:SHA-256_RO_NUL_";
        <NistP256 as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&[bytes], &[DST])
            .expect("hash_to_scalar failed")
    }
}
