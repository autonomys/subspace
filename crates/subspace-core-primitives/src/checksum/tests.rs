use super::Blake3Checksummed;
use crate::Blake3Hash;
use parity_scale_codec::{Decode, Encode};
use rand::prelude::*;
use std::mem;

#[test]
fn basic() {
    let random_bytes = random::<[u8; 64]>();

    let plain_encoding = random_bytes.encode();
    let checksummed_encoding = Blake3Checksummed(random_bytes).encode();

    // Encoding is extended with checksum
    assert_eq!(
        plain_encoding.len() + Blake3Hash::SIZE,
        checksummed_encoding.len()
    );

    // Decoding succeeds
    let Blake3Checksummed(decoded_random_bytes) =
        Blake3Checksummed::<[u8; 64]>::decode(&mut checksummed_encoding.as_slice()).unwrap();
    // Decodes to original data
    assert_eq!(random_bytes, decoded_random_bytes);

    // Non-checksummed encoding fails to decode
    assert!(Blake3Checksummed::<[u8; 64]>::decode(&mut plain_encoding.as_slice()).is_err());
    // Incorrectly checksummed data fails to decode
    assert!(Blake3Checksummed::<[u8; 32]>::decode(&mut random::<[u8; 64]>().as_ref()).is_err());
}
