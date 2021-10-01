use crate::{Tag, PRIME_SIZE};
use ring::{digest, hmac};
use schnorrkel::PublicKey;
use std::convert::TryInto;

pub(crate) fn hash_public_key(public_key: &PublicKey) -> [u8; PRIME_SIZE] {
    let mut array = [0u8; PRIME_SIZE];
    let hash = digest::digest(&digest::SHA256, public_key.as_ref());
    array.copy_from_slice(&hash.as_ref()[..PRIME_SIZE]);
    array
}

pub(crate) fn create_tag(encoding: &[u8], salt: &[u8]) -> Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    hmac::sign(&key, encoding).as_ref()[0..8]
        .try_into()
        .unwrap()
}
