use crate::{Piece, Tag, PIECE_SIZE, PRIME_SIZE};
use ring::{digest, hmac};
use schnorrkel::PublicKey;
use std::convert::TryInto;
use std::io::Write;

pub(crate) fn genesis_piece_from_seed(seed: &str) -> Piece {
    // This is not efficient, but it also doesn't matter as it is called just once
    let mut piece = [0u8; PIECE_SIZE];
    let mut input = seed.as_bytes().to_vec();
    for mut chunk in piece.chunks_mut(digest::SHA256.output_len) {
        input = digest::digest(&digest::SHA256, &input).as_ref().to_vec();
        chunk.write_all(input.as_ref()).unwrap();
    }
    piece
}

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
