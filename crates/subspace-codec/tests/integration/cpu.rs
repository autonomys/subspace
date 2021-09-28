use subspace_codec::Spartan;

#[test]
fn test_random_piece() {
    let encoding_key = rand::random();
    let nonce = rand::random();

    let spartan = Spartan::new();
    let encoding = spartan.encode(encoding_key, nonce);

    assert!(spartan.is_encoding_valid(encoding, encoding_key, nonce));
}
