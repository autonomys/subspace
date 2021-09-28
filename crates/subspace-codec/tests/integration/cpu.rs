use subspace_codec::Spartan;

#[test]
fn test_random_piece() {
    let public_key = rand::random::<[u8; 32]>();
    let nonce = rand::random();

    let spartan = Spartan::new(public_key.as_ref());
    let encoding = spartan.encode(nonce);

    assert!(spartan.is_encoding_valid(encoding, nonce));
}
