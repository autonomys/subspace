use std::convert::TryInto;
use subspace_codec::Spartan;
use subspace_core_primitives::{Piece, PIECE_SIZE};

// CUDA accepts multiples of 1024 pieces, and any remainder piece will be handled on CPU
// this test aims to process 1024 pieces in GPU, and 2 pieces in CPU, hence 1026 pieces.
#[test]
fn test_1026_piece() {
    let genesis_piece: Piece = rand::random();
    let mut piece_array: Vec<u8> = Vec::with_capacity(PIECE_SIZE * 1026);
    let public_key = rand::random::<[u8; 32]>();
    let nonce: u64 = rand::random();
    let nonce_array = vec![nonce; 1026];

    let spartan = Spartan::new(public_key.as_ref());

    if !spartan.is_cuda_available() {
        // TODO: This will be unnecessary once we have generic batching instead CUDA-specific API
        return;
    }

    for _ in 0..1026 {
        piece_array.extend_from_slice(&genesis_piece);
    }

    spartan.cuda_batch_encode(&mut piece_array, nonce_array.as_slice());

    for i in 0..1026 {
        assert!(spartan.is_encoding_valid(
            piece_array[i * PIECE_SIZE..(i + 1) * PIECE_SIZE]
                .as_ref()
                .try_into()
                .unwrap(),
            nonce_array[i],
        ));
    }
}
