// TODO: Unlock tests once batching is fixed
// use subspace_solving::SubspaceCodec;
// use subspace_core_primitives::{Piece, PIECE_SIZE};
//
// // CUDA accepts multiples of 1024 pieces, and any remainder piece will be handled on CPU
// // this test aims to process 1024 pieces in GPU, and 2 pieces in CPU, hence 1026 pieces.
// #[test]
// fn test_1026_piece() {
//     let genesis_piece: Piece = rand::random();
//     let mut piece_array: Vec<u8> = Vec::with_capacity(PIECE_SIZE * 1026);
//     let public_key = rand::random::<[u8; 32]>();
//     let nonce: u64 = rand::random();
//     let nonce_array = vec![nonce; 1026];
//
//     let subspace_solving = SubspaceCodec::new(&public_key);
//
//     if !subspace_solving.is_cuda_available() {
//         // TODO: This will be unnecessary once we have generic batching instead CUDA-specific API
//         return;
//     }
//
//     for _ in 0..1026 {
//         piece_array.extend_from_slice(&genesis_piece);
//     }
//
//     subspace_solving.cuda_batch_encode(&mut piece_array, nonce_array.as_slice());
//
//     for i in 0..1026 {
//         assert!(subspace_solving.decode(
//             piece_array[i * PIECE_SIZE..(i + 1) * PIECE_SIZE]
//                 .as_ref()
//                 .try_into()
//                 .unwrap(),
//             nonce_array[i],
//         ));
//     }
// }
