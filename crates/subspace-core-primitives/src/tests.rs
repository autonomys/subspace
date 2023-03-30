use crate::crypto::Scalar;
use crate::{Piece, PLOT_SECTOR_SIZE, U256};
use num_integer::Roots;
use rand::thread_rng;
use rand_core::RngCore;

#[test]
fn piece_distance_middle() {
    assert_eq!(U256::MIDDLE, U256::MAX / 2);
}

#[test]
fn piece_size_multiple_of_scalar() {
    assert_eq!(Piece::SIZE % Scalar::SAFE_BYTES, 0);
}

#[test]
fn sector_side_size_in_scalars_power_of_two() {
    let sector_size_in_scalars = PLOT_SECTOR_SIZE / Scalar::FULL_BYTES as u64;
    let sector_side_size_in_scalars = sector_size_in_scalars.sqrt();

    assert!(sector_side_size_in_scalars.is_power_of_two());
}

#[test]
fn bytes_scalars_conversion() {
    {
        let mut bytes = vec![0u8; Scalar::SAFE_BYTES * 16];
        thread_rng().fill_bytes(&mut bytes);

        let scalars = bytes
            .chunks_exact(Scalar::SAFE_BYTES)
            .map(|bytes| {
                Scalar::from(
                    <&[u8; Scalar::SAFE_BYTES]>::try_from(bytes)
                        .expect("Chunked into correct size; qed"),
                )
            })
            .collect::<Vec<_>>();

        {
            let mut decoded_bytes = vec![0u8; bytes.len()];
            decoded_bytes
                .chunks_exact_mut(Scalar::SAFE_BYTES)
                .zip(scalars.iter())
                .for_each(|(bytes, scalar)| {
                    bytes.copy_from_slice(&scalar.to_bytes()[..Scalar::SAFE_BYTES]);
                });

            assert_eq!(bytes, decoded_bytes);
        }

        {
            let mut decoded_bytes = vec![0u8; bytes.len()];
            decoded_bytes
                .chunks_exact_mut(Scalar::SAFE_BYTES)
                .zip(scalars.iter())
                .for_each(|(bytes, scalar)| {
                    bytes.copy_from_slice(&scalar.to_bytes()[..Scalar::SAFE_BYTES]);
                });

            assert_eq!(bytes, decoded_bytes);
        }
    }

    {
        let bytes = {
            let mut bytes = [0u8; Scalar::FULL_BYTES];
            bytes[..Scalar::SAFE_BYTES]
                .copy_from_slice(&rand::random::<[u8; Scalar::SAFE_BYTES]>());
            bytes
        };

        {
            let scalar = Scalar::try_from(&bytes).unwrap();

            assert_eq!(bytes, scalar.to_bytes());
        }
    }
}
