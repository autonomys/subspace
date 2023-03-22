use crate::crypto::ScalarLegacy;
use crate::{PIECE_SIZE, PLOT_SECTOR_SIZE, U256};
use num_integer::Roots;
use rand::thread_rng;
use rand_core::RngCore;

#[test]
fn piece_distance_middle() {
    assert_eq!(U256::MIDDLE, U256::MAX / 2);
}

#[test]
fn piece_size_multiple_of_scalar() {
    assert_eq!(PIECE_SIZE % ScalarLegacy::SAFE_BYTES, 0);
}

#[test]
fn sector_side_size_in_scalars_power_of_two() {
    let sector_size_in_scalars = PLOT_SECTOR_SIZE / ScalarLegacy::FULL_BYTES as u64;
    let sector_side_size_in_scalars = sector_size_in_scalars.sqrt();

    assert!(sector_side_size_in_scalars.is_power_of_two());
}

#[test]
fn bytes_scalars_conversion() {
    {
        let mut bytes = vec![0u8; ScalarLegacy::SAFE_BYTES * 16];
        thread_rng().fill_bytes(&mut bytes);

        let scalars = bytes
            .chunks_exact(ScalarLegacy::SAFE_BYTES)
            .map(|bytes| {
                ScalarLegacy::try_from(
                    <&[u8; ScalarLegacy::SAFE_BYTES]>::try_from(bytes)
                        .expect("Chunked into correct size; qed"),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        {
            let mut decoded_bytes = vec![0u8; bytes.len()];
            decoded_bytes
                .chunks_exact_mut(ScalarLegacy::SAFE_BYTES)
                .zip(scalars.iter())
                .for_each(|(bytes, scalar)| {
                    let mut tmp = [0u8; ScalarLegacy::FULL_BYTES];
                    scalar.write_to_bytes(&mut tmp);
                    bytes.copy_from_slice(&tmp[..ScalarLegacy::SAFE_BYTES]);
                });

            assert_eq!(bytes, decoded_bytes);
        }

        {
            let mut decoded_bytes = vec![0u8; bytes.len()];
            decoded_bytes
                .chunks_exact_mut(ScalarLegacy::SAFE_BYTES)
                .zip(scalars.iter())
                .for_each(|(bytes, scalar)| {
                    bytes.copy_from_slice(&scalar.to_bytes()[..ScalarLegacy::SAFE_BYTES]);
                });

            assert_eq!(bytes, decoded_bytes);
        }
    }

    {
        let bytes = {
            let mut bytes = [0u8; ScalarLegacy::FULL_BYTES];
            bytes[..ScalarLegacy::SAFE_BYTES]
                .copy_from_slice(&rand::random::<[u8; ScalarLegacy::SAFE_BYTES]>());
            bytes
        };

        {
            let scalar = ScalarLegacy::try_from(&bytes).unwrap();

            assert_eq!(bytes, scalar.to_bytes());
        }

        {
            let scalar = ScalarLegacy::from(&bytes);

            assert_eq!(bytes, scalar.to_bytes());
        }
    }
}
