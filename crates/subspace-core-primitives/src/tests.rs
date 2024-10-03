use crate::crypto::Scalar;
use crate::U256;
use rand::thread_rng;
use rand_core::RngCore;

#[test]
fn piece_distance_middle() {
    assert_eq!(U256::MIDDLE, U256::MAX / 2);
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
                    bytes.copy_from_slice(&scalar.to_bytes()[1..]);
                });

            assert_eq!(bytes, decoded_bytes);
        }

        {
            let mut decoded_bytes = vec![0u8; bytes.len()];
            decoded_bytes
                .chunks_exact_mut(Scalar::SAFE_BYTES)
                .zip(scalars.iter())
                .for_each(|(bytes, scalar)| {
                    bytes.copy_from_slice(&scalar.to_bytes()[1..]);
                });

            assert_eq!(bytes, decoded_bytes);
        }
    }

    {
        let bytes = {
            let mut bytes = [0u8; Scalar::FULL_BYTES];
            bytes[1..].copy_from_slice(&rand::random::<[u8; Scalar::SAFE_BYTES]>());
            bytes
        };

        {
            let scalar = Scalar::try_from(&bytes).unwrap();

            assert_eq!(bytes, scalar.to_bytes());
        }
    }
}
