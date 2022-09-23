use crate::crypto::kzg::dusk_bytes::Serializable;
use crate::crypto::kzg::{BlsScalar, Kzg};

#[test]
fn basic() {
    let data = {
        // Multiple of 32
        let mut data = rand::random::<[u8; 256]>();

        // We can only store 254 bits, set last byte to zero because of that
        data.chunks_exact_mut(BlsScalar::SIZE)
            .flat_map(|chunk| chunk.iter_mut().last())
            .for_each(|last_byte| *last_byte = 0);

        data
    };

    let kzg = Kzg::random(256).unwrap();
    let polynomial = kzg.poly(&data).unwrap();
    let commitment = kzg.commit(&polynomial).unwrap();

    let values = data.chunks_exact(BlsScalar::SIZE);
    let num_values = values.len() as u32;

    for (index, value) in values.enumerate() {
        let index = index.try_into().unwrap();

        let witness = kzg.create_witness(&polynomial, index).unwrap();

        assert!(
            kzg.verify(&commitment, num_values, index, value, &witness),
            "failed on index {index}"
        );
    }
}
