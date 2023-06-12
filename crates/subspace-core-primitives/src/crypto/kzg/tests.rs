use crate::crypto::kzg::{embedded_kzg_settings, Kzg};
use crate::crypto::Scalar;

#[test]
fn basic() {
    let values = (0..8)
        .map(|_| Scalar::from(rand::random::<[u8; Scalar::SAFE_BYTES]>()))
        .collect::<Vec<_>>();

    let kzg = Kzg::new(embedded_kzg_settings());
    let polynomial = kzg.poly(&values).unwrap();
    let commitment = kzg.commit(&polynomial).unwrap();

    let num_values = values.len();

    for (index, value) in values.iter().enumerate() {
        let index = index.try_into().unwrap();

        let witness = kzg.create_witness(&polynomial, num_values, index).unwrap();

        assert!(
            kzg.verify(&commitment, num_values, index, value, &witness),
            "failed on index {index}"
        );
    }
}
