use crate::crypto::kzg::{embedded_kzg_settings, Kzg};
use crate::Scalar;
use blst_from_scratch::consts::{G1_GENERATOR, G2_GENERATOR};
use blst_from_scratch::eip_4844::{bytes_from_g1_rust, bytes_from_g2_rust};
use blst_from_scratch::types::fft_settings::FsFFTSettings;
use blst_from_scratch::types::fr::FsFr;
use blst_from_scratch::types::kzg_settings::FsKZGSettings;
use kzg::{FFTSettings, Fr, G1Mul, G2Mul};
use rand::Rng;
use rand_core::SeedableRng;

#[test]
fn basic() {
    let data = {
        // Multiple of 32
        let mut data = rand::random::<[u8; 256]>();

        // We can only store 254 bits, set last byte to zero because of that
        data.chunks_exact_mut(Scalar::FULL_BYTES)
            .flat_map(|chunk| chunk.iter_mut().last())
            .for_each(|last_byte| *last_byte = 0);

        data
    };

    let kzg = Kzg::new(embedded_kzg_settings());
    let polynomial = kzg.poly(&data).unwrap();
    let commitment = kzg.commit(&polynomial).unwrap();

    let values = data.chunks_exact(Scalar::FULL_BYTES);
    let num_values = values.len();

    for (index, value) in values.enumerate() {
        let index = index.try_into().unwrap();

        let witness = kzg.create_witness(&polynomial, index).unwrap();

        assert!(
            kzg.verify(&commitment, num_values, index, value, &witness),
            "failed on index {index}"
        );
    }
}

fn test_public_parameters_generate() -> FsKZGSettings {
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(1969897683899915189);
    let scale = 15;
    let secret_len = 2usize.pow(scale) + 1;

    let s = FsFr::hash_to_bls_field(rng.gen());
    let mut s_pow = FsFr::one();

    let mut secret_g1 = Vec::with_capacity(secret_len);
    let mut secret_g2 = Vec::with_capacity(secret_len);

    for _ in 0..secret_len {
        secret_g1.push(G1_GENERATOR.mul(&s_pow));
        secret_g2.push(G2_GENERATOR.mul(&s_pow));

        s_pow = s_pow.mul(&s);
    }

    let fft_settings =
        FsFFTSettings::new(scale as usize).expect("Scale is within allowed bounds; qed");

    // Below is the same as `FsKZGSettings::new(&s1, &s2, secret_len, &fft_settings)`, but without
    // extra checks (parameters are static anyway) and without unnecessary allocations
    FsKZGSettings {
        fs: fft_settings,
        secret_g1,
        secret_g2,
    }
}

fn kzg_settings_to_bytes(kzg_settings: &FsKZGSettings) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(kzg_settings.secret_g1.len() * 48 + kzg_settings.secret_g2.len() * 96);
    for g1 in kzg_settings.secret_g1.iter().map(bytes_from_g1_rust) {
        bytes.extend_from_slice(&g1);
    }
    for g2 in kzg_settings.secret_g2.iter().map(bytes_from_g2_rust) {
        bytes.extend_from_slice(&g2);
    }

    bytes
}

#[test]
fn test_public_parameters_correct() {
    assert_eq!(
        kzg_settings_to_bytes(&test_public_parameters_generate()),
        kzg_settings_to_bytes(&embedded_kzg_settings())
    );
}
