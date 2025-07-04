use crate::bundle::InvalidBundleType;
use crate::{EMPTY_EXTRINSIC_ROOT, signer_in_tx_range};
use num_traits::ops::wrapping::{WrappingAdd, WrappingSub};
use parity_scale_codec::Encode;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::traits::{BlakeTwo256, Hash};
use subspace_core_primitives::U256;

#[test]
fn test_tx_range() {
    let tx_range = U256::MAX / 4;
    let bundle_vrf_hash = U256::MAX / 2;

    let signer_id_hash = bundle_vrf_hash + U256::from(10_u64);
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash - U256::from(10_u64);
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash + U256::MAX / 8;
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash - U256::MAX / 8;
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash + U256::MAX / 8 + U256::from(1_u64);
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash - U256::MAX / 8 - U256::from(1_u64);
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash + U256::MAX / 4;
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash - U256::MAX / 4;
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));
}

#[test]
fn test_tx_range_wrap_under_flow() {
    let tx_range = U256::MAX / 4;
    let bundle_vrf_hash = U256::from(100_u64);

    let signer_id_hash = bundle_vrf_hash + U256::from(1000_u64);
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash.wrapping_sub(&U256::from(1000_u64));
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash + U256::MAX / 8;
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let v = U256::MAX / 8;
    let signer_id_hash = bundle_vrf_hash.wrapping_sub(&v);
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash + U256::MAX / 8 + U256::from(1_u64);
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let v = U256::MAX / 8 + U256::from(1_u64);
    let signer_id_hash = bundle_vrf_hash.wrapping_sub(&v);
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash + U256::MAX / 4;
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let v = U256::MAX / 4;
    let signer_id_hash = bundle_vrf_hash.wrapping_sub(&v);
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));
}

#[test]
fn test_tx_range_wrap_over_flow() {
    let tx_range = U256::MAX / 4;
    let v = U256::MAX;
    let bundle_vrf_hash = v.wrapping_sub(&U256::from(100_u64));

    let signer_id_hash = bundle_vrf_hash.wrapping_add(&U256::from(1000_u64));
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash - U256::from(1000_u64);
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let v = U256::MAX / 8;
    let signer_id_hash = bundle_vrf_hash.wrapping_add(&v);
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash - U256::MAX / 8;
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let v = U256::MAX / 8 + U256::from(1_u64);
    let signer_id_hash = bundle_vrf_hash.wrapping_add(&v);
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash - U256::MAX / 8 - U256::from(1_u64);
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let v = U256::MAX / 4;
    let signer_id_hash = bundle_vrf_hash.wrapping_add(&v);
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));

    let signer_id_hash = bundle_vrf_hash - U256::MAX / 4;
    assert!(!signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));
}

#[test]
fn test_tx_range_max() {
    let tx_range = U256::MAX;
    let bundle_vrf_hash = U256::MAX / 2;

    let signer_id_hash = bundle_vrf_hash + U256::from(10_u64);
    assert!(signer_in_tx_range(
        &bundle_vrf_hash,
        &signer_id_hash,
        &tx_range,
    ));
}

#[test]
fn test_empty_extrinsic_root() {
    let root = BlakeTwo256::ordered_trie_root(
        Vec::<OpaqueExtrinsic>::default()
            .iter()
            .map(|xt| xt.encode())
            .collect(),
        sp_core::storage::StateVersion::V1,
    );
    assert_eq!(root, EMPTY_EXTRINSIC_ROOT);
}

#[test]
fn test_invalid_bundle_type_checking_order() {
    fn invalid_type(extrinsic_index: u32, rule_order: u32) -> InvalidBundleType {
        match rule_order {
            1 => InvalidBundleType::UndecodableTx(extrinsic_index),
            2 => InvalidBundleType::OutOfRangeTx(extrinsic_index),
            3 => InvalidBundleType::InherentExtrinsic(extrinsic_index),
            4 => InvalidBundleType::InvalidXDM(extrinsic_index),
            5 => InvalidBundleType::IllegalTx(extrinsic_index),
            6 => InvalidBundleType::InvalidBundleWeight,
            _ => unreachable!(),
        }
    }

    // The checking order is a combination of the `extrinsic_order` and `rule_order`
    // it presents as an `u64` where the first 32 bits is the `extrinsic_order` and
    // last 32 bits is the `rule_order` meaning the `extrinsic_order` is checked first
    // then the `rule_order`.
    assert_eq!(invalid_type(0, 1).checking_order(), 1);
    assert_eq!(invalid_type(0, 2).checking_order(), 2);
    assert_eq!(invalid_type(0, 3).checking_order(), 3);
    assert_eq!(invalid_type(0, 5).checking_order(), 5);
    assert_eq!(
        invalid_type(1, 1).checking_order(),
        (u32::MAX as u64 + 1) + 1
    );
    assert_eq!(
        invalid_type(12345, 2).checking_order(),
        (12345u64 * (u32::MAX as u64 + 1)) + 2
    );
    assert_eq!(
        invalid_type(u32::MAX - 1, 3).checking_order(),
        ((u32::MAX - 1) as u64 * (u32::MAX as u64 + 1)) + 3
    );
    assert_eq!(
        invalid_type(u32::MAX, 5).checking_order(),
        (u32::MAX as u64 * (u32::MAX as u64 + 1)) + 5
    );
    assert_eq!(
        InvalidBundleType::InvalidBundleWeight.checking_order(),
        // The extrinsic index of `InvalidBundleWeight` is `u32::MAX`
        (u32::MAX as u64 * (u32::MAX as u64 + 1)) + 6
    );

    // The `extrinsic_order` is checked first then the `rule_order`
    assert!(invalid_type(0, 1).checking_order() < invalid_type(0, 2).checking_order());
    assert!(invalid_type(1, 1).checking_order() < invalid_type(1, 2).checking_order());
    assert!(invalid_type(0, 1).checking_order() < invalid_type(1, 1).checking_order());
    assert!(invalid_type(0, 2).checking_order() < invalid_type(1, 1).checking_order());
    assert!(invalid_type(0, 1).checking_order() < invalid_type(1, 2).checking_order());
    assert_eq!(
        invalid_type(9876, 5).checking_order(),
        invalid_type(9876, 5).checking_order()
    );
}
