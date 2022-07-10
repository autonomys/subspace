use crate::object_mappings::ObjectMappings;
use num_traits::{WrappingAdd, WrappingSub};
use parity_scale_codec::Encode;
use rand::random;
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::{PublicKey, U256};
use tempfile::TempDir;

fn init() {
    let _ = tracing_subscriber::fmt::try_init();
}

#[test]
fn basic() {
    init();
    let public_key = PublicKey::from(random::<[u8; 32]>());
    let public_key_as_number = U256::from_be_bytes(public_key.into());
    let global_mappings = vec![
        (
            public_key_as_number
                .wrapping_sub(&U256::from(5u64))
                .to_be_bytes(),
            GlobalObject::V0 {
                piece_index: 0,
                offset: 0,
            },
        ),
        (
            public_key_as_number
                .wrapping_sub(&U256::from(2u64))
                .to_be_bytes(),
            GlobalObject::V0 {
                piece_index: 0,
                offset: 0,
            },
        ),
        (
            (public_key_as_number).to_be_bytes(),
            GlobalObject::V0 {
                piece_index: 0,
                offset: 0,
            },
        ),
        (
            public_key_as_number
                .wrapping_add(&U256::from(1u64))
                .to_be_bytes(),
            GlobalObject::V0 {
                piece_index: 0,
                offset: 0,
            },
        ),
        (
            public_key_as_number
                .wrapping_add(&U256::from(20u64))
                .to_be_bytes(),
            GlobalObject::V0 {
                piece_index: 0,
                offset: 0,
            },
        ),
    ];

    // Test basic retrievability
    {
        let base_directory = TempDir::new().unwrap();
        let object_mappings =
            ObjectMappings::open_or_create(base_directory.path(), public_key, u64::MAX).unwrap();
        object_mappings.store(&global_mappings).unwrap();

        for (hash, global_mapping) in &global_mappings {
            assert_eq!(
                object_mappings.retrieve(hash).unwrap().as_ref(),
                Some(global_mapping)
            );
        }
    }

    // Test pruning
    {
        let base_directory = TempDir::new().unwrap();
        let object_mappings = ObjectMappings::open_or_create(
            base_directory.path(),
            public_key,
            global_mappings[0].encoded_size() as u64 * 3,
        )
        .unwrap();
        object_mappings.store(&global_mappings).unwrap();

        assert!(object_mappings
            .retrieve(&global_mappings[0].0)
            .unwrap()
            .is_none());
        assert!(object_mappings
            .retrieve(&global_mappings[1].0)
            .unwrap()
            .is_none());
        for (hash, global_mapping) in global_mappings.iter().skip(2).take(2) {
            assert_eq!(
                object_mappings.retrieve(hash).unwrap().as_ref(),
                Some(global_mapping)
            );
        }
        assert!(object_mappings
            .retrieve(&global_mappings[4].0)
            .unwrap()
            .is_none());
    }
}
