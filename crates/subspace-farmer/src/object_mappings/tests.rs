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
            // Store up to 4 elements, prune down to 3
            global_mappings[0].encoded_size() as u64 * 5 - 1,
        )
        .unwrap();
        object_mappings.store(&global_mappings).unwrap();

        assert!(object_mappings
            .retrieve(&global_mappings[0].0)
            .unwrap()
            .is_none());
        for (hash, global_mapping) in global_mappings.iter().skip(1).take(3) {
            assert_eq!(
                object_mappings.retrieve(hash).unwrap().as_ref(),
                Some(global_mapping)
            );
        }
        assert!(object_mappings
            .retrieve(&global_mappings[4].0)
            .unwrap()
            .is_none());

        // This key is further that keys pruned before and shouldn't be stored once attempted
        let key_very_far = (
            public_key_as_number
                .wrapping_add(&U256::from(21u64))
                .to_be_bytes(),
            GlobalObject::V0 {
                piece_index: 0,
                offset: 0,
            },
        );

        object_mappings.store(&[key_very_far]).unwrap();

        // Not stored because too far
        assert!(object_mappings.retrieve(&key_very_far.0).unwrap().is_none());

        // This key is close enough to be stored
        let key_close_enough = (
            public_key_as_number
                .wrapping_add(&U256::from(2u64))
                .to_be_bytes(),
            GlobalObject::V0 {
                piece_index: 0,
                offset: 0,
            },
        );

        object_mappings.store(&[key_close_enough]).unwrap();

        // Stored because close enough
        assert_eq!(
            object_mappings.retrieve(&key_close_enough.0).unwrap(),
            Some(key_close_enough.1)
        );
        // Keys previously stored are still there, so no pruning took effect yet
        for (hash, global_mapping) in global_mappings.iter().skip(1).take(3) {
            assert_eq!(
                object_mappings.retrieve(hash).unwrap().as_ref(),
                Some(global_mapping)
            );
        }

        // Close and re-open database to check reading of parameters on restart
        drop(object_mappings);
        let object_mappings = ObjectMappings::open_or_create(
            base_directory.path(),
            public_key,
            // Store up to 4 elements, prune down to 3
            global_mappings[0].encoded_size() as u64 * 5 - 1,
        )
        .unwrap();

        // Make sure old key is still not stored because too far
        object_mappings.store(&[key_very_far]).unwrap();
        assert!(object_mappings.retrieve(&key_very_far.0).unwrap().is_none());

        // And no pruning too place because nothing was inserted
        assert_eq!(
            object_mappings.retrieve(&key_close_enough.0).unwrap(),
            Some(key_close_enough.1)
        );
        for (hash, global_mapping) in global_mappings.iter().skip(1).take(3) {
            assert_eq!(
                object_mappings.retrieve(hash).unwrap().as_ref(),
                Some(global_mapping)
            );
        }
    }
}
