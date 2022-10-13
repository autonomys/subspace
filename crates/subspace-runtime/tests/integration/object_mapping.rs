use codec::Encode;
use frame_support::sp_io;
use hex_literal::hex;
use sp_objects::runtime_decl_for_ObjectsApi::ObjectsApi;
use sp_runtime::traits::{BlakeTwo256, Hash as HashT};
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{crypto, Blake2b256Hash};
use subspace_runtime::{
    Block, Call, FeedProcessorKind, Feeds, Header, Origin, Runtime, System, UncheckedExtrinsic,
};
use subspace_runtime_primitives::Hash;

#[test]
fn object_mapping() {
    let data0: Vec<u8> = (0..=99).collect();
    let data1: Vec<u8> = (123..=255).collect();
    let data2: Vec<u8> = (0..=99).rev().collect();
    let data3: Vec<u8> = (123..=255).rev().collect();
    // let (init_data, key, object) = get_encoded_blocks();
    let block = Block {
        header: Header {
            parent_hash: Default::default(),
            number: Default::default(),
            state_root: Default::default(),
            extrinsics_root: Default::default(),
            digest: Default::default(),
        },
        extrinsics: vec![
            UncheckedExtrinsic {
                signature: None,
                function: Call::Feeds(pallet_feeds::Call::put {
                    feed_id: 0,
                    object: data0.clone(),
                }),
            },
            UncheckedExtrinsic {
                signature: None,
                function: Call::Feeds(pallet_feeds::Call::put {
                    feed_id: 0,
                    object: data1.clone(),
                }),
            },
            // assuming this call fails, we will remove the 3rd hash from calls
            UncheckedExtrinsic {
                signature: None,
                function: Call::Feeds(pallet_feeds::Call::put {
                    feed_id: 0,
                    object: data0.clone(),
                }),
            },
            UncheckedExtrinsic {
                signature: None,
                function: Call::Utility(pallet_utility::Call::batch {
                    calls: vec![
                        Call::Feeds(pallet_feeds::Call::put {
                            feed_id: 0,
                            object: data2.clone(),
                        }),
                        Call::Feeds(pallet_feeds::Call::put {
                            feed_id: 0,
                            object: data3.clone(),
                        }),
                    ],
                }),
            },
            UncheckedExtrinsic {
                signature: None,
                function: Call::Utility(pallet_utility::Call::as_derivative {
                    index: 0,
                    call: Box::new(Call::Feeds(pallet_feeds::Call::put {
                        feed_id: 0,
                        object: data0.clone(),
                    })),
                }),
            },
            UncheckedExtrinsic {
                signature: None,
                function: Call::Utility(pallet_utility::Call::batch_all {
                    calls: vec![
                        Call::Feeds(pallet_feeds::Call::put {
                            feed_id: 0,
                            object: data2.clone(),
                        }),
                        Call::Feeds(pallet_feeds::Call::put {
                            feed_id: 0,
                            object: data3.clone(),
                        }),
                    ],
                }),
            },
        ],
    };

    let mut successful_calls = get_successful_calls(block.clone());
    assert_eq!(successful_calls.len(), 8);
    // remove third call signifying that it failed
    successful_calls.remove(2);

    let encoded_block = block.encode();
    let BlockObjectMapping { objects } = new_test_ext().execute_with(|| {
        // init feed
        Feeds::create(
            Origin::signed([0u8; 32].into()),
            FeedProcessorKind::default(),
            None,
        )
        .expect("create feed should not fail");

        Runtime::extract_block_object_mapping(block, successful_calls)
    });

    // Expect all 7 objects to be mapped.
    assert_eq!(objects.len(), 7);

    // Hashes should be computed correctly.
    assert_eq!(objects[0].hash(), crypto::blake2b_256_hash(&data0),);
    assert_eq!(objects[1].hash(), crypto::blake2b_256_hash(&data1));
    assert_eq!(objects[2].hash(), crypto::blake2b_256_hash(&data2));
    assert_eq!(objects[3].hash(), crypto::blake2b_256_hash(&data3));
    assert_eq!(objects[4].hash(), crypto::blake2b_256_hash(&data0));
    assert_eq!(objects[5].hash(), crypto::blake2b_256_hash(&data2));
    assert_eq!(objects[6].hash(), crypto::blake2b_256_hash(&data3));

    // Offsets for mapped objects should be correct
    assert_eq!(
        &encoded_block[objects[0].offset() as usize..][..data0.encoded_size()],
        &data0.encode()
    );
    assert_eq!(
        &encoded_block[objects[1].offset() as usize..][..data1.encoded_size()],
        &data1.encode()
    );
    assert_eq!(
        &encoded_block[objects[2].offset() as usize..][..data2.encoded_size()],
        &data2.encode()
    );
    assert_eq!(
        &encoded_block[objects[3].offset() as usize..][..data3.encoded_size()],
        &data3.encode()
    );
    assert_eq!(
        &encoded_block[objects[4].offset() as usize..][..data0.encoded_size()],
        &data0.encode()
    );
    assert_eq!(
        &encoded_block[objects[5].offset() as usize..][..data2.encoded_size()],
        &data2.encode()
    );
    assert_eq!(
        &encoded_block[objects[6].offset() as usize..][..data3.encoded_size()],
        &data3.encode()
    );
}

fn get_successful_calls(block: Block) -> Vec<Hash> {
    block
        .extrinsics
        .iter()
        .filter_map(|ext| match &ext.function {
            Call::Feeds(call) => Some(vec![call.encode()]),
            Call::Utility(call) => match call {
                pallet_utility::Call::batch { calls }
                | pallet_utility::Call::batch_all { calls } => Some(
                    calls
                        .iter()
                        .filter_map(|call| match &call {
                            Call::Feeds(call) => Some(call.encode()),
                            _ => None,
                        })
                        .collect(),
                ),
                pallet_utility::Call::as_derivative { call, .. } => match call.as_ref() {
                    Call::Feeds(call) => Some(vec![call.encode()]),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        })
        .flatten()
        .map(|call_encoded| BlakeTwo256::hash(call_encoded.as_slice()))
        .collect()
}

fn key(feed_id: u64, data: &[u8]) -> Blake2b256Hash {
    crypto::blake2b_256_hash_list(&[&feed_id.encode(), data])
}

#[test]
fn grandpa_object_mapping() {
    let (init_data, keys, object) = get_encoded_blocks();
    let block = Block {
        header: Header {
            parent_hash: Default::default(),
            number: Default::default(),
            state_root: Default::default(),
            extrinsics_root: Default::default(),
            digest: Default::default(),
        },
        extrinsics: vec![UncheckedExtrinsic {
            signature: None,
            function: Call::Feeds(pallet_feeds::Call::put {
                feed_id: 0,
                object: object.clone(),
            }),
        }],
    };
    let successful_calls = get_successful_calls(block.clone());
    let encoded_block = block.encode();
    let BlockObjectMapping { objects } = new_test_ext().execute_with(|| {
        // init feed
        Feeds::create(
            Origin::signed([0u8; 32].into()),
            FeedProcessorKind::PolkadotLike,
            Some(init_data),
        )
        .expect("create feed should not fail");

        Runtime::extract_block_object_mapping(block, successful_calls)
    });

    assert_eq!(objects.len(), 2);
    // Hashes should be computed correctly.
    assert_eq!(objects[0].hash(), keys[0]);
    assert_eq!(objects[1].hash(), keys[1]);

    // Offsets for mapped objects should be correct
    assert_eq!(
        &encoded_block[objects[0].offset() as usize..][..object.encoded_size()],
        object.encode()
    );

    // Offsets for mapped objects should be correct
    assert_eq!(
        &encoded_block[objects[1].offset() as usize..][..object.encoded_size()],
        object.encode()
    );
}

fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::default()
        .build_storage::<Runtime>()
        .unwrap();

    let mut t: sp_io::TestExternalities = t.into();

    t.execute_with(|| System::set_block_number(1));

    t
}

// returns init data, encoded signed block with finality verification, and the block hash
fn get_encoded_blocks() -> (Vec<u8>, Vec<Blake2b256Hash>, Vec<u8>) {
    let init_data = vec![
        157, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 12, 66, 41, 215, 144, 185, 38, 223, 251, 103, 136, 167, 205, 48, 247,
        245, 28, 200, 92, 210, 10, 234, 212, 165, 58, 82, 218, 131, 252, 28, 13, 4, 4, 4, 70, 82,
        78, 75, 249, 1, 1, 12, 59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13,
        115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41, 1, 0, 0, 0, 0,
        0, 0, 0, 206, 204, 21, 7, 220, 29, 221, 114, 149, 149, 28, 41, 8, 136, 240, 149, 173, 185,
        4, 77, 27, 115, 214, 150, 230, 223, 6, 93, 104, 59, 212, 252, 1, 0, 0, 0, 0, 0, 0, 0, 107,
        121, 197, 126, 106, 9, 82, 57, 40, 44, 4, 129, 142, 150, 17, 47, 63, 3, 164, 0, 27, 169,
        122, 86, 76, 35, 133, 42, 63, 30, 165, 252, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        0, 0, 0, 0,
    ];

    (
        init_data,
        vec![
            key(0, 0u32.encode().as_slice()),
            key(
                0,
                hex!("9ab5950cd99156c777eea82c159b26d12474921d755ae404c07695fcaaf83ea1").as_slice(),
            ),
        ],
        vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 12, 66, 41, 215, 144, 185, 38, 223, 251, 103, 136, 167, 205, 48,
            247, 245, 28, 200, 92, 210, 10, 234, 212, 165, 58, 82, 218, 131, 252, 28, 13, 4, 4, 4,
            70, 82, 78, 75, 249, 1, 1, 12, 59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208,
            42, 111, 13, 115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218,
            41, 1, 0, 0, 0, 0, 0, 0, 0, 206, 204, 21, 7, 220, 29, 221, 114, 149, 149, 28, 41, 8,
            136, 240, 149, 173, 185, 4, 77, 27, 115, 214, 150, 230, 223, 6, 93, 104, 59, 212, 252,
            1, 0, 0, 0, 0, 0, 0, 0, 107, 121, 197, 126, 106, 9, 82, 57, 40, 44, 4, 129, 142, 150,
            17, 47, 63, 3, 164, 0, 27, 169, 122, 86, 76, 35, 133, 42, 63, 30, 165, 252, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 4, 253, 3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
            37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
            59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
            81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
            102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
            119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135,
            136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152,
            153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169,
            170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186,
            187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203,
            204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
            221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237,
            238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 1,
            4, 70, 82, 78, 75, 41, 10, 1, 0, 0, 0, 0, 0, 0, 0, 154, 181, 149, 12, 217, 145, 86,
            199, 119, 238, 168, 44, 21, 155, 38, 209, 36, 116, 146, 29, 117, 90, 228, 4, 192, 118,
            149, 252, 170, 248, 62, 161, 0, 0, 0, 0, 12, 194, 59, 33, 177, 167, 99, 139, 55, 214,
            52, 34, 123, 121, 206, 178, 56, 129, 10, 241, 247, 80, 167, 175, 231, 60, 66, 31, 225,
            129, 164, 145, 115, 2, 0, 0, 0, 146, 123, 28, 194, 224, 21, 138, 186, 136, 98, 86, 236,
            179, 191, 237, 249, 131, 92, 149, 42, 94, 6, 243, 65, 95, 67, 5, 83, 164, 86, 191, 190,
            61, 178, 214, 66, 169, 63, 198, 67, 44, 251, 31, 96, 224, 201, 117, 209, 250, 130, 219,
            142, 112, 2, 219, 208, 78, 182, 235, 104, 128, 223, 44, 12, 59, 106, 39, 188, 206, 182,
            164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29, 226, 67, 166, 58,
            192, 72, 161, 139, 89, 218, 41, 194, 59, 33, 177, 167, 99, 139, 55, 214, 52, 34, 123,
            121, 206, 178, 56, 129, 10, 241, 247, 80, 167, 175, 231, 60, 66, 31, 225, 129, 164,
            145, 115, 2, 0, 0, 0, 252, 83, 154, 187, 244, 207, 175, 247, 38, 175, 88, 94, 168, 210,
            97, 128, 48, 36, 67, 125, 63, 84, 110, 123, 111, 149, 79, 12, 93, 205, 150, 230, 129,
            59, 15, 140, 253, 188, 213, 44, 130, 254, 16, 221, 141, 201, 99, 122, 219, 41, 236,
            179, 80, 177, 156, 44, 126, 61, 144, 197, 9, 1, 114, 1, 206, 204, 21, 7, 220, 29, 221,
            114, 149, 149, 28, 41, 8, 136, 240, 149, 173, 185, 4, 77, 27, 115, 214, 150, 230, 223,
            6, 93, 104, 59, 212, 252, 194, 59, 33, 177, 167, 99, 139, 55, 214, 52, 34, 123, 121,
            206, 178, 56, 129, 10, 241, 247, 80, 167, 175, 231, 60, 66, 31, 225, 129, 164, 145,
            115, 2, 0, 0, 0, 163, 20, 66, 157, 116, 143, 137, 49, 28, 129, 222, 207, 26, 70, 101,
            230, 237, 107, 243, 76, 78, 2, 87, 139, 200, 218, 199, 80, 132, 207, 232, 212, 205,
            222, 246, 19, 142, 134, 245, 15, 16, 121, 200, 48, 8, 101, 143, 95, 70, 132, 243, 197,
            157, 110, 126, 36, 167, 12, 93, 25, 2, 224, 66, 9, 107, 121, 197, 126, 106, 9, 82, 57,
            40, 44, 4, 129, 142, 150, 17, 47, 63, 3, 164, 0, 27, 169, 122, 86, 76, 35, 133, 42, 63,
            30, 165, 252, 8, 154, 181, 149, 12, 217, 145, 86, 199, 119, 238, 168, 44, 21, 155, 38,
            209, 36, 116, 146, 29, 117, 90, 228, 4, 192, 118, 149, 252, 170, 248, 62, 161, 4, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 12, 66, 41, 215, 144, 185, 38, 223, 251, 103, 136, 167, 205, 48, 247, 245, 28, 200,
            92, 210, 10, 234, 212, 165, 58, 82, 218, 131, 252, 28, 13, 4, 4, 0, 16, 0, 0, 0, 0,
            222, 46, 166, 66, 115, 122, 201, 206, 232, 161, 134, 15, 159, 154, 51, 219, 59, 155,
            162, 58, 4, 248, 240, 204, 152, 96, 186, 255, 125, 225, 73, 232, 8, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 66,
            41, 215, 144, 185, 38, 223, 251, 103, 136, 167, 205, 48, 247, 245, 28, 200, 92, 210,
            10, 234, 212, 165, 58, 82, 218, 131, 252, 28, 13, 4, 4, 0, 16, 0, 0, 0, 0,
        ],
    )
}
