use codec::Encode;
use frame_support::sp_io;
use hex_literal::hex;
use sp_objects::runtime_decl_for_ObjectsApi::ObjectsApi;
use sp_runtime::traits::{BlakeTwo256, Hash as HashT};
use subspace_core_primitives::{crypto, objects::BlockObjectMapping, Sha256Hash};
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
    assert_eq!(objects[0].hash(), crypto::sha256_hash(&data0),);
    assert_eq!(objects[1].hash(), crypto::sha256_hash(&data1));
    assert_eq!(objects[2].hash(), crypto::sha256_hash(&data2));
    assert_eq!(objects[3].hash(), crypto::sha256_hash(&data3));
    assert_eq!(objects[4].hash(), crypto::sha256_hash(&data0));
    assert_eq!(objects[5].hash(), crypto::sha256_hash(&data2));
    assert_eq!(objects[6].hash(), crypto::sha256_hash(&data3));

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

fn key(feed_id: u64, data: &[u8]) -> Sha256Hash {
    crypto::sha256_hash_pair(feed_id.encode(), data)
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
fn get_encoded_blocks() -> (Vec<u8>, Vec<Sha256Hash>, Vec<u8>) {
    let init_data = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 154, 181, 149, 12, 217, 145, 86, 199, 119, 238, 168, 44, 21, 155,
        38, 209, 36, 116, 146, 29, 117, 90, 228, 4, 192, 118, 149, 252, 170, 248, 62, 161, 157, 3,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 12, 66, 41, 215, 144, 185, 38, 223, 251, 103, 136, 167, 205, 48, 247, 245,
        28, 200, 92, 210, 10, 234, 212, 165, 58, 82, 218, 131, 252, 28, 13, 4, 4, 4, 70, 82, 78,
        75, 249, 1, 1, 12, 59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13,
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
            key(0, 1u32.encode().as_slice()),
            key(
                0,
                hex!("4b919fcd09bd9599881637dcabd2f0687a149b0d8dc1985b8783a35a2e094a74").as_slice(),
            ),
        ],
        vec![
            154, 181, 149, 12, 217, 145, 86, 199, 119, 238, 168, 44, 21, 155, 38, 209, 36, 116,
            146, 29, 117, 90, 228, 4, 192, 118, 149, 252, 170, 248, 62, 161, 4, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 66,
            41, 215, 144, 185, 38, 223, 251, 103, 136, 167, 205, 48, 247, 245, 28, 200, 92, 210,
            10, 234, 212, 165, 58, 82, 218, 131, 252, 28, 13, 4, 0, 4, 253, 3, 0, 1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
            51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
            73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94,
            95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
            113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
            130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146,
            147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163,
            164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180,
            181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
            198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214,
            215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
            232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248,
            249, 250, 251, 252, 253, 254, 1, 4, 70, 82, 78, 75, 41, 10, 1, 0, 0, 0, 0, 0, 0, 0, 75,
            145, 159, 205, 9, 189, 149, 153, 136, 22, 55, 220, 171, 210, 240, 104, 122, 20, 155,
            13, 141, 193, 152, 91, 135, 131, 163, 90, 46, 9, 74, 116, 1, 0, 0, 0, 12, 117, 249,
            107, 252, 231, 158, 116, 127, 197, 188, 151, 171, 100, 152, 151, 228, 10, 111, 84, 6,
            26, 196, 5, 81, 181, 218, 171, 181, 245, 73, 220, 231, 3, 0, 0, 0, 47, 91, 123, 137,
            178, 227, 81, 15, 138, 78, 149, 36, 225, 69, 3, 152, 247, 2, 241, 218, 12, 66, 195,
            185, 79, 245, 236, 34, 152, 71, 9, 203, 165, 188, 128, 246, 30, 26, 82, 247, 84, 180,
            244, 148, 112, 218, 184, 229, 86, 199, 135, 188, 32, 111, 229, 247, 228, 148, 70, 41,
            109, 117, 231, 9, 59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13,
            115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41, 117, 249,
            107, 252, 231, 158, 116, 127, 197, 188, 151, 171, 100, 152, 151, 228, 10, 111, 84, 6,
            26, 196, 5, 81, 181, 218, 171, 181, 245, 73, 220, 231, 3, 0, 0, 0, 223, 34, 247, 71,
            75, 93, 109, 142, 140, 89, 14, 86, 142, 26, 75, 32, 162, 237, 98, 212, 193, 147, 190,
            138, 17, 196, 192, 72, 222, 29, 15, 153, 157, 122, 128, 36, 212, 96, 136, 93, 147, 112,
            15, 62, 39, 61, 231, 89, 223, 38, 220, 158, 32, 147, 47, 209, 112, 91, 127, 67, 3, 169,
            246, 0, 206, 204, 21, 7, 220, 29, 221, 114, 149, 149, 28, 41, 8, 136, 240, 149, 173,
            185, 4, 77, 27, 115, 214, 150, 230, 223, 6, 93, 104, 59, 212, 252, 117, 249, 107, 252,
            231, 158, 116, 127, 197, 188, 151, 171, 100, 152, 151, 228, 10, 111, 84, 6, 26, 196, 5,
            81, 181, 218, 171, 181, 245, 73, 220, 231, 3, 0, 0, 0, 71, 237, 181, 145, 168, 100, 55,
            95, 98, 238, 255, 47, 123, 151, 183, 88, 157, 23, 244, 127, 99, 57, 177, 195, 50, 244,
            129, 73, 29, 31, 218, 147, 185, 151, 255, 61, 225, 42, 16, 108, 223, 179, 47, 71, 108,
            64, 223, 87, 174, 167, 91, 78, 18, 237, 191, 65, 54, 177, 66, 163, 246, 112, 221, 7,
            107, 121, 197, 126, 106, 9, 82, 57, 40, 44, 4, 129, 142, 150, 17, 47, 63, 3, 164, 0,
            27, 169, 122, 86, 76, 35, 133, 42, 63, 30, 165, 252, 8, 75, 145, 159, 205, 9, 189, 149,
            153, 136, 22, 55, 220, 171, 210, 240, 104, 122, 20, 155, 13, 141, 193, 152, 91, 135,
            131, 163, 90, 46, 9, 74, 116, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 66, 41, 215, 144, 185, 38, 223, 251, 103,
            136, 167, 205, 48, 247, 245, 28, 200, 92, 210, 10, 234, 212, 165, 58, 82, 218, 131,
            252, 28, 13, 4, 4, 0, 16, 0, 0, 0, 0, 167, 196, 189, 53, 38, 86, 80, 202, 7, 134, 39,
            144, 146, 5, 150, 81, 181, 63, 58, 101, 230, 241, 163, 115, 214, 125, 233, 192, 95,
            131, 89, 161, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 66, 41, 215, 144, 185, 38, 223, 251, 103, 136, 167, 205,
            48, 247, 245, 28, 200, 92, 210, 10, 234, 212, 165, 58, 82, 218, 131, 252, 28, 13, 4, 4,
            0, 16, 0, 0, 0, 0,
        ],
    )
}
