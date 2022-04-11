use codec::Encode;
use frame_support::sp_io;
use hex_literal::hex;
use sp_consensus_subspace::runtime_decl_for_SubspaceApi::SubspaceApi;
use subspace_core_primitives::{crypto, objects::BlockObjectMapping, Sha256Hash};
use subspace_runtime::{
    Block, Call, FeedProcessorKind, Feeds, Header, Origin, Runtime, System, UncheckedExtrinsic,
};

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

    let encoded_block = block.encode();
    let BlockObjectMapping { objects } = new_test_ext().execute_with(|| {
        // init feed
        Feeds::create(
            Origin::signed([0u8; 32].into()),
            FeedProcessorKind::default(),
            None,
        )
        .expect("create feed should not fail");

        Runtime::extract_block_object_mapping(block)
    });

    // Expect all 7 objects to be mapped.
    assert_eq!(objects.len(), 7);

    // Hashes should be computed correctly.
    assert_eq!(objects[0].hash(), crypto::sha256_hash(&data0));
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

#[test]
fn grandpa_object_mapping() {
    let (init_data, key, object) = get_encoded_blocks();
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
    let encoded_block = block.encode();
    let BlockObjectMapping { objects } = new_test_ext().execute_with(|| {
        // init feed
        Feeds::create(
            Origin::signed([0u8; 32].into()),
            FeedProcessorKind::PolkadotLike,
            Some(init_data),
        )
        .expect("create feed should not fail");

        Runtime::extract_block_object_mapping(block)
    });

    assert_eq!(objects.len(), 1);
    // Hashes should be computed correctly.
    assert_eq!(objects[0].hash(), key);

    // Offsets for mapped objects should be correct
    assert_eq!(
        &encoded_block[objects[0].offset() as usize..][..object.encoded_size()],
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
fn get_encoded_blocks() -> (Vec<u8>, Sha256Hash, Vec<u8>) {
    let init_data = vec![
        157, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 70, 82, 78, 75, 249, 1, 1, 12, 59, 106, 39, 188, 206, 182,
        164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192,
        72, 161, 139, 89, 218, 41, 1, 0, 0, 0, 0, 0, 0, 0, 206, 204, 21, 7, 220, 29, 221, 114, 149,
        149, 28, 41, 8, 136, 240, 149, 173, 185, 4, 77, 27, 115, 214, 150, 230, 223, 6, 93, 104,
        59, 212, 252, 1, 0, 0, 0, 0, 0, 0, 0, 107, 121, 197, 126, 106, 9, 82, 57, 40, 44, 4, 129,
        142, 150, 17, 47, 63, 3, 164, 0, 27, 169, 122, 86, 76, 35, 133, 42, 63, 30, 165, 252, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    ];

    (
        init_data,
        hex!("b9e292877e74b5632ff9cb7253204c8810932bec4b4713a03a41c54b0b245e04"),
        vec![
            220, 221, 137, 146, 125, 138, 52, 142, 0, 37, 126, 30, 204, 134, 23, 244, 94, 219, 81,
            24, 239, 255, 62, 162, 249, 150, 27, 42, 217, 183, 105, 10, 4, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 4, 70, 82, 78, 75, 41, 10, 1, 0, 0, 0, 0, 0, 0, 0, 185, 226, 146, 135, 126, 116,
            181, 99, 47, 249, 203, 114, 83, 32, 76, 136, 16, 147, 43, 236, 75, 71, 19, 160, 58, 65,
            197, 75, 11, 36, 94, 4, 1, 0, 0, 0, 12, 230, 156, 16, 221, 114, 232, 28, 98, 45, 143,
            204, 67, 247, 76, 105, 9, 194, 198, 36, 33, 32, 41, 210, 95, 247, 132, 167, 240, 207,
            24, 215, 133, 3, 0, 0, 0, 223, 146, 5, 4, 0, 159, 100, 116, 51, 185, 179, 213, 254,
            134, 98, 180, 178, 234, 9, 135, 0, 80, 59, 172, 70, 93, 146, 211, 158, 253, 71, 127,
            173, 89, 56, 69, 151, 25, 45, 32, 63, 221, 216, 110, 191, 136, 83, 113, 76, 65, 230,
            69, 124, 252, 2, 93, 82, 206, 62, 153, 189, 85, 37, 0, 59, 106, 39, 188, 206, 182, 164,
            45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192,
            72, 161, 139, 89, 218, 41, 230, 156, 16, 221, 114, 232, 28, 98, 45, 143, 204, 67, 247,
            76, 105, 9, 194, 198, 36, 33, 32, 41, 210, 95, 247, 132, 167, 240, 207, 24, 215, 133,
            3, 0, 0, 0, 1, 91, 218, 207, 252, 200, 211, 176, 24, 237, 191, 10, 18, 222, 22, 111,
            23, 186, 217, 53, 241, 142, 242, 231, 185, 103, 125, 43, 21, 24, 216, 83, 166, 54, 176,
            20, 232, 77, 197, 26, 50, 87, 251, 107, 175, 131, 153, 18, 243, 190, 218, 86, 37, 89,
            225, 58, 58, 252, 3, 106, 142, 56, 3, 9, 206, 204, 21, 7, 220, 29, 221, 114, 149, 149,
            28, 41, 8, 136, 240, 149, 173, 185, 4, 77, 27, 115, 214, 150, 230, 223, 6, 93, 104, 59,
            212, 252, 230, 156, 16, 221, 114, 232, 28, 98, 45, 143, 204, 67, 247, 76, 105, 9, 194,
            198, 36, 33, 32, 41, 210, 95, 247, 132, 167, 240, 207, 24, 215, 133, 3, 0, 0, 0, 166,
            221, 153, 225, 112, 205, 86, 29, 172, 35, 245, 192, 85, 238, 94, 130, 9, 217, 229, 33,
            122, 215, 108, 68, 20, 171, 118, 88, 193, 57, 51, 193, 167, 75, 189, 27, 161, 33, 198,
            159, 22, 74, 107, 15, 168, 87, 154, 26, 0, 44, 10, 6, 176, 41, 122, 61, 22, 158, 141,
            254, 53, 33, 48, 14, 107, 121, 197, 126, 106, 9, 82, 57, 40, 44, 4, 129, 142, 150, 17,
            47, 63, 3, 164, 0, 27, 169, 122, 86, 76, 35, 133, 42, 63, 30, 165, 252, 8, 185, 226,
            146, 135, 126, 116, 181, 99, 47, 249, 203, 114, 83, 32, 76, 136, 16, 147, 43, 236, 75,
            71, 19, 160, 58, 65, 197, 75, 11, 36, 94, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 16, 0, 0, 0, 0,
            87, 123, 223, 91, 135, 83, 252, 53, 71, 92, 157, 143, 102, 191, 11, 131, 103, 150, 149,
            179, 14, 199, 191, 50, 125, 196, 191, 227, 202, 183, 152, 231, 12, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
            0, 16, 0, 0, 0, 0,
        ],
    )
}
