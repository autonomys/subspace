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
        161, 60, 150, 1, 156, 55, 105, 69, 117, 98, 246, 175, 92, 109, 151, 209, 155, 95, 189, 11,
        53, 69, 71, 155, 241, 87, 164, 97, 66, 154, 73, 25, 157, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 157, 136, 9,
        44, 178, 226, 252, 203, 48, 105, 21, 169, 57, 152, 132, 210, 214, 24, 71, 166, 161, 238,
        79, 188, 139, 198, 134, 210, 62, 75, 251, 4, 4, 70, 82, 78, 75, 249, 1, 1, 12, 59, 106, 39,
        188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29, 226, 67,
        166, 58, 192, 72, 161, 139, 89, 218, 41, 1, 0, 0, 0, 0, 0, 0, 0, 206, 204, 21, 7, 220, 29,
        221, 114, 149, 149, 28, 41, 8, 136, 240, 149, 173, 185, 4, 77, 27, 115, 214, 150, 230, 223,
        6, 93, 104, 59, 212, 252, 1, 0, 0, 0, 0, 0, 0, 0, 107, 121, 197, 126, 106, 9, 82, 57, 40,
        44, 4, 129, 142, 150, 17, 47, 63, 3, 164, 0, 27, 169, 122, 86, 76, 35, 133, 42, 63, 30,
        165, 252, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
    ];

    (
        init_data,
        vec![
            key(0, 1u32.encode().as_slice()),
            key(
                0,
                hex!("4ce326893e8c83317fc528986d220e37c8508d43ced9626551b456864ae0783d").as_slice(),
            ),
        ],
        vec![
            161, 60, 150, 1, 156, 55, 105, 69, 117, 98, 246, 175, 92, 109, 151, 209, 155, 95, 189,
            11, 53, 69, 71, 155, 241, 87, 164, 97, 66, 154, 73, 25, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 157, 136, 9,
            44, 178, 226, 252, 203, 48, 105, 21, 169, 57, 152, 132, 210, 214, 24, 71, 166, 161,
            238, 79, 188, 139, 198, 134, 210, 62, 75, 251, 0, 4, 253, 3, 0, 1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
            53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
            75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
            97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
            115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
            132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
            149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
            166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182,
            183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
            200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216,
            217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
            234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
            251, 252, 253, 254, 1, 4, 70, 82, 78, 75, 41, 10, 1, 0, 0, 0, 0, 0, 0, 0, 76, 227, 38,
            137, 62, 140, 131, 49, 127, 197, 40, 152, 109, 34, 14, 55, 200, 80, 141, 67, 206, 217,
            98, 101, 81, 180, 86, 134, 74, 224, 120, 61, 1, 0, 0, 0, 12, 66, 191, 206, 195, 159,
            169, 138, 90, 43, 223, 50, 125, 29, 62, 69, 244, 80, 85, 110, 152, 1, 216, 169, 24,
            191, 0, 96, 71, 171, 65, 233, 35, 3, 0, 0, 0, 239, 31, 12, 25, 53, 68, 24, 12, 3, 187,
            82, 196, 204, 238, 159, 185, 27, 18, 78, 19, 46, 220, 192, 190, 38, 196, 219, 131, 55,
            90, 112, 234, 246, 113, 173, 200, 58, 237, 28, 184, 21, 219, 181, 231, 102, 188, 203,
            107, 40, 17, 93, 236, 168, 55, 147, 38, 234, 210, 169, 180, 233, 9, 21, 8, 59, 106, 39,
            188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29, 226,
            67, 166, 58, 192, 72, 161, 139, 89, 218, 41, 66, 191, 206, 195, 159, 169, 138, 90, 43,
            223, 50, 125, 29, 62, 69, 244, 80, 85, 110, 152, 1, 216, 169, 24, 191, 0, 96, 71, 171,
            65, 233, 35, 3, 0, 0, 0, 242, 23, 244, 65, 135, 96, 14, 63, 39, 254, 185, 142, 19, 4,
            206, 216, 175, 180, 13, 234, 192, 162, 125, 67, 15, 165, 64, 165, 132, 181, 20, 48, 82,
            130, 35, 183, 213, 41, 34, 79, 155, 111, 213, 18, 5, 175, 167, 176, 114, 106, 200, 157,
            135, 41, 164, 4, 29, 200, 47, 123, 207, 131, 152, 14, 206, 204, 21, 7, 220, 29, 221,
            114, 149, 149, 28, 41, 8, 136, 240, 149, 173, 185, 4, 77, 27, 115, 214, 150, 230, 223,
            6, 93, 104, 59, 212, 252, 66, 191, 206, 195, 159, 169, 138, 90, 43, 223, 50, 125, 29,
            62, 69, 244, 80, 85, 110, 152, 1, 216, 169, 24, 191, 0, 96, 71, 171, 65, 233, 35, 3, 0,
            0, 0, 3, 159, 107, 61, 243, 194, 127, 158, 56, 127, 119, 107, 76, 47, 7, 189, 43, 6,
            84, 128, 66, 42, 201, 240, 47, 190, 142, 138, 246, 158, 137, 223, 253, 117, 82, 101,
            116, 166, 8, 165, 46, 79, 223, 30, 0, 65, 21, 135, 33, 217, 152, 188, 211, 122, 110,
            65, 55, 71, 205, 45, 161, 177, 140, 2, 107, 121, 197, 126, 106, 9, 82, 57, 40, 44, 4,
            129, 142, 150, 17, 47, 63, 3, 164, 0, 27, 169, 122, 86, 76, 35, 133, 42, 63, 30, 165,
            252, 8, 76, 227, 38, 137, 62, 140, 131, 49, 127, 197, 40, 152, 109, 34, 14, 55, 200,
            80, 141, 67, 206, 217, 98, 101, 81, 180, 86, 134, 74, 224, 120, 61, 8, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36,
            157, 136, 9, 44, 178, 226, 252, 203, 48, 105, 21, 169, 57, 152, 132, 210, 214, 24, 71,
            166, 161, 238, 79, 188, 139, 198, 134, 210, 62, 75, 251, 4, 0, 16, 0, 0, 0, 0, 203,
            102, 25, 158, 252, 54, 0, 101, 183, 105, 119, 68, 111, 219, 27, 176, 204, 114, 57, 115,
            4, 120, 44, 113, 191, 243, 83, 216, 119, 5, 142, 208, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 157, 136, 9, 44,
            178, 226, 252, 203, 48, 105, 21, 169, 57, 152, 132, 210, 214, 24, 71, 166, 161, 238,
            79, 188, 139, 198, 134, 210, 62, 75, 251, 4, 0, 16, 0, 0, 0, 0,
        ],
    )
}
