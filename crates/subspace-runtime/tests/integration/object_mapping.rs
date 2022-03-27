use codec::Encode;
use sp_consensus_subspace::runtime_decl_for_SubspaceApi::SubspaceApi;
use subspace_core_primitives::crypto;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_runtime::{Block, Call, Header, Runtime, UncheckedExtrinsic};

#[test]
fn object_mapping() {
    let data0: Vec<u8> = (0..=99).collect();
    let data1: Vec<u8> = (123..=255).collect();
    let data2: Vec<u8> = (0..=99).rev().collect();
    let data3: Vec<u8> = (123..=255).rev().collect();
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
                    metadata: vec![1, 2, 3],
                }),
            },
            UncheckedExtrinsic {
                signature: None,
                function: Call::Feeds(pallet_feeds::Call::put {
                    feed_id: 0,
                    object: data1.clone(),
                    metadata: vec![],
                }),
            },
            UncheckedExtrinsic {
                signature: None,
                function: Call::Utility(pallet_utility::Call::batch {
                    calls: vec![
                        Call::Feeds(pallet_feeds::Call::put {
                            feed_id: 0,
                            object: data2.clone(),
                            metadata: vec![1, 2, 3],
                        }),
                        Call::Feeds(pallet_feeds::Call::put {
                            feed_id: 0,
                            object: data3.clone(),
                            metadata: vec![],
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
                        metadata: vec![1, 2, 3],
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
                            metadata: vec![1, 2, 3],
                        }),
                        Call::Feeds(pallet_feeds::Call::put {
                            feed_id: 0,
                            object: data3.clone(),
                            metadata: vec![],
                        }),
                    ],
                }),
            },
        ],
    };

    let encoded_block = block.encode();
    let BlockObjectMapping { objects } = Runtime::extract_block_object_mapping(block);

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
