use crate as ethereum_beacon_client;
use crate::merkleization::MerkleizationError;
use crate::mock::{new_tester, *};
use crate::ssz::{
    SSZAttestation, SSZAttestationData, SSZAttesterSlashing, SSZCheckpoint, SSZEth1Data,
    SSZExecutionPayload, SSZSyncAggregate,
};
use crate::{config, merkleization, Error, PublicKey};
use frame_support::{assert_err, assert_ok};
use hex_literal::hex;
use snowbridge_beacon_primitives::{
    Attestation, AttestationData, BeaconHeader, Checkpoint, Eth1Data, ExecutionPayload,
    SyncAggregate,
};
use sp_core::{H256, U256};
use ssz_rs::prelude::Vector;

#[test]
pub fn test_get_sync_committee_sum() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        assert_eq!(
            mock_mainnet::EthereumBeaconClient::get_sync_committee_sum(vec![
                0, 1, 0, 1, 1, 0, 1, 0, 1
            ]),
            5
        );
    });
}

#[test]
pub fn test_compute_domain() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        let domain = mock_mainnet::EthereumBeaconClient::compute_domain(
            hex!("07000000").into(),
            hex!("00000001"),
            hex!("5dec7ae03261fde20d5b024dfabce8bac3276c9a4908e23d50ba8c9b50b0adff").into(),
        );

        assert_ok!(&domain);
        assert_eq!(
            domain.unwrap(),
            hex!("0700000046324489ceb6ada6d118eacdbe94f49b1fcb49d5481a685979670c7c").into()
        );
    });
}

#[test]
pub fn test_compute_domain_kiln() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        let domain = mock_mainnet::EthereumBeaconClient::compute_domain(
            hex!("07000000").into(),
            hex!("70000071"),
            hex!("99b09fcd43e5905236c370f184056bec6e6638cfc31a323b304fc4aa789cb4ad").into(),
        );

        assert_ok!(&domain);
        assert_eq!(
            domain.unwrap(),
            hex!("07000000e7acb21061790987fa1c1e745cccfb358370b33e8af2b2c18938e6c2").into()
        );
    });
}

#[test]
pub fn test_compute_signing_root_bls() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        let signing_root = mock_mainnet::EthereumBeaconClient::compute_signing_root(
            BeaconHeader {
                slot: 3529537,
                proposer_index: 192549,
                parent_root: hex!(
                    "1f8dc05ea427f78e84e2e2666e13c3befb7106fd1d40ef8a3f67cf615f3f2a4c"
                )
                .into(),
                state_root: hex!(
                    "0dfb492a83da711996d2d76b64604f9bca9dc08b6c13cf63b3be91742afe724b"
                )
                .into(),
                body_root: hex!("66fba38f7c8c2526f7ddfe09c1a54dd12ff93bdd4d0df6a0950e88e802228bfa")
                    .into(),
            },
            hex!("07000000afcaaba0efab1ca832a15152469bb09bb84641c405171dfa2d3fb45f").into(),
        );

        assert_ok!(&signing_root);
        assert_eq!(
            signing_root.unwrap(),
            hex!("3ff6e9807da70b2f65cdd58ea1b25ed441a1d589025d2c4091182026d7af08fb").into()
        );
    });
}

#[test]
pub fn test_compute_signing_root_kiln() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        let signing_root = mock_mainnet::EthereumBeaconClient::compute_signing_root(
            BeaconHeader {
                slot: 221316,
                proposer_index: 79088,
                parent_root: hex!(
                    "b4c15cd79da1a4e645b0104fa66d226cb6dce0fae3522789cc4d0b3ae41d96f7"
                )
                .into(),
                state_root: hex!(
                    "6f711ef2e36decbc8f7037e73bbdace42c11f2896a43e44ab8a78dcb2ba66122"
                )
                .into(),
                body_root: hex!("963eaa01341c16dc8f288da47eedad0792978fdaab9f1f97ae0a1103494d1a10")
                    .into(),
            },
            hex!("07000000afcaaba0efab1ca832a15152469bb09bb84641c405171dfa2d3fb45f").into(),
        );

        assert_ok!(&signing_root);
        assert_eq!(
            signing_root.unwrap(),
            hex!("4ce7b4192c0292a2bbf4107766ddc0f613261bb8e6968ccd0e6b71b30fad6d7c").into()
        );
    });
}

#[test]
pub fn test_compute_signing_root_kiln_head_update() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        let signing_root = mock_mainnet::EthereumBeaconClient::compute_signing_root(
            BeaconHeader {
                slot: 222472,
                proposer_index: 10726,
                parent_root: hex!(
                    "5d481a9721f0ecce9610eab51d400d223683d599b7fcebca7e4c4d10cdef6ebb"
                )
                .into(),
                state_root: hex!(
                    "14eb4575895f996a84528b789ff2e4d5148242e2983f03068353b2c37015507a"
                )
                .into(),
                body_root: hex!("7bb669c75b12e0781d6fa85d7fc2f32d64eafba89f39678815b084c156e46cac")
                    .into(),
            },
            hex!("07000000e7acb21061790987fa1c1e745cccfb358370b33e8af2b2c18938e6c2").into(),
        );

        assert_ok!(&signing_root);
        assert_eq!(
            signing_root.unwrap(),
            hex!("da12b6a6d3516bc891e8a49f82fc1925cec40b9327e06457f695035303f55cd8").into()
        );
    });
}

#[test]
pub fn test_compute_domain_bls() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        let domain = mock_mainnet::EthereumBeaconClient::compute_domain(
            hex!("07000000").into(),
            hex!("01000000"),
            hex!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95").into(),
        );

        assert_ok!(&domain);
        assert_eq!(
            domain.unwrap(),
            hex!("07000000afcaaba0efab1ca832a15152469bb09bb84641c405171dfa2d3fb45f").into()
        );
    });
}

#[test]
pub fn test_is_valid_merkle_proof() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        assert!(mock_mainnet::EthereumBeaconClient::is_valid_merkle_branch(
            hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
            vec![
                hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
                hex!("5f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf371").into(),
                hex!("e7125ff9ab5a840c44bedb4731f440a405b44e15f2d1a89e27341b432fabe13d").into(),
                hex!("002c1fe5bc0bd62db6f299a582f2a80a6d5748ccc82e7ed843eaf0ae0739f74a").into(),
                hex!("d2dc4ba9fd4edff6716984136831e70a6b2e74fca27b8097a820cbbaa5a6e3c3").into(),
                hex!("91f77a19d8afa4a08e81164bb2e570ecd10477b3b65c305566a6d2be88510584").into(),
            ]
            .to_vec()
            .try_into()
            .expect("proof branch is too long"),
            6,
            41,
            hex!("e46559327592741956f6beaa0f52e49625eb85dce037a0bd2eff333c743b287f").into()
        ));
    });
}

#[test]
pub fn test_merkle_proof_fails_if_depth_and_branch_dont_match() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        assert!(!mock_mainnet::EthereumBeaconClient::is_valid_merkle_branch(
            hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
            vec![
                hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
                hex!("5f6f02af29218292d21a69b64a794a7c0873b3e0f54611972863706e8cbdf371").into(),
                hex!("e7125ff9ab5a840c44bedb4731f440a405b44e15f2d1a89e27341b432fabe13d").into(),
            ]
            .to_vec()
            .try_into()
            .expect("proof branch is too long"),
            6,
            41,
            hex!("e46559327592741956f6beaa0f52e49625eb85dce037a0bd2eff333c743b287f").into()
        ));
    });
}

#[test]
pub fn test_bls_fast_aggregate_verify_minimal() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
		assert_ok!(mock_mainnet::EthereumBeaconClient::bls_fast_aggregate_verify(
			vec![
				PublicKey(hex!("a73eb991aa22cdb794da6fcde55a427f0a4df5a4a70de23a988b5e5fc8c4d844f66d990273267a54dd21579b7ba6a086")),
				PublicKey(hex!("b29043a7273d0a2dbc2b747dcf6a5eccbd7ccb44b2d72e985537b117929bc3fd3a99001481327788ad040b4077c47c0d")),
				PublicKey(hex!("b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7")),
				PublicKey(hex!("9446407bcd8e5efe9f2ac0efbfa9e07d136e68b03c5ebc5bde43db3b94773de8605c30419eb2596513707e4e7448bb50")),
			],
			hex!("69241e7146cdcc5a5ddc9a60bab8f378c0271e548065a38bcc60624e1dbed97f").into(),
			hex!("b204e9656cbeb79a9a8e397920fd8e60c5f5d9443f58d42186f773c6ade2bd263e2fe6dbdc47f148f871ed9a00b8ac8b17a40d65c8d02120c00dca77495888366b4ccc10f1c6daa02db6a7516555ca0665bca92a647b5f3a514fa083fdc53b6e").to_vec().try_into().expect("signature is too long"),
		));
	});
}

#[test]
pub fn test_bls_fast_aggregate_verify_invalid_point() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
		assert_err!(mock_mainnet::EthereumBeaconClient::bls_fast_aggregate_verify(
			vec![
				PublicKey(hex!("973eb991aa22cdb794da6fcde55a427f0a4df5a4a70de23a988b5e5fc8c4d844f66d990273267a54dd21579b7ba6a086")),
				PublicKey(hex!("b29043a7273d0a2dbc2b747dcf6a5eccbd7ccb44b2d72e985537b117929bc3fd3a99001481327788ad040b4077c47c0d")),
				PublicKey(hex!("b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7")),
				PublicKey(hex!("9446407bcd8e5efe9f2ac0efbfa9e07d136e68b03c5ebc5bde43db3b94773de8605c30419eb2596513707e4e7448bb50")),
			],
			hex!("69241e7146cdcc5a5ddc9a60bab8f378c0271e548065a38bcc60624e1dbed97f").into(),
			hex!("b204e9656cbeb79a9a8e397920fd8e60c5f5d9443f58d42186f773c6ade2bd263e2fe6dbdc47f148f871ed9a00b8ac8b17a40d65c8d02120c00dca77495888366b4ccc10f1c6daa02db6a7516555ca0665bca92a647b5f3a514fa083fdc53b6e").to_vec().try_into().expect("signature is too long"),
		), Error::<mock_mainnet::Test>::InvalidSignaturePoint);
	});
}

#[test]
pub fn test_bls_fast_aggregate_verify_invalid_message() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
		assert_err!(mock_mainnet::EthereumBeaconClient::bls_fast_aggregate_verify(
			vec![
				PublicKey(hex!("a73eb991aa22cdb794da6fcde55a427f0a4df5a4a70de23a988b5e5fc8c4d844f66d990273267a54dd21579b7ba6a086")),
				PublicKey(hex!("b29043a7273d0a2dbc2b747dcf6a5eccbd7ccb44b2d72e985537b117929bc3fd3a99001481327788ad040b4077c47c0d")),
				PublicKey(hex!("b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7")),
				PublicKey(hex!("9446407bcd8e5efe9f2ac0efbfa9e07d136e68b03c5ebc5bde43db3b94773de8605c30419eb2596513707e4e7448bb50")),
			],
			hex!("99241e7146cdcc5a5ddc9a60bab8f378c0271e548065a38bcc60624e1dbed97f").into(),
			hex!("b204e9656cbeb79a9a8e397920fd8e60c5f5d9443f58d42186f773c6ade2bd263e2fe6dbdc47f148f871ed9a00b8ac8b17a40d65c8d02120c00dca77495888366b4ccc10f1c6daa02db6a7516555ca0665bca92a647b5f3a514fa083fdc53b6e").to_vec().try_into().expect("signature is too long"),
		), Error::<mock_mainnet::Test>::SignatureVerificationFailed);
	});
}

#[test]
pub fn test_bls_fast_aggregate_verify_invalid_signature() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
		assert_err!(mock_mainnet::EthereumBeaconClient::bls_fast_aggregate_verify(
			vec![
				PublicKey(hex!("a73eb991aa22cdb794da6fcde55a427f0a4df5a4a70de23a988b5e5fc8c4d844f66d990273267a54dd21579b7ba6a086")),
				PublicKey(hex!("b29043a7273d0a2dbc2b747dcf6a5eccbd7ccb44b2d72e985537b117929bc3fd3a99001481327788ad040b4077c47c0d")),
				PublicKey(hex!("b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7")),
				PublicKey(hex!("9446407bcd8e5efe9f2ac0efbfa9e07d136e68b03c5ebc5bde43db3b94773de8605c30419eb2596513707e4e7448bb50")),
			],
			hex!("69241e7146cdcc5a5ddc9a60bab8f378c0271e548065a38bcc60624e1dbed97f").into(),
			hex!("c204e9656cbeb79a9a8e397920fd8e60c5f5d9443f58d42186f773c6ade2bd263e2fe6dbdc47f148f871ed9a00b8ac8b17a40d65c8d02120c00dca77495888366b4ccc10f1c6daa02db6a7516555ca0665bca92a647b5f3a514fa083fdc53b6e").to_vec().try_into().expect("signature is too long"),
		), Error::<mock_mainnet::Test>::InvalidSignature);
	});
}

pub fn sync_committee_participation_is_supermajority(bits: Vec<u8>) {
    let sync_committee_bits = merkleization::get_sync_committee_bits(
        bits.try_into().expect("too many sync committee bits"),
    );

    assert_ok!(&sync_committee_bits);

    assert_ok!(
        mock_mainnet::EthereumBeaconClient::sync_committee_participation_is_supermajority(
            sync_committee_bits.unwrap()
        )
    );
}

#[test]
pub fn test_sync_committee_participation_is_supermajority() {
    #[cfg(feature = "mainnet")]
	sync_committee_participation_is_supermajority(hex!("cffffffff8f1ffdfcfeffeffbfdffffbfffffdffffefefffdffff7f7ffff77fffdf7bff77ffdf7fffafffffff77fefffeff7effffffff5f7fedfffdfb6ddff7b").to_vec());

    #[cfg(not(feature = "mainnet"))]
	sync_committee_participation_is_supermajority(hex!("bffffffff7f1ffdfcfeffeffbfdffffbfffffdffffefefffdffff7f7ffff77fffdf7bff77ffdf7fffafffffff77fefffeff7effffffff5f7fedfffdfb6ddff7b").to_vec());
}

pub fn sync_committee_bits_too_short(bits: Vec<u8>) {
    let sync_committee_bits = merkleization::get_sync_committee_bits(
        bits.try_into().expect("invalid sync committee bits"),
    );

    assert_err!(
        sync_committee_bits,
        MerkleizationError::ExpectedFurtherInput {
            provided: 47,
            expected: 64
        }
    );
}

#[test]
pub fn test_sync_committee_bits_too_short() {
    #[cfg(feature = "mainnet")]
	sync_committee_bits_too_short(hex!("cffffffff8f1ffdfcfeffeffbfdffffbfffffdffffefefffdffff7f7ffff77fffdf7bffff5f7fedfffdfb6ddff7bf7").to_vec());

    #[cfg(not(feature = "mainnet"))]
	sync_committee_bits_too_short(hex!("bffffffff7f1ffdfcfeffeffbfdffffbfffffdffffefefffdffff7f7ffff77fffdf7bffff5f7fedfffdfb6ddff7bf7").to_vec());
}

pub fn sync_committee_bits_extra_input(bits: Vec<u8>) {
    let sync_committee_bits = merkleization::get_sync_committee_bits(
        bits.try_into().expect("invalid sync committee bits"),
    );

    assert_err!(
        sync_committee_bits,
        MerkleizationError::AdditionalInput {
            provided: 130,
            expected: 64
        }
    );
}

#[test]
pub fn test_sync_committee_bits_extra_input() {
    #[cfg(feature = "mainnet")]
	sync_committee_bits_extra_input(hex!("cffffffff8f1ffdfcfeffeffbfdffffbfffffdffffefefffdffff7f7ffff77fffdf7bff77ffdf7fffafffffff77fefffeff7effffffff5f7fedfffdfb6ddff7bf7bffffffff7f1ffdfcfeffeffbfdffffbfffffdffffefefffdffff7f7ffff77fffdf7bff77ffdf7fffafffffff77fefffeff7effffffff5f7fedfffdfb6ddff7bf7").to_vec());

    #[cfg(not(feature = "mainnet"))]
	sync_committee_bits_extra_input(hex!("bffffffff7f1ffdfcfeffeffbfdffffbfffffdffffefefffdffff7f7ffff77fffdf7bff77ffdf7fffafffffff77fefffeff7effffffff5f7fedfffdfb6ddff7bf7bffffffff7f1ffdfcfeffeffbfdffffbfffffdffffefefffdffff7f7ffff77fffdf7bff77ffdf7fffafffffff77fefffeff7effffffff5f7fedfffdfb6ddff7bf7").to_vec());
}

#[test]
pub fn test_sync_committee_participation_is_supermajority_errors_when_not_supermajority() {
    new_tester::<mock_mainnet::Test>().execute_with(|| {
        let sync_committee_bits = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1,
            1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0,
            1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1,
            0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        ];

        assert_err!(
            mock_mainnet::EthereumBeaconClient::sync_committee_participation_is_supermajority(
                sync_committee_bits
            ),
            Error::<mock_mainnet::Test>::SyncCommitteeParticipantsNotSupermajority
        );
    });
}

#[test]
pub fn test_hash_tree_root_beacon_header() {
    let hash_root = merkleization::hash_tree_root_beacon_header(BeaconHeader {
        slot: 3,
        proposer_index: 2,
        parent_root: hex!("796ea53efb534eab7777809cc5ee2d84e7f25024b9d0c4d7e5bcaab657e4bdbd")
            .into(),
        state_root: hex!("ba3ff080912be5c9c158b2e962c1b39a91bc0615762ba6fa2ecacafa94e9ae0a").into(),
        body_root: hex!("a18d7fcefbb74a177c959160e0ee89c23546482154e6831237710414465dcae5").into(),
    });

    assert_ok!(&hash_root);
    assert_eq!(
        hash_root.unwrap(),
        hex!("7d42595818709e805dd2fa710a2d2c1f62576ef1ab7273941ac9130fb94b91f7")
    );
}

#[test]
pub fn test_hash_tree_root_beacon_header_more_test_values() {
    let hash_root =
        merkleization::hash_tree_root_beacon_header(ethereum_beacon_client::BeaconHeader {
            slot: 3476424,
            proposer_index: 314905,
            parent_root: hex!("c069d7b49cffd2b815b0fb8007eb9ca91202ea548df6f3db60000f29b2489f28")
                .into(),
            state_root: hex!("444d293e4533501ee508ad608783a7d677c3c566f001313e8a02ce08adf590a3")
                .into(),
            body_root: hex!("6508a0241047f21ba88f05d05b15534156ab6a6f8e029a9a5423da429834e04a")
                .into(),
        });

    assert_ok!(&hash_root);
    assert_eq!(
        hash_root.unwrap(),
        hex!("0aa41166ff01e58e111ac8c42309a738ab453cf8d7285ed8477b1c484acb123e")
    );
}

#[test]
pub fn test_hash_tree_root_fork_data() {
    let hash_root = merkleization::hash_tree_root_fork_data(ethereum_beacon_client::ForkData {
        current_version: hex!("83f38a34"),
        genesis_validators_root: hex!(
            "22370bbbb358800f5711a10ea9845284272d8493bed0348cab87b8ab1e127930"
        ),
    });

    assert_ok!(&hash_root);
    assert_eq!(
        hash_root.unwrap(),
        hex!("57c12c4246bc7152b174b51920506bf943eff9c7ffa50b9533708e9cc1f680fc")
    );
}

#[test]
pub fn test_hash_tree_root_signing_data() {
    let hash_root =
        merkleization::hash_tree_root_signing_data(ethereum_beacon_client::SigningData {
            object_root: hex!("63654cbe64fc07853f1198c165dd3d49c54fc53bc417989bbcc66da15f850c54")
                .into(),
            domain: hex!("037da907d1c3a03c0091b2254e1480d9b1783476e228ab29adaaa8f133e08f7a").into(),
        });

    assert_ok!(&hash_root);
    assert_eq!(
        hash_root.unwrap(),
        hex!("b9eb2caf2d691b183c2d57f322afe505c078cd08101324f61c3641714789a54e")
    );
}

#[test]
pub fn test_hash_eth1_data() {
    let payload: Result<SSZEth1Data, MerkleizationError> = Eth1Data {
        deposit_root: hex!("d70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e")
            .into(),
        deposit_count: 0,
        block_hash: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
    }
    .try_into();
    assert_ok!(&payload);

    let hash_root = merkleization::hash_tree_root(payload.unwrap());
    assert_eq!(
        hash_root.unwrap(),
        hex!("aa247f2dfbb6e5d77b7e9f637f9bb70842cbec34cb4238d5bcb491f4e4b3fa5e")
    );
}

pub fn hash_sync_aggregate(
    sync_aggregate: SyncAggregate<config::SyncCommitteeSize, config::SignatureSize>,
    expected_hash_root: H256,
) {
    let payload: Result<SSZSyncAggregate, MerkleizationError> = sync_aggregate.try_into();
    assert_ok!(&payload);

    let hash_root_result = merkleization::hash_tree_root(payload.unwrap());
    assert_ok!(&hash_root_result);

    let hash_root: H256 = hash_root_result.unwrap().into();
    assert_eq!(hash_root, expected_hash_root);
}

#[test]
pub fn test_hash_sync_aggregate() {
    #[cfg(feature = "mainnet")]
	hash_sync_aggregate(SyncAggregate{
		sync_committee_bits: hex!("cefffffefffffff767fffbedffffeffffeeffdffffdebffffff7f7dbdf7fffdffffbffcfffdff79dfffbbfefff2ffffff7ddeff7ffffc98ff7fbfffffffffff7").to_vec().try_into().expect("sync committee bits are too long"),
		sync_committee_signature: hex!("8af1a8577bba419fe054ee49b16ed28e081dda6d3ba41651634685e890992a0b675e20f8d9f2ec137fe9eb50e838aa6117f9f5410e2e1024c4b4f0e098e55144843ce90b7acde52fe7b94f2a1037342c951dc59f501c92acf7ed944cb6d2b5f7").to_vec().try_into().expect("signature is too long"),
	}, hex!("e6dcad4f60ce9ff8a587b110facbaf94721f06cd810b6d8bf6cffa641272808d").into());

    #[cfg(not(feature = "mainnet"))]
	hash_sync_aggregate(SyncAggregate{
		sync_committee_bits: hex!("cefffffefffffff767fffbedffffeffffeeffdffffdebffffff7f7dbdf7fffdffffbffcfffdff79dfffbbfefff2ffffff7ddeff7ffffc98ff7fbfffffffffff7").to_vec().try_into().expect("sync committee bits are too long"),
		sync_committee_signature: hex!("8af1a8577bba419fe054ee49b16ed28e081dda6d3ba41651634685e890992a0b675e20f8d9f2ec137fe9eb50e838aa6117f9f5410e2e1024c4b4f0e098e55144843ce90b7acde52fe7b94f2a1037342c951dc59f501c92acf7ed944cb6d2b5f7").to_vec().try_into().expect("signature is too long"),
	}, hex!("e6dcad4f60ce9ff8a587b110facbaf94721f06cd810b6d8bf6cffa641272808d").into());
}

#[test]
pub fn test_hash_sync_signature() {
    let payload = Vector::<u8, 96>::from_iter(hex!("82c58d251044ab938b84747524e9b5ecbf6f71f6f1ac10a834806d033bbc49ecd2391072f9bbb4758a960342f8ee03930dc8195f15649c654a56767632230fe3d196f6499d94cd239ba964fe21d7e4715127a385ee018d405719428178172188").to_vec());

    let hash_root = merkleization::hash_tree_root(payload);

    assert_eq!(
        hash_root.unwrap(),
        hex!("2068ede33715fd1eee4a940cea6ebc7d353ea791c18ed0cdc65ab6f4bd367af1")
    );
}

#[test]
pub fn test_hash_tree_root_execution_payload() {
    let payload: Result<SSZExecutionPayload, MerkleizationError> =
		ExecutionPayload::<config::FeeRecipientSize, config::BytesPerLogsBloom, config::MaxExtraDataBytes>{
			parent_hash: hex!("eadee5ab098dde64e9fd02ae5858064bad67064070679625b09f8d82dec183f7").into(),
			fee_recipient: hex!("f97e180c050e5ab072211ad2c213eb5aee4df134").to_vec().try_into().expect("fee recipient bits are too long"),
			state_root: hex!("564fa064c2a324c2b5978d7fdfc5d4224d4f421a45388af1ed405a399c845dff").into(),
			receipts_root: hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").into(),
			logs_bloom: hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").to_vec().try_into().expect("logs bloom is too long"),
			prev_randao: hex!("6bf538bdfbdf1c96ff528726a40658a91d0bda0f1351448c4c4f3604db2a0ccf").into(),
			block_number: 477434,
			gas_limit: 8154925,
			gas_used: 0,
			timestamp: 1652816940,
			extra_data: vec![].try_into().expect("extra data field is too long"),
			base_fee_per_gas: U256::from(7_i16),
			block_hash: hex!("cd8df91b4503adb8f2f1c7a4f60e07a1f1a2cbdfa2a95bceba581f3ff65c1968").into(),
			transactions_root: hex!("7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1").into(),
		}.try_into();
    assert_ok!(&payload);

    let hash_root = merkleization::hash_tree_root(payload.unwrap());
    assert_eq!(
        hash_root.unwrap(),
        hex!("4c74e6119faeee22c04ef02fb6d8db26799753e2a9efcde6ea60cbac1f38cfd2")
    );
}

#[test]
pub fn test_hash_tree_root_attestation() {
    let payload: Result<SSZAttestation, MerkleizationError> =
		Attestation::<config::MaxValidatorsPerCommittee, config::SignatureSize>{
			aggregation_bits: hex!("ffcffeff7ffffffffefbf7ffffffdff73e").to_vec().try_into().expect("aggregation bits are too long"),
			data: AttestationData{
				slot: 484119,
				index: 0,
				beacon_block_root: hex!("2e93202be9ab790aea3d84ae1313a6daaf115c7de54a05038fba715be67b06d5").into(),
				source: Checkpoint{
					epoch: 15127,
					root: hex!("e665df84b5f1b4db9112b5c3876f5c10063347bfaf1025732137cf9abca28b75").into(),
				},
				target: Checkpoint{
					epoch: 15128,
					root: hex!("3a667c20c78352228169181f19757c774ca93d81047a6c121a0e88b2c385c7f7").into(),
				}
			},
			signature: hex!("af8e57aadf092443bd6675927ca84875419233fb7a5eb3ae626621d3339fe738b00af4a0edcc55efbe1198a815600784074388d366c4add789aa6126bb1ec5ed63ad8d8f22b5f158ae4c25d46b08d46d1188f7ed7e8f99d96ff6c3c69a240c18").to_vec().try_into().expect("signature is too long"),
		}.try_into();

    assert_ok!(&payload);

    let hash_root = merkleization::hash_tree_root(payload.unwrap());

    assert_ok!(&hash_root);
    assert_eq!(
        hash_root.unwrap(),
        hex!("a60acb46465c9eda6047e2cc18b3d509b7610efcbc7a02d28aea3ffa67e89f5a")
    );
}

#[test]
pub fn test_hash_tree_root_attestation_data() {
    let payload: Result<SSZAttestationData, MerkleizationError> = AttestationData {
        slot: 484119,
        index: 25,
        beacon_block_root: hex!("2e93202be9ab790aea3d84ae1313a6daaf115c7de54a05038fba715be67b06d5")
            .into(),
        source: Checkpoint {
            epoch: 15127,
            root: hex!("e665df84b5f1b4db9112b5c3876f5c10063347bfaf1025732137cf9abca28b75").into(),
        },
        target: Checkpoint {
            epoch: 15128,
            root: hex!("3a667c20c78352228169181f19757c774ca93d81047a6c121a0e88b2c385c7f7").into(),
        },
    }
    .try_into();

    assert_ok!(&payload);

    let hash_root = merkleization::hash_tree_root(payload.unwrap());

    assert_ok!(&hash_root);
    assert_eq!(
        hash_root.unwrap(),
        hex!("351d24efe677a40e3b687f8c95821158c3a3bb7c41c43b51187d4c1df690c849")
    );
}

#[test]
pub fn test_hash_tree_root_checkpoint() {
    let payload: Result<SSZCheckpoint, MerkleizationError> = Checkpoint {
        epoch: 15127,
        root: hex!("e665df84b5f1b4db9112b5c3876f5c10063347bfaf1025732137cf9abca28b75").into(),
    }
    .try_into();

    assert_ok!(&payload);

    let hash_root = merkleization::hash_tree_root(payload.unwrap());

    assert_ok!(&hash_root);
    assert_eq!(
        hash_root.unwrap(),
        hex!("c83bfcaa363a349b6869d70dcfe430f6199f8da7b01eb92d05a0860efe19dcec")
    );
}

#[test]
pub fn test_hash_tree_root_attester_slashing() {
    let payload: Result<SSZAttesterSlashing, MerkleizationError> =
        get_attester_slashing().try_into();

    assert_ok!(&payload);

    let hash_root = merkleization::hash_tree_root(payload.unwrap());

    assert_ok!(&hash_root);
    assert_eq!(
        hash_root.unwrap(),
        hex!("b1d13ea52fbb24639eee459fdd37e60c56710b51ef07eb32e525f3099dea9251")
    );
}

#[cfg(feature = "mainnet")]
mod beacon_tests {
    use crate::merkleization;
    use crate::merkleization::MerkleizationError;
    use crate::mock::{
        get_bls_signature_verify_test_data, get_committee_sync_period_update,
        get_finalized_header_update, get_header_update, get_initial_sync, get_validators_root,
        mock_mainnet as mock, new_tester,
    };
    use crate::pallet::{
        Error, ExecutionHeaders, GenesisValidatorsRoot, LatestFinalizedHeaderState, SyncCommittees,
    };
    use crate::ssz::SSZBeaconBlockBody;
    use frame_support::{assert_err, assert_ok};
    use hex_literal::hex;
    use snowbridge_beacon_primitives::{BeaconHeader, FinalizedHeaderState};
    use sp_core::H256;

    #[test]
    fn it_syncs_from_an_initial_checkpoint() {
        let initial_sync = get_initial_sync();

        new_tester::<mock::Test>().execute_with(|| {
            assert_ok!(mock::EthereumBeaconClient::initial_sync(
                initial_sync.clone()
            ));

            let block_root: H256 =
                merkleization::hash_tree_root_beacon_header(initial_sync.header.clone())
                    .unwrap()
                    .into();

            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(latest_finalized_header_state.beacon_block_root, block_root);
        });
    }

    #[test]
    fn it_updates_a_committee_period_sync_update() {
        let initial_sync = get_initial_sync();
        let update = get_committee_sync_period_update("");
        let second_update = get_committee_sync_period_update("_second");
        let third_update = get_committee_sync_period_update("_third");

        let current_period =
            mock::EthereumBeaconClient::compute_sync_committee_period(update.attested_header.slot);

        new_tester::<mock::Test>().execute_with(|| {
            assert_ok!(mock::EthereumBeaconClient::initial_sync(
                initial_sync.clone()
            ));

            assert_ok!(mock::EthereumBeaconClient::light_client_update(
                mock::RuntimeOrigin::signed(1),
                update.clone(),
            ));

            // We are expecting initial sync header to be latest as its slot is greater than the
            // update we received
            let expected_latest_finalized_block_root: H256 =
                merkleization::hash_tree_root_beacon_header(initial_sync.header.clone())
                    .unwrap()
                    .into();

            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(
                latest_finalized_header_state.beacon_block_root,
                expected_latest_finalized_block_root
            );

            // Even though we did not update latest finalized header, we should have updated next
            // sync committee
            let next_sync_committee_stored = <SyncCommittees<mock::Test>>::get(current_period + 1);
            assert_eq!(next_sync_committee_stored, update.next_sync_committee);

            assert_err!(
                mock::EthereumBeaconClient::light_client_update(
                    mock::RuntimeOrigin::signed(1),
                    second_update.clone(),
                ),
                Error::<mock::Test>::NotApplicableUpdate
            );

            // We are expecting that latest block root still won't be updated as last update was
            // deemed as not applicable
            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(
                latest_finalized_header_state.beacon_block_root,
                expected_latest_finalized_block_root
            );

            assert_ok!(mock::EthereumBeaconClient::light_client_update(
                mock::RuntimeOrigin::signed(1),
                third_update.clone(),
            ));

            // Latest finalized header should be updated as third update contains the new finalized
            // header
            let expected_latest_finalized_block_root: H256 =
                merkleization::hash_tree_root_beacon_header(third_update.finalized_header.clone())
                    .unwrap()
                    .into();
            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(
                latest_finalized_header_state.beacon_block_root,
                expected_latest_finalized_block_root
            );

            // We should have updated next sync committee
            let next_sync_committee_stored = <SyncCommittees<mock::Test>>::get(current_period + 2);
            assert_eq!(next_sync_committee_stored, third_update.next_sync_committee);
        });
    }

    #[test]
    fn it_processes_a_finalized_header_update() {
        let update = get_finalized_header_update();

        let initial_sync = get_initial_sync();

        new_tester::<mock::Test>().execute_with(|| {
            assert_ok!(mock::EthereumBeaconClient::initial_sync(
                initial_sync.clone()
            ));

            assert_ok!(mock::EthereumBeaconClient::light_client_update(
                mock::RuntimeOrigin::signed(1),
                update.clone()
            ));

            let expected_latest_finalized_block_root: H256 =
                merkleization::hash_tree_root_beacon_header(update.finalized_header.clone())
                    .unwrap()
                    .into();

            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(
                latest_finalized_header_state.beacon_block_root,
                expected_latest_finalized_block_root
            );
        });
    }

    #[test]
    fn it_processes_a_header_update() {
        let update = get_header_update();

        let current_sync_committee = get_initial_sync().current_sync_committee;

        let current_period =
            mock::EthereumBeaconClient::compute_sync_committee_period(update.block.slot);

        new_tester::<mock::Test>().execute_with(|| {
            SyncCommittees::<mock::Test>::insert(current_period, current_sync_committee);
            GenesisValidatorsRoot::<mock::Test>::set(get_validators_root());
            LatestFinalizedHeaderState::<mock::Test>::set(FinalizedHeaderState {
                beacon_block_root: H256::default(),
                beacon_slot: update.block.slot,
                import_time: 0,
                beacon_block_header: BeaconHeader::default(),
            });

            assert_ok!(mock::EthereumBeaconClient::import_execution_header(
                mock::RuntimeOrigin::signed(1),
                update.clone()
            ));

            let execution_block_root: H256 = update
                .block
                .body
                .execution_payload
                .block_hash
                .clone()
                .into();

            assert!(<ExecutionHeaders<mock::Test>>::contains_key(
                execution_block_root
            ));
        });
    }

    #[test]
    fn it_errors_when_importing_a_header_with_no_sync_committee_for_period() {
        let update = get_finalized_header_update();

        new_tester::<mock::Test>().execute_with(|| {
            GenesisValidatorsRoot::<mock::Test>::set(
                hex!("99b09fcd43e5905236c370f184056bec6e6638cfc31a323b304fc4aa789cb4ad").into(),
            );

            assert_err!(
                mock::EthereumBeaconClient::light_client_update(
                    mock::RuntimeOrigin::signed(1),
                    update
                ),
                Error::<mock::Test>::UnrecognizedSyncCommittee
            );
        });
    }

    #[test]
    pub fn test_hash_tree_root_sync_committee() {
        let sync_committee = get_committee_sync_period_update("");
        let hash_root_result =
            merkleization::hash_tree_root_sync_committee(&sync_committee.next_sync_committee);
        assert_ok!(&hash_root_result);

        let hash_root: H256 = hash_root_result.unwrap().into();
        assert_eq!(
            hash_root,
            hex!("f54adddc5f77ad5784b02980b03c4964154fae187f1a87421d4ada8380eac0c6").into()
        );
    }

    #[test]
    pub fn test_hash_block_body() {
        let block_update = get_header_update();
        let payload: Result<SSZBeaconBlockBody, MerkleizationError> =
            block_update.block.body.try_into();
        assert_ok!(&payload);

        let hash_root_result = merkleization::hash_tree_root(payload.unwrap());
        assert_ok!(&hash_root_result);

        let hash_root: H256 = hash_root_result.unwrap().into();
        assert_eq!(
            hash_root,
            hex!("671ff2a25afeefc81a80792778dd510de578e8b2b26a46f0c66c0f112bfc571b").into()
        );
    }

    #[test]
    pub fn test_bls_fast_aggregate_verify() {
        let test_data = get_bls_signature_verify_test_data();

        let sync_committee_bits = merkleization::get_sync_committee_bits(
            test_data
                .sync_committee_bits
                .try_into()
                .expect("too many sync committee bits"),
        );

        assert_ok!(&sync_committee_bits);

        assert_ok!(mock::EthereumBeaconClient::verify_signed_header(
            sync_committee_bits.unwrap(),
            test_data
                .sync_committee_signature
                .try_into()
                .expect("signature is too long"),
            test_data
                .pubkeys
                .to_vec()
                .try_into()
                .expect("to many pubkeys"),
            test_data.header,
            test_data.validators_root,
            test_data.signature_slot,
        ));
    }
}

#[cfg(not(feature = "mainnet"))]
mod beacon_tests {
    use crate::merkleization;
    use crate::merkleization::MerkleizationError;
    use crate::mock::{
        get_bls_signature_verify_test_data, get_committee_sync_period_update,
        get_finalized_header_update, get_header_update, get_initial_sync, get_validators_root,
        mock_goerli as mock, mock_goerli, new_tester,
    };
    use crate::pallet::{
        ExecutionHeaders, GenesisValidatorsRoot, LatestFinalizedHeaderState, SyncCommittees,
    };
    use crate::ssz::SSZBeaconBlockBody;
    use frame_support::assert_ok;
    use hex_literal::hex;
    use snowbridge_beacon_primitives::{BeaconHeader, FinalizedHeaderState};
    use sp_core::H256;

    #[test]
    fn it_syncs_from_an_initial_checkpoint() {
        let initial_sync = get_initial_sync();

        new_tester::<mock::Test>().execute_with(|| {
            assert_ok!(mock_goerli::EthereumBeaconClient::initial_sync(
                initial_sync.clone()
            ));

            let block_root: H256 =
                merkleization::hash_tree_root_beacon_header(initial_sync.header.clone())
                    .unwrap()
                    .into();

            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(latest_finalized_header_state.beacon_block_root, block_root);
        });
    }

    #[test]
    fn it_updates_a_committee_period_sync_update() {
        let initial_sync = get_initial_sync();
        let update = get_committee_sync_period_update("");
        let next_update = get_committee_sync_period_update("_next");

        let current_period =
            mock::EthereumBeaconClient::compute_sync_committee_period(update.attested_header.slot);

        new_tester::<mock::Test>().execute_with(|| {
            assert_ok!(mock::EthereumBeaconClient::initial_sync(
                initial_sync.clone()
            ));

            assert_ok!(mock::EthereumBeaconClient::light_client_update(
                mock::RuntimeOrigin::signed(1),
                update.clone(),
            ));

            // We are expecting initial sync header to be latest as its slot is greater than the
            // update we received
            let expected_latest_finalized_block_root: H256 =
                merkleization::hash_tree_root_beacon_header(initial_sync.header.clone())
                    .unwrap()
                    .into();

            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(
                latest_finalized_header_state.beacon_block_root,
                expected_latest_finalized_block_root
            );

            // Even though we did not update latest finalized header, we should have updated next
            // sync committee
            let next_sync_committee_stored = <SyncCommittees<mock::Test>>::get(current_period + 1);
            assert_eq!(next_sync_committee_stored, update.next_sync_committee);

            assert_ok!(mock::EthereumBeaconClient::light_client_update(
                mock::RuntimeOrigin::signed(1),
                next_update.clone(),
            ));

            // We are expecting next update sync header to be latest as its slot is greater than the
            // current stored header
            let expected_latest_finalized_block_root: H256 =
                merkleization::hash_tree_root_beacon_header(next_update.finalized_header.clone())
                    .unwrap()
                    .into();

            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(
                latest_finalized_header_state.beacon_block_root,
                expected_latest_finalized_block_root
            );

            // We should have updated next sync committee
            let next_sync_committee_stored = <SyncCommittees<mock::Test>>::get(current_period + 2);
            assert_eq!(next_sync_committee_stored, next_update.next_sync_committee);
        });
    }

    #[test]
    fn it_processes_a_finalized_header_update() {
        let update = get_finalized_header_update();

        let initial_sync = get_initial_sync();

        new_tester::<mock::Test>().execute_with(|| {
            assert_ok!(mock::EthereumBeaconClient::initial_sync(
                initial_sync.clone()
            ));

            assert_ok!(mock::EthereumBeaconClient::light_client_update(
                mock::RuntimeOrigin::signed(1),
                update.clone()
            ));

            let expected_latest_finalized_block_root: H256 =
                merkleization::hash_tree_root_beacon_header(update.finalized_header.clone())
                    .unwrap()
                    .into();

            let latest_finalized_header_state = <LatestFinalizedHeaderState<mock::Test>>::get();
            assert_eq!(
                latest_finalized_header_state.beacon_block_root,
                expected_latest_finalized_block_root
            );
        });
    }

    #[test]
    fn it_processes_a_header_update() {
        let update = get_header_update();

        let current_sync_committee = get_initial_sync().current_sync_committee;

        let current_period =
            mock::EthereumBeaconClient::compute_sync_committee_period(update.block.slot);

        new_tester::<mock::Test>().execute_with(|| {
            SyncCommittees::<mock::Test>::insert(current_period, current_sync_committee);
            GenesisValidatorsRoot::<mock::Test>::set(get_validators_root());
            LatestFinalizedHeaderState::<mock::Test>::set(FinalizedHeaderState {
                beacon_block_root: H256::default(),
                beacon_slot: update.block.slot,
                import_time: 0,
                beacon_block_header: BeaconHeader::default(),
            });

            assert_ok!(mock::EthereumBeaconClient::import_execution_header(
                mock::RuntimeOrigin::signed(1),
                update.clone()
            ));

            let execution_block_root: H256 = update.block.body.execution_payload.block_hash;

            assert!(<ExecutionHeaders<mock::Test>>::contains_key(
                execution_block_root
            ));
        });
    }

    #[test]
    pub fn test_hash_tree_root_sync_committee() {
        let sync_committee = get_committee_sync_period_update("");
        let hash_root_result =
            merkleization::hash_tree_root_sync_committee(&sync_committee.next_sync_committee);
        assert_ok!(&hash_root_result);

        let hash_root: H256 = hash_root_result.unwrap().into();
        assert_eq!(
            hash_root,
            hex!("a18ae4d83f81638e41ae4bd43b005b2730b0710cb178ffb50766c93ea3d812c9").into()
        );
    }

    #[test]
    pub fn test_bls_fast_aggregate_verify() {
        let test_data = get_bls_signature_verify_test_data();

        let sync_committee_bits = merkleization::get_sync_committee_bits(
            test_data
                .sync_committee_bits
                .try_into()
                .expect("too many sync committee bits"),
        );

        assert_ok!(&sync_committee_bits);

        assert_ok!(mock::EthereumBeaconClient::verify_signed_header(
            sync_committee_bits.unwrap(),
            test_data
                .sync_committee_signature
                .try_into()
                .expect("signature is too long"),
            test_data
                .pubkeys
                .to_vec()
                .try_into()
                .expect("to many pubkeys"),
            test_data.header,
            test_data.validators_root,
            test_data.signature_slot,
        ));
    }

    #[test]
    pub fn test_hash_block_body() {
        let block_update = get_header_update();
        let payload: Result<SSZBeaconBlockBody, MerkleizationError> =
            block_update.block.body.try_into();
        assert_ok!(&payload);

        let hash_root_result = merkleization::hash_tree_root(payload.unwrap());
        assert_ok!(&hash_root_result);

        let hash_root: H256 = hash_root_result.unwrap().into();
        assert_eq!(
            hash_root,
            hex!("e9581ec84c95cd3e02f17ee304bca3202fb843111aa36af9698a1ff64373f1dd").into()
        );
    }
}
