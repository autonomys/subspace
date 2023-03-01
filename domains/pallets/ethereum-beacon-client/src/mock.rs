use super::*;
use frame_support::parameter_types;
use snowbridge_beacon_primitives::{AttesterSlashing, BeaconHeader, Fork, ForkVersions};
use sp_core::H256;
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use std::fs::File;
use std::path::PathBuf;
use {crate as ethereum_beacon_client, frame_system as system};

pub mod mock_mainnet {
    use super::*;

    type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
    type Block = frame_system::mocking::MockBlock<Test>;

    frame_support::construct_runtime!(
        pub enum Test where
            Block = Block,
            NodeBlock = Block,
            UncheckedExtrinsic = UncheckedExtrinsic,
        {
            System: frame_system::{Pallet, Call, Storage, Event<T>},
            Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
            EthereumBeaconClient: ethereum_beacon_client::{Pallet, Call, Config, Storage, Event<T>},
        }
    );

    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const SS58Prefix: u8 = 42;
    }

    impl frame_system::Config for Test {
        type BaseCallFilter = frame_support::traits::Everything;
        type OnSetCode = ();
        type BlockWeights = ();
        type BlockLength = ();
        type DbWeight = ();
        type RuntimeOrigin = RuntimeOrigin;
        type RuntimeCall = RuntimeCall;
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type RuntimeEvent = RuntimeEvent;
        type BlockHashCount = BlockHashCount;
        type Version = ();
        type PalletInfo = PalletInfo;
        type AccountData = ();
        type OnNewAccount = ();
        type OnKilledAccount = ();
        type SystemWeightInfo = ();
        type SS58Prefix = SS58Prefix;
        type MaxConsumers = frame_support::traits::ConstU32<16>;
    }

    impl pallet_timestamp::Config for Test {
        type Moment = u64;
        type OnTimestampSet = ();
        type MinimumPeriod = ();
        type WeightInfo = ();
    }

    parameter_types! {
        pub const WeakSubjectivityPeriodSeconds: u32 = 97200;
        pub const SyncCommitteePruneThreshold: u32 = 10;
        pub const ExecutionHeadersPruneThreshold: u32 = 64;
        pub const ChainForkVersions: ForkVersions = ForkVersions{
            genesis: Fork {
                version: [0, 0, 0, 0], // 0x00000000
                epoch: 0,
            },
            altair: Fork {
                version: [1, 0, 0, 0], // 0x01000000
                epoch: 36660,
            },
            bellatrix: Fork {
                version: [2, 0, 0, 0], // 0x02000000
                epoch: 112260,
            },
        };
    }

    impl ethereum_beacon_client::Config for Test {
        type TimeProvider = pallet_timestamp::Pallet<Test>;
        type RuntimeEvent = RuntimeEvent;
        type ForkVersions = ChainForkVersions;
        type WeakSubjectivityPeriodSeconds = WeakSubjectivityPeriodSeconds;
        type WeightInfo = ();
        type SyncCommitteePruneThreshold = SyncCommitteePruneThreshold;
        type ExecutionHeadersPruneThreshold = ExecutionHeadersPruneThreshold;
    }
}

pub mod mock_goerli {
    use super::*;

    type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
    type Block = frame_system::mocking::MockBlock<Test>;

    frame_support::construct_runtime!(
        pub enum Test where
            Block = Block,
            NodeBlock = Block,
            UncheckedExtrinsic = UncheckedExtrinsic,
        {
            System: frame_system::{Pallet, Call, Storage, Event<T>},
            Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
            EthereumBeaconClient: ethereum_beacon_client::{Pallet, Call, Config, Storage, Event<T>},
        }
    );

    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const SS58Prefix: u8 = 42;
    }

    impl frame_system::Config for Test {
        type BaseCallFilter = frame_support::traits::Everything;
        type OnSetCode = ();
        type BlockWeights = ();
        type BlockLength = ();
        type DbWeight = ();
        type RuntimeOrigin = RuntimeOrigin;
        type RuntimeCall = RuntimeCall;
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type RuntimeEvent = RuntimeEvent;
        type BlockHashCount = BlockHashCount;
        type Version = ();
        type PalletInfo = PalletInfo;
        type AccountData = ();
        type OnNewAccount = ();
        type OnKilledAccount = ();
        type SystemWeightInfo = ();
        type SS58Prefix = SS58Prefix;
        type MaxConsumers = frame_support::traits::ConstU32<16>;
    }

    impl pallet_timestamp::Config for Test {
        type Moment = u64;
        type OnTimestampSet = ();
        type MinimumPeriod = ();
        type WeightInfo = ();
    }

    parameter_types! {
        pub const WeakSubjectivityPeriodSeconds: u32 = 97200;
        pub const SyncCommitteePruneThreshold: u32 = 10;
        pub const ExecutionHeadersPruneThreshold: u32 = 64;
        pub const ChainForkVersions: ForkVersions = ForkVersions{
            genesis: Fork {
                version: [0, 0, 16, 32], // 0x00001020
                epoch: 0,
            },
            altair: Fork {
                version: [1, 0, 16, 32], // 0x01001020
                epoch: 36660,
            },
            bellatrix: Fork {
                version: [2, 0, 16, 32], // 0x02001020
                epoch: 112260,
            },
        };
    }

    impl Config for Test {
        type RuntimeEvent = RuntimeEvent;
        type TimeProvider = pallet_timestamp::Pallet<Test>;
        type ForkVersions = ChainForkVersions;
        type WeakSubjectivityPeriodSeconds = WeakSubjectivityPeriodSeconds;
        type WeightInfo = ();
        type SyncCommitteePruneThreshold = SyncCommitteePruneThreshold;
        type ExecutionHeadersPruneThreshold = ExecutionHeadersPruneThreshold;
    }
}

// Build genesis storage according to the mock runtime.
pub fn new_tester<T: Config>() -> sp_io::TestExternalities {
    system::GenesisConfig::default()
        .build_storage::<T>()
        .unwrap()
        .into()
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockBodyTest {
    pub body: BlockBodyOf,
    pub result: H256,
}

pub struct BLSSignatureVerifyTest {
    pub sync_committee_bits: Vec<u8>,
    pub sync_committee_signature: Vec<u8>,
    pub pubkeys: Vec<PublicKey>,
    pub header: BeaconHeader,
    pub validators_root: H256,
    pub signature_slot: u64,
}

fn fixture_path(name: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect()
}

fn initial_sync_from_file(
    name: &str,
) -> InitialSync<config::SyncCommitteeSize, config::MaxProofBranchSize> {
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(filepath).unwrap()).unwrap()
}

fn sync_committee_update_from_file(
    name: &str,
) -> LightClientUpdate<config::SignatureSize, config::MaxProofBranchSize, config::SyncCommitteeSize>
{
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(filepath).unwrap()).unwrap()
}

fn block_update_from_file(name: &str) -> BlockUpdateOf {
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(filepath).unwrap()).unwrap()
}

fn attester_slashing_from_file(
    name: &str,
) -> AttesterSlashing<config::MaxValidatorsPerCommittee, config::SignatureSize> {
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(filepath).unwrap()).unwrap()
}

fn add_file_prefix(name: &str) -> String {
    let prefix = match config::IS_MAINNET {
        true => "mainnet_",
        false => "goerli_",
    };

    let mut result = prefix.to_owned();
    result.push_str(name);
    result
}

pub fn get_initial_sync() -> InitialSync<config::SyncCommitteeSize, config::MaxProofBranchSize> {
    initial_sync_from_file(&add_file_prefix("initial_sync.json"))
}

pub fn get_committee_sync_period_update(
    suffix: &str,
) -> LightClientUpdate<config::SignatureSize, config::MaxProofBranchSize, config::SyncCommitteeSize>
{
    sync_committee_update_from_file(&add_file_prefix(
        format!("sync_committee_update{suffix}.json").as_str(),
    ))
}

pub fn get_header_update() -> BlockUpdateOf {
    block_update_from_file(&add_file_prefix("block_update.json"))
}

pub fn get_finalized_header_update(
) -> LightClientUpdate<config::SignatureSize, config::MaxProofBranchSize, config::SyncCommitteeSize>
{
    sync_committee_update_from_file(&add_file_prefix("finalized_header_update.json"))
}

pub fn get_validators_root() -> H256 {
    get_initial_sync().validators_root
}

pub fn get_bls_signature_verify_test_data() -> BLSSignatureVerifyTest {
    let finalized_update = get_finalized_header_update();
    let initial_sync = get_initial_sync();

    BLSSignatureVerifyTest {
        sync_committee_bits: finalized_update
            .sync_aggregate
            .sync_committee_bits
            .try_into()
            .expect("sync committee bits are too long"),
        sync_committee_signature: finalized_update
            .sync_aggregate
            .sync_committee_signature
            .to_vec(),
        pubkeys: initial_sync.current_sync_committee.pubkeys.to_vec(),
        header: finalized_update.attested_header,
        validators_root: initial_sync.validators_root,
        signature_slot: finalized_update.signature_slot,
    }
}

pub fn get_attester_slashing(
) -> AttesterSlashing<config::MaxValidatorsPerCommittee, config::SignatureSize> {
    attester_slashing_from_file("attester_slashing.json")
}
