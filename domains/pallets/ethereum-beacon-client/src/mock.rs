use super::*;
use frame_support::parameter_types;
use snowbridge_beacon_primitives::{AttesterSlashing, BeaconHeader, Body, Fork, ForkVersions};
use sp_core::H256;
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use std::fs::File;
use std::path::PathBuf;
use {crate as ethereum_beacon_client, frame_system as system, pallet_timestamp};

pub mod mock_minimal {
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
            EthereumBeaconClient: ethereum_beacon_client::{Pallet, Call, Config<T>, Storage, Event<T>},
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
        pub const MaxSyncCommitteeSize: u32 = config::SYNC_COMMITTEE_SIZE as u32;
        pub const MaxProofBranchSize: u32 = 6;
        pub const MaxExtraDataSize: u32 = config::MAX_EXTRA_DATA_BYTES as u32;
        pub const MaxLogsBloomSize: u32 = config::MAX_LOGS_BLOOM_SIZE as u32;
        pub const MaxFeeRecipientSize: u32 = config::MAX_FEE_RECIPIENT_SIZE as u32;
        pub const MaxDepositDataSize: u32 = config::MAX_DEPOSITS as u32;
        pub const MaxPublicKeySize: u32 = config::PUBKEY_SIZE as u32;
        pub const MaxSignatureSize: u32 = config::SIGNATURE_SIZE as u32;
        pub const MaxProposerSlashingSize: u32 = config::MAX_PROPOSER_SLASHINGS as u32;
        pub const MaxAttesterSlashingSize: u32 = config::MAX_ATTESTER_SLASHINGS as u32;
        pub const MaxVoluntaryExitSize: u32 = config::MAX_VOLUNTARY_EXITS as u32;
        pub const MaxAttestationSize: u32 = config::MAX_ATTESTATIONS as u32;
        pub const MaxValidatorsPerCommittee: u32 = config::MAX_VALIDATORS_PER_COMMITTEE as u32;
        pub const WeakSubjectivityPeriodSeconds: u32 = 97200;
        pub const ChainForkVersions: ForkVersions = ForkVersions{
            genesis: Fork {
                version: [0, 0, 0, 1], // 0x00000001
                epoch: 0,
            },
            altair: Fork {
                version: [1, 0, 0, 1], // 0x01000001
                epoch: 0,
            },
            bellatrix: Fork {
                version: [2, 0, 0, 1], // 0x02000001
                epoch: 0,
            },
        };
    }

    impl ethereum_beacon_client::Config for Test {
        type TimeProvider = pallet_timestamp::Pallet<Test>;
        type RuntimeEvent = RuntimeEvent;
        type MaxSyncCommitteeSize = MaxSyncCommitteeSize;
        type MaxProofBranchSize = MaxProofBranchSize;
        type MaxExtraDataSize = MaxExtraDataSize;
        type MaxLogsBloomSize = MaxLogsBloomSize;
        type MaxFeeRecipientSize = MaxFeeRecipientSize;
        type MaxDepositDataSize = MaxDepositDataSize;
        type MaxPublicKeySize = MaxPublicKeySize;
        type MaxSignatureSize = MaxSignatureSize;
        type MaxProposerSlashingSize = MaxProposerSlashingSize;
        type MaxAttesterSlashingSize = MaxAttesterSlashingSize;
        type MaxVoluntaryExitSize = MaxVoluntaryExitSize;
        type MaxAttestationSize = MaxAttestationSize;
        type MaxValidatorsPerCommittee = MaxValidatorsPerCommittee;
        type ForkVersions = ChainForkVersions;
        type WeakSubjectivityPeriodSeconds = WeakSubjectivityPeriodSeconds;
        type WeightInfo = ();
    }
}

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
            EthereumBeaconClient: ethereum_beacon_client::{Pallet, Call, Config<T>, Storage, Event<T>},
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

    impl ethereum_beacon_client::Config for Test {
        type RuntimeEvent = RuntimeEvent;
        type TimeProvider = pallet_timestamp::Pallet<Test>;
        type ForkVersions = ChainForkVersions;
        type WeakSubjectivityPeriodSeconds = WeakSubjectivityPeriodSeconds;
        type WeightInfo = ();
    }
}

// Build genesis storage according to the mock runtime.
pub fn new_tester<T: crate::Config>() -> sp_io::TestExternalities {
    system::GenesisConfig::default()
        .build_storage::<T>()
        .unwrap()
        .into()
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct BlockBodyTest<T: crate::Config> {
    pub body: Body<
        T::MaxFeeRecipientSize,
        T::MaxLogsBloomSize,
        T::MaxExtraDataSize,
        T::MaxDepositDataSize,
        T::MaxPublicKeySize,
        T::MaxSignatureSize,
        T::MaxProofBranchSize,
        T::MaxProposerSlashingSize,
        T::MaxAttesterSlashingSize,
        T::MaxVoluntaryExitSize,
        T::MaxAttestationSize,
        T::MaxValidatorsPerCommittee,
        T::MaxSyncCommitteeSize,
    >,
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

fn initial_sync_from_file<T: crate::Config>(
    name: &str,
) -> InitialSync<T::MaxSyncCommitteeSize, T::MaxProofBranchSize> {
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(&filepath).unwrap()).unwrap()
}

fn sync_committee_update_from_file<T: crate::Config>(
    name: &str,
) -> SyncCommitteePeriodUpdate<T::MaxSignatureSize, T::MaxProofBranchSize, T::MaxSyncCommitteeSize>
{
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(&filepath).unwrap()).unwrap()
}

fn finalized_header_update_from_file<T: crate::Config>(
    name: &str,
) -> FinalizedHeaderUpdate<T::MaxSignatureSize, T::MaxProofBranchSize, T::MaxSyncCommitteeSize> {
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(&filepath).unwrap()).unwrap()
}

fn block_update_from_file<T: crate::Config>(
    name: &str,
) -> BlockUpdate<
    T::MaxFeeRecipientSize,
    T::MaxLogsBloomSize,
    T::MaxExtraDataSize,
    T::MaxDepositDataSize,
    T::MaxPublicKeySize,
    T::MaxSignatureSize,
    T::MaxProofBranchSize,
    T::MaxProposerSlashingSize,
    T::MaxAttesterSlashingSize,
    T::MaxVoluntaryExitSize,
    T::MaxAttestationSize,
    T::MaxValidatorsPerCommittee,
    T::MaxSyncCommitteeSize,
> {
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(&filepath).unwrap()).unwrap()
}

fn attester_slashing_from_file<T: crate::Config>(
    name: &str,
) -> AttesterSlashing<T::MaxValidatorsPerCommittee, T::MaxSignatureSize> {
    let filepath = fixture_path(name);
    serde_json::from_reader(File::open(&filepath).unwrap()).unwrap()
}

fn add_file_prefix(name: &str) -> String {
    let prefix = match config::IS_MINIMAL {
        true => "minimal_",
        false => "goerli_",
    };

    let mut result = prefix.to_owned();
    result.push_str(name);
    result
}

pub fn get_initial_sync<T: crate::Config>(
) -> InitialSync<T::MaxSyncCommitteeSize, T::MaxProofBranchSize> {
    initial_sync_from_file::<T>(&add_file_prefix("initial_sync.json"))
}

pub fn get_committee_sync_period_update<T: crate::Config>(
) -> SyncCommitteePeriodUpdate<T::MaxSignatureSize, T::MaxProofBranchSize, T::MaxSyncCommitteeSize>
{
    sync_committee_update_from_file::<T>(&add_file_prefix("sync_committee_update.json"))
}

pub fn get_header_update<T: crate::Config>() -> BlockUpdate<
    T::MaxFeeRecipientSize,
    T::MaxLogsBloomSize,
    T::MaxExtraDataSize,
    T::MaxDepositDataSize,
    T::MaxPublicKeySize,
    T::MaxSignatureSize,
    T::MaxProofBranchSize,
    T::MaxProposerSlashingSize,
    T::MaxAttesterSlashingSize,
    T::MaxVoluntaryExitSize,
    T::MaxAttestationSize,
    T::MaxValidatorsPerCommittee,
    T::MaxSyncCommitteeSize,
> {
    block_update_from_file::<T>(&add_file_prefix("block_update.json"))
}

pub fn get_finalized_header_update<T: crate::Config>(
) -> FinalizedHeaderUpdate<T::MaxSignatureSize, T::MaxProofBranchSize, T::MaxSyncCommitteeSize> {
    finalized_header_update_from_file::<T>(&add_file_prefix("finalized_header_update.json"))
}

pub fn get_validators_root<T: crate::Config>() -> H256 {
    get_initial_sync::<T>().validators_root
}

pub fn get_bls_signature_verify_test_data<T: crate::Config>() -> BLSSignatureVerifyTest {
    let finalized_update = get_finalized_header_update::<T>();
    let initial_sync = get_initial_sync::<T>();

    BLSSignatureVerifyTest {
        sync_committee_bits: finalized_update
            .sync_aggregate
            .sync_committee_bits
            .try_into()
            .expect("sync committee bits are too long"),
        sync_committee_signature: finalized_update
            .sync_aggregate
            .sync_committee_signature
            .to_vec()
            .try_into()
            .expect("signature is too long"),
        pubkeys: initial_sync
            .current_sync_committee
            .pubkeys
            .to_vec()
            .try_into()
            .expect("pubkeys are too long"),
        header: finalized_update.attested_header,
        validators_root: initial_sync.validators_root,
        signature_slot: finalized_update.signature_slot,
    }
}

pub fn get_attester_slashing<T: crate::Config>(
) -> AttesterSlashing<T::MaxValidatorsPerCommittee, T::MaxSignatureSize> {
    attester_slashing_from_file::<T>("attester_slashing.json")
}
