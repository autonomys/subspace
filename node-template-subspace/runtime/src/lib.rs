#![feature(int_log)]
#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use codec::{Compact, CompactLen, Decode, Encode};
use frame_support::{
    construct_runtime, parameter_types,
    weights::{
        constants::{RocksDbWeight, WEIGHT_PER_SECOND},
        IdentityFee, Weight,
    },
};
use pallet_transaction_payment::CurrencyAdapter;
use sp_api::impl_runtime_apis;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata};
use sp_runtime::traits::{AccountIdLookup, BlakeTwo256, Block as BlockT, IdentifyAccount, Verify};
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, MultiSignature, Perbill,
};
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
use subspace_core_primitives::objects::{BlockObject, BlockObjectMapping};
use subspace_core_primitives::{RootBlock, Sha256Hash, PIECE_SIZE, SHA256_HASH_SIZE};

/// An index to a block.
pub type BlockNumber = u32;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Index = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// Type used for expressing timestamp.
pub type Moment = u64;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;

    use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;

    impl_opaque_keys! {
        pub struct SessionKeys {
            pub subspace: Subspace,
        }
    }
}

// To learn more about runtime versioning and what each of the following value means:
//   https://substrate.dev/docs/en/knowledgebase/runtime/upgrades#runtime-versioning
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("node-template-subspace"),
    impl_name: create_runtime_str!("node-template-subspace"),
    authoring_version: 1,
    // The version of the runtime specification. A full node will not attempt to use its native
    //   runtime in substitute for the on-chain Wasm runtime unless all of `spec_name`,
    //   `spec_version`, and `authoring_version` are the same between Wasm and native.
    // This value is set to 100 to notify Polkadot-JS App (https://polkadot.js.org/apps) to use
    //   the compatible custom types.
    spec_version: 100,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
};

// TODO: Many of below constants should probably be updatable but currently they are not

/// Since Subspace is probabilistic this is the average expected block time that
/// we are targeting. Blocks will be produced at a minimum duration defined
/// by `SLOT_DURATION`, but some slots will not be allocated to any
/// farmer and hence no block will be produced. We expect to have this
/// block time on average following the defined slot duration and the value
/// of `c` configured for Subspace (where `1 - c` represents the probability of
/// a slot being empty).
/// This value is only used indirectly to define the unit constants below
/// that are expressed in blocks. The rest of the code should use
/// `SLOT_DURATION` instead (like the Timestamp pallet for calculating the
/// minimum period).
///
/// Based on:
/// <https://research.web3.foundation/en/latest/polkadot/block-production/Babe.html#-6.-practical-results>
const MILLISECS_PER_BLOCK: u64 = 6000;

// NOTE: Currently it is not possible to change the slot duration after the chain has started.
//       Attempting to do so will brick block production.
const SLOT_DURATION: u64 = 1000;

// Time is measured by number of blocks.
// pub const MINUTES: BlockNumber = 3_200 / (MILLISECS_PER_BLOCK as BlockNumber);
// pub const HOURS: BlockNumber = MINUTES * 60;
// pub const DAYS: BlockNumber = HOURS * 24;

/// 1 in 6 slots (on average, not counting collisions) will have a block.
/// Must match ratio between block and slot duration in constants above.
const SLOT_PROBABILITY: (u64, u64) = (1, 6);

/// Era duration in blocks.
const ERA_DURATION_IN_BLOCKS: u32 = 2016;

const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 256;
const EPOCH_DURATION_IN_SLOTS: u64 =
    EPOCH_DURATION_IN_BLOCKS as u64 * SLOT_PROBABILITY.1 / SLOT_PROBABILITY.0;

const EON_DURATION_IN_SLOTS: u64 = 2u64.pow(14);

/// The Subspace epoch configuration at genesis.
pub const SUBSPACE_GENESIS_EPOCH_CONFIG: sp_consensus_subspace::SubspaceEpochConfiguration =
    sp_consensus_subspace::SubspaceEpochConfiguration {
        c: SLOT_PROBABILITY,
    };

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

// TODO: Proper value here
const CONFIRMATION_DEPTH_K: u32 = 10;
// This is a nice power of 2 for Merkle Tree
const MERKLE_NUM_LEAVES: u32 = 256;
const WITNESS_SIZE: u32 = SHA256_HASH_SIZE as u32 * MERKLE_NUM_LEAVES.log2();
const RECORD_SIZE: u32 = PIECE_SIZE as u32 - WITNESS_SIZE;
const RECORDED_HISTORY_SEGMENT_SIZE: u32 = RECORD_SIZE * MERKLE_NUM_LEAVES / 2;
const PRE_GENESIS_OBJECT_SIZE: u32 = RECORDED_HISTORY_SEGMENT_SIZE;
const PRE_GENESIS_OBJECT_COUNT: u32 = 10;
const PRE_GENESIS_OBJECT_SEED: &[u8] = b"subspace";

// We assume initial plot size starts with the size of pre-genesis history (roughly, there is some
// overhead in archiving process)
const INITIAL_SOLUTION_RANGE: u64 = u64::MAX
    / (PRE_GENESIS_OBJECT_SIZE * PRE_GENESIS_OBJECT_COUNT / PIECE_SIZE as u32) as u64
    * SLOT_PROBABILITY.0
    / SLOT_PROBABILITY.1;

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub const BlockHashCount: BlockNumber = 2400;
    /// We allow for 2 seconds of compute with a 6 second average block time.
    pub BlockWeights: frame_system::limits::BlockWeights = frame_system::limits::BlockWeights
        ::with_sensible_defaults(2 * WEIGHT_PER_SECOND, NORMAL_DISPATCH_RATIO);
    pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
        ::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
    pub const SS58Prefix: u8 = 42;
}

// Configure FRAME pallets to include in runtime.

impl frame_system::Config for Runtime {
    /// The basic call filter to use in dispatchable.
    type BaseCallFilter = frame_support::traits::Everything;
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = BlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = BlockLength;
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The aggregated dispatch type that is available for extrinsics.
    type Call = Call;
    /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
    type Lookup = AccountIdLookup<AccountId, ()>;
    /// The index type for storing how many extrinsics an account has signed.
    type Index = Index;
    /// The index type for blocks.
    type BlockNumber = BlockNumber;
    /// The type for hashing blocks and tries.
    type Hash = Hash;
    /// The hashing algorithm used.
    type Hashing = BlakeTwo256;
    /// The header type.
    type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// The ubiquitous event type.
    type Event = Event;
    /// The ubiquitous origin type.
    type Origin = Origin;
    /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
    type BlockHashCount = BlockHashCount;
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = RocksDbWeight;
    /// Version of the runtime.
    type Version = Version;
    /// Converts a module to the index of the module in `construct_runtime!`.
    ///
    /// This type is being generated by `construct_runtime!`.
    type PalletInfo = PalletInfo;
    /// What to do if a new account is created.
    type OnNewAccount = ();
    /// What to do if an account is fully reaped from the system.
    type OnKilledAccount = ();
    /// The data to be stored in an account.
    type AccountData = pallet_balances::AccountData<Balance>;
    /// Weight information for the extrinsics of this pallet.
    type SystemWeightInfo = ();
    /// This is used as an identifier of the chain. 42 is the generic substrate prefix.
    type SS58Prefix = SS58Prefix;
    /// The set code logic, just the default since we're not a parachain.
    type OnSetCode = ();
}

impl pallet_randomness_collective_flip::Config for Runtime {}

parameter_types! {
    pub const EpochDuration: u64 = EPOCH_DURATION_IN_SLOTS;
    pub const EraDuration: u32 = ERA_DURATION_IN_BLOCKS;
    pub const EonDuration: u64 = EON_DURATION_IN_SLOTS;
    pub const InitialSolutionRange: u64 = INITIAL_SOLUTION_RANGE;
    pub const SlotProbability: (u64, u64) = SLOT_PROBABILITY;
    pub const ExpectedBlockTime: Moment = MILLISECS_PER_BLOCK;
    pub const ConfirmationDepthK: u32 = CONFIRMATION_DEPTH_K;
    pub const RecordSize: u32 = RECORD_SIZE;
    pub const RecordedHistorySegmentSize: u32 = RECORDED_HISTORY_SEGMENT_SIZE;
    pub const PreGenesisObjectSize: u32 = PRE_GENESIS_OBJECT_SIZE;
    pub const PreGenesisObjectCount: u32 = PRE_GENESIS_OBJECT_COUNT;
    pub const PreGenesisObjectSeed: &'static [u8] = PRE_GENESIS_OBJECT_SEED;
    pub const ReportLongevity: u64 = EPOCH_DURATION_IN_BLOCKS as u64;
}

impl pallet_subspace::Config for Runtime {
    type Event = Event;
    type EpochDuration = EpochDuration;
    type EraDuration = EraDuration;
    type EonDuration = EonDuration;
    type InitialSolutionRange = InitialSolutionRange;
    type SlotProbability = SlotProbability;
    type ExpectedBlockTime = ExpectedBlockTime;
    type ConfirmationDepthK = ConfirmationDepthK;
    type RecordSize = RecordSize;
    type RecordedHistorySegmentSize = RecordedHistorySegmentSize;
    type PreGenesisObjectSize = PreGenesisObjectSize;
    type PreGenesisObjectCount = PreGenesisObjectCount;
    type PreGenesisObjectSeed = PreGenesisObjectSeed;
    type EpochChangeTrigger = pallet_subspace::NormalEpochChange;
    type EraChangeTrigger = pallet_subspace::NormalEraChange;
    type EonChangeTrigger = pallet_subspace::NormalEonChange;

    type HandleEquivocation =
        pallet_subspace::equivocation::EquivocationHandler<OffencesSubspace, ReportLongevity>;

    type WeightInfo = ();
}

parameter_types! {
    pub const MinimumPeriod: u64 = SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = Moment;
    type OnTimestampSet = Subspace;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

parameter_types! {
    pub const ExistentialDeposit: u128 = 500;
    pub const MaxLocks: u32 = 50;
}

impl pallet_balances::Config for Runtime {
    type MaxLocks = MaxLocks;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type Event = Event;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const TransactionByteFee: Balance = 1;
}

impl pallet_transaction_payment::Config for Runtime {
    type OnChargeTransaction = CurrencyAdapter<Balances, ()>;
    type TransactionByteFee = TransactionByteFee;
    type WeightToFee = IdentityFee<Balance>;
    type FeeMultiplierUpdate = ();
}

impl pallet_sudo::Config for Runtime {
    type Event = Event;
    type Call = Call;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
    Call: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type OverarchingCall = Call;
}

parameter_types! {
    pub OffencesWeightSoftLimit: Weight = Perbill::from_percent(60) *
        BlockWeights::get().max_block;
}

impl pallet_offences_subspace::Config for Runtime {
    type Event = Event;
    type OnOffenceHandler = Subspace;
}

impl pallet_feeds::Config for Runtime {
    type Event = Event;
}

// Create the runtime by composing the FRAME pallets that were previously configured.
construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        RandomnessCollectiveFlip: pallet_randomness_collective_flip::{Pallet, Storage},
        Timestamp: pallet_timestamp::{Pallet, Call, Storage, Inherent},
        Subspace: pallet_subspace::{Pallet, Call, Storage, Config, Event, ValidateUnsigned},
        Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
        TransactionPayment: pallet_transaction_payment::{Pallet, Storage},
        Sudo: pallet_sudo::{Pallet, Call, Config<T>, Storage, Event<T>},
        OffencesSubspace: pallet_offences_subspace::{Pallet, Storage, Event},
        Feeds: pallet_feeds::{Pallet, Call, Storage, Event<T>},
    }
);

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);
/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, Call, Signature, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPallets,
>;

fn extract_root_block(encoded_extrinsic: Vec<u8>) -> Option<RootBlock> {
    if let Ok(extrinsic) = UncheckedExtrinsic::decode(&mut encoded_extrinsic.as_slice()) {
        if let Call::Subspace(pallet_subspace::Call::store_root_block { root_block }) =
            extrinsic.function
        {
            return Some(root_block);
        }
    }

    None
}

fn extract_block_object_mapping(block: Block) -> BlockObjectMapping {
    let mut block_object_mapping = BlockObjectMapping::default();
    let mut base_offset =
        block.header.encoded_size() + Compact::compact_len(&(block.extrinsics.len() as u32));
    for extrinsic in block.extrinsics {
        let signature_size = extrinsic
            .signature
            .as_ref()
            .map(|s| s.encoded_size())
            .unwrap_or_default();
        // Extrinsic starts with vector length and version byte, followed by optional signature and
        // `function` encoding.
        // The last `+1` accounts for `Call::X()` enum variant encoding.
        let base_extrinsic_offset = base_offset
            + Compact::compact_len(
                &((1 + signature_size + extrinsic.function.encoded_size()) as u32),
            )
            + 1
            + signature_size
            + 1;

        if let Call::Feeds(call) = &extrinsic.function {
            if let Some(call_object_location) = call.extract_object_location() {
                let offset = (base_extrinsic_offset + call_object_location.offset).to_le_bytes();
                let size = call_object_location.size.to_le_bytes();

                // Block is known to never exceed 16MiB, hence 24-bit addressing
                block_object_mapping.objects.push(BlockObject::V0 {
                    offset: [offset[0], offset[1], offset[2]],
                    size: [size[0], size[1], size[2]],
                });
            }
        }

        base_offset += extrinsic.encoded_size();
    }

    block_object_mapping
}

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block);
        }

        fn initialize_block(header: &<Block as BlockT>::Header) {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: Block,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as BlockT>::Header) {
            Executive::offchain_worker(header)
        }
    }

    impl sp_consensus_subspace::SubspaceApi<Block> for Runtime {
        fn confirmation_depth_k() -> u32 {
            ConfirmationDepthK::get()
        }

        fn record_size() -> u32 {
            RecordSize::get()
        }

        fn recorded_history_segment_size() -> u32 {
            RecordedHistorySegmentSize::get()
        }

        fn pre_genesis_object_size() -> u32 {
            PreGenesisObjectSize::get()
        }

        fn pre_genesis_object_count() -> u32 {
            PreGenesisObjectCount::get()
        }

        fn pre_genesis_object_seed() -> Vec<u8> {
            Vec::from(PreGenesisObjectSeed::get())
        }

        fn configuration() -> sp_consensus_subspace::SubspaceGenesisConfiguration {
            // The choice of `c` parameter (where `1 - c` represents the
            // probability of a slot being empty), is done in accordance to the
            // slot duration and expected target block time, for safely
            // resisting network delays of maximum two seconds.
            // <https://research.web3.foundation/en/latest/polkadot/BABE/Babe/#6-practical-results>
            sp_consensus_subspace::SubspaceGenesisConfiguration {
                slot_duration: Subspace::slot_duration(),
                epoch_length: EpochDuration::get(),
                c: SlotProbability::get(),
                randomness: Subspace::randomness(),
            }
        }

        fn solution_range() -> u64 {
            Subspace::solution_range().unwrap_or_else(InitialSolutionRange::get)
        }

        fn salt() -> u64 {
            Subspace::salt()
        }

        fn current_epoch_start() -> sp_consensus_slots::Slot {
            Subspace::current_epoch_start()
        }

        fn current_epoch() -> sp_consensus_subspace::Epoch {
            Subspace::current_epoch()
        }

        fn next_epoch() -> sp_consensus_subspace::Epoch {
            Subspace::next_epoch()
        }

        fn submit_report_equivocation_extrinsic(
            equivocation_proof: sp_consensus_subspace::EquivocationProof<<Block as BlockT>::Header>,
        ) -> Option<()> {
            Subspace::submit_equivocation_report(equivocation_proof)
        }

        fn submit_store_root_block_extrinsic(root_block: RootBlock) {
            Subspace::submit_store_root_block(root_block)
        }

        fn is_in_block_list(farmer_public_key: &sp_consensus_subspace::FarmerPublicKey) -> bool {
            // TODO: Either check tx pool too for pending equivocations or replace equivocation
            //  mechanism with an alternative one, so that blocking happens faster
            Subspace::is_in_block_list(farmer_public_key)
        }

        fn merkle_tree_for_segment_index(segment_index: u64) -> Option<Sha256Hash> {
            Subspace::merkle_tree_for_segment_index(segment_index)
        }

        fn extract_root_block(encoded_extrinsic: Vec<u8>) -> Option<RootBlock> {
            extract_root_block(encoded_extrinsic)
        }

        fn extract_block_object_mapping(block: Block) -> BlockObjectMapping {
            extract_block_object_mapping(block)
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            opaque::SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Index> for Runtime {
        fn account_nonce(account: AccountId) -> Index {
            System::account_nonce(account)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }
        fn query_fee_details(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment::FeeDetails<Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame_benchmarking::{list_benchmark, Benchmarking, BenchmarkList};
            use frame_support::traits::StorageInfoTrait;
            use frame_system_benchmarking::Pallet as SystemBench;

            let mut list = Vec::<BenchmarkList>::new();

            list_benchmark!(list, extra, frame_system, SystemBench::<Runtime>);
            list_benchmark!(list, extra, pallet_balances, Balances);
            list_benchmark!(list, extra, pallet_timestamp, Timestamp);
            list_benchmark!(list, extra, pallet_template, TemplateModule);

            let storage_info = AllPalletsWithSystem::storage_info();

            return (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame_benchmarking::{Benchmarking, BenchmarkBatch, add_benchmark, TrackedStorageKey};

            use frame_system_benchmarking::Pallet as SystemBench;
            impl frame_system_benchmarking::Config for Runtime {}

            let whitelist: Vec<TrackedStorageKey> = vec![
                // Block Number
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac").to_vec().into(),
                // Total Issuance
                hex_literal::hex!("c2261276cc9d1f8598ea4b6a74b15c2f57c875e4cff74148e4628f264b974c80").to_vec().into(),
                // Execution Phase
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef7ff553b5a9862a516939d82b3d3d8661a").to_vec().into(),
                // Event Count
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef70a98fdbe9ce6c55837576c60c7af3850").to_vec().into(),
                // System Events
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7").to_vec().into(),
            ];

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);

            add_benchmark!(params, batches, frame_system, SystemBench::<Runtime>);
            add_benchmark!(params, batches, pallet_balances, Balances);
            add_benchmark!(params, batches, pallet_timestamp, Timestamp);
            add_benchmark!(params, batches, pallet_template, TemplateModule);

            if batches.is_empty() { return Err("Benchmark not found for this pallet.".into()) }
            Ok(batches)
        }
    }
}
