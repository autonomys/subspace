use crate::feed_processor::{feed_processor, FeedProcessorId, FeedProcessorKind};
use codec::{Decode, Encode};
use core::time::Duration;
use domain_runtime_primitives::opaque;
pub use domain_runtime_primitives::{
    AccountId, Address, Balance, BlockNumber, Hash, Index, Signature,
};
use frame_support::dispatch::DispatchClass;
use frame_support::traits::{ConstU16, ConstU32, Everything, UnixTime};
use frame_support::weights::constants::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight};
use frame_support::weights::{ConstantMultiplier, IdentityFee, Weight};
use frame_support::{construct_runtime, parameter_types};
use frame_system::limits::{BlockLength, BlockWeights};
use pallet_feeds::feed_processor::FeedProcessor;
use pallet_transporter::EndpointHandler;
use snowbridge_beacon_primitives::{Fork, ForkVersions};
use snowbridge_ethereum_beacon_client as pallet_ethereum_beacon_client;
use sp_api::impl_runtime_apis;
use sp_core::crypto::KeyTypeId;
use sp_core::OpaqueMetadata;
use sp_domains::DomainId;
use sp_messenger::endpoint::{Endpoint, EndpointHandler as EndpointHandlerT, EndpointId};
use sp_messenger::messages::{
    CrossDomainMessage, ExtractedStateRootsFromProof, MessageId, RelayerMessagesWithStorageKey,
};
use sp_runtime::traits::{AccountIdLookup, BlakeTwo256, Block as BlockT};
use sp_runtime::transaction_validity::{TransactionSource, TransactionValidity};
use sp_runtime::{create_runtime_str, generic, impl_opaque_keys, ApplyExtrinsicResult};
pub use sp_runtime::{MultiAddress, Perbill, Permill};
use sp_std::marker::PhantomData;
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
use subspace_runtime_primitives::{SHANNON, SSC};

/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckMortality<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra>;

/// Executive: handles dispatch to the various modules.
pub type Executive = domain_pallet_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
    Runtime,
>;

impl_opaque_keys! {
    pub struct SessionKeys {
        /// Primarily used for adding the executor authority key into the keystore in the dev mode.
        pub executor: sp_domains::ExecutorKey,
    }
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("subspace-eth-relay-domain"),
    impl_name: create_runtime_str!("subspace-eth-relay-domain"),
    authoring_version: 0,
    spec_version: 0,
    impl_version: 0,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 0,
    state_version: 0,
};

/// The existential deposit. Same with the one on primary chain.
pub const EXISTENTIAL_DEPOSIT: Balance = 500 * SHANNON;

/// We assume that ~5% of the block weight is consumed by `on_initialize` handlers. This is
/// used to limit the maximal weight of a single extrinsic.
const AVERAGE_ON_INITIALIZE_RATIO: Perbill = Perbill::from_percent(5);

/// We allow `Normal` extrinsics to fill up the block up to 75%, the rest can be used by
/// `Operational` extrinsics.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

/// TODO: Proper max block weight
const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::MAX;

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub const BlockHashCount: BlockNumber = 2400;

    // This part is copied from Substrate's `bin/node/runtime/src/lib.rs`.
    //  The `RuntimeBlockLength` and `RuntimeBlockWeights` exist here because the
    // `DeletionWeightLimit` and `DeletionQueueDepth` depend on those to parameterize
    // the lazy contract deletion.
    pub RuntimeBlockLength: BlockLength =
        BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
    pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
        .base_block(BlockExecutionWeight::get())
        .for_class(DispatchClass::all(), |weights| {
            weights.base_extrinsic = ExtrinsicBaseWeight::get();
        })
        .for_class(DispatchClass::Normal, |weights| {
            weights.max_total = Some(NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT);
        })
        .for_class(DispatchClass::Operational, |weights| {
            weights.max_total = Some(MAXIMUM_BLOCK_WEIGHT);
            // Operational transactions have some extra reserved space, so that they
            // are included even if block reached `MAXIMUM_BLOCK_WEIGHT`.
            weights.reserved = Some(
                MAXIMUM_BLOCK_WEIGHT - NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT
            );
        })
        .avg_block_initialization(AVERAGE_ON_INITIALIZE_RATIO)
        .build_or_panic();
}

// Configure FRAME pallets to include in runtime.

impl frame_system::Config for Runtime {
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The aggregated dispatch type that is available for extrinsics.
    type RuntimeCall = RuntimeCall;
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
    type RuntimeEvent = RuntimeEvent;
    /// The ubiquitous origin type.
    type RuntimeOrigin = RuntimeOrigin;
    /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
    type BlockHashCount = BlockHashCount;
    /// Runtime version.
    type Version = Version;
    /// Converts a module to an index of this module in the runtime.
    type PalletInfo = PalletInfo;
    /// The data to be stored in an account.
    type AccountData = pallet_balances::AccountData<Balance>;
    /// What to do if a new account is created.
    type OnNewAccount = ();
    /// What to do if an account is fully reaped from the system.
    type OnKilledAccount = ();
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = RocksDbWeight;
    /// The basic call filter to use in dispatchable.
    type BaseCallFilter = Everything;
    /// Weight information for the extrinsics of this pallet.
    type SystemWeightInfo = ();
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = RuntimeBlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = RuntimeBlockLength;
    /// This is used as an identifier of the chain. 42 is the generic substrate prefix.
    type SS58Prefix = ConstU16<42>;
    /// The action to take on a Runtime Upgrade
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT;
    pub const MaxLocks: u32 = 50;
    pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
    type MaxLocks = MaxLocks;
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type MaxReserves = MaxReserves;
    type ReserveIdentifier = [u8; 8];
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type HoldIdentifier = ();
    type MaxHolds = ();
}

parameter_types! {
    pub const TransactionByteFee: Balance = 1;
    pub const OperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = pallet_transaction_payment::CurrencyAdapter<Balances, ()>;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
    type FeeMultiplierUpdate = ();
    type OperationalFeeMultiplier = OperationalFeeMultiplier;
}

impl domain_pallet_executive::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
}

parameter_types! {
    pub const StateRootsBound: u32 = 50;
    pub const RelayConfirmationDepth: BlockNumber = 7;
}

parameter_types! {
    pub const MaximumRelayers: u32 = 100;
    pub const RelayerDeposit: Balance = 100 * SSC;
    pub const CoreEthRelayDomainId: DomainId = DomainId::CORE_ETH_RELAY;
}

impl pallet_messenger::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfDomainId = CoreEthRelayDomainId;

    fn get_endpoint_response_handler(
        endpoint: &Endpoint,
    ) -> Option<Box<dyn EndpointHandlerT<MessageId>>> {
        if endpoint == &Endpoint::Id(TransporterEndpointId::get()) {
            Some(Box::new(EndpointHandler(PhantomData::<Runtime>::default())))
        } else {
            None
        }
    }

    type Currency = Balances;
    type MaximumRelayers = MaximumRelayers;
    type RelayerDeposit = RelayerDeposit;
    type DomainInfo = ();
    type ConfirmationDepth = RelayConfirmationDepth;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
    RuntimeCall: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type OverarchingCall = RuntimeCall;
}

parameter_types! {
    pub const TransporterEndpointId: EndpointId = 1;
}

impl pallet_transporter::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfDomainId = CoreEthRelayDomainId;
    type SelfEndpointId = TransporterEndpointId;
    type Currency = Balances;
    type Sender = Messenger;
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
}

/// Dummy time provider that always returns zero.
pub struct DummyTimeProvider;

impl UnixTime for DummyTimeProvider {
    fn now() -> Duration {
        Duration::ZERO
    }
}

// Ethereum mainnet configuration
parameter_types! {
    pub const MaxSyncCommitteeSize: u32 = 512;
    pub const MaxProofBranchSize: u32 = 20;
    pub const MaxExtraDataSize: u32 = 32;
    pub const MaxLogsBloomSize: u32 = 256;
    pub const MaxFeeRecipientSize: u32 = 20;
    pub const MaxPublicKeySize: u32 = 48;
    pub const MaxSignatureSize: u32 = 96;
    pub const MaxSlotsPerHistoricalRoot: u64 = 8192;
    pub const MaxFinalizedHeaderSlotArray: u32 = 1000;
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
        capella: Fork {
            version: [3, 0, 16, 32], // 0x03001020
            epoch: 162304,
        },
    };
}

impl pallet_ethereum_beacon_client::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    // TODO: Replace this with proper implementation once we can retrieve timestamp in domain runtime
    type TimeProvider = DummyTimeProvider;
    type MaxSyncCommitteeSize = MaxSyncCommitteeSize;
    type MaxProofBranchSize = MaxProofBranchSize;
    type MaxExtraDataSize = MaxExtraDataSize;
    type MaxLogsBloomSize = MaxLogsBloomSize;
    type MaxFeeRecipientSize = MaxFeeRecipientSize;
    type MaxPublicKeySize = MaxPublicKeySize;
    type MaxSignatureSize = MaxSignatureSize;
    type MaxSlotsPerHistoricalRoot = MaxSlotsPerHistoricalRoot;
    type MaxFinalizedHeaderSlotArray = MaxFinalizedHeaderSlotArray;
    type ForkVersions = ChainForkVersions;
    type WeakSubjectivityPeriodSeconds = WeakSubjectivityPeriodSeconds;
    type WeightInfo = pallet_ethereum_beacon_client::weights::SnowbridgeWeight<Self>;
}

pub type FeedId = u64;

parameter_types! {
    // Limit maximum number of feeds per account
    pub const MaxFeeds: u32 = 1;
    pub const EthereumFeedProcessorId: FeedProcessorId  = FeedProcessorId(*b"py/feprx");
}

impl pallet_feeds::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type FeedId = FeedId;
    type FeedProcessorKind = FeedProcessorKind;
    type MaxFeeds = MaxFeeds;

    fn feed_processor(
        feed_processor_kind: Self::FeedProcessorKind,
    ) -> Box<dyn FeedProcessor<Self::FeedId>> {
        feed_processor(EthereumFeedProcessorId::get(), feed_processor_kind)
    }
}

// Create the runtime by composing the FRAME pallets that were previously configured.
//
// NOTE: Currently domain runtime does not naturally support the pallets with inherent extrinsics.
construct_runtime!(
    pub struct Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        // System support stuff.
        System: frame_system = 0,
        ExecutivePallet: domain_pallet_executive = 1,

        // Monetary stuff.
        Balances: pallet_balances = 2,
        TransactionPayment: pallet_transaction_payment = 3,

        // messenger stuff
        // Note: Indexes should match the indexes of the System domain runtime
        Messenger: pallet_messenger = 6,
        Transporter: pallet_transporter = 7,

        // Having beacon client at 90 to have plenty of room for system domain runtime pallets
        // (w.r.t future upgrade of system domain runtime) as well as some room for adding light client
        // related pallets after 90
        EthereumBeaconClient: pallet_ethereum_beacon_client::{Pallet, Config<T>, Storage, Event<T>} = 90,
        Feeds: pallet_feeds = 91,

        // Sudo account
        Sudo: pallet_sudo = 100,
    }
);

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block)
        }

        fn initialize_block(header: &<Block as BlockT>::Header) {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }

        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }

        fn metadata_versions() -> sp_std::vec::Vec<u32> {
            Runtime::metadata_versions()
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

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            SessionKeys::decode_into_raw_public_keys(&encoded)
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
        fn query_weight_to_fee(weight: Weight) -> Balance {
            TransactionPayment::weight_to_fee(weight)
        }
        fn query_length_to_fee(length: u32) -> Balance {
            TransactionPayment::length_to_fee(length)
        }
    }

    impl domain_runtime_primitives::DomainCoreApi<Block> for Runtime {
        fn extract_signer(
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<(Option<opaque::AccountId>, <Block as BlockT>::Extrinsic)> {
            use domain_runtime_primitives::Signer;
            let lookup = frame_system::ChainContext::<Runtime>::default();
            extrinsics.into_iter().map(|xt| (xt.signer(&lookup).map(|signer| signer.encode()), xt)).collect()
        }

        fn intermediate_roots() -> Vec<[u8; 32]> {
            ExecutivePallet::intermediate_roots()
        }

        fn initialize_block_with_post_state_root(header: &<Block as BlockT>::Header) -> Vec<u8> {
            Executive::initialize_block(header);
            Executive::storage_root()
        }

        fn apply_extrinsic_with_post_state_root(extrinsic: <Block as BlockT>::Extrinsic) -> Vec<u8> {
            let _ = Executive::apply_extrinsic(extrinsic);
            Executive::storage_root()
        }

        fn construct_set_code_extrinsic(code: Vec<u8>) -> Vec<u8> {
            use codec::Encode;
            let set_code_call = frame_system::Call::set_code { code };
            UncheckedExtrinsic::new_unsigned(
                domain_pallet_executive::Call::sudo_unchecked_weight_unsigned {
                    call: Box::new(set_code_call.into()),
                    weight: Weight::from_parts(0, 0),
                }.into()
            ).encode()
        }

        fn check_transaction_fee(
            uxt: <Block as BlockT>::Extrinsic,
        ) -> Result<(), domain_runtime_primitives::CheckTransactionFeeError> {
            use codec::Encode;
            use frame_support::traits::{Currency, ExistenceRequirement, WithdrawReasons};
            use sp_runtime::traits::{StaticLookup, Zero};

            let maybe_address_and_tip = uxt.signature.as_ref().map(|(address, _signature, extra)| {
                let (_, _, _, _, _, _, _, charge_transaction_payment) = extra;
                (address.clone(), charge_transaction_payment.tip())
            });

            if let Some((address, tip)) = maybe_address_and_tip {
                let len = uxt.encode().len().try_into().expect("Size of extrinsic must fit into u32");
                let fee = TransactionPayment::query_fee_details(uxt, len).final_fee() + tip;

                let sender = <Runtime as frame_system::Config>::Lookup::lookup(address)?;

                let withdraw_reason = if tip.is_zero() {
                    WithdrawReasons::TRANSACTION_PAYMENT
                } else {
                    WithdrawReasons::TRANSACTION_PAYMENT | WithdrawReasons::TIP
                };

                Balances::withdraw(&sender, fee, withdraw_reason, ExistenceRequirement::KeepAlive)
                    .map(|_| ())
                    .map_err(Into::into)
            } else {
                Ok(())
            }
        }
    }

    impl sp_messenger::MessengerApi<Block, BlockNumber> for Runtime {
        fn extract_xdm_proof_state_roots(
            extrinsic: Vec<u8>,
        ) -> Option<ExtractedStateRootsFromProof<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>> {
            extract_xdm_proof_state_roots(extrinsic)
        }

        fn confirmation_depth() -> BlockNumber {
            RelayConfirmationDepth::get()
        }
    }

    impl sp_messenger::RelayerApi<Block, AccountId, BlockNumber> for Runtime {
        fn domain_id() -> DomainId {
            CoreEthRelayDomainId::get()
        }

        fn relay_confirmation_depth() -> BlockNumber {
            RelayConfirmationDepth::get()
        }

        fn domain_best_number(_domain_id: DomainId) -> Option<BlockNumber> {
            None
        }

        fn domain_state_root(_domain_id: DomainId, _number: BlockNumber, _hash: Hash) -> Option<Hash>{
            None
        }

        fn relayer_assigned_messages(relayer_id: AccountId) -> RelayerMessagesWithStorageKey {
            Messenger::relayer_assigned_messages(relayer_id)
        }

        fn outbox_message_unsigned(msg: CrossDomainMessage<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::outbox_message_unsigned(msg)
        }

        fn inbox_response_message_unsigned(msg: CrossDomainMessage<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::inbox_response_message_unsigned(msg)
        }

        fn should_relay_outbox_message(dst_domain_id: DomainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_outbox_message(dst_domain_id, msg_id)
        }

        fn should_relay_inbox_message_response(dst_domain_id: DomainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_inbox_message_response(dst_domain_id, msg_id)
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame_benchmarking::{Benchmarking, BenchmarkList, list_benchmark};
            use frame_support::traits::StorageInfoTrait;
            use frame_system_benchmarking::Pallet as SystemBench;

            let mut list = Vec::<BenchmarkList>::new();

            list_benchmark!(list, extra, frame_system, SystemBench::<Runtime>);
            list_benchmark!(list, extra, ethereum_beacon_client, EthereumBeaconClient);

            let storage_info = AllPalletsWithSystem::storage_info();

            return (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame_benchmarking::{Benchmarking, BenchmarkBatch, TrackedStorageKey, add_benchmark};

            use frame_system_benchmarking::Pallet as SystemBench;
            impl frame_system_benchmarking::Config for Runtime {}

            let whitelist: Vec<TrackedStorageKey> = vec![
                // Block Number
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef702a5c1b19ab7a04f536c519aca4983ac").to_vec().into(),
                // Total Issuance
                hex_literal::hex!("c2261276cc9d1f8598ea4b6a74b15c2f57c875e4cff74148e4628f264b974c80").to_vec().into(),
                // Execution Phase
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef7ff553b5a9862a516939d82b3d3d8661a").to_vec().into(),
                // RuntimeEvent Count
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef70a98fdbe9ce6c55837576c60c7af3850").to_vec().into(),
                // System Events
                hex_literal::hex!("26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7").to_vec().into(),
            ];

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);

            add_benchmark!(params, batches, frame_system, SystemBench::<Runtime>);
            add_benchmark!(params, batches, ethereum_beacon_client, EthereumBeaconClient);

            if batches.is_empty() { return Err("Benchmark not found for this pallet.".into()) }
            Ok(batches)
        }
    }
}

fn extract_xdm_proof_state_roots(
    encoded_ext: Vec<u8>,
) -> Option<ExtractedStateRootsFromProof<BlockNumber, Hash, Hash>> {
    if let Ok(ext) = UncheckedExtrinsic::decode(&mut encoded_ext.as_slice()) {
        match &ext.function {
            RuntimeCall::Messenger(pallet_messenger::Call::relay_message { msg }) => {
                msg.extract_state_roots_from_proof::<BlakeTwo256>()
            }
            RuntimeCall::Messenger(pallet_messenger::Call::relay_message_response { msg }) => {
                msg.extract_state_roots_from_proof::<BlakeTwo256>()
            }
            _ => None,
        }
    } else {
        None
    }
}
