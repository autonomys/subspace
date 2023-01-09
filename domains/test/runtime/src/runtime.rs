use domain_runtime_primitives::RelayerId;
pub use domain_runtime_primitives::{
    AccountId, Address, Balance, BlockNumber, Hash, Index, Signature,
};
use frame_support::dispatch::DispatchClass;
use frame_support::traits::{ConstU16, ConstU32, Everything};
use frame_support::weights::constants::{
    BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND,
};
use frame_support::weights::{ConstantMultiplier, IdentityFee, Weight};
use frame_support::{construct_runtime, parameter_types};
use frame_system::limits::{BlockLength, BlockWeights};
use sp_api::impl_runtime_apis;
use sp_core::crypto::KeyTypeId;
use sp_core::OpaqueMetadata;
use sp_domains::bundle_election::BundleElectionParams;
use sp_domains::fraud_proof::FraudProof;
use sp_domains::transaction::PreValidationObject;
use sp_domains::{DomainId, ExecutorPublicKey, SignedOpaqueBundle};
use sp_messenger::endpoint::{Endpoint, EndpointHandler};
use sp_messenger::messages::{CrossDomainMessage, MessageId, RelayerMessagesWithStorageKey};
use sp_runtime::traits::{AccountIdLookup, BlakeTwo256, Block as BlockT, NumberFor};
use sp_runtime::transaction_validity::{TransactionSource, TransactionValidity};
use sp_runtime::{create_runtime_str, generic, impl_opaque_keys, ApplyExtrinsicResult};
pub use sp_runtime::{MultiAddress, Perbill, Permill};
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
use subspace_runtime_primitives::{SHANNON, SSC};

#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

// Make core-payments WASM runtime available.
include!(concat!(env!("OUT_DIR"), "/core_payments_wasm_bundle.rs"));

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

/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;
    use sp_runtime::generic;
    use sp_runtime::traits::BlakeTwo256;

    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;
}

impl_opaque_keys! {
    pub struct SessionKeys {
        /// Primarily used for adding the executor authority key into the keystore in the dev mode.
        pub executor: sp_domains::ExecutorKey,
    }
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("subspace-executor"),
    impl_name: create_runtime_str!("subspace-executor"),
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

/// We allow for 0.5 of a second of compute with a 12 second average block time.
const MAXIMUM_BLOCK_WEIGHT: Weight =
    Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_div(2), u64::MAX);

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
    pub const MinExecutorStake: Balance = 10 * SSC;
    pub const MaxExecutorStake: Balance = 10_000 * SSC;
    pub const MinExecutors: u32 = 1;
    pub const MaxExecutors: u32 = 10;
    pub const EpochDuration: BlockNumber = 3;
    pub const MaxWithdrawals: u32 = 1;
    pub const WithdrawalDuration: BlockNumber = 10;
}

impl pallet_executor_registry::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type StakeWeight = sp_domains::StakeWeight;
    type MinExecutorStake = MinExecutorStake;
    type MaxExecutorStake = MaxExecutorStake;
    type MinExecutors = MinExecutors;
    type MaxExecutors = MaxExecutors;
    type MaxWithdrawals = MaxWithdrawals;
    type WithdrawalDuration = WithdrawalDuration;
    type EpochDuration = EpochDuration;
    type OnNewEpoch = ();
}

parameter_types! {
    pub const MinDomainDeposit: Balance = 10 * SSC;
    pub const MaxDomainDeposit: Balance = 1000 * SSC;
    pub const MinDomainOperatorStake: Balance = 10 * SSC;
    pub const MaximumReceiptDrift: BlockNumber = 128;
    pub const ReceiptsPruningDepth: BlockNumber = 256;
}

impl pallet_domain_registry::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type StakeWeight = sp_domains::StakeWeight;
    type ExecutorRegistry = ExecutorRegistry;
    type MinDomainDeposit = MinDomainDeposit;
    type MaxDomainDeposit = MaxDomainDeposit;
    type MinDomainOperatorStake = MinDomainOperatorStake;
    type MaximumReceiptDrift = MaximumReceiptDrift;
    type ReceiptsPruningDepth = ReceiptsPruningDepth;
    type CoreDomainTracker = DomainTracker;
}

parameter_types! {
    pub const StateRootsBound: u32 = 50;
    pub const RelayConfirmationDepth: BlockNumber = 7;
}

impl pallet_domain_tracker::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ConfirmedStateRootsBound = StateRootsBound;
    type RelayerConfirmationDepth = RelayConfirmationDepth;
}

parameter_types! {
    pub const MaximumRelayers: u32 = 100;
    pub const RelayerDeposit: Balance = 100 * SSC;
    pub const SystemDomainId: DomainId = DomainId::SYSTEM;
}

impl pallet_messenger::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfDomainId = SystemDomainId;
    type DomainTracker = DomainTracker;

    fn get_endpoint_response_handler(
        _endpoint: &Endpoint,
    ) -> Option<Box<dyn EndpointHandler<MessageId>>> {
        None
    }

    type Currency = Balances;
    type MaximumRelayers = MaximumRelayers;
    type RelayerDeposit = RelayerDeposit;
}

impl<C> frame_system::offchain::SendTransactionTypes<C> for Runtime
where
    RuntimeCall: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type OverarchingCall = RuntimeCall;
}

// Create the runtime by composing the FRAME pallets that were previously configured.
construct_runtime!(
    pub struct Runtime
    where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        // System support stuff.
        System: frame_system,
        ExecutivePallet: domain_pallet_executive,

        // Monetary stuff.
        Balances: pallet_balances,
        TransactionPayment: pallet_transaction_payment,

        // System domain.
        //
        // Must be after Balances pallet so that its genesis is built after the Balances genesis is
        // built.
        ExecutorRegistry: pallet_executor_registry,
        DomainRegistry: pallet_domain_registry,
        DomainTracker: pallet_domain_tracker,
        Messenger: pallet_messenger,
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
    }

    impl domain_runtime_primitives::DomainCoreApi<Block, AccountId> for Runtime {
        fn extract_signer(
            extrinsics: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<(Option<AccountId>, <Block as BlockT>::Extrinsic)> {
            use domain_runtime_primitives::Signer;
            let lookup = frame_system::ChainContext::<Runtime>::default();
            extrinsics.into_iter().map(|xt| (xt.signer(&lookup), xt)).collect()
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
            // Use `set_code_without_checks` instead of `set_code` in the test environment.
            let set_code_call = frame_system::Call::set_code_without_checks { code };
            UncheckedExtrinsic::new_unsigned(
                domain_pallet_executive::Call::sudo_unchecked_weight_unsigned {
                    call: Box::new(set_code_call.into()),
                    weight: Weight::zero()
                }.into()
            ).encode()
        }
    }

    impl system_runtime_primitives::SystemDomainApi<Block, BlockNumber, Hash> for Runtime {
        fn construct_submit_core_bundle_extrinsics(
            signed_opaque_bundles: Vec<SignedOpaqueBundle<BlockNumber, Hash, <Block as BlockT>::Hash>>,
        ) -> Vec<Vec<u8>> {
            use codec::Encode;
            signed_opaque_bundles
                .into_iter()
                .map(|signed_opaque_bundle| {
                    UncheckedExtrinsic::new_unsigned(
                        pallet_domain_registry::Call::submit_core_bundle {
                            signed_opaque_bundle
                        }.into()
                    ).encode()
                })
                .collect()
        }

        fn bundle_elections_params(domain_id: DomainId) -> BundleElectionParams {
            if domain_id.is_system() {
                BundleElectionParams {
                    authorities: ExecutorRegistry::authorities().into(),
                    total_stake_weight: ExecutorRegistry::total_stake_weight(),
                    slot_probability: ExecutorRegistry::slot_probability(),
                }
            } else {
                match (
                    DomainRegistry::domain_authorities(domain_id),
                    DomainRegistry::domain_total_stake_weight(domain_id),
                    DomainRegistry::domain_slot_probability(domain_id),
                ) {
                    (authorities, Some(total_stake_weight), Some(slot_probability)) => {
                        BundleElectionParams {
                            authorities,
                            total_stake_weight,
                            slot_probability,
                        }
                    }
                    _ => BundleElectionParams::empty(),
                }
            }
        }

        fn core_bundle_election_storage_keys(
            domain_id: DomainId,
            executor_public_key: ExecutorPublicKey,
        ) -> Option<Vec<Vec<u8>>> {
            let executor = ExecutorRegistry::key_owner(&executor_public_key)?;
            let mut storage_keys = DomainRegistry::core_bundle_election_storage_keys(domain_id, executor);
            storage_keys.push(ExecutorRegistry::key_owner_hashed_key_for(&executor_public_key));
            Some(storage_keys)
        }

        fn head_receipt_number(domain_id: DomainId) -> NumberFor<Block> {
            DomainRegistry::head_receipt_number(domain_id)
        }

        fn oldest_receipt_number(domain_id: DomainId) -> NumberFor<Block> {
            DomainRegistry::oldest_receipt_number(domain_id)
        }

        fn maximum_receipt_drift() -> NumberFor<Block> {
            MaximumReceiptDrift::get()
        }

        fn submit_fraud_proof_unsigned(fraud_proof: FraudProof) {
            DomainRegistry::submit_fraud_proof_unsigned(fraud_proof)
        }
    }

    impl sp_domain_tracker::DomainTrackerApi<Block, BlockNumber> for Runtime {
        fn storage_key_for_core_domain_state_root(
            domain_id: DomainId,
            block_number: BlockNumber,
        ) -> Option<Vec<u8>> {
            DomainTracker::storage_key_for_core_domain_state_root(domain_id, block_number)
        }
    }

    impl sp_messenger::RelayerApi<Block, RelayerId, BlockNumber> for Runtime {
        fn domain_id() -> DomainId {
            SystemDomainId::get()
        }

        fn relay_confirmation_depth() -> BlockNumber {
            RelayConfirmationDepth::get()
        }

        fn relayer_assigned_messages(relayer_id: RelayerId) -> RelayerMessagesWithStorageKey {
            Messenger::relayer_assigned_messages(relayer_id)
        }

        fn outbox_message_unsigned(msg: CrossDomainMessage<<Block as BlockT>::Hash, BlockNumber>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::outbox_message_unsigned(msg)
        }

        fn inbox_response_message_unsigned(msg: CrossDomainMessage<<Block as BlockT>::Hash, BlockNumber>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::inbox_response_message_unsigned(msg)
        }

        fn should_relay_outbox_message(dst_domain_id: DomainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_outbox_message(dst_domain_id, msg_id)
        }

        fn should_relay_inbox_message_response(dst_domain_id: DomainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_inbox_message_response(dst_domain_id, msg_id)
        }
    }

    impl sp_domains::transaction::PreValidationObjectApi<Block, domain_runtime_primitives::Hash> for Runtime {
        fn extract_pre_validation_object(
            extrinsic: <Block as BlockT>::Extrinsic,
        ) -> PreValidationObject<Block, domain_runtime_primitives::Hash> {
            match extrinsic.function {
                RuntimeCall::DomainRegistry(pallet_domain_registry::Call::submit_fraud_proof { fraud_proof }) => {
                    PreValidationObject::FraudProof(fraud_proof)
                }
                _ => PreValidationObject::Null,
            }
        }
    }
}
