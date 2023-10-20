#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

mod precompiles;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use codec::{Decode, Encode};
use domain_runtime_primitives::opaque::Header;
pub use domain_runtime_primitives::{opaque, Balance, BlockNumber, Hash, Nonce};
use domain_runtime_primitives::{MultiAccountId, TryConvertBack, SLOT_DURATION};
use fp_account::EthereumSignature;
use fp_self_contained::SelfContainedCall;
use frame_support::dispatch::{DispatchClass, GetDispatchInfo};
use frame_support::inherent::ProvideInherent;
use frame_support::traits::{
    ConstU16, ConstU32, ConstU64, Currency, Everything, FindAuthor, Imbalance, OnFinalize,
    OnUnbalanced, PalletInfoAccess,
};
use frame_support::weights::constants::{
    BlockExecutionWeight, ExtrinsicBaseWeight, ParityDbWeight, WEIGHT_REF_TIME_PER_MILLIS,
    WEIGHT_REF_TIME_PER_SECOND,
};
use frame_support::weights::{ConstantMultiplier, IdentityFee, Weight};
use frame_support::{construct_runtime, parameter_types};
use frame_system::limits::{BlockLength, BlockWeights};
use pallet_ethereum::Call::transact;
use pallet_ethereum::{PostLogContent, Transaction as EthereumTransaction, TransactionStatus};
use pallet_evm::{
    Account as EVMAccount, EnsureAddressNever, EnsureAddressRoot, FeeCalculator,
    IdentityAddressMapping, Runner,
};
use pallet_transporter::EndpointHandler;
use sp_api::impl_runtime_apis;
use sp_core::crypto::KeyTypeId;
use sp_core::storage::StateVersion;
use sp_core::{Get, OpaqueMetadata, H160, H256, U256};
use sp_domains::DomainId;
use sp_messenger::endpoint::{Endpoint, EndpointHandler as EndpointHandlerT, EndpointId};
use sp_messenger::messages::{
    BlockInfo, BlockMessagesWithStorageKey, ChainId, CrossDomainMessage,
    ExtractedStateRootsFromProof, MessageId,
};
use sp_runtime::generic::Era;
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, Convert, DispatchInfoOf, Dispatchable, IdentifyAccount,
    IdentityLookup, PostDispatchInfoOf, UniqueSaturatedInto, Verify,
};
use sp_runtime::transaction_validity::{
    TransactionSource, TransactionValidity, TransactionValidityError,
};
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys, ApplyExtrinsicResult, ConsensusEngineId, Digest,
};
pub use sp_runtime::{MultiAddress, Perbill, Permill, SaturatedConversion};
use sp_std::marker::PhantomData;
use sp_std::prelude::*;
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;
use subspace_runtime_primitives::{Moment, SHANNON};

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = EthereumSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// The address format for describing accounts.
pub type Address = AccountId;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// Precompiles we use for EVM
pub type Precompiles = crate::precompiles::Precompiles<Runtime>;

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
    fp_self_contained::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic =
    fp_self_contained::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra, H160>;

/// Executive: handles dispatch to the various modules.
pub type Executive = domain_pallet_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
    Runtime,
>;

impl fp_self_contained::SelfContainedCall for RuntimeCall {
    type SignedInfo = H160;

    fn is_self_contained(&self) -> bool {
        match self {
            RuntimeCall::Ethereum(call) => call.is_self_contained(),
            _ => false,
        }
    }

    fn check_self_contained(&self) -> Option<Result<Self::SignedInfo, TransactionValidityError>> {
        match self {
            RuntimeCall::Ethereum(call) => call.check_self_contained(),
            _ => None,
        }
    }

    fn validate_self_contained(
        &self,
        info: &Self::SignedInfo,
        dispatch_info: &DispatchInfoOf<RuntimeCall>,
        len: usize,
    ) -> Option<TransactionValidity> {
        match self {
            RuntimeCall::Ethereum(call) => call.validate_self_contained(info, dispatch_info, len),
            _ => None,
        }
    }

    fn pre_dispatch_self_contained(
        &self,
        info: &Self::SignedInfo,
        dispatch_info: &DispatchInfoOf<RuntimeCall>,
        len: usize,
    ) -> Option<Result<(), TransactionValidityError>> {
        match self {
            RuntimeCall::Ethereum(call) => {
                call.pre_dispatch_self_contained(info, dispatch_info, len)
            }
            _ => None,
        }
    }

    fn apply_self_contained(
        self,
        info: Self::SignedInfo,
    ) -> Option<sp_runtime::DispatchResultWithInfo<PostDispatchInfoOf<Self>>> {
        match self {
            call @ RuntimeCall::Ethereum(pallet_ethereum::Call::transact { .. }) => {
                Some(call.dispatch(RuntimeOrigin::from(
                    pallet_ethereum::RawOrigin::EthereumTransaction(info),
                )))
            }
            _ => None,
        }
    }
}

impl_opaque_keys! {
    pub struct SessionKeys {
        /// Primarily used for adding the executor authority key into the keystore in the dev mode.
        pub executor: sp_domains::OperatorKey,
    }
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("subspace-evm-domain"),
    impl_name: create_runtime_str!("subspace-evm-domain"),
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
/// We allow for 2000ms of compute with a 6 second average block time.
pub const WEIGHT_MILLISECS_PER_BLOCK: u64 = 2000;
pub const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::from_parts(
    WEIGHT_MILLISECS_PER_BLOCK * WEIGHT_REF_TIME_PER_MILLIS,
    u64::MAX,
);
pub const MAXIMUM_BLOCK_LENGTH: u32 = 5 * 1024 * 1024;

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
    pub const ExtrinsicsRootStateVersion: StateVersion = StateVersion::V1;
}

impl frame_system::Config for Runtime {
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The aggregated dispatch type that is available for extrinsics.
    type RuntimeCall = RuntimeCall;
    /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
    type Lookup = IdentityLookup<AccountId>;
    /// The type for storing how many extrinsics an account has signed.
    type Nonce = Nonce;
    /// The type for hashing blocks and tries.
    type Hash = Hash;
    /// The hashing algorithm used.
    type Hashing = BlakeTwo256;
    /// The block type.
    type Block = Block;
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
    type DbWeight = ParityDbWeight;
    /// The basic call filter to use in dispatchable.
    type BaseCallFilter = Everything;
    /// Weight information for the extrinsics of this pallet.
    type SystemWeightInfo = ();
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = RuntimeBlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = RuntimeBlockLength;
    type SS58Prefix = ConstU16<2254>;
    /// The action to take on a Runtime Upgrade
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
    type ExtrinsicsRootStateVersion = ExtrinsicsRootStateVersion;
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = ();
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
    type RuntimeHoldReason = ();
    type MaxHolds = ();
}

impl pallet_operator_rewards::Config for Runtime {
    type Balance = Balance;
}

type NegativeImbalance = <Balances as Currency<AccountId>>::NegativeImbalance;

/// `ActualPaidFeesHandler` used to collect all the fee in `pallet_operator_rewards`
pub struct ActualPaidFeesHandler;

impl OnUnbalanced<NegativeImbalance> for ActualPaidFeesHandler {
    fn on_unbalanceds<B>(fees_then_tips: impl Iterator<Item = NegativeImbalance>) {
        // Record both actual paid transaction fee and tip in `pallet_operator_rewards`
        for fee in fees_then_tips {
            OperatorRewards::note_operator_rewards(fee.peek());
        }
    }
}

parameter_types! {
    pub const TransactionByteFee: Balance = 1;
    pub const OperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction =
        pallet_transaction_payment::CurrencyAdapter<Balances, ActualPaidFeesHandler>;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
    type FeeMultiplierUpdate = ();
    type OperationalFeeMultiplier = OperationalFeeMultiplier;
}

impl domain_pallet_executive::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = domain_pallet_executive::weights::SubstrateWeight<Runtime>;
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const RelayConfirmationDepth: BlockNumber = 18;
    pub SelfChainId: ChainId = SelfDomainId::self_domain_id().into();
}

pub struct OnXDMRewards;

impl sp_messenger::OnXDMRewards<Balance> for OnXDMRewards {
    fn on_xdm_rewards(rewards: Balance) {
        OperatorRewards::note_operator_rewards(rewards)
    }
}

impl pallet_messenger::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;

    fn get_endpoint_handler(endpoint: &Endpoint) -> Option<Box<dyn EndpointHandlerT<MessageId>>> {
        if endpoint == &Endpoint::Id(TransporterEndpointId::get()) {
            Some(Box::new(EndpointHandler(PhantomData::<Runtime>)))
        } else {
            None
        }
    }

    type Currency = Balances;
    type DomainInfo = ();
    type ConfirmationDepth = RelayConfirmationDepth;
    type WeightInfo = pallet_messenger::weights::SubstrateWeight<Runtime>;
    type WeightToFee = IdentityFee<Balance>;
    type OnXDMRewards = OnXDMRewards;
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

pub struct AccountId20Converter;

impl Convert<AccountId, MultiAccountId> for AccountId20Converter {
    fn convert(account_id: AccountId) -> MultiAccountId {
        MultiAccountId::AccountId20(account_id.into())
    }
}

impl TryConvertBack<AccountId, MultiAccountId> for AccountId20Converter {
    fn try_convert_back(multi_account_id: MultiAccountId) -> Option<AccountId> {
        match multi_account_id {
            MultiAccountId::AccountId20(acc) => Some(AccountId::from(acc)),
            _ => None,
        }
    }
}

impl pallet_transporter::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;
    type SelfEndpointId = TransporterEndpointId;
    type Currency = Balances;
    type Sender = Messenger;
    type AccountIdConverter = AccountId20Converter;
    type WeightInfo = pallet_transporter::weights::SubstrateWeight<Runtime>;
}

impl pallet_evm_chain_id::Config for Runtime {}

pub struct FindAuthorTruncated;

impl FindAuthor<H160> for FindAuthorTruncated {
    fn find_author<'a, I>(_digests: I) -> Option<H160>
    where
        I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
    {
        // TODO: returns the executor reward address once we start collecting them
        None
    }
}

/// Current approximation of the gas/s consumption considering
/// EVM execution over compiled WASM (on 4.4Ghz CPU).
/// Given the 500ms Weight, from which 75% only are used for transactions,
/// the total EVM execution gas limit is: GAS_PER_SECOND * 0.500 * 0.75 ~= 15_000_000.
pub const GAS_PER_SECOND: u64 = 40_000_000;

/// Approximate ratio of the amount of Weight per Gas.
/// u64 works for approximations because Weight is a very small unit compared to gas.
pub const WEIGHT_PER_GAS: u64 = WEIGHT_REF_TIME_PER_SECOND.saturating_div(GAS_PER_SECOND);

parameter_types! {
    /// EVM gas limit
    pub BlockGasLimit: U256 = U256::from(
        NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT.ref_time() / WEIGHT_PER_GAS
    );
    pub PrecompilesValue: Precompiles = Precompiles::default();
    pub WeightPerGas: Weight = Weight::from_parts(WEIGHT_PER_GAS, 0);
}

type InnerEVMCurrencyAdapter = pallet_evm::EVMCurrencyAdapter<Balances, ()>;

// Implementation of [`pallet_transaction_payment::OnChargeTransaction`] that charges evm transaction
// fees from the transaction sender and collect all the fees (including both the base fee and tip) in
// `pallet_operator_rewards`
pub struct EVMCurrencyAdapter;

impl pallet_evm::OnChargeEVMTransaction<Runtime> for EVMCurrencyAdapter {
    type LiquidityInfo = Option<NegativeImbalance>;

    fn withdraw_fee(
        who: &H160,
        fee: U256,
    ) -> Result<Self::LiquidityInfo, pallet_evm::Error<Runtime>> {
        InnerEVMCurrencyAdapter::withdraw_fee(who, fee)
    }

    fn correct_and_deposit_fee(
        who: &H160,
        corrected_fee: U256,
        base_fee: U256,
        already_withdrawn: Self::LiquidityInfo,
    ) -> Self::LiquidityInfo {
        if already_withdrawn.is_some() {
            // Record the evm actual transaction fee
            OperatorRewards::note_operator_rewards(corrected_fee.as_u128());
        }

        <InnerEVMCurrencyAdapter as pallet_evm::OnChargeEVMTransaction<
            Runtime,
        >>::correct_and_deposit_fee(who, corrected_fee, base_fee, already_withdrawn)
    }

    fn pay_priority_fee(tip: Self::LiquidityInfo) {
        <InnerEVMCurrencyAdapter as pallet_evm::OnChargeEVMTransaction<Runtime>>::pay_priority_fee(
            tip,
        );
    }
}

impl pallet_evm::Config for Runtime {
    type FeeCalculator = BaseFee;
    type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
    type WeightPerGas = WeightPerGas;
    type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Self>;
    type CallOrigin = EnsureAddressRoot<AccountId>;
    type WithdrawOrigin = EnsureAddressNever<AccountId>;
    type AddressMapping = IdentityAddressMapping;
    type Currency = Balances;
    type RuntimeEvent = RuntimeEvent;
    type PrecompilesType = Precompiles;
    type PrecompilesValue = PrecompilesValue;
    type ChainId = EVMChainId;
    type BlockGasLimit = BlockGasLimit;
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type OnChargeTransaction = EVMCurrencyAdapter;
    type OnCreate = ();
    type FindAuthor = FindAuthorTruncated;
    type GasLimitPovSizeRatio = ();
    type Timestamp = Timestamp;
    type WeightInfo = pallet_evm::weights::SubstrateWeight<Self>;
}

parameter_types! {
    pub const PostOnlyBlockHash: PostLogContent = PostLogContent::OnlyBlockHash;
}

impl pallet_ethereum::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type StateRoot = pallet_ethereum::IntermediateStateRoot<Self>;
    type PostLogContent = PostOnlyBlockHash;
    type ExtraDataLength = ConstU32<30>;
}

parameter_types! {
    pub BoundDivision: U256 = U256::from(1024);
}

parameter_types! {
    pub DefaultBaseFeePerGas: U256 = U256::from(1_000_000_000);
    // mark it to 5% increments on beyond target weight.
    pub DefaultElasticity: Permill = Permill::from_parts(50_000);
}

pub struct BaseFeeThreshold;

impl pallet_base_fee::BaseFeeThreshold for BaseFeeThreshold {
    fn lower() -> Permill {
        Permill::zero()
    }
    fn ideal() -> Permill {
        Permill::from_parts(500_000)
    }
    fn upper() -> Permill {
        Permill::from_parts(1_000_000)
    }
}

impl pallet_base_fee::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Threshold = BaseFeeThreshold;
    type DefaultBaseFeePerGas = DefaultBaseFeePerGas;
    type DefaultElasticity = DefaultElasticity;
}

impl pallet_domain_id::Config for Runtime {}

// Create the runtime by composing the FRAME pallets that were previously configured.
//
// NOTE: Currently domain runtime does not naturally support the pallets with inherent extrinsics.
construct_runtime!(
    pub struct Runtime {
        // System support stuff.
        System: frame_system = 0,
        // Note: Ensure index of the timestamp matches with the index of timestamp on Consensus
        //  so that consensus can constructed encoded extrinsic that matches with Domain encoded
        //  extrinsic.
        Timestamp: pallet_timestamp = 1,
        ExecutivePallet: domain_pallet_executive = 2,

        // monetary stuff
        Balances: pallet_balances = 20,
        TransactionPayment: pallet_transaction_payment = 21,

        // messenger stuff
        // Note: Indexes should match with indexes on other chains and domains
        Messenger: pallet_messenger = 60,
        Transporter: pallet_transporter = 61,

        // evm stuff
        Ethereum: pallet_ethereum = 80,
        EVM: pallet_evm = 81,
        EVMChainId: pallet_evm_chain_id = 82,
        BaseFee: pallet_base_fee = 83,

        // domain instance stuff
        SelfDomainId: pallet_domain_id = 90,
        OperatorRewards: pallet_operator_rewards = 91,

        // Sudo account
        Sudo: pallet_sudo = 100,
    }
);

#[derive(Clone, Default)]
pub struct TransactionConverter;

impl fp_rpc::ConvertTransaction<UncheckedExtrinsic> for TransactionConverter {
    fn convert_transaction(&self, transaction: pallet_ethereum::Transaction) -> UncheckedExtrinsic {
        UncheckedExtrinsic::new_unsigned(
            pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
        )
    }
}

impl fp_rpc::ConvertTransaction<opaque::UncheckedExtrinsic> for TransactionConverter {
    fn convert_transaction(
        &self,
        transaction: pallet_ethereum::Transaction,
    ) -> opaque::UncheckedExtrinsic {
        let extrinsic = UncheckedExtrinsic::new_unsigned(
            pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
        );
        let encoded = extrinsic.encode();
        opaque::UncheckedExtrinsic::decode(&mut &encoded[..])
            .expect("Encoded extrinsic is always valid")
    }
}

fn extract_xdm_proof_state_roots(
    encoded_ext: Vec<u8>,
) -> Option<ExtractedStateRootsFromProof<BlockNumber, Hash, Hash>> {
    if let Ok(ext) = UncheckedExtrinsic::decode(&mut encoded_ext.as_slice()) {
        match &ext.0.function {
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

fn extract_signer_inner<Lookup>(
    ext: &UncheckedExtrinsic,
    lookup: &Lookup,
) -> Option<Result<AccountId, TransactionValidityError>>
where
    Lookup: sp_runtime::traits::Lookup<Source = Address, Target = AccountId>,
{
    if ext.0.function.is_self_contained() {
        ext.0
            .function
            .check_self_contained()
            .map(|signed_info| signed_info.map(|signer| signer.into()))
    } else {
        ext.0
            .signature
            .as_ref()
            .map(|(signed, _, _)| lookup.lookup(*signed).map_err(|e| e.into()))
    }
}

pub fn extract_signer(
    extrinsics: Vec<UncheckedExtrinsic>,
) -> Vec<(Option<opaque::AccountId>, UncheckedExtrinsic)> {
    let lookup = frame_system::ChainContext::<Runtime>::default();

    extrinsics
        .into_iter()
        .map(|extrinsic| {
            let maybe_signer =
                extract_signer_inner(&extrinsic, &lookup).and_then(|account_result| {
                    account_result.ok().map(|account_id| account_id.encode())
                });
            (maybe_signer, extrinsic)
        })
        .collect()
}

fn storage_keys_for_verifying_tx_validity_inner(
    sender: AccountId,
    block_number: BlockNumber,
    maybe_tx_era: Option<Era>,
) -> Vec<Vec<u8>> {
    let mut storage_keys = sp_std::vec![
        frame_system::BlockHash::<Runtime>::hashed_key_for(BlockNumber::from(0u32)),
        frame_support::storage::storage_prefix(System::name().as_bytes(), b"Number").to_vec(),
        frame_system::Account::<Runtime>::hashed_key_for(sender),
        pallet_transaction_payment::NextFeeMultiplier::<Runtime>::hashed_key().to_vec()
    ];

    match maybe_tx_era {
        None => storage_keys,
        Some(era) => {
            let birth_number = era
                .birth(block_number.saturated_into::<u64>())
                .saturated_into::<BlockNumber>();
            storage_keys.push(frame_system::BlockHash::<Runtime>::hashed_key_for(
                birth_number,
            ));
            storage_keys
        }
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benches {
    frame_benchmarking::define_benchmarks!(
        [frame_benchmarking, BaselineBench::<Runtime>]
        [frame_system, SystemBench::<Runtime>]
        [domain_pallet_executive, ExecutivePallet]
    );
}

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

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
        fn account_nonce(account: AccountId) -> Nonce {
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
            extract_signer(extrinsics)
        }

        fn is_within_tx_range(
            extrinsic: &<Block as BlockT>::Extrinsic,
            bundle_vrf_hash: &subspace_core_primitives::U256,
            tx_range: &subspace_core_primitives::U256
        ) -> bool {
            use subspace_core_primitives::U256;
            use subspace_core_primitives::crypto::blake3_hash;

            let lookup = frame_system::ChainContext::<Runtime>::default();
            if let Some(signer) = extract_signer_inner(extrinsic, &lookup).and_then(|account_result| {
                    account_result.ok().map(|account_id| account_id.encode())
                }) {
                // Check if the signer Id hash is within the tx range
                let signer_id_hash = U256::from_be_bytes(blake3_hash(&signer.encode()));
                sp_domains::signer_in_tx_range(bundle_vrf_hash, &signer_id_hash, tx_range)
            } else {
                // Unsigned transactions are always in the range.
                true
            }
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
            UncheckedExtrinsic::new_unsigned(
                domain_pallet_executive::Call::set_code {
                    code
                }.into()
            ).encode()
        }

        fn construct_timestamp_extrinsic(moment: Moment) -> <Block as BlockT>::Extrinsic {
            UncheckedExtrinsic::new_unsigned(
                pallet_timestamp::Call::set{ now: moment }.into()
            )
        }

        fn is_inherent_extrinsic(extrinsic: &<Block as BlockT>::Extrinsic) -> bool {
            match &extrinsic.0.function {
                RuntimeCall::Timestamp(call) => Timestamp::is_inherent(call),
                RuntimeCall::ExecutivePallet(call) => ExecutivePallet::is_inherent(call),
                _ => false,
            }
        }

        fn check_transaction_validity(
            uxt: &<Block as BlockT>::Extrinsic,
            block_number: BlockNumber,
            block_hash: <Block as BlockT>::Hash
        ) -> Result<(), domain_runtime_primitives::CheckTxValidityError> {
            let lookup = frame_system::ChainContext::<Runtime>::default();
            let maybe_signer_info = extract_signer_inner(uxt, &lookup);

            if let Some(signer_info) = maybe_signer_info {
                let signer = signer_info.map_err(|tx_validity_error| {
                    domain_runtime_primitives::CheckTxValidityError::UnableToExtractSigner {
                        error: tx_validity_error
                    }
                })?;

                let tx_validity =
                    Executive::validate_transaction(TransactionSource::External, uxt.clone(), block_hash);

                tx_validity.map(|_| ()).map_err(|tx_validity_error| {
                    domain_runtime_primitives::CheckTxValidityError::InvalidTransaction {
                        error: tx_validity_error,
                        storage_keys: storage_keys_for_verifying_tx_validity_inner(signer, block_number, Self::extrinsic_era(uxt)),
                    }
                })
            } else {
                Ok(())
            }
        }

        fn storage_keys_for_verifying_transaction_validity(
            who: opaque::AccountId,
            block_number: BlockNumber,
            maybe_tx_era: Option<Era>
        ) -> Result<Vec<Vec<u8>>, domain_runtime_primitives::VerifyTxValidityError> {
            let sender = AccountId::decode(&mut who.as_slice())
                .map_err(|_| domain_runtime_primitives::VerifyTxValidityError::FailedToDecodeAccountId)?;
            Ok(storage_keys_for_verifying_tx_validity_inner(sender, block_number, maybe_tx_era))
        }

        fn extrinsic_era(
          extrinsic: &<Block as BlockT>::Extrinsic
        ) -> Option<Era> {
            extrinsic.0.signature.as_ref().map(|(_, _, extra)| extra.4.0)
        }

        fn extrinsic_weight(ext: &<Block as BlockT>::Extrinsic) -> Weight {
            ext.get_dispatch_info().weight
        }

        fn block_rewards() -> Balance {
            OperatorRewards::block_rewards()
        }

        fn block_digest() -> Digest {
            System::digest()
        }
    }

    impl sp_messenger::MessengerApi<Block, BlockNumber> for Runtime {
        fn extract_xdm_proof_state_roots(
            extrinsic: Vec<u8>,
        ) -> Option<ExtractedStateRootsFromProof<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>> {
            extract_xdm_proof_state_roots(extrinsic)
        }

        fn is_domain_info_confirmed(
            _domain_id: DomainId,
            _domain_block_info: BlockInfo<BlockNumber, <Block as BlockT>::Hash>,
            _domain_state_root: <Block as BlockT>::Hash,
        ) -> bool{
            // not valid on evm domain
            false
        }
    }

    impl sp_messenger::RelayerApi<Block, BlockNumber> for Runtime {
        fn chain_id() -> ChainId {
            SelfChainId::get()
        }

        fn relay_confirmation_depth() -> BlockNumber {
            RelayConfirmationDepth::get()
        }

        fn block_messages() -> BlockMessagesWithStorageKey {
            Messenger::get_block_messages()
        }

        fn outbox_message_unsigned(msg: CrossDomainMessage<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::outbox_message_unsigned(msg)
        }

        fn inbox_response_message_unsigned(msg: CrossDomainMessage<BlockNumber, <Block as BlockT>::Hash, <Block as BlockT>::Hash>) -> Option<<Block as BlockT>::Extrinsic> {
            Messenger::inbox_response_message_unsigned(msg)
        }

        fn should_relay_outbox_message(dst_chain_id: ChainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_outbox_message(dst_chain_id, msg_id)
        }

        fn should_relay_inbox_message_response(dst_chain_id: ChainId, msg_id: MessageId) -> bool {
            Messenger::should_relay_inbox_message_response(dst_chain_id, msg_id)
        }
    }

    impl fp_rpc::EthereumRuntimeRPCApi<Block> for Runtime {
        fn chain_id() -> u64 {
            <Runtime as pallet_evm::Config>::ChainId::get()
        }

        fn account_basic(address: H160) -> EVMAccount {
            let (account, _) = EVM::account_basic(&address);
            account
        }

        fn gas_price() -> U256 {
            let (gas_price, _) = <Runtime as pallet_evm::Config>::FeeCalculator::min_gas_price();
            gas_price
        }

        fn account_code_at(address: H160) -> Vec<u8> {
            pallet_evm::AccountCodes::<Runtime>::get(address)
        }

        fn author() -> H160 {
            <pallet_evm::Pallet<Runtime>>::find_author()
        }

        fn storage_at(address: H160, index: U256) -> H256 {
            let mut tmp = [0u8; 32];
            index.to_big_endian(&mut tmp);
            pallet_evm::AccountStorages::<Runtime>::get(address, H256::from_slice(&tmp[..]))
        }

        fn call(
            from: H160,
            to: H160,
            data: Vec<u8>,
            value: U256,
            gas_limit: U256,
            max_fee_per_gas: Option<U256>,
            max_priority_fee_per_gas: Option<U256>,
            nonce: Option<U256>,
            estimate: bool,
            access_list: Option<Vec<(H160, Vec<H256>)>>,
        ) -> Result<pallet_evm::CallInfo, sp_runtime::DispatchError> {
            let config = if estimate {
                let mut config = <Runtime as pallet_evm::Config>::config().clone();
                config.estimate = true;
                Some(config)
            } else {
                None
            };

            let is_transactional = false;
            let validate = true;
            let weight_limit = None;
            let proof_size_base_cost = None;
            let evm_config = config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config());
            <Runtime as pallet_evm::Config>::Runner::call(
                from,
                to,
                data,
                value,
                gas_limit.unique_saturated_into(),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                access_list.unwrap_or_default(),
                is_transactional,
                validate,
                weight_limit,
                proof_size_base_cost,
                evm_config,
            ).map_err(|err| err.error.into())
        }

        fn create(
            from: H160,
            data: Vec<u8>,
            value: U256,
            gas_limit: U256,
            max_fee_per_gas: Option<U256>,
            max_priority_fee_per_gas: Option<U256>,
            nonce: Option<U256>,
            estimate: bool,
            access_list: Option<Vec<(H160, Vec<H256>)>>,
        ) -> Result<pallet_evm::CreateInfo, sp_runtime::DispatchError> {
            let config = if estimate {
                let mut config = <Runtime as pallet_evm::Config>::config().clone();
                config.estimate = true;
                Some(config)
            } else {
                None
            };

            let is_transactional = false;
            let validate = true;
            let weight_limit = None;
            let proof_size_base_cost = None;
            let evm_config = config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config());
            <Runtime as pallet_evm::Config>::Runner::create(
                from,
                data,
                value,
                gas_limit.unique_saturated_into(),
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                access_list.unwrap_or_default(),
                is_transactional,
                validate,
                weight_limit,
                proof_size_base_cost,
                evm_config,
            ).map_err(|err| err.error.into())
        }

        fn current_transaction_statuses() -> Option<Vec<TransactionStatus>> {
            pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
        }

        fn current_block() -> Option<pallet_ethereum::Block> {
            pallet_ethereum::CurrentBlock::<Runtime>::get()
        }

        fn current_receipts() -> Option<Vec<pallet_ethereum::Receipt>> {
            pallet_ethereum::CurrentReceipts::<Runtime>::get()
        }

        fn current_all() -> (
            Option<pallet_ethereum::Block>,
            Option<Vec<pallet_ethereum::Receipt>>,
            Option<Vec<TransactionStatus>>
        ) {
            (
                pallet_ethereum::CurrentBlock::<Runtime>::get(),
                pallet_ethereum::CurrentReceipts::<Runtime>::get(),
                pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
            )
        }

        fn extrinsic_filter(
            xts: Vec<<Block as BlockT>::Extrinsic>,
        ) -> Vec<EthereumTransaction> {
            xts.into_iter().filter_map(|xt| match xt.0.function {
                RuntimeCall::Ethereum(transact { transaction }) => Some(transaction),
                _ => None
            }).collect::<Vec<EthereumTransaction>>()
        }

        fn elasticity() -> Option<Permill> {
            Some(pallet_base_fee::Elasticity::<Runtime>::get())
        }

        fn gas_limit_multiplier_support() {}

        fn pending_block(
            xts: Vec<<Block as BlockT>::Extrinsic>,
        ) -> (Option<pallet_ethereum::Block>, Option<Vec<TransactionStatus>>) {
            for ext in xts.into_iter() {
                let _ = Executive::apply_extrinsic(ext);
            }

            Ethereum::on_finalize(System::block_number() + 1);

            (
                pallet_ethereum::CurrentBlock::<Runtime>::get(),
                pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
            )
        }
    }

    impl fp_rpc::ConvertTransactionRuntimeApi<Block> for Runtime {
        fn convert_transaction(transaction: EthereumTransaction) -> <Block as BlockT>::Extrinsic {
            UncheckedExtrinsic::new_unsigned(
                pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
            )
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    impl frame_benchmarking::Benchmark<Block> for Runtime {
        fn benchmark_metadata(extra: bool) -> (
            Vec<frame_benchmarking::BenchmarkList>,
            Vec<frame_support::traits::StorageInfo>,
        ) {
            use frame_benchmarking::{baseline, Benchmarking, BenchmarkList};
            use frame_support::traits::StorageInfoTrait;
            use frame_system_benchmarking::Pallet as SystemBench;
            use baseline::Pallet as BaselineBench;

            let mut list = Vec::<BenchmarkList>::new();

            list_benchmarks!(list, extra);

            let storage_info = AllPalletsWithSystem::storage_info();

            (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, sp_runtime::RuntimeString> {
            use frame_benchmarking::{baseline, Benchmarking, BenchmarkBatch};
            use sp_storage::TrackedStorageKey;
            use frame_system_benchmarking::Pallet as SystemBench;
            use frame_support::traits::WhitelistedStorageKeys;
            use baseline::Pallet as BaselineBench;

            impl frame_system_benchmarking::Config for Runtime {}
            impl baseline::Config for Runtime {}

            let whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);

            add_benchmarks!(params, batches);

            if batches.is_empty() { return Err("Benchmark not found for this pallet.".into()) }
            Ok(batches)
        }
    }
}
