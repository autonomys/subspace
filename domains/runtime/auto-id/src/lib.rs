#![feature(variant_count)]
#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

mod weights;

use alloc::borrow::Cow;
#[cfg(not(feature = "std"))]
use alloc::format;
use core::mem;
use domain_runtime_primitives::opaque::Header;
use domain_runtime_primitives::{
    AccountId, Address, CheckExtrinsicsValidityError, DecodeExtrinsicError, ERR_BALANCE_OVERFLOW,
    HoldIdentifier, SLOT_DURATION, Signature, TargetBlockFullness,
};
pub use domain_runtime_primitives::{
    Balance, BlockNumber, EXISTENTIAL_DEPOSIT, Hash, MAX_OUTGOING_MESSAGES, Nonce, block_weights,
    maximum_block_length, opaque,
};
use frame_support::dispatch::{DispatchClass, DispatchInfo, GetDispatchInfo};
use frame_support::genesis_builder_helper::{build_state, get_preset};
use frame_support::pallet_prelude::TypeInfo;
use frame_support::traits::fungible::Credit;
use frame_support::traits::{
    ConstU16, ConstU32, ConstU64, Everything, Imbalance, IsInherent, OnUnbalanced, VariantCount,
};
use frame_support::weights::constants::ParityDbWeight;
use frame_support::weights::{ConstantMultiplier, Weight};
use frame_support::{construct_runtime, parameter_types};
use frame_system::limits::{BlockLength, BlockWeights};
use pallet_block_fees::fees::OnChargeDomainTransaction;
use pallet_transporter::EndpointHandler;
use parity_scale_codec::{Decode, DecodeLimit, Encode, MaxEncodedLen};
use sp_api::impl_runtime_apis;
use sp_core::crypto::KeyTypeId;
use sp_core::{Get, OpaqueMetadata};
use sp_domains::{ChannelId, DomainAllowlistUpdates, DomainId, Transfers};
use sp_messenger::endpoint::{Endpoint, EndpointHandler as EndpointHandlerT, EndpointId};
use sp_messenger::messages::{
    BlockMessagesQuery, BlockMessagesWithStorageKey, ChainId, ChannelStateWithNonce,
    CrossDomainMessage, MessageId, MessageKey, MessagesWithStorageKey, Nonce as XdmNonce,
};
use sp_messenger::{ChannelNonce, XdmId};
use sp_messenger_host_functions::{StorageKeyRequest, get_storage_key};
use sp_mmr_primitives::EncodableOpaqueLeaf;
use sp_runtime::generic::{Era, ExtrinsicFormat, Preamble};
use sp_runtime::traits::{
    AccountIdLookup, BlakeTwo256, Checkable, DispatchTransaction, Keccak256, NumberFor, One,
    TransactionExtension, ValidateUnsigned, Zero,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError,
};
use sp_runtime::type_with_default::TypeWithDefault;
use sp_runtime::{ApplyExtrinsicResult, Digest, ExtrinsicInclusionMode, generic, impl_opaque_keys};
pub use sp_runtime::{MultiAddress, Perbill, Permill};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::marker::PhantomData;
use sp_std::prelude::*;
use sp_subspace_mmr::domain_mmr_runtime_interface::{
    is_consensus_block_finalized, verify_mmr_proof,
};
use sp_subspace_mmr::{ConsensusChainMmrLeafProof, MmrLeaf};
use sp_version::RuntimeVersion;
use static_assertions::const_assert;
use subspace_runtime_primitives::utility::DefaultNonceProvider;
use subspace_runtime_primitives::{
    AI3, BlockHashFor, BlockNumber as ConsensusBlockNumber, DomainEventSegmentSize, ExtrinsicFor,
    Hash as ConsensusBlockHash, HeaderFor, MAX_CALL_RECURSION_DEPTH, Moment, SHANNON,
    SlowAdjustingFeeUpdate, XdmAdjustedWeightToFee, XdmFeeMultipler,
};

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
    domain_check_weight::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    pallet_messenger::extensions::MessengerExtension<Runtime>,
);

/// The Custom SignedExtension used for pre_dispatch checks for bundle extrinsic verification
pub type CustomSignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckMortality<Runtime>,
    frame_system::CheckNonce<Runtime>,
    domain_check_weight::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    pallet_messenger::extensions::MessengerTrustedMmrExtension<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra>;

/// Executive: handles dispatch to the various modules.
pub type Executive = domain_pallet_executive::Executive<
    Runtime,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

impl_opaque_keys! {
    pub struct SessionKeys {
        /// Primarily used for adding the operator signing key into the Keystore.
        pub operator: sp_domains::OperatorKey,
    }
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: Cow::Borrowed("subspace-auto-id-domain"),
    impl_name: Cow::Borrowed("subspace-auto-id-domain"),
    authoring_version: 0,
    // The spec version can be different on Taurus and Mainnet
    spec_version: 0,
    impl_version: 0,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 0,
    system_version: 2,
};

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub const BlockHashCount: BlockNumber = 2400;
    pub RuntimeBlockLength: BlockLength = maximum_block_length();
    pub RuntimeBlockWeights: BlockWeights = block_weights();
}

impl frame_system::Config for Runtime {
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The aggregated dispatch type that is available for extrinsics.
    type RuntimeCall = RuntimeCall;
    /// The aggregated `RuntimeTask` type.
    type RuntimeTask = RuntimeTask;
    /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
    type Lookup = AccountIdLookup<AccountId, ()>;
    /// The type for storing how many extrinsics an account has signed.
    type Nonce = TypeWithDefault<Nonce, DefaultNonceProvider<System, Nonce>>;
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
    type SystemWeightInfo = weights::frame_system::WeightInfo<Runtime>;
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = RuntimeBlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = RuntimeBlockLength;
    type SS58Prefix = ConstU16<6094>;
    /// The action to take on a Runtime Upgrade
    type OnSetCode = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
    type MaxConsumers = ConstU32<16>;
    type ExtensionsWeightInfo = frame_system::ExtensionsWeight<Runtime>;
    type EventSegmentSize = DomainEventSegmentSize;
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = weights::pallet_timestamp::WeightInfo<Runtime>;
}

parameter_types! {
    pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT;
    pub const MaxLocks: u32 = 50;
    pub const MaxReserves: u32 = 50;
}

/// `DustRemovalHandler` used to collect all the AI3 dust left when the account is reaped.
pub struct DustRemovalHandler;

impl OnUnbalanced<Credit<AccountId, Balances>> for DustRemovalHandler {
    fn on_nonzero_unbalanced(dusted_amount: Credit<AccountId, Balances>) {
        BlockFees::note_burned_balance(dusted_amount.peek());
    }
}

impl pallet_balances::Config for Runtime {
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type MaxLocks = MaxLocks;
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = DustRemovalHandler;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = weights::pallet_balances::WeightInfo<Runtime>;
    type MaxReserves = MaxReserves;
    type ReserveIdentifier = [u8; 8];
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = HoldIdentifierWrapper;
    type DoneSlashHandler = ();
}

parameter_types! {
    pub const OperationalFeeMultiplier: u8 = 5;
    pub const DomainChainByteFee: Balance = 1;
    pub TransactionWeightFee: Balance = 100_000 * SHANNON;
}

impl pallet_block_fees::Config for Runtime {
    type Balance = Balance;
    type DomainChainByteFee = DomainChainByteFee;
}

pub struct FinalDomainTransactionByteFee;

impl Get<Balance> for FinalDomainTransactionByteFee {
    fn get() -> Balance {
        BlockFees::final_domain_transaction_byte_fee()
    }
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = OnChargeDomainTransaction<Balances>;
    type WeightToFee = ConstantMultiplier<Balance, TransactionWeightFee>;
    type LengthToFee = ConstantMultiplier<Balance, FinalDomainTransactionByteFee>;
    type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Runtime, TargetBlockFullness>;
    type OperationalFeeMultiplier = OperationalFeeMultiplier;
    type WeightInfo = weights::pallet_transaction_payment::WeightInfo<Runtime>;
}

impl pallet_auto_id::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Time = Timestamp;
    type Weights = weights::pallet_auto_id::WeightInfo<Runtime>;
}

pub struct ExtrinsicStorageFees;

impl domain_pallet_executive::ExtrinsicStorageFees<Runtime> for ExtrinsicStorageFees {
    fn extract_signer(xt: UncheckedExtrinsic) -> (Option<AccountId>, DispatchInfo) {
        let dispatch_info = xt.get_dispatch_info();
        let lookup = frame_system::ChainContext::<Runtime>::default();
        let maybe_signer = extract_signer_inner(&xt, &lookup).and_then(|res| res.ok());
        (maybe_signer, dispatch_info)
    }

    fn on_storage_fees_charged(
        charged_fees: Balance,
        tx_size: u32,
    ) -> Result<(), TransactionValidityError> {
        let consensus_storage_fee = BlockFees::consensus_chain_byte_fee()
            .checked_mul(Balance::from(tx_size))
            .ok_or(InvalidTransaction::Custom(ERR_BALANCE_OVERFLOW))?;

        let (paid_consensus_storage_fee, paid_domain_fee) = if charged_fees <= consensus_storage_fee
        {
            (charged_fees, Zero::zero())
        } else {
            (consensus_storage_fee, charged_fees - consensus_storage_fee)
        };

        BlockFees::note_consensus_storage_fee(paid_consensus_storage_fee);
        BlockFees::note_domain_execution_fee(paid_domain_fee);
        Ok(())
    }
}

impl domain_pallet_executive::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = weights::domain_pallet_executive::WeightInfo<Runtime>;
    type Currency = Balances;
    type LengthToFee = <Runtime as pallet_transaction_payment::Config>::LengthToFee;
    type ExtrinsicStorageFees = ExtrinsicStorageFees;
}

parameter_types! {
    pub SelfChainId: ChainId = SelfDomainId::self_domain_id().into();
}

pub struct OnXDMRewards;

impl sp_messenger::OnXDMRewards<Balance> for OnXDMRewards {
    fn on_xdm_rewards(rewards: Balance) {
        BlockFees::note_domain_execution_fee(rewards)
    }
    fn on_chain_protocol_fees(chain_id: ChainId, fees: Balance) {
        // note the chain rewards
        BlockFees::note_chain_rewards(chain_id, fees);
    }
}

type MmrHash = <Keccak256 as sp_runtime::traits::Hash>::Output;

pub struct MmrProofVerifier;

impl sp_subspace_mmr::MmrProofVerifier<MmrHash, NumberFor<Block>, Hash> for MmrProofVerifier {
    fn verify_proof_and_extract_leaf(
        mmr_leaf_proof: ConsensusChainMmrLeafProof<NumberFor<Block>, Hash, MmrHash>,
    ) -> Option<MmrLeaf<ConsensusBlockNumber, ConsensusBlockHash>> {
        let ConsensusChainMmrLeafProof {
            consensus_block_number,
            opaque_mmr_leaf: opaque_leaf,
            proof,
            ..
        } = mmr_leaf_proof;

        if !is_consensus_block_finalized(consensus_block_number) {
            return None;
        }

        let leaf: MmrLeaf<ConsensusBlockNumber, ConsensusBlockHash> =
            opaque_leaf.into_opaque_leaf().try_decode()?;

        verify_mmr_proof(vec![EncodableOpaqueLeaf::from_leaf(&leaf)], proof.encode())
            .then_some(leaf)
    }
}

pub struct StorageKeys;

impl sp_messenger::StorageKeys for StorageKeys {
    fn confirmed_domain_block_storage_key(domain_id: DomainId) -> Option<Vec<u8>> {
        get_storage_key(StorageKeyRequest::ConfirmedDomainBlockStorageKey(domain_id))
    }

    fn outbox_storage_key(chain_id: ChainId, message_key: MessageKey) -> Option<Vec<u8>> {
        get_storage_key(StorageKeyRequest::OutboxStorageKey {
            chain_id,
            message_key,
        })
    }

    fn inbox_responses_storage_key(chain_id: ChainId, message_key: MessageKey) -> Option<Vec<u8>> {
        get_storage_key(StorageKeyRequest::InboxResponseStorageKey {
            chain_id,
            message_key,
        })
    }
}

/// Hold identifier for balances for this runtime.
#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub struct HoldIdentifierWrapper(HoldIdentifier);

impl VariantCount for HoldIdentifierWrapper {
    const VARIANT_COUNT: u32 = mem::variant_count::<HoldIdentifier>() as u32;
}

impl pallet_messenger::HoldIdentifier<Runtime> for HoldIdentifierWrapper {
    fn messenger_channel() -> Self {
        Self(HoldIdentifier::MessengerChannel)
    }
}

parameter_types! {
    pub const ChannelReserveFee: Balance = 100 * AI3;
    pub const ChannelInitReservePortion: Perbill = Perbill::from_percent(20);
    pub const MaxOutgoingMessages: u32 = MAX_OUTGOING_MESSAGES;
}

// ensure the max outgoing messages is not 0.
const_assert!(MaxOutgoingMessages::get() >= 1);

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
    type WeightInfo = weights::pallet_messenger::WeightInfo<Runtime>;
    type WeightToFee = ConstantMultiplier<Balance, TransactionWeightFee>;
    type AdjustedWeightToFee = XdmAdjustedWeightToFee<Runtime>;
    type FeeMultiplier = XdmFeeMultipler;
    type OnXDMRewards = OnXDMRewards;
    type MmrHash = MmrHash;
    type MmrProofVerifier = MmrProofVerifier;
    #[cfg(feature = "runtime-benchmarks")]
    type StorageKeys = sp_messenger::BenchmarkStorageKeys;
    #[cfg(not(feature = "runtime-benchmarks"))]
    type StorageKeys = StorageKeys;
    type DomainOwner = ();
    type HoldIdentifier = HoldIdentifierWrapper;
    type ChannelReserveFee = ChannelReserveFee;
    type ChannelInitReservePortion = ChannelInitReservePortion;
    type DomainRegistration = ();
    type MaxOutgoingMessages = MaxOutgoingMessages;
    type MessengerOrigin = pallet_messenger::EnsureMessengerOrigin;
    type NoteChainTransfer = Transporter;
    type ExtensionWeightInfo = pallet_messenger::extensions::weights::SubstrateWeight<
        Runtime,
        weights::pallet_messenger_from_consensus_extension::WeightInfo<Runtime>,
        weights::pallet_messenger_between_domains_extension::WeightInfo<Runtime>,
    >;
}

impl<C> frame_system::offchain::CreateTransactionBase<C> for Runtime
where
    RuntimeCall: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type RuntimeCall = RuntimeCall;
}

parameter_types! {
    pub const TransporterEndpointId: EndpointId = 1;
    pub const MinimumTransfer: Balance = AI3;
}

impl pallet_transporter::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;
    type SelfEndpointId = TransporterEndpointId;
    type Currency = Balances;
    type Sender = Messenger;
    type AccountIdConverter = domain_runtime_primitives::AccountIdConverter;
    type WeightInfo = weights::pallet_transporter::WeightInfo<Runtime>;
    type SkipBalanceTransferChecks = ();
    type MinimumTransfer = MinimumTransfer;
}

impl pallet_domain_id::Config for Runtime {}

pub struct IntoRuntimeCall;

impl sp_domain_sudo::IntoRuntimeCall<RuntimeCall> for IntoRuntimeCall {
    fn runtime_call(call: Vec<u8>) -> RuntimeCall {
        UncheckedExtrinsic::decode(&mut call.as_slice())
            .expect("must always be a valid extrinsic as checked by consensus chain; qed")
            .function
    }
}

impl pallet_domain_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type IntoRuntimeCall = IntoRuntimeCall;
}

impl pallet_utility::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type PalletsOrigin = OriginCaller;
    type WeightInfo = weights::pallet_utility::WeightInfo<Runtime>;
}

// Create the runtime by composing the FRAME pallets that were previously configured.
//
// NOTE: Currently domain runtime does not naturally support the pallets with inherent extrinsics.
construct_runtime!(
    pub struct Runtime {
        // System support stuff.
        System: frame_system = 0,
        // Note: Ensure index of the timestamp matches with the index of timestamp on Consensus
        //  so that consensus can construct encoded extrinsic that matches with Domain encoded
        //  extrinsic.
        Timestamp: pallet_timestamp = 1,
        ExecutivePallet: domain_pallet_executive = 2,
        Utility: pallet_utility = 8,

        // monetary stuff
        Balances: pallet_balances = 20,
        TransactionPayment: pallet_transaction_payment = 21,

        // AutoId
        AutoId: pallet_auto_id = 40,

        // messenger stuff
        // Note: Indexes should match with indexes on other chains and domains
        Messenger: pallet_messenger = 60,
        Transporter: pallet_transporter = 61,

        // domain instance stuff
        SelfDomainId: pallet_domain_id = 90,
        BlockFees: pallet_block_fees = 91,

        // Sudo account
        Sudo: pallet_domain_sudo = 100,
    }
);

impl pallet_messenger::extensions::MaybeMessengerCall<Runtime> for RuntimeCall {
    fn maybe_messenger_call(&self) -> Option<&pallet_messenger::Call<Runtime>> {
        match self {
            RuntimeCall::Messenger(call) => Some(call),
            _ => None,
        }
    }
}

impl<C> subspace_runtime_primitives::CreateUnsigned<C> for Runtime
where
    RuntimeCall: From<C>,
{
    fn create_unsigned(call: Self::RuntimeCall) -> Self::Extrinsic {
        create_unsigned_general_extrinsic(call)
    }
}

fn create_unsigned_general_extrinsic(call: RuntimeCall) -> UncheckedExtrinsic {
    let extra: SignedExtra = (
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckMortality::<Runtime>::from(generic::Era::Immortal),
        // for unsigned extrinsic, nonce check will be skipped
        // so set a default value
        frame_system::CheckNonce::<Runtime>::from(0u32.into()),
        domain_check_weight::CheckWeight::<Runtime>::new(),
        // for unsigned extrinsic, transaction fee check will be skipped
        // so set a default value
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0u128),
        pallet_messenger::extensions::MessengerExtension::<Runtime>::new(),
    );

    UncheckedExtrinsic::new_transaction(call, extra)
}

fn is_xdm_mmr_proof_valid(ext: &ExtrinsicFor<Block>) -> Option<bool> {
    match &ext.function {
        RuntimeCall::Messenger(pallet_messenger::Call::relay_message { msg })
        | RuntimeCall::Messenger(pallet_messenger::Call::relay_message_response { msg }) => {
            let ConsensusChainMmrLeafProof {
                consensus_block_number,
                opaque_mmr_leaf,
                proof,
                ..
            } = msg.proof.consensus_mmr_proof();

            if !is_consensus_block_finalized(consensus_block_number) {
                return Some(false);
            }

            Some(verify_mmr_proof(vec![opaque_mmr_leaf], proof.encode()))
        }
        _ => None,
    }
}

/// Returns `true` if this is a validly encoded Sudo call.
fn is_valid_sudo_call(encoded_ext: Vec<u8>) -> bool {
    UncheckedExtrinsic::decode_with_depth_limit(
        MAX_CALL_RECURSION_DEPTH,
        &mut encoded_ext.as_slice(),
    )
    .is_ok()
}

fn construct_sudo_call_extrinsic(encoded_ext: Vec<u8>) -> ExtrinsicFor<Block> {
    let ext = UncheckedExtrinsic::decode(&mut encoded_ext.as_slice()).expect(
        "must always be a valid extrinsic due to the check above and storage proof check; qed",
    );
    UncheckedExtrinsic::new_bare(
        pallet_domain_sudo::Call::sudo {
            call: Box::new(ext.function),
        }
        .into(),
    )
}

fn extract_signer_inner<Lookup>(
    ext: &UncheckedExtrinsic,
    lookup: &Lookup,
) -> Option<Result<AccountId, TransactionValidityError>>
where
    Lookup: sp_runtime::traits::Lookup<Source = Address, Target = AccountId>,
{
    match &ext.preamble {
        Preamble::Bare(_) | Preamble::General(_, _) => None,
        Preamble::Signed(signed, _, _) => Some(lookup.lookup(signed.clone()).map_err(|e| e.into())),
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

fn extrinsic_era(extrinsic: &ExtrinsicFor<Block>) -> Option<Era> {
    match &extrinsic.preamble {
        Preamble::Bare(_) | Preamble::General(_, _) => None,
        Preamble::Signed(_, _, extra) => Some(extra.4.0),
    }
}

#[cfg(feature = "runtime-benchmarks")]
mod benches {
    frame_benchmarking::define_benchmarks!(
        [frame_benchmarking, BaselineBench::<Runtime>]
        [frame_system, SystemBench::<Runtime>]
        [pallet_timestamp, Timestamp]
        [domain_pallet_executive, ExecutivePallet]
        [pallet_utility, Utility]
        [pallet_balances, Balances]
        [pallet_transaction_payment, TransactionPayment]
        [pallet_auto_id, AutoId]
        [pallet_messenger, Messenger]
        [pallet_messenger_from_consensus_extension, MessengerFromConsensusExtensionBench::<Runtime>]
        [pallet_messenger_between_domains_extension, MessengerBetweenDomainsExtensionBench::<Runtime>]
        [pallet_transporter, Transporter]
        // pallet_domain_id has no calls to benchmark
        // pallet_block_fees only has inherent calls
        // pallet_domain_sudo only has inherent calls
    );
}

fn check_transaction_and_do_pre_dispatch_inner(
    uxt: &ExtrinsicFor<Block>,
) -> Result<(), TransactionValidityError> {
    let lookup = frame_system::ChainContext::<Runtime>::default();

    let xt = uxt.clone().check(&lookup)?;

    let dispatch_info = xt.get_dispatch_info();

    if dispatch_info.class == DispatchClass::Mandatory {
        return Err(InvalidTransaction::MandatoryValidation.into());
    }

    let encoded_len = uxt.encoded_size();

    // We invoke `pre_dispatch` in addition to `validate_transaction`(even though the validation is almost same)
    // as that will add the side effect of SignedExtension in the storage buffer
    // which would help to maintain context across multiple transaction validity check against same
    // runtime instance.
    match xt.format {
        ExtrinsicFormat::General(extension_version, extra) => {
            let custom_extra: CustomSignedExtra = (
                extra.0,
                extra.1,
                extra.2,
                extra.3,
                extra.4,
                extra.5,
                extra.6.clone(),
                extra.7,
                pallet_messenger::extensions::MessengerTrustedMmrExtension::<Runtime>::new(),
            );

            let origin = RuntimeOrigin::none();
            <CustomSignedExtra as DispatchTransaction<RuntimeCall>>::validate_and_prepare(
                custom_extra,
                origin,
                &xt.function,
                &dispatch_info,
                encoded_len,
                extension_version,
            )
            .map(|_| ())
        }
        // signed transaction
        ExtrinsicFormat::Signed(account_id, extra) => {
            let origin = RuntimeOrigin::signed(account_id);
            <SignedExtra as DispatchTransaction<RuntimeCall>>::validate_and_prepare(
                extra,
                origin,
                &xt.function,
                &dispatch_info,
                encoded_len,
                // default extension version define here -
                // https://github.com/paritytech/polkadot-sdk/blob/master/substrate/primitives/runtime/src/generic/checked_extrinsic.rs#L37
                0,
            )
            .map(|_| ())
        }
        // unsigned transaction
        ExtrinsicFormat::Bare => {
            Runtime::pre_dispatch(&xt.function).map(|_| ())?;
            <SignedExtra as TransactionExtension<RuntimeCall>>::bare_validate_and_prepare(
                &xt.function,
                &dispatch_info,
                encoded_len,
            )
            .map(|_| ())
        }
    }
}

#[cfg(feature = "runtime-benchmarks")]
impl frame_system_benchmarking::Config for Runtime {}

#[cfg(feature = "runtime-benchmarks")]
impl frame_benchmarking::baseline::Config for Runtime {}

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block)
        }

        fn initialize_block(header: &HeaderFor<Block>) -> ExtrinsicInclusionMode {
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

        fn metadata_versions() -> Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: ExtrinsicFor<Block>) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> HeaderFor<Block> {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<ExtrinsicFor<Block>> {
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
            tx: ExtrinsicFor<Block>,
            block_hash: BlockHashFor<Block>,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &HeaderFor<Block>) {
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
            *System::account_nonce(account)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: ExtrinsicFor<Block>,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }
        fn query_fee_details(
            uxt: ExtrinsicFor<Block>,
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

    impl sp_domains::core_api::DomainCoreApi<Block> for Runtime {
        fn extract_signer(
            extrinsics: Vec<ExtrinsicFor<Block>>,
        ) -> Vec<(Option<opaque::AccountId>, ExtrinsicFor<Block>)> {
            extract_signer(extrinsics)
        }

        fn is_within_tx_range(
            extrinsic: &ExtrinsicFor<Block>,
            bundle_vrf_hash: &subspace_core_primitives::U256,
            tx_range: &subspace_core_primitives::U256
        ) -> bool {
            use subspace_core_primitives::U256;
            use subspace_core_primitives::hashes::blake3_hash;

            let lookup = frame_system::ChainContext::<Runtime>::default();
            if let Some(signer) = extract_signer_inner(extrinsic, &lookup).and_then(|account_result| {
                    account_result.ok().map(|account_id| account_id.encode())
                }) {
                // Check if the signer Id hash is within the tx range
                let signer_id_hash = U256::from_be_bytes(*blake3_hash(&signer.encode()));
                sp_domains::signer_in_tx_range(bundle_vrf_hash, &signer_id_hash, tx_range)
            } else {
                // Unsigned transactions are always in the range.
                true
            }
        }

        fn extract_signer_if_all_within_tx_range(
            extrinsics: &Vec<ExtrinsicFor<Block>>,
            bundle_vrf_hash: &subspace_core_primitives::U256,
            tx_range: &subspace_core_primitives::U256
        ) -> Result<Vec<Option<opaque::AccountId>> , u32> {
            use subspace_core_primitives::U256;
            use subspace_core_primitives::hashes::blake3_hash;

            let mut signers = Vec::with_capacity(extrinsics.len());
            let lookup = frame_system::ChainContext::<Runtime>::default();
            for (index, extrinsic) in extrinsics.iter().enumerate() {
                let maybe_signer = extract_signer_inner(extrinsic, &lookup).and_then(|account_result| {
                    account_result.ok().map(|account_id| account_id.encode())
                });
                if let Some(signer) = &maybe_signer {
                    // Check if the signer Id hash is within the tx range
                    let signer_id_hash = U256::from_be_bytes(*blake3_hash(&signer.encode()));
                    if !sp_domains::signer_in_tx_range(bundle_vrf_hash, &signer_id_hash, tx_range) {
                        return Err(index as u32)
                    }
                }
                signers.push(maybe_signer);
            }

            Ok(signers)
        }

        fn initialize_block_with_post_state_root(header: &HeaderFor<Block>) -> Vec<u8> {
            Executive::initialize_block(header);
            Executive::storage_root()
        }

        fn apply_extrinsic_with_post_state_root(extrinsic: ExtrinsicFor<Block>) -> Vec<u8> {
            let _ = Executive::apply_extrinsic(extrinsic);
            Executive::storage_root()
        }

        fn construct_set_code_extrinsic(code: Vec<u8>) -> Vec<u8> {
            UncheckedExtrinsic::new_bare(
                domain_pallet_executive::Call::set_code {
                    code
                }.into()
            ).encode()
        }

        fn construct_timestamp_extrinsic(moment: Moment) -> ExtrinsicFor<Block> {
            UncheckedExtrinsic::new_bare(
                pallet_timestamp::Call::set{ now: moment }.into()
            )
        }

        fn is_inherent_extrinsic(extrinsic: &ExtrinsicFor<Block>) -> bool {
            <Self as IsInherent<_>>::is_inherent(extrinsic)
        }

        fn find_first_inherent_extrinsic(extrinsics: &Vec<ExtrinsicFor<Block>>) -> Option<u32> {
            for (index, extrinsic) in extrinsics.iter().enumerate() {
                if <Self as IsInherent<_>>::is_inherent(extrinsic) {
                    return Some(index as u32)
                }
            }
            None
        }

        fn check_extrinsics_and_do_pre_dispatch(uxts: Vec<ExtrinsicFor<Block>>, block_number: BlockNumber,
            block_hash: BlockHashFor<Block>) -> Result<(), CheckExtrinsicsValidityError> {
            // Initializing block related storage required for validation
            System::initialize(
                &(block_number + BlockNumber::one()),
                &block_hash,
                &Default::default(),
            );

            for (extrinsic_index, uxt) in uxts.iter().enumerate() {
                check_transaction_and_do_pre_dispatch_inner(uxt).map_err(|e| {
                    CheckExtrinsicsValidityError {
                        extrinsic_index: extrinsic_index as u32,
                        transaction_validity_error: e
                    }
                })?;
            }

            Ok(())
        }

        fn decode_extrinsic(
            opaque_extrinsic: sp_runtime::OpaqueExtrinsic,
        ) -> Result<ExtrinsicFor<Block>, DecodeExtrinsicError> {
            let encoded = opaque_extrinsic.encode();

            UncheckedExtrinsic::decode_with_depth_limit(
                MAX_CALL_RECURSION_DEPTH,
                &mut encoded.as_slice(),
            ).map_err(|err| DecodeExtrinsicError(format!("{err}")))
        }

        fn decode_extrinsics_prefix(
            opaque_extrinsics: Vec<sp_runtime::OpaqueExtrinsic>,
        ) -> Vec<ExtrinsicFor<Block>> {
            let mut extrinsics = Vec::with_capacity(opaque_extrinsics.len());
            for opaque_ext in opaque_extrinsics {
                match UncheckedExtrinsic::decode_with_depth_limit(
                    MAX_CALL_RECURSION_DEPTH,
                    &mut opaque_ext.encode().as_slice(),
                ) {
                    Ok(tx) => extrinsics.push(tx),
                    Err(_) => return extrinsics,
                }
            }
            extrinsics
        }

        fn extrinsic_era(
          extrinsic: &ExtrinsicFor<Block>
        ) -> Option<Era> {
            extrinsic_era(extrinsic)
        }

        fn extrinsic_weight(ext: &ExtrinsicFor<Block>) -> Weight {
            let len = ext.encoded_size() as u64;
            let info = ext.get_dispatch_info();
            info.call_weight.saturating_add(info.extension_weight)
                .saturating_add(<Runtime as frame_system::Config>::BlockWeights::get().get(info.class).base_extrinsic)
                .saturating_add(Weight::from_parts(0, len))
        }

        fn extrinsics_weight(extrinsics: &Vec<ExtrinsicFor<Block>>) -> Weight {
            let mut total_weight = Weight::zero();
            for ext in extrinsics {
                let ext_weight = {
                    let len = ext.encoded_size() as u64;
                    let info = ext.get_dispatch_info();
                    info.call_weight.saturating_add(info.extension_weight)
                        .saturating_add(<Runtime as frame_system::Config>::BlockWeights::get().get(info.class).base_extrinsic)
                        .saturating_add(Weight::from_parts(0, len))
                };
                total_weight = total_weight.saturating_add(ext_weight);
            }
            total_weight
        }

        fn block_fees() -> sp_domains::BlockFees<Balance> {
            BlockFees::collected_block_fees()
        }

        fn block_digest() -> Digest {
            System::digest()
        }

        fn block_weight() -> Weight {
            System::block_weight().total()
        }

        fn construct_consensus_chain_byte_fee_extrinsic(transaction_byte_fee: Balance) -> ExtrinsicFor<Block> {
            UncheckedExtrinsic::new_bare(
                pallet_block_fees::Call::set_next_consensus_chain_byte_fee{ transaction_byte_fee }.into()
            )
        }

        fn construct_domain_update_chain_allowlist_extrinsic(updates: DomainAllowlistUpdates) -> ExtrinsicFor<Block> {
             UncheckedExtrinsic::new_bare(
                pallet_messenger::Call::update_domain_allowlist{ updates }.into()
            )
        }

        fn transfers() -> Transfers<Balance> {
            Transporter::chain_transfers()
        }

        fn transfers_storage_key() -> Vec<u8> {
            Transporter::transfers_storage_key()
        }

        fn block_fees_storage_key() -> Vec<u8> {
            BlockFees::block_fees_storage_key()
        }
    }

    impl sp_messenger::MessengerApi<Block, ConsensusBlockNumber, ConsensusBlockHash> for Runtime {
        fn is_xdm_mmr_proof_valid(
            extrinsic: &ExtrinsicFor<Block>,
        ) -> Option<bool> {
            is_xdm_mmr_proof_valid(extrinsic)
        }

        fn extract_xdm_mmr_proof(ext: &ExtrinsicFor<Block>) -> Option<ConsensusChainMmrLeafProof<ConsensusBlockNumber, ConsensusBlockHash, sp_core::H256>> {
            match &ext.function {
                RuntimeCall::Messenger(pallet_messenger::Call::relay_message { msg })
                | RuntimeCall::Messenger(pallet_messenger::Call::relay_message_response { msg }) => {
                    Some(msg.proof.consensus_mmr_proof())
                }
                _ => None,
            }
        }

        fn batch_extract_xdm_mmr_proof(extrinsics: &Vec<ExtrinsicFor<Block>>) -> BTreeMap<u32, ConsensusChainMmrLeafProof<ConsensusBlockNumber, ConsensusBlockHash, sp_core::H256>> {
            let mut mmr_proofs = BTreeMap::new();
            for (index, ext) in extrinsics.iter().enumerate() {
                match &ext.function {
                    RuntimeCall::Messenger(pallet_messenger::Call::relay_message { msg })
                    | RuntimeCall::Messenger(pallet_messenger::Call::relay_message_response { msg }) => {
                        mmr_proofs.insert(index as u32, msg.proof.consensus_mmr_proof());
                    }
                    _ => {},
                }
            }
            mmr_proofs
        }

        fn confirmed_domain_block_storage_key(_domain_id: DomainId) -> Vec<u8> {
            // invalid call from Domain runtime
            vec![]
        }

        fn outbox_storage_key(message_key: MessageKey) -> Vec<u8> {
            Messenger::outbox_storage_key(message_key)
        }

        fn inbox_response_storage_key(message_key: MessageKey) -> Vec<u8> {
            Messenger::inbox_response_storage_key(message_key)
        }

        fn domain_chains_allowlist_update(_domain_id: DomainId) -> Option<DomainAllowlistUpdates>{
            // not valid call on domains
            None
        }

        fn xdm_id(ext: &ExtrinsicFor<Block>) -> Option<XdmId> {
            match &ext.function {
                RuntimeCall::Messenger(pallet_messenger::Call::relay_message { msg })=> {
                    Some(XdmId::RelayMessage((msg.src_chain_id, msg.channel_id, msg.nonce)))
                }
                RuntimeCall::Messenger(pallet_messenger::Call::relay_message_response { msg }) => {
                    Some(XdmId::RelayResponseMessage((msg.src_chain_id, msg.channel_id, msg.nonce)))
                }
                _ => None,
            }
        }

        fn channel_nonce(chain_id: ChainId, channel_id: ChannelId) -> Option<ChannelNonce> {
            Messenger::channel_nonce(chain_id, channel_id)
        }
    }

    impl sp_messenger::RelayerApi<Block, BlockNumber, ConsensusBlockNumber, ConsensusBlockHash> for Runtime {
        fn block_messages() -> BlockMessagesWithStorageKey {
            BlockMessagesWithStorageKey::default()
        }

        fn outbox_message_unsigned(msg: CrossDomainMessage<NumberFor<Block>, BlockHashFor<Block>, BlockHashFor<Block>>) -> Option<ExtrinsicFor<Block>> {
            Messenger::outbox_message_unsigned(msg)
        }

        fn inbox_response_message_unsigned(msg: CrossDomainMessage<NumberFor<Block>, BlockHashFor<Block>, BlockHashFor<Block>>) -> Option<ExtrinsicFor<Block>> {
            Messenger::inbox_response_message_unsigned(msg)
        }

        fn should_relay_outbox_message(_: ChainId, _: MessageId) -> bool {
            false
        }

        fn should_relay_inbox_message_response(_: ChainId, _: MessageId) -> bool {
            false
        }

        fn updated_channels() -> BTreeSet<(ChainId, ChannelId)> {
            Messenger::updated_channels()
        }

        fn channel_storage_key(chain_id: ChainId, channel_id: ChannelId) -> Vec<u8> {
            Messenger::channel_storage_key(chain_id, channel_id)
        }

        fn open_channels() -> BTreeSet<(ChainId, ChannelId)> {
            Messenger::open_channels()
        }

        fn block_messages_with_query(query: BlockMessagesQuery) -> MessagesWithStorageKey {
            Messenger::get_block_messages(query)
        }

        fn channels_and_state() -> Vec<(ChainId, ChannelId, ChannelStateWithNonce)> {
            Messenger::channels_and_states()
        }

        fn first_outbox_message_nonce_to_relay(dst_chain_id: ChainId, channel_id: ChannelId, from_nonce: XdmNonce) -> Option<XdmNonce> {
            Messenger::first_outbox_message_nonce_to_relay(dst_chain_id, channel_id, from_nonce)
        }

        fn first_inbox_message_response_nonce_to_relay(dst_chain_id: ChainId, channel_id: ChannelId, from_nonce: XdmNonce) -> Option<XdmNonce> {
            Messenger::first_inbox_message_response_nonce_to_relay(dst_chain_id, channel_id, from_nonce)
        }
    }

    impl sp_domain_sudo::DomainSudoApi<Block> for Runtime {
        fn is_valid_sudo_call(extrinsic: Vec<u8>) -> bool {
            is_valid_sudo_call(extrinsic)
        }

        fn construct_domain_sudo_extrinsic(inner: Vec<u8>) -> ExtrinsicFor<Block> {
            construct_sudo_call_extrinsic(inner)
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
            build_state::<RuntimeGenesisConfig>(config)
        }

        fn get_preset(_id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
            // By passing `None` the upstream `get_preset` will return the default value of `RuntimeGenesisConfig`
            get_preset::<RuntimeGenesisConfig>(&None, |_| None)
        }

        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            vec![]
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
            use pallet_messenger::extensions::benchmarking_from_consensus::Pallet as MessengerFromConsensusExtensionBench;
            use pallet_messenger::extensions::benchmarking_between_domains::Pallet as MessengerBetweenDomainsExtensionBench;

            let mut list = Vec::<BenchmarkList>::new();

            list_benchmarks!(list, extra);

            let storage_info = AllPalletsWithSystem::storage_info();

            (list, storage_info)
        }

        fn dispatch_benchmark(
            config: frame_benchmarking::BenchmarkConfig
        ) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, alloc::string::String> {
            use frame_benchmarking::{baseline, Benchmarking, BenchmarkBatch};
            use sp_storage::TrackedStorageKey;
            use frame_system_benchmarking::Pallet as SystemBench;
            use frame_support::traits::WhitelistedStorageKeys;
            use baseline::Pallet as BaselineBench;
            use pallet_messenger::extensions::benchmarking_from_consensus::Pallet as MessengerFromConsensusExtensionBench;
            use pallet_messenger::extensions::benchmarking_between_domains::Pallet as MessengerBetweenDomainsExtensionBench;

            let whitelist: Vec<TrackedStorageKey> = AllPalletsWithSystem::whitelisted_storage_keys();

            let mut batches = Vec::<BenchmarkBatch>::new();
            let params = (&config, &whitelist);

            add_benchmarks!(params, batches);

            if batches.is_empty() { return Err("Benchmark not found for this pallet.".into()) }
            Ok(batches)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Runtime, RuntimeBlockWeights as BlockWeights};
    use subspace_runtime_primitives::tests_utils::FeeMultiplierUtils;

    #[test]
    fn multiplier_can_grow_from_zero() {
        FeeMultiplierUtils::<Runtime, BlockWeights>::multiplier_can_grow_from_zero()
    }
}
