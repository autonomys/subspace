#![feature(variant_count)]
#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

mod weights;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

use alloc::borrow::Cow;
#[cfg(not(feature = "std"))]
use alloc::format;
use core::mem;
use domain_runtime_primitives::opaque::Header;
use domain_runtime_primitives::{
    AccountId20, CheckExtrinsicsValidityError, DEFAULT_EXTENSION_VERSION, DecodeExtrinsicError,
    ERR_BALANCE_OVERFLOW, ERR_CONTRACT_CREATION_NOT_ALLOWED, ERR_EVM_NONCE_OVERFLOW,
    HoldIdentifier, MAX_OUTGOING_MESSAGES, SLOT_DURATION, TargetBlockFullness,
};
pub use domain_runtime_primitives::{
    Balance, BlockNumber, EXISTENTIAL_DEPOSIT, EthereumAccountId as AccountId,
    EthereumSignature as Signature, Hash, Nonce, block_weights, maximum_block_length,
    maximum_domain_block_weight, opaque,
};
use ethereum::AuthorizationList;
use fp_self_contained::{CheckedSignature, SelfContainedCall};
use frame_support::dispatch::{DispatchClass, DispatchInfo, GetDispatchInfo};
use frame_support::genesis_builder_helper::{build_state, get_preset};
use frame_support::pallet_prelude::TypeInfo;
use frame_support::traits::fungible::Credit;
use frame_support::traits::{
    ConstU16, ConstU32, ConstU64, Currency, Everything, FindAuthor, Imbalance, IsInherent,
    OnFinalize, OnUnbalanced, VariantCount,
};
use frame_support::weights::constants::ParityDbWeight;
use frame_support::weights::{ConstantMultiplier, Weight};
use frame_support::{construct_runtime, parameter_types};
use frame_system::limits::{BlockLength, BlockWeights};
use frame_system::pallet_prelude::RuntimeCallFor;
use pallet_block_fees::fees::OnChargeDomainTransaction;
use pallet_ethereum::{
    PostLogContent, Transaction as EthereumTransaction, TransactionData, TransactionStatus,
};
use pallet_evm::{
    Account as EVMAccount, EnsureAddressNever, EnsureAddressRoot, FeeCalculator, GasWeightMapping,
    IdentityAddressMapping, Runner,
};
use pallet_evm_tracker::create_contract::{CheckContractCreation, is_create_contract_allowed};
use pallet_evm_tracker::traits::{MaybeIntoEthCall, MaybeIntoEvmCall};
use pallet_transporter::EndpointHandler;
use parity_scale_codec::{Decode, DecodeLimit, DecodeWithMemTracking, Encode, MaxEncodedLen};
use sp_api::impl_runtime_apis;
use sp_core::crypto::KeyTypeId;
use sp_core::{Get, H160, H256, OpaqueMetadata, U256};
use sp_domains::execution_receipt::Transfers;
use sp_domains::{ChannelId, DomainAllowlistUpdates, DomainId, PermissionedActionAllowedBy};
use sp_evm_tracker::{
    BlockGasLimit, GasLimitPovSizeRatio, GasPerByte, StorageFeeRatio, WeightPerGas,
};
use sp_messenger::endpoint::{Endpoint, EndpointHandler as EndpointHandlerT, EndpointId};
use sp_messenger::messages::{
    BlockMessagesQuery, ChainId, ChannelStateWithNonce, CrossDomainMessage, MessageId, MessageKey,
    MessagesWithStorageKey, Nonce as XdmNonce,
};
use sp_messenger::{ChannelNonce, XdmId};
use sp_messenger_host_functions::{StorageKeyRequest, get_storage_key};
use sp_mmr_primitives::EncodableOpaqueLeaf;
use sp_runtime::generic::{Era, ExtrinsicFormat, Preamble};
use sp_runtime::traits::{
    BlakeTwo256, Checkable, DispatchInfoOf, DispatchTransaction, Dispatchable, IdentityLookup,
    Keccak256, NumberFor, One, PostDispatchInfoOf, TransactionExtension, UniqueSaturatedInto,
    ValidateUnsigned, Zero,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError,
};
use sp_runtime::{
    ApplyExtrinsicResult, ConsensusEngineId, Digest, ExtrinsicInclusionMode, generic,
    impl_opaque_keys,
};
pub use sp_runtime::{MultiAddress, Perbill, Permill};
use sp_std::cmp::{Ordering, max};
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
use subspace_runtime_primitives::utility::{MaybeNestedCall, MaybeUtilityCall};
use subspace_runtime_primitives::{
    AI3, BlockHashFor, BlockNumber as ConsensusBlockNumber, DomainEventSegmentSize, ExtrinsicFor,
    Hash as ConsensusBlockHash, HeaderFor, MAX_CALL_RECURSION_DEPTH, Moment, SHANNON,
    SlowAdjustingFeeUpdate, XdmAdjustedWeightToFee, XdmFeeMultipler,
};

/// The address format for describing accounts.
pub type Address = AccountId;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// Precompiles we use for EVM
pub type Precompiles = sp_evm_precompiles::Precompiles<Runtime>;

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
    CheckContractCreation<Runtime>,
    pallet_messenger::extensions::MessengerExtension<Runtime>,
);

/// Custom signed extra for check_and_pre_dispatch.
/// Only Nonce check is updated and rest remains same
type CustomSignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckMortality<Runtime>,
    pallet_evm_tracker::CheckNonce<Runtime>,
    domain_check_weight::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    CheckContractCreation<Runtime>,
    pallet_messenger::extensions::MessengerTrustedMmrExtension<Runtime>,
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
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

/// Returns the storage fee for `len` bytes, or an overflow error.
fn consensus_storage_fee(len: impl TryInto<Balance>) -> Result<Balance, TransactionValidityError> {
    // This should never fail with the current types.
    // But if converting to Balance would overflow, so would any multiplication.
    let len = len.try_into().map_err(|_| {
        TransactionValidityError::Invalid(InvalidTransaction::Custom(ERR_BALANCE_OVERFLOW))
    })?;

    BlockFees::consensus_chain_byte_fee()
        .checked_mul(Into::<Balance>::into(len))
        .ok_or(TransactionValidityError::Invalid(
            InvalidTransaction::Custom(ERR_BALANCE_OVERFLOW),
        ))
}

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
        let (is_allowed, _call_count) =
            is_create_contract_allowed::<Runtime>(self, &(*info).into());
        if !is_allowed {
            return Some(Err(InvalidTransaction::Custom(
                ERR_CONTRACT_CREATION_NOT_ALLOWED,
            )
            .into()));
        }

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
        let (is_allowed, _call_count) =
            is_create_contract_allowed::<Runtime>(self, &(*info).into());
        if !is_allowed {
            return Some(Err(InvalidTransaction::Custom(
                ERR_CONTRACT_CREATION_NOT_ALLOWED,
            )
            .into()));
        }

        // TODO: move this code into pallet-block-fees, so it can be used from the production and
        // test runtimes.
        match self {
            RuntimeCall::Ethereum(call) => {
                // Copied from [`pallet_ethereum::Call::pre_dispatch_self_contained`] with `frame_system::CheckWeight`
                // replaced with `domain_check_weight::CheckWeight`
                if let pallet_ethereum::Call::transact { transaction } = call {
                    let origin = RuntimeOrigin::signed(AccountId20::from(*info));
                    if let Err(err) =
                        <domain_check_weight::CheckWeight<Runtime> as DispatchTransaction<
                            RuntimeCall,
                        >>::validate_and_prepare(
                            domain_check_weight::CheckWeight::<Runtime>::new(),
                            origin,
                            self,
                            dispatch_info,
                            len,
                            DEFAULT_EXTENSION_VERSION,
                        )
                    {
                        return Some(Err(err));
                    }

                    Some(Ethereum::validate_transaction_in_block(*info, transaction))
                } else {
                    None
                }
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
                let post_info = call.dispatch(RuntimeOrigin::from(
                    pallet_ethereum::RawOrigin::EthereumTransaction(info),
                ));

                // is_self_contained() checks for an Ethereum call, which is always a single call.
                // This call has the same number of contract checks as an EVM call, and similar
                // fields, so we can use the EVM benchmark weight here.
                let create_contract_ext_weight = CheckContractCreation::<Runtime>::get_weights(1);

                // Add the weight of the contract creation extension check to the post info
                Some(
                    post_info
                        .map(|mut post_info| {
                            post_info.actual_weight = Some(
                                post_info
                                    .actual_weight
                                    .unwrap_or_default()
                                    .saturating_add(create_contract_ext_weight),
                            );
                            post_info
                        })
                        .map_err(|mut err_with_post_info| {
                            err_with_post_info.post_info.actual_weight = Some(
                                err_with_post_info
                                    .post_info
                                    .actual_weight
                                    .unwrap_or_default()
                                    .saturating_add(create_contract_ext_weight),
                            );
                            err_with_post_info
                        }),
                )
            }
            _ => None,
        }
    }
}

impl_opaque_keys! {
    pub struct SessionKeys {
        /// Primarily used for adding the operator signing key into the Keystore.
        pub operator: sp_domains::OperatorKey,
    }
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: Cow::Borrowed("subspace-evm-domain"),
    impl_name: Cow::Borrowed("subspace-evm-domain"),
    authoring_version: 0,
    spec_version: 2,
    impl_version: 0,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    system_version: 2,
};

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub const BlockHashCount: BlockNumber = 2400;

    // This part is copied from Substrate's `bin/node/runtime/src/lib.rs`.
    //  The `RuntimeBlockLength` and `RuntimeBlockWeights` exist here because the
    // `DeletionWeightLimit` and `DeletionQueueDepth` depend on those to parameterize
    // the lazy contract deletion.
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
    type ExtensionsWeightInfo = frame_system::SubstrateExtensionsWeight<Runtime>;
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
    pub const DomainChainByteFee: Balance = 100_000 * SHANNON;
    pub TransactionWeightFee: Balance = 100_000 * SHANNON;
}

impl pallet_block_fees::Config for Runtime {
    type Balance = Balance;
    type DomainChainByteFee = DomainChainByteFee;
}

type NegativeImbalance = <Balances as Currency<AccountId>>::NegativeImbalance;

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
        let consensus_storage_fee = consensus_storage_fee(tx_size)?;

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
    PartialEq,
    Eq,
    Clone,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
    Ord,
    PartialOrd,
    Copy,
    Debug,
    DecodeWithMemTracking,
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
    type AccountIdConverter = domain_runtime_primitives::AccountId20Converter;
    type WeightInfo = weights::pallet_transporter::WeightInfo<Runtime>;
    type MinimumTransfer = MinimumTransfer;
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

parameter_types! {
    pub PrecompilesValue: Precompiles = Precompiles::default();
}

/// UnbalancedHandler that will just burn any unbalanced funds
pub struct UnbalancedHandler {}
impl OnUnbalanced<NegativeImbalance> for UnbalancedHandler {}

type InnerEVMCurrencyAdapter = pallet_evm::EVMCurrencyAdapter<Balances, UnbalancedHandler>;

// Implementation of [`pallet_transaction_payment::OnChargeTransaction`] that charges evm transaction
// fees from the transaction sender and collect all the fees (including both the base fee and tip) in
// `pallet_block_fees`
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
            // Record the evm actual transaction fee and storage fee
            let (storage_fee, execution_fee) =
                EvmGasPriceCalculator::split_fee_into_storage_and_execution(
                    corrected_fee.as_u128(),
                );
            BlockFees::note_consensus_storage_fee(storage_fee);
            BlockFees::note_domain_execution_fee(execution_fee);
        }

        <InnerEVMCurrencyAdapter as pallet_evm::OnChargeEVMTransaction<
            Runtime,
        >>::correct_and_deposit_fee(who, corrected_fee, base_fee, already_withdrawn)
    }

    fn pay_priority_fee(tip: Self::LiquidityInfo) {
        if let Some(fee) = tip {
            // handle the priority fee just like the base fee.
            // for eip-1559, total fees will be base_fee + priority_fee
            UnbalancedHandler::on_unbalanced(fee)
        }
    }
}

pub type EvmGasPriceCalculator = pallet_evm_tracker::fees::EvmGasPriceCalculator<
    Runtime,
    TransactionWeightFee,
    GasPerByte,
    StorageFeeRatio,
>;

impl pallet_evm::Config for Runtime {
    type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
    type FeeCalculator = EvmGasPriceCalculator;
    type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
    type WeightPerGas = WeightPerGas;
    type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Self>;
    type CallOrigin = EnsureAddressRoot<AccountId>;
    type CreateOriginFilter = ();
    type CreateInnerOriginFilter = ();
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
    type GasLimitPovSizeRatio = GasLimitPovSizeRatio;
    // TODO: re-check this value mostly from moonbeam
    type GasLimitStorageGrowthRatio = ();
    type Timestamp = Timestamp;
    type WeightInfo = weights::pallet_evm::WeightInfo<Runtime>;
}

impl MaybeIntoEvmCall<Runtime> for RuntimeCall {
    /// If this call is a `pallet_evm::Call<Runtime>` call, returns the inner call.
    fn maybe_into_evm_call(&self) -> Option<&pallet_evm::Call<Runtime>> {
        match self {
            RuntimeCall::EVM(call) => Some(call),
            _ => None,
        }
    }
}

impl pallet_evm_tracker::Config for Runtime {}

parameter_types! {
    pub const PostOnlyBlockHash: PostLogContent = PostLogContent::OnlyBlockHash;
}

impl pallet_ethereum::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type StateRoot = pallet_ethereum::IntermediateStateRoot<Self::Version>;
    type PostLogContent = PostOnlyBlockHash;
    type ExtraDataLength = ConstU32<30>;
}

impl MaybeIntoEthCall<Runtime> for RuntimeCall {
    /// If this call is a `pallet_ethereum::Call<Runtime>` call, returns the inner call.
    fn maybe_into_eth_call(&self) -> Option<&pallet_ethereum::Call<Runtime>> {
        match self {
            RuntimeCall::Ethereum(call) => Some(call),
            _ => None,
        }
    }
}

impl pallet_domain_id::Config for Runtime {}

pub struct IntoRuntimeCall;

impl sp_domain_sudo::IntoRuntimeCall<RuntimeCall> for IntoRuntimeCall {
    fn runtime_call(call: Vec<u8>) -> RuntimeCall {
        UncheckedExtrinsic::decode(&mut call.as_slice())
            .expect("must always be a valid domain extrinsic as checked by consensus chain; qed")
            .0
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

impl MaybeUtilityCall<Runtime> for RuntimeCall {
    /// If this call is a `pallet_utility::Call<Runtime>` call, returns the inner call.
    fn maybe_utility_call(&self) -> Option<&pallet_utility::Call<Runtime>> {
        match self {
            RuntimeCall::Utility(call) => Some(call),
            _ => None,
        }
    }
}

impl MaybeNestedCall<Runtime> for RuntimeCall {
    /// If this call is a nested runtime call, returns the inner call(s).
    ///
    /// Ignored calls (such as `pallet_utility::Call::__Ignore`) should be yielded themsevles, but
    /// their contents should not be yielded.
    fn maybe_nested_call(&self) -> Option<Vec<&RuntimeCallFor<Runtime>>> {
        // We currently ignore privileged calls, because privileged users can already change
        // runtime code. Domain sudo `RuntimeCall`s also have to pass inherent validation.
        self.maybe_nested_utility_calls()
    }
}

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
        Utility: pallet_utility = 8,

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
        EVMNoncetracker: pallet_evm_tracker = 84,

        // domain instance stuff
        SelfDomainId: pallet_domain_id = 90,
        BlockFees: pallet_block_fees = 91,

        // Sudo account
        Sudo: pallet_domain_sudo = 100,
    }
);

#[derive(Clone, Default)]
pub struct TransactionConverter;

impl fp_rpc::ConvertTransaction<UncheckedExtrinsic> for TransactionConverter {
    fn convert_transaction(&self, transaction: pallet_ethereum::Transaction) -> UncheckedExtrinsic {
        UncheckedExtrinsic::new_bare(
            pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
        )
    }
}

impl fp_rpc::ConvertTransaction<opaque::UncheckedExtrinsic> for TransactionConverter {
    fn convert_transaction(
        &self,
        transaction: pallet_ethereum::Transaction,
    ) -> opaque::UncheckedExtrinsic {
        let extrinsic = UncheckedExtrinsic::new_bare(
            pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
        );
        let encoded = extrinsic.encode();
        opaque::UncheckedExtrinsic::decode(&mut &encoded[..])
            .expect("Encoded extrinsic is always valid")
    }
}

fn is_xdm_mmr_proof_valid(ext: &ExtrinsicFor<Block>) -> Option<bool> {
    match &ext.0.function {
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
    UncheckedExtrinsic::decode_all_with_depth_limit(
        MAX_CALL_RECURSION_DEPTH,
        &mut encoded_ext.as_slice(),
    )
    .is_ok()
}

/// Constructs a domain-sudo call extrinsic from the given encoded extrinsic.
fn construct_sudo_call_extrinsic(encoded_ext: Vec<u8>) -> ExtrinsicFor<Block> {
    let ext = UncheckedExtrinsic::decode(&mut encoded_ext.as_slice()).expect(
        "must always be a valid extrinsic due to the check above and storage proof check; qed",
    );
    UncheckedExtrinsic::new_bare(
        pallet_domain_sudo::Call::sudo {
            call: Box::new(ext.0.function),
        }
        .into(),
    )
}

/// Constructs an evm-tracker call extrinsic from the given extrinsic.
fn construct_evm_contract_creation_allowed_by_extrinsic(
    decoded_argument: PermissionedActionAllowedBy<AccountId>,
) -> ExtrinsicFor<Block> {
    UncheckedExtrinsic::new_bare(
        pallet_evm_tracker::Call::set_contract_creation_allowed_by {
            contract_creation_allowed_by: decoded_argument,
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
    if ext.0.function.is_self_contained() {
        ext.0
            .function
            .check_self_contained()
            .map(|signed_info| signed_info.map(|signer| signer.into()))
    } else {
        match &ext.0.preamble {
            Preamble::Bare(_) | Preamble::General(_, _) => None,
            Preamble::Signed(address, _, _) => Some(lookup.lookup(*address).map_err(|e| e.into())),
        }
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
    match &extrinsic.0.preamble {
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
        [pallet_messenger, Messenger]
        [pallet_messenger_from_consensus_extension, MessengerFromConsensusExtensionBench::<Runtime>]
        [pallet_messenger_between_domains_extension, MessengerBetweenDomainsExtensionBench::<Runtime>]
        [pallet_transporter, Transporter]
        // pallet_ethereum uses `pallet_evm::Config::GasWeightMapping::gas_to_weight` to weight its calls
        [pallet_evm, EVM]
        // pallet_evm_chain_id has no calls to benchmark
        [pallet_evm_tracker, EVMNoncetracker]
        // TODO: pallet_evm_tracker CheckNonce extension benchmarks
        // pallet_domain_id has no calls to benchmark
        // pallet_block_fees uses a default over-estimated weight
        // pallet_domain_sudo only has inherent calls
    );
}

/// Custom pre_dispatch for extrinsic verification.
/// Most of the logic is same as `pre_dispatch_self_contained` except
/// - we use `validate_self_contained` instead `pre_dispatch_self_contained`
///   since the nonce is not incremented in `pre_dispatch_self_contained`
/// - Manually track the account nonce to check either Stale or Future nonce.
fn pre_dispatch_evm_transaction(
    account_id: H160,
    call: RuntimeCall,
    dispatch_info: &DispatchInfoOf<RuntimeCall>,
    len: usize,
) -> Result<(), TransactionValidityError> {
    match call {
        RuntimeCall::Ethereum(call) => {
            if let Some(transaction_validity) =
                call.validate_self_contained(&account_id, dispatch_info, len)
            {
                let _ = transaction_validity?;

                let pallet_ethereum::Call::transact { transaction } = call;
                frame_system::CheckWeight::<Runtime>::do_validate(dispatch_info, len).and_then(
                    |(_, next_len)| {
                        domain_check_weight::CheckWeight::<Runtime>::do_prepare(
                            dispatch_info,
                            len,
                            next_len,
                        )
                    },
                )?;

                let transaction_data: TransactionData = (&transaction).into();
                let transaction_nonce = transaction_data.nonce;
                // If the current account nonce is greater than the tracked nonce, then
                // pick the highest nonce
                let account_nonce = {
                    let tracked_nonce = EVMNoncetracker::account_nonce(AccountId::from(account_id))
                        .unwrap_or(U256::zero());
                    let account_nonce = EVM::account_basic(&account_id).0.nonce;
                    max(tracked_nonce, account_nonce)
                };

                match transaction_nonce.cmp(&account_nonce) {
                    Ordering::Less => return Err(InvalidTransaction::Stale.into()),
                    Ordering::Greater => return Err(InvalidTransaction::Future.into()),
                    Ordering::Equal => {}
                }

                let next_nonce = account_nonce
                    .checked_add(U256::one())
                    .ok_or(InvalidTransaction::Custom(ERR_EVM_NONCE_OVERFLOW))?;

                EVMNoncetracker::set_account_nonce(AccountId::from(account_id), next_nonce);
            }

            Ok(())
        }
        _ => Err(InvalidTransaction::Call.into()),
    }
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
    match xt.signed {
        CheckedSignature::GenericDelegated(format) => match format {
            ExtrinsicFormat::Bare => {
                Runtime::pre_dispatch(&xt.function).map(|_| ())?;
                <SignedExtra as TransactionExtension<RuntimeCall>>::bare_validate_and_prepare(
                    &xt.function,
                    &dispatch_info,
                    encoded_len,
                )
                .map(|_| ())
            }
            ExtrinsicFormat::General(extension_version, extra) => {
                let custom_extra: CustomSignedExtra = (
                    extra.0,
                    extra.1,
                    extra.2,
                    extra.3,
                    extra.4,
                    pallet_evm_tracker::CheckNonce::from(extra.5.0),
                    extra.6,
                    extra.7.clone(),
                    extra.8,
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
            ExtrinsicFormat::Signed(account_id, extra) => {
                let custom_extra: CustomSignedExtra = (
                    extra.0,
                    extra.1,
                    extra.2,
                    extra.3,
                    extra.4,
                    pallet_evm_tracker::CheckNonce::from(extra.5.0),
                    extra.6,
                    extra.7.clone(),
                    extra.8,
                    // trusted MMR extension here does not matter since this extension
                    // will only affect unsigned extrinsics but not signed extrinsics
                    pallet_messenger::extensions::MessengerTrustedMmrExtension::<Runtime>::new(),
                );

                let origin = RuntimeOrigin::signed(account_id);
                <CustomSignedExtra as DispatchTransaction<RuntimeCall>>::validate_and_prepare(
                    custom_extra,
                    origin,
                    &xt.function,
                    &dispatch_info,
                    encoded_len,
                    DEFAULT_EXTENSION_VERSION,
                )
                .map(|_| ())
            }
        },
        CheckedSignature::SelfContained(account_id) => {
            pre_dispatch_evm_transaction(account_id, xt.function, &dispatch_info, encoded_len)
        }
    }
}

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
        frame_system::CheckNonce::<Runtime>::from(0u32),
        domain_check_weight::CheckWeight::<Runtime>::new(),
        // for unsigned extrinsic, transaction fee check will be skipped
        // so set a default value
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0u128),
        CheckContractCreation::<Runtime>::new(),
        pallet_messenger::extensions::MessengerExtension::<Runtime>::new(),
    );

    UncheckedExtrinsic::from(generic::UncheckedExtrinsic::new_transaction(call, extra))
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
            System::account_nonce(account)
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

            UncheckedExtrinsic::decode_all_with_depth_limit(
                MAX_CALL_RECURSION_DEPTH,
                &mut encoded.as_slice(),
            ).map_err(|err| DecodeExtrinsicError(format!("{err}")))
        }

        fn decode_extrinsics_prefix(
            opaque_extrinsics: Vec<sp_runtime::OpaqueExtrinsic>,
        ) -> Vec<ExtrinsicFor<Block>> {
            let mut extrinsics = Vec::with_capacity(opaque_extrinsics.len());
            for opaque_ext in opaque_extrinsics {
                match UncheckedExtrinsic::decode_all_with_depth_limit(
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

        fn block_fees() -> sp_domains::execution_receipt::BlockFees<Balance> {
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
                pallet_block_fees::Call::set_next_consensus_chain_byte_fee { transaction_byte_fee }.into()
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
            extrinsic: &ExtrinsicFor<Block>
        ) -> Option<bool> {
            is_xdm_mmr_proof_valid(extrinsic)
        }

        fn extract_xdm_mmr_proof(ext: &ExtrinsicFor<Block>) -> Option<ConsensusChainMmrLeafProof<ConsensusBlockNumber, ConsensusBlockHash, sp_core::H256>> {
            match &ext.0.function {
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
                match &ext.0.function {
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
            match &ext.0.function {
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
        fn outbox_message_unsigned(msg: CrossDomainMessage<NumberFor<Block>, BlockHashFor<Block>, BlockHashFor<Block>>) -> Option<ExtrinsicFor<Block>> {
            Messenger::outbox_message_unsigned(msg)
        }

        fn inbox_response_message_unsigned(msg: CrossDomainMessage<NumberFor<Block>, BlockHashFor<Block>, BlockHashFor<Block>>) -> Option<ExtrinsicFor<Block>> {
            Messenger::inbox_response_message_unsigned(msg)
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
            let tmp = index.to_big_endian();
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
            authorization_list: Option<AuthorizationList>,
        ) -> Result<pallet_evm::CallInfo, sp_runtime::DispatchError> {
            let config = if estimate {
                let mut config = <Runtime as pallet_evm::Config>::config().clone();
                config.estimate = true;
                Some(config)
            } else {
                None
            };

            // Estimated encoded transaction size must be based on the heaviest transaction
            // type (EIP7702Transaction) to be compatible with all transaction types.
            let mut estimated_transaction_len = data.len() +
                // pallet ethereum index: 1
                // transact call index: 1
                // Transaction enum variant: 1
                // chain_id 8 bytes
                // nonce: 32
                // max_priority_fee_per_gas: 32
                // max_fee_per_gas: 32
                // gas_limit: 32
                // action: 21 (enum varianrt + call address)
                // value: 32
                // access_list: 1 (empty vec size)
                // authorization_list: 1 (empty vec size)
                // 65 bytes signature
                259;

            if access_list.is_some() {
                estimated_transaction_len += access_list.encoded_size();
            }

            if authorization_list.is_some() {
                estimated_transaction_len += authorization_list.encoded_size();
            }

            let gas_limit = if gas_limit > U256::from(u64::MAX) {
                u64::MAX
            } else {
                gas_limit.low_u64()
            };
            let without_base_extrinsic_weight = true;

            let (weight_limit, proof_size_base_cost) =
                match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
                    gas_limit,
                    without_base_extrinsic_weight
                ) {
                    weight_limit if weight_limit.proof_size() > 0 => {
                        (Some(weight_limit), Some(estimated_transaction_len as u64))
                    }
                    _ => (None, None),
                };

            let is_transactional = false;
            let validate = true;
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
                authorization_list.unwrap_or_default(),
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
            authorization_list: Option<AuthorizationList>,
        ) -> Result<pallet_evm::CreateInfo, sp_runtime::DispatchError> {
            let config = if estimate {
                let mut config = <Runtime as pallet_evm::Config>::config().clone();
                config.estimate = true;
                Some(config)
            } else {
                None
            };

            let mut estimated_transaction_len = data.len() +
                // from: 20
                // value: 32
                // gas_limit: 32
                // nonce: 32
                // 1 byte transaction action variant
                // chain id 8 bytes
                // 65 bytes signature
                190;

            if max_fee_per_gas.is_some() {
                estimated_transaction_len += 32;
            }
            if max_priority_fee_per_gas.is_some() {
                estimated_transaction_len += 32;
            }
            if access_list.is_some() {
                estimated_transaction_len += access_list.encoded_size();
            }
            if authorization_list.is_some() {
                estimated_transaction_len += authorization_list.encoded_size();
            }

            let gas_limit = if gas_limit > U256::from(u64::MAX) {
                u64::MAX
            } else {
                gas_limit.low_u64()
            };
            let without_base_extrinsic_weight = true;

            let (weight_limit, proof_size_base_cost) =
                match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
                    gas_limit,
                    without_base_extrinsic_weight
                ) {
                    weight_limit if weight_limit.proof_size() > 0 => {
                        (Some(weight_limit), Some(estimated_transaction_len as u64))
                    }
                    _ => (None, None),
                };

            let is_transactional = false;
            let validate = true;
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
                authorization_list.unwrap_or_default(),
                is_transactional,
                validate,
                weight_limit,
                proof_size_base_cost,
                evm_config
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
            xts: Vec<ExtrinsicFor<Block>>,
        ) -> Vec<EthereumTransaction> {
            xts.into_iter().filter_map(|xt| match xt.0.function {
                RuntimeCall::Ethereum(pallet_ethereum::Call::transact { transaction }) => Some(transaction),
                _ => None
            }).collect::<Vec<EthereumTransaction>>()
        }

        fn elasticity() -> Option<Permill> {
            None
        }

        fn gas_limit_multiplier_support() {}

        fn pending_block(
            xts: Vec<ExtrinsicFor<Block>>,
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

        fn initialize_pending_block(header: &HeaderFor<Block>) {
            Executive::initialize_block(header);
        }
    }

    impl fp_rpc::ConvertTransactionRuntimeApi<Block> for Runtime {
        fn convert_transaction(transaction: EthereumTransaction) -> ExtrinsicFor<Block> {
            UncheckedExtrinsic::new_bare(
                pallet_ethereum::Call::transact { transaction }.into(),
            )
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

    impl sp_evm_tracker::EvmTrackerApi<Block> for Runtime {
        fn construct_evm_contract_creation_allowed_by_extrinsic(decoded_argument: PermissionedActionAllowedBy<AccountId>) -> ExtrinsicFor<Block> {
            construct_evm_contract_creation_allowed_by_extrinsic(decoded_argument)
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
            use frame_benchmarking::{baseline, BenchmarkList};
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
            use frame_benchmarking::{baseline, BenchmarkBatch};
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
