// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(variant_count)]
// `generic_const_exprs` is an incomplete feature
#![allow(incomplete_features)]
// TODO: This feature is not actually used in this crate, but is added as a workaround for
//  https://github.com/rust-lang/rust/issues/133199
#![feature(generic_const_exprs)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]
// TODO: remove when upstream issue is fixed
#![allow(
    non_camel_case_types,
    reason = "https://github.com/rust-lang/rust-analyzer/issues/16514"
)]

extern crate alloc;

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use alloc::borrow::Cow;
use core::mem;
use core::num::NonZeroU64;
use domain_runtime_primitives::opaque::Header as DomainHeader;
use domain_runtime_primitives::{
    AccountIdConverter, BlockNumber as DomainNumber, EthereumAccountId, Hash as DomainHash,
    MAX_OUTGOING_MESSAGES,
};
use frame_support::genesis_builder_helper::{build_state, get_preset};
use frame_support::inherent::ProvideInherent;
use frame_support::traits::fungible::Inspect;
use frame_support::traits::tokens::WithdrawConsequence;
use frame_support::traits::{
    ConstU128, ConstU16, ConstU32, ConstU64, ConstU8, Currency, Everything, ExistenceRequirement,
    Get, Imbalance, Time, VariantCount, WithdrawReasons,
};
use frame_support::weights::constants::{ParityDbWeight, WEIGHT_REF_TIME_PER_SECOND};
use frame_support::weights::{ConstantMultiplier, Weight};
use frame_support::{construct_runtime, parameter_types, PalletId};
use frame_system::limits::{BlockLength, BlockWeights};
use frame_system::pallet_prelude::{OriginFor, RuntimeCallFor};
use pallet_balances::NegativeImbalance;
pub use pallet_rewards::RewardPoint;
pub use pallet_subspace::{AllowAuthoringBy, EnableRewardsAt};
use pallet_transporter::EndpointHandler;
use parity_scale_codec::{Compact, CompactLen, Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_api::impl_runtime_apis;
use sp_consensus_slots::{Slot, SlotDuration};
use sp_consensus_subspace::{ChainConstants, PotParameters, SignedVote, SolutionRanges, Vote};
use sp_core::crypto::KeyTypeId;
use sp_core::{OpaqueMetadata, H256};
use sp_domains::bundle_producer_election::BundleProducerElectionParams;
use sp_domains::{
    DomainAllowlistUpdates, DomainId, DomainInstanceData, ExecutionReceiptFor, OpaqueBundle,
    OpaqueBundles, OperatorId, OperatorPublicKey, OperatorRewardSource,
    PermissionedActionAllowedBy, DOMAIN_STORAGE_FEE_MULTIPLIER, INITIAL_DOMAIN_TX_RANGE,
};
use sp_domains_fraud_proof::fraud_proof::FraudProof;
use sp_domains_fraud_proof::storage_proof::{
    FraudProofStorageKeyProvider, FraudProofStorageKeyRequest,
};
use sp_messenger::endpoint::{Endpoint, EndpointHandler as EndpointHandlerT, EndpointId};
use sp_messenger::messages::{
    BlockMessagesQuery, BlockMessagesWithStorageKey, ChainId, ChannelId, ChannelStateWithNonce,
    CrossDomainMessage, MessageId, MessageKey, MessagesWithStorageKey, Nonce as XdmNonce,
};
use sp_messenger::{ChannelNonce, XdmId};
use sp_messenger_host_functions::{get_storage_key, StorageKeyRequest};
use sp_mmr_primitives::EncodableOpaqueLeaf;
use sp_runtime::traits::{
    AccountIdConversion, AccountIdLookup, AsSystemOriginSigner, BlakeTwo256, ConstBool,
    DispatchInfoOf, Keccak256, NumberFor, PostDispatchInfoOf, TransactionExtension, ValidateResult,
    Zero,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError,
    ValidTransaction,
};
use sp_runtime::type_with_default::TypeWithDefault;
use sp_runtime::{
    generic, impl_tx_ext_default, AccountId32, ApplyExtrinsicResult, ExtrinsicInclusionMode,
    Perbill,
};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::marker::PhantomData;
use sp_std::prelude::*;
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_version::RuntimeVersion;
use static_assertions::const_assert;
use subspace_core_primitives::objects::{BlockObject, BlockObjectMapping};
use subspace_core_primitives::pieces::Piece;
use subspace_core_primitives::segments::{
    HistorySize, SegmentCommitment, SegmentHeader, SegmentIndex,
};
use subspace_core_primitives::solutions::SolutionRange;
use subspace_core_primitives::{hashes, PublicKey, Randomness, SlotNumber, U256};
use subspace_runtime_primitives::utility::{
    nested_call_iter, DefaultNonceProvider, MaybeMultisigCall, MaybeNestedCall, MaybeUtilityCall,
};
use subspace_runtime_primitives::{
    AccountId, Balance, BlockHashFor, BlockNumber, ConsensusEventSegmentSize, ExtrinsicFor,
    FindBlockRewardAddress, Hash, HeaderFor, HoldIdentifier, Moment, Nonce, Signature,
    SlowAdjustingFeeUpdate, TargetBlockFullness, XdmAdjustedWeightToFee, XdmFeeMultipler,
    MAX_BLOCK_LENGTH, MAX_CALL_RECURSION_DEPTH, MIN_REPLICATION_FACTOR, SHANNON, SSC,
};
use subspace_test_primitives::DOMAINS_BLOCK_PRUNING_DEPTH;

sp_runtime::impl_opaque_keys! {
    pub struct SessionKeys {
    }
}

// Smaller value for testing purposes
const MAX_PIECES_IN_SECTOR: u16 = 32;

// To learn more about runtime versioning and what each of the following value means:
//   https://substrate.dev/docs/en/knowledgebase/runtime/upgrades#runtime-versioning
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: Cow::Borrowed("subspace"),
    impl_name: Cow::Borrowed("subspace"),
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
    system_version: 2,
};

// TODO: Many of below constants should probably be updatable but currently they are not

/// Expected block time in milliseconds.
///
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
pub const MILLISECS_PER_BLOCK: u64 = 2000;

// NOTE: Currently it is not possible to change the slot duration after the chain has started.
//       Attempting to do so will brick block production.
pub const SLOT_DURATION: u64 = 2000;

/// 1 in 6 slots (on average, not counting collisions) will have a block.
/// Must match ratio between block and slot duration in constants above.
const SLOT_PROBABILITY: (u64, u64) = (1, 1);
/// Number of slots between slot arrival and when corresponding block can be produced.
const BLOCK_AUTHORING_DELAY: SlotNumber = 2;

/// Interval, in blocks, between blockchain entropy injection into proof of time chain.
const POT_ENTROPY_INJECTION_INTERVAL: BlockNumber = 5;

/// Interval, in entropy injection intervals, where to take entropy for injection from.
const POT_ENTROPY_INJECTION_LOOKBACK_DEPTH: u8 = 2;

/// Delay after block, in slots, when entropy injection takes effect.
const POT_ENTROPY_INJECTION_DELAY: SlotNumber = 4;

// Entropy injection interval must be bigger than injection delay or else we may end up in a
// situation where we'll need to do more than one injection at the same slot
const_assert!(POT_ENTROPY_INJECTION_INTERVAL as u64 > POT_ENTROPY_INJECTION_DELAY);
// Entropy injection delay must be bigger than block authoring delay or else we may include
// invalid future proofs in parent block, +1 ensures we do not have unnecessary reorgs that will
// inevitably happen otherwise
const_assert!(POT_ENTROPY_INJECTION_DELAY > BLOCK_AUTHORING_DELAY + 1);

/// Era duration in blocks.
const ERA_DURATION_IN_BLOCKS: BlockNumber = 2016;

/// Any solution range is valid in the test environment.
const INITIAL_SOLUTION_RANGE: SolutionRange = SolutionRange::MAX;

/// A ratio of `Normal` dispatch class within block, for `BlockWeight` and `BlockLength`.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

/// The block weight for 2 seconds of compute
const BLOCK_WEIGHT_FOR_2_SEC: Weight =
    Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_mul(2), u64::MAX);

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub const BlockHashCount: BlockNumber = 250;
    /// We allow for 2 seconds of compute with a 6 second average block time.
    pub SubspaceBlockWeights: BlockWeights = BlockWeights::with_sensible_defaults(BLOCK_WEIGHT_FOR_2_SEC, NORMAL_DISPATCH_RATIO);
    /// We allow for 3.75 MiB for `Normal` extrinsic with 5 MiB maximum block length.
    pub SubspaceBlockLength: BlockLength = BlockLength::max_with_normal_ratio(MAX_BLOCK_LENGTH, NORMAL_DISPATCH_RATIO);
}

pub type SS58Prefix = ConstU16<6094>;

// Configure FRAME pallets to include in runtime.

impl frame_system::Config for Runtime {
    /// The basic call filter to use in dispatchable.
    ///
    /// `Everything` is used here as we use the signed extension
    /// `DisablePallets` as the actual call filter.
    type BaseCallFilter = Everything;
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = SubspaceBlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = SubspaceBlockLength;
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
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = ParityDbWeight;
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
    type SystemWeightInfo = frame_system::weights::SubstrateWeight<Runtime>;
    /// This is used as an identifier of the chain.
    type SS58Prefix = SS58Prefix;
    /// The set code logic, just the default since we're not a parachain.
    type OnSetCode = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
    type MaxConsumers = ConstU32<16>;
    type ExtensionsWeightInfo = frame_system::ExtensionsWeight<Runtime>;
    type EventSegmentSize = ConsensusEventSegmentSize;
}

parameter_types! {
    pub const BlockAuthoringDelay: SlotNumber = BLOCK_AUTHORING_DELAY;
    pub const PotEntropyInjectionInterval: BlockNumber = POT_ENTROPY_INJECTION_INTERVAL;
    pub const PotEntropyInjectionLookbackDepth: u8 = POT_ENTROPY_INJECTION_LOOKBACK_DEPTH;
    pub const PotEntropyInjectionDelay: SlotNumber = POT_ENTROPY_INJECTION_DELAY;
    pub const EraDuration: BlockNumber = ERA_DURATION_IN_BLOCKS;
    pub const SlotProbability: (u64, u64) = SLOT_PROBABILITY;
    pub const ShouldAdjustSolutionRange: bool = false;
    pub const ExpectedVotesPerBlock: u32 = 9;
    pub const ConfirmationDepthK: u32 = 5;
    pub const RecentSegments: HistorySize = HistorySize::new(NonZeroU64::new(5).unwrap());
    pub const RecentHistoryFraction: (HistorySize, HistorySize) = (
        HistorySize::new(NonZeroU64::new(1).unwrap()),
        HistorySize::new(NonZeroU64::new(10).unwrap()),
    );
    pub const MinSectorLifetime: HistorySize = HistorySize::new(NonZeroU64::new(4).unwrap());
    pub const BlockSlotCount: u32 = 6;
    pub TransactionWeightFee: Balance = 100_000 * SHANNON;
}

impl pallet_subspace::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SubspaceOrigin = pallet_subspace::EnsureSubspaceOrigin;
    type BlockAuthoringDelay = BlockAuthoringDelay;
    type PotEntropyInjectionInterval = PotEntropyInjectionInterval;
    type PotEntropyInjectionLookbackDepth = PotEntropyInjectionLookbackDepth;
    type PotEntropyInjectionDelay = PotEntropyInjectionDelay;
    type EraDuration = EraDuration;
    type InitialSolutionRange = ConstU64<INITIAL_SOLUTION_RANGE>;
    type SlotProbability = SlotProbability;
    type ConfirmationDepthK = ConfirmationDepthK;
    type RecentSegments = RecentSegments;
    type RecentHistoryFraction = RecentHistoryFraction;
    type MinSectorLifetime = MinSectorLifetime;
    type ExpectedVotesPerBlock = ExpectedVotesPerBlock;
    type MaxPiecesInSector = ConstU16<{ MAX_PIECES_IN_SECTOR }>;
    type ShouldAdjustSolutionRange = ShouldAdjustSolutionRange;
    type EraChangeTrigger = pallet_subspace::NormalEraChange;
    type WeightInfo = pallet_subspace::weights::SubstrateWeight<Runtime>;
    type BlockSlotCount = BlockSlotCount;
    type ExtensionWeightInfo = pallet_subspace::extensions::weights::SubstrateWeight<Runtime>;
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = pallet_timestamp::weights::SubstrateWeight<Runtime>;
}

#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub struct HoldIdentifierWrapper(HoldIdentifier);

impl pallet_domains::HoldIdentifier<Runtime> for HoldIdentifierWrapper {
    fn staking_staked() -> Self {
        Self(HoldIdentifier::DomainStaking)
    }

    fn domain_instantiation_id() -> Self {
        Self(HoldIdentifier::DomainInstantiation)
    }

    fn storage_fund_withdrawal() -> Self {
        Self(HoldIdentifier::DomainStorageFund)
    }
}

impl pallet_messenger::HoldIdentifier<Runtime> for HoldIdentifierWrapper {
    fn messenger_channel() -> Self {
        Self(HoldIdentifier::MessengerChannel)
    }
}

impl VariantCount for HoldIdentifierWrapper {
    const VARIANT_COUNT: u32 = mem::variant_count::<HoldIdentifier>() as u32;
}

impl pallet_balances::Config for Runtime {
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ConstU128<{ 10_000_000_000_000 * SHANNON }>;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = HoldIdentifierWrapper;
    type DoneSlashHandler = ();
}

pub struct CreditSupply;

impl Get<Balance> for CreditSupply {
    fn get() -> Balance {
        Balances::total_issuance()
    }
}

pub struct TotalSpacePledged;

impl Get<u128> for TotalSpacePledged {
    fn get() -> u128 {
        // Operations reordered to avoid data loss, but essentially are:
        // u64::MAX * SlotProbability / (solution_range / PIECE_SIZE)
        u128::from(u64::MAX)
            .saturating_mul(Piece::SIZE as u128)
            .saturating_mul(u128::from(SlotProbability::get().0))
            / u128::from(Subspace::solution_ranges().current)
            / u128::from(SlotProbability::get().1)
    }
}

pub struct BlockchainHistorySize;

impl Get<u128> for BlockchainHistorySize {
    fn get() -> u128 {
        u128::from(Subspace::archived_history_size())
    }
}

impl pallet_transaction_fees::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MinReplicationFactor = ConstU16<MIN_REPLICATION_FACTOR>;
    type CreditSupply = CreditSupply;
    type TotalSpacePledged = TotalSpacePledged;
    type BlockchainHistorySize = BlockchainHistorySize;
    type Currency = Balances;
    type FindBlockRewardAddress = Subspace;
    type DynamicCostOfStorage = ConstBool<false>;
    type WeightInfo = pallet_transaction_fees::weights::SubstrateWeight<Runtime>;
}

pub struct TransactionByteFee;

impl Get<Balance> for TransactionByteFee {
    fn get() -> Balance {
        TransactionFees::transaction_byte_fee()
    }
}

pub struct LiquidityInfo {
    storage_fee: Balance,
    imbalance: NegativeImbalance<Runtime>,
}

/// Implementation of [`pallet_transaction_payment::OnChargeTransaction`] that charges transaction
/// fees and distributes storage/compute fees and tip separately.
pub struct OnChargeTransaction;

impl pallet_transaction_payment::OnChargeTransaction<Runtime> for OnChargeTransaction {
    type LiquidityInfo = Option<LiquidityInfo>;
    type Balance = Balance;

    fn withdraw_fee(
        who: &AccountId,
        call: &RuntimeCall,
        _info: &DispatchInfoOf<RuntimeCall>,
        fee: Self::Balance,
        tip: Self::Balance,
    ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
        if fee.is_zero() {
            return Ok(None);
        }

        let withdraw_reason = if tip.is_zero() {
            WithdrawReasons::TRANSACTION_PAYMENT
        } else {
            WithdrawReasons::TRANSACTION_PAYMENT | WithdrawReasons::TIP
        };

        let withdraw_result =
            Balances::withdraw(who, fee, withdraw_reason, ExistenceRequirement::KeepAlive);
        let imbalance = withdraw_result.map_err(|_error| InvalidTransaction::Payment)?;

        // Separate storage fee while we have access to the call data structure to calculate it.
        let storage_fee = TransactionByteFee::get()
            * Balance::try_from(call.encoded_size())
                .expect("Size of the call never exceeds balance units; qed");

        Ok(Some(LiquidityInfo {
            storage_fee,
            imbalance,
        }))
    }

    fn correct_and_deposit_fee(
        who: &AccountId,
        _dispatch_info: &DispatchInfoOf<RuntimeCall>,
        _post_info: &PostDispatchInfoOf<RuntimeCall>,
        corrected_fee: Self::Balance,
        tip: Self::Balance,
        liquidity_info: Self::LiquidityInfo,
    ) -> Result<(), TransactionValidityError> {
        if let Some(LiquidityInfo {
            storage_fee,
            imbalance,
        }) = liquidity_info
        {
            // Calculate how much refund we should return
            let refund_amount = imbalance.peek().saturating_sub(corrected_fee);
            // Refund to the account that paid the fees. If this fails, the account might have
            // dropped below the existential balance. In that case we don't refund anything.
            let refund_imbalance = Balances::deposit_into_existing(who, refund_amount)
                .unwrap_or_else(|_| <Balances as Currency<AccountId>>::PositiveImbalance::zero());
            // Merge the imbalance caused by paying the fees and refunding parts of it again.
            let adjusted_paid = imbalance
                .offset(refund_imbalance)
                .same()
                .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;

            // Split the tip from the total fee that ended up being paid.
            let (tip, fee) = adjusted_paid.split(tip);
            // Split paid storage and compute fees so that they can be distributed separately.
            let (paid_storage_fee, paid_compute_fee) = fee.split(storage_fee);

            TransactionFees::note_transaction_fees(
                paid_storage_fee.peek(),
                paid_compute_fee.peek(),
                tip.peek(),
            );
        }
        Ok(())
    }

    fn can_withdraw_fee(
        who: &AccountId,
        _call: &RuntimeCall,
        _dispatch_info: &DispatchInfoOf<RuntimeCall>,
        fee: Self::Balance,
        _tip: Self::Balance,
    ) -> Result<(), TransactionValidityError> {
        if fee.is_zero() {
            return Ok(());
        }

        match Balances::can_withdraw(who, fee) {
            WithdrawConsequence::Success => Ok(()),
            _ => Err(InvalidTransaction::Payment.into()),
        }
    }
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = OnChargeTransaction;
    type OperationalFeeMultiplier = ConstU8<5>;
    type WeightToFee = ConstantMultiplier<Balance, TransactionWeightFee>;
    type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
    type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Runtime, TargetBlockFullness>;
    type WeightInfo = pallet_transaction_payment::weights::SubstrateWeight<Runtime>;
}

impl pallet_utility::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type PalletsOrigin = OriginCaller;
    type WeightInfo = pallet_utility::weights::SubstrateWeight<Runtime>;
}

impl MaybeMultisigCall<Runtime> for RuntimeCall {
    /// If this call is a `pallet_multisig::Call<Runtime>` call, returns the inner call.
    fn maybe_multisig_call(&self) -> Option<&pallet_multisig::Call<Runtime>> {
        match self {
            RuntimeCall::Multisig(call) => Some(call),
            _ => None,
        }
    }
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
        // runtime code. This includes sudo, collective, and scheduler nested `RuntimeCall`s,
        // and democracy nested `BoundedCall`s.

        // It is ok to return early, because each call can only belong to one pallet.
        let calls = self.maybe_nested_utility_calls();
        if calls.is_some() {
            return calls;
        }

        let calls = self.maybe_nested_multisig_calls();
        if calls.is_some() {
            return calls;
        }

        None
    }
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub SelfChainId: ChainId = ChainId::Consensus;
}

pub struct MmrProofVerifier;

impl sp_subspace_mmr::MmrProofVerifier<mmr::Hash, NumberFor<Block>, Hash> for MmrProofVerifier {
    fn verify_proof_and_extract_leaf(
        mmr_leaf_proof: ConsensusChainMmrLeafProof<NumberFor<Block>, Hash, mmr::Hash>,
    ) -> Option<mmr::Leaf> {
        let mmr_root = SubspaceMmr::mmr_root_hash(mmr_leaf_proof.consensus_block_number)?;
        Self::verify_proof_stateless(mmr_root, mmr_leaf_proof)
    }

    fn verify_proof_stateless(
        mmr_root: mmr::Hash,
        mmr_leaf_proof: ConsensusChainMmrLeafProof<NumberFor<Block>, Hash, mmr::Hash>,
    ) -> Option<mmr::Leaf> {
        let ConsensusChainMmrLeafProof {
            opaque_mmr_leaf,
            proof,
            ..
        } = mmr_leaf_proof;

        pallet_mmr::verify_leaves_proof::<mmr::Hashing, _>(
            mmr_root,
            vec![mmr::DataOrHash::Data(
                EncodableOpaqueLeaf(opaque_mmr_leaf.0.clone()).into_opaque_leaf(),
            )],
            proof,
        )
        .ok()?;

        let leaf: mmr::Leaf = opaque_mmr_leaf.into_opaque_leaf().try_decode()?;

        Some(leaf)
    }
}

pub struct StorageKeys;

impl sp_messenger::StorageKeys for StorageKeys {
    fn confirmed_domain_block_storage_key(domain_id: DomainId) -> Option<Vec<u8>> {
        Some(Domains::confirmed_domain_block_storage_key(domain_id))
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

pub struct DomainRegistration;
impl sp_messenger::DomainRegistration for DomainRegistration {
    fn is_domain_registered(domain_id: DomainId) -> bool {
        Domains::is_domain_registered(domain_id)
    }
}

parameter_types! {
    pub const ChannelReserveFee: Balance = SSC;
    pub const ChannelInitReservePortion: Perbill = Perbill::from_percent(20);
    pub const MaxOutgoingMessages: u32 = MAX_OUTGOING_MESSAGES;
}

// ensure the max outgoing messages is not 0.
const_assert!(MaxOutgoingMessages::get() >= 1);

pub struct OnXDMRewards;

impl sp_messenger::OnXDMRewards<Balance> for OnXDMRewards {
    fn on_xdm_rewards(reward: Balance) {
        if let Some(block_author) = Subspace::find_block_reward_address() {
            let _ = Balances::deposit_creating(&block_author, reward);
        }
    }

    fn on_chain_protocol_fees(chain_id: ChainId, fees: Balance) {
        // on consensus chain, reward the domain operators
        // balance is already on this consensus runtime
        if let ChainId::Domain(domain_id) = chain_id {
            Domains::reward_domain_operators(domain_id, OperatorRewardSource::XDMProtocolFees, fees)
        }
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
    type WeightInfo = pallet_messenger::weights::SubstrateWeight<Runtime>;
    type WeightToFee = ConstantMultiplier<Balance, TransactionWeightFee>;
    type AdjustedWeightToFee = XdmAdjustedWeightToFee<Runtime>;
    type FeeMultiplier = XdmFeeMultipler;
    type OnXDMRewards = OnXDMRewards;
    type MmrHash = mmr::Hash;
    type MmrProofVerifier = MmrProofVerifier;
    type StorageKeys = StorageKeys;
    type DomainOwner = Domains;
    type HoldIdentifier = HoldIdentifierWrapper;
    type ChannelReserveFee = ChannelReserveFee;
    type ChannelInitReservePortion = ChannelInitReservePortion;
    type DomainRegistration = DomainRegistration;
    type MaxOutgoingMessages = MaxOutgoingMessages;
    type MessengerOrigin = pallet_messenger::EnsureMessengerOrigin;
    type NoteChainTransfer = Transporter;
    type ExtensionWeightInfo = pallet_messenger::extensions::weights::SubstrateWeight<Runtime>;
}

impl<C> frame_system::offchain::CreateTransactionBase<C> for Runtime
where
    RuntimeCall: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type RuntimeCall = RuntimeCall;
}

impl<C> subspace_runtime_primitives::CreateUnsigned<C> for Runtime
where
    RuntimeCall: From<C>,
{
    fn create_unsigned(call: Self::RuntimeCall) -> Self::Extrinsic {
        create_unsigned_general_extrinsic(call)
    }
}

parameter_types! {
    pub const TransporterEndpointId: EndpointId = 1;
    pub const MinimumTransfer: Balance = 1;
}

impl pallet_transporter::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;
    type SelfEndpointId = TransporterEndpointId;
    type Currency = Balances;
    type Sender = Messenger;
    type AccountIdConverter = AccountIdConverter;
    type WeightInfo = pallet_transporter::weights::SubstrateWeight<Runtime>;
    type SkipBalanceTransferChecks = ();
    type MinimumTransfer = MinimumTransfer;
}

parameter_types! {
    pub const MaximumReceiptDrift: BlockNumber = 2;
    pub const InitialDomainTxRange: u64 = INITIAL_DOMAIN_TX_RANGE;
    pub const DomainTxRangeAdjustmentInterval: u64 = 100;
    pub const MinOperatorStake: Balance = 100 * SSC;
    pub const MinNominatorStake: Balance = SSC;
    /// Use the consensus chain's `Normal` extrinsics block size limit as the domain block size limit
    pub MaxDomainBlockSize: u32 = NORMAL_DISPATCH_RATIO * MAX_BLOCK_LENGTH;
    /// Use the consensus chain's `Normal` extrinsics block weight limit as the domain block weight limit
    pub MaxDomainBlockWeight: Weight = NORMAL_DISPATCH_RATIO * BLOCK_WEIGHT_FOR_2_SEC;
    pub const DomainInstantiationDeposit: Balance = 100 * SSC;
    pub const MaxDomainNameLength: u32 = 32;
    pub const BlockTreePruningDepth: u32 = DOMAINS_BLOCK_PRUNING_DEPTH;
    pub const StakeWithdrawalLockingPeriod: BlockNumber = 20;
    pub const StakeEpochDuration: DomainNumber = 5;
    pub TreasuryAccount: AccountId = PalletId(*b"treasury").into_account_truncating();
    pub const MaxPendingStakingOperation: u32 = 512;
    pub const DomainsPalletId: PalletId = PalletId(*b"domains_");
    pub const MaxInitialDomainAccounts: u32 = 20;
    pub const MinInitialDomainAccountBalance: Balance = SSC;
    pub const BundleLongevity: u32 = 5;
    pub const WithdrawalLimit: u32 = 32;
}

// `BlockSlotCount` must at least keep the slot for the current and the parent block, it also need to
// keep enough block slot for bundle validation
const_assert!(BlockSlotCount::get() >= 2 && BlockSlotCount::get() > BundleLongevity::get());

// `BlockHashCount` must greater than `BlockSlotCount` because we need to use the block number found
// with `BlockSlotCount` to get the block hash.
const_assert!(BlockHashCount::get() > BlockSlotCount::get());

// Minimum operator stake must be >= minimum nominator stake since operator is also a nominator.
const_assert!(MinOperatorStake::get() >= MinNominatorStake::get());

pub struct BlockSlot;

impl pallet_domains::BlockSlot<Runtime> for BlockSlot {
    fn future_slot(block_number: BlockNumber) -> Option<Slot> {
        let block_slots = Subspace::block_slots();
        block_slots
            .get(&block_number)
            .map(|slot| *slot + Slot::from(BlockAuthoringDelay::get()))
    }

    fn slot_produced_after(to_check: Slot) -> Option<BlockNumber> {
        let block_slots = Subspace::block_slots();
        for (block_number, slot) in block_slots.into_iter().rev() {
            if to_check > slot {
                return Some(block_number);
            }
        }
        None
    }
}

pub struct OnChainRewards;

impl sp_domains::OnChainRewards<Balance> for OnChainRewards {
    fn on_chain_rewards(chain_id: ChainId, reward: Balance) {
        match chain_id {
            ChainId::Consensus => {
                if let Some(block_author) = Subspace::find_block_reward_address() {
                    let _ = Balances::deposit_creating(&block_author, reward);
                }
            }
            ChainId::Domain(domain_id) => Domains::reward_domain_operators(
                domain_id,
                OperatorRewardSource::XDMProtocolFees,
                reward,
            ),
        }
    }
}

impl pallet_domains::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type DomainOrigin = pallet_domains::EnsureDomainOrigin;
    type DomainHash = DomainHash;
    type Balance = Balance;
    type DomainHeader = DomainHeader;
    type ConfirmationDepthK = ConfirmationDepthK;
    type Currency = Balances;
    type Share = Balance;
    type HoldIdentifier = HoldIdentifierWrapper;
    type BlockTreePruningDepth = BlockTreePruningDepth;
    type ConsensusSlotProbability = SlotProbability;
    type MaxDomainBlockSize = MaxDomainBlockSize;
    type MaxDomainBlockWeight = MaxDomainBlockWeight;
    type MaxDomainNameLength = MaxDomainNameLength;
    type DomainInstantiationDeposit = DomainInstantiationDeposit;
    type WeightInfo = pallet_domains::weights::SubstrateWeight<Runtime>;
    type InitialDomainTxRange = InitialDomainTxRange;
    type DomainTxRangeAdjustmentInterval = DomainTxRangeAdjustmentInterval;
    type MinOperatorStake = MinOperatorStake;
    type MinNominatorStake = MinNominatorStake;
    type StakeWithdrawalLockingPeriod = StakeWithdrawalLockingPeriod;
    type StakeEpochDuration = StakeEpochDuration;
    type TreasuryAccount = TreasuryAccount;
    type MaxPendingStakingOperation = MaxPendingStakingOperation;
    type Randomness = Subspace;
    type PalletId = DomainsPalletId;
    type StorageFee = TransactionFees;
    type BlockTimestamp = pallet_timestamp::Pallet<Runtime>;
    type BlockSlot = BlockSlot;
    type DomainsTransfersTracker = Transporter;
    type MaxInitialDomainAccounts = MaxInitialDomainAccounts;
    type MinInitialDomainAccountBalance = MinInitialDomainAccountBalance;
    type BundleLongevity = BundleLongevity;
    type DomainBundleSubmitted = Messenger;
    type OnDomainInstantiated = Messenger;
    type MmrHash = mmr::Hash;
    type MmrProofVerifier = MmrProofVerifier;
    type FraudProofStorageKeyProvider = StorageKeyProvider;
    type OnChainRewards = OnChainRewards;
    type WithdrawalLimit = WithdrawalLimit;
}

parameter_types! {
    pub const AvgBlockspaceUsageNumBlocks: BlockNumber = 100;
    pub const ProposerTaxOnVotes: (u32, u32) = (1, 10);
}

impl pallet_rewards::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type AvgBlockspaceUsageNumBlocks = AvgBlockspaceUsageNumBlocks;
    type TransactionByteFee = TransactionByteFee;
    type MaxRewardPoints = ConstU32<20>;
    type ProposerTaxOnVotes = ProposerTaxOnVotes;
    type RewardsEnabled = Subspace;
    type FindBlockRewardAddress = Subspace;
    type FindVotingRewardAddresses = Subspace;
    type WeightInfo = pallet_rewards::weights::SubstrateWeight<Runtime>;
    type OnReward = ();
}

mod mmr {
    use super::Runtime;
    pub use pallet_mmr::primitives::*;

    pub type Leaf = <<Runtime as pallet_mmr::Config>::LeafData as LeafDataProvider>::LeafData;
    pub type Hashing = <Runtime as pallet_mmr::Config>::Hashing;
    pub type Hash = <Hashing as sp_runtime::traits::Hash>::Output;
}

pub struct BlockHashProvider;

impl pallet_mmr::BlockHashProvider<BlockNumber, Hash> for BlockHashProvider {
    fn block_hash(block_number: BlockNumber) -> Hash {
        sp_subspace_mmr::subspace_mmr_runtime_interface::consensus_block_hash(block_number)
            .expect("Hash must exist for a given block number.")
    }
}

impl pallet_mmr::Config for Runtime {
    const INDEXING_PREFIX: &'static [u8] = mmr::INDEXING_PREFIX;
    type Hashing = Keccak256;
    type LeafData = SubspaceMmr;
    type OnNewRoot = SubspaceMmr;
    type BlockHashProvider = BlockHashProvider;
    type WeightInfo = ();
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = ();
}

parameter_types! {
    pub const MmrRootHashCount: u32 = 15;
}

impl pallet_subspace_mmr::Config for Runtime {
    type MmrRootHash = mmr::Hash;
    type MmrRootHashCount = MmrRootHashCount;
}

impl pallet_runtime_configs::Config for Runtime {
    type WeightInfo = pallet_runtime_configs::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const MaxSignatories: u32 = 100;
}

macro_rules! deposit {
    ($name:ident, $item_fee:expr, $items:expr, $bytes:expr) => {
        pub struct $name;

        impl Get<Balance> for $name {
            fn get() -> Balance {
                $item_fee.saturating_mul($items.into()).saturating_add(
                    TransactionFees::transaction_byte_fee().saturating_mul($bytes.into()),
                )
            }
        }
    };
}

// One storage item; key size is 32; value is size 4+4+16+32 bytes = 56 bytes.
// Each multisig costs 20 SSC + bytes_of_storge * TransactionByteFee
deposit!(DepositBaseFee, 20 * SSC, 1u32, 88u32);

// Additional storage item size of 32 bytes.
deposit!(DepositFactor, 0u128, 0u32, 32u32);

impl pallet_multisig::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type DepositBase = DepositBaseFee;
    type DepositFactor = DepositFactor;
    type MaxSignatories = MaxSignatories;
    type WeightInfo = pallet_multisig::weights::SubstrateWeight<Runtime>;
}

construct_runtime!(
    pub struct Runtime {
        System: frame_system = 0,
        Timestamp: pallet_timestamp = 1,

        Subspace: pallet_subspace = 2,
        Rewards: pallet_rewards = 9,

        Balances: pallet_balances = 4,
        TransactionFees: pallet_transaction_fees = 12,
        TransactionPayment: pallet_transaction_payment = 5,
        Utility: pallet_utility = 8,

        Domains: pallet_domains = 11,
        RuntimeConfigs: pallet_runtime_configs = 14,

        Mmr: pallet_mmr = 30,
        SubspaceMmr: pallet_subspace_mmr = 31,

        // messenger stuff
        // Note: Indexes should match with indexes on other chains and domains
        Messenger: pallet_messenger exclude_parts { Inherent } = 60,
        Transporter: pallet_transporter = 61,

        // Multisig
        Multisig: pallet_multisig = 90,

        // Reserve some room for other pallets as we'll remove sudo pallet eventually.
        Sudo: pallet_sudo = 100,
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
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckMortality<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    DisablePallets,
    pallet_subspace::extensions::SubspaceExtension<Runtime>,
    pallet_domains::extensions::DomainsExtension<Runtime>,
    pallet_messenger::extensions::MessengerExtension<Runtime>,
);
/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;
/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;

impl pallet_subspace::extensions::MaybeSubspaceCall<Runtime> for RuntimeCall {
    fn maybe_subspace_call(&self) -> Option<&pallet_subspace::Call<Runtime>> {
        match self {
            RuntimeCall::Subspace(call) => Some(call),
            _ => None,
        }
    }
}

impl pallet_domains::extensions::MaybeDomainsCall<Runtime> for RuntimeCall {
    fn maybe_domains_call(&self) -> Option<&pallet_domains::Call<Runtime>> {
        match self {
            RuntimeCall::Domains(call) => Some(call),
            _ => None,
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

fn extract_segment_headers(ext: &UncheckedExtrinsic) -> Option<Vec<SegmentHeader>> {
    match &ext.function {
        RuntimeCall::Subspace(pallet_subspace::Call::store_segment_headers { segment_headers }) => {
            Some(segment_headers.clone())
        }
        _ => None,
    }
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

            let mmr_root = SubspaceMmr::mmr_root_hash(consensus_block_number)?;

            Some(
                pallet_mmr::verify_leaves_proof::<mmr::Hashing, _>(
                    mmr_root,
                    vec![mmr::DataOrHash::Data(
                        EncodableOpaqueLeaf(opaque_mmr_leaf.0.clone()).into_opaque_leaf(),
                    )],
                    proof,
                )
                .is_ok(),
            )
        }
        _ => None,
    }
}

// This code must be kept in sync with `crates/subspace-runtime/src/object_mapping.rs`.
fn extract_utility_block_object_mapping(
    mut base_offset: u32,
    objects: &mut Vec<BlockObject>,
    call: &pallet_utility::Call<Runtime>,
    mut recursion_depth_left: u16,
) {
    if recursion_depth_left == 0 {
        return;
    }

    recursion_depth_left -= 1;

    // Add enum variant to the base offset.
    base_offset += 1;

    match call {
        pallet_utility::Call::batch { calls }
        | pallet_utility::Call::batch_all { calls }
        | pallet_utility::Call::force_batch { calls } => {
            base_offset += Compact::compact_len(&(calls.len() as u32)) as u32;

            for call in calls {
                extract_call_block_object_mapping(base_offset, objects, call, recursion_depth_left);

                base_offset += call.encoded_size() as u32;
            }
        }
        pallet_utility::Call::as_derivative { index, call } => {
            base_offset += index.encoded_size() as u32;

            extract_call_block_object_mapping(
                base_offset,
                objects,
                call.as_ref(),
                recursion_depth_left,
            );
        }
        pallet_utility::Call::dispatch_as { as_origin, call } => {
            base_offset += as_origin.encoded_size() as u32;

            extract_call_block_object_mapping(
                base_offset,
                objects,
                call.as_ref(),
                recursion_depth_left,
            );
        }
        pallet_utility::Call::with_weight { call, .. } => {
            extract_call_block_object_mapping(
                base_offset,
                objects,
                call.as_ref(),
                recursion_depth_left,
            );
        }
        pallet_utility::Call::__Ignore(_, _) => {
            // Ignore.
        }
    }
}

fn extract_call_block_object_mapping(
    mut base_offset: u32,
    objects: &mut Vec<BlockObject>,
    call: &RuntimeCall,
    recursion_depth_left: u16,
) {
    // Add RuntimeCall enum variant to the base offset.
    base_offset += 1;

    match call {
        // Extract the actual object mappings.
        RuntimeCall::System(frame_system::Call::remark { remark }) => {
            objects.push(BlockObject {
                hash: hashes::blake3_hash(remark),
                // Add frame_system::Call enum variant to the base offset.
                offset: base_offset + 1,
            });
        }
        RuntimeCall::System(frame_system::Call::remark_with_event { remark }) => {
            objects.push(BlockObject {
                hash: hashes::blake3_hash(remark),
                // Add frame_system::Call enum variant to the base offset.
                offset: base_offset + 1,
            });
        }

        // Recursively extract object mappings for the call.
        RuntimeCall::Utility(call) => {
            extract_utility_block_object_mapping(base_offset, objects, call, recursion_depth_left)
        }
        // Other calls don't contain object mappings.
        _ => {}
    }
}

fn extract_block_object_mapping(block: Block) -> BlockObjectMapping {
    let mut block_object_mapping = BlockObjectMapping::default();
    let mut base_offset =
        block.header.encoded_size() + Compact::compact_len(&(block.extrinsics.len() as u32));
    for extrinsic in block.extrinsics {
        let preamble_size = extrinsic.preamble.encoded_size();
        // Extrinsic starts with vector length followed by preamble and
        // `function` encoding.
        let base_extrinsic_offset = base_offset
            + Compact::compact_len(&((preamble_size + extrinsic.function.encoded_size()) as u32))
            + preamble_size;

        extract_call_block_object_mapping(
            base_extrinsic_offset as u32,
            block_object_mapping.objects_mut(),
            &extrinsic.function,
            MAX_CALL_RECURSION_DEPTH as u16,
        );

        base_offset += extrinsic.encoded_size();
    }

    block_object_mapping
}

fn extract_successful_bundles(
    domain_id: DomainId,
    extrinsics: Vec<UncheckedExtrinsic>,
) -> OpaqueBundles<Block, DomainHeader, Balance> {
    let successful_bundles = Domains::successful_bundles(domain_id);
    extrinsics
        .into_iter()
        .filter_map(|uxt| match uxt.function {
            RuntimeCall::Domains(pallet_domains::Call::submit_bundle { opaque_bundle })
                if opaque_bundle.domain_id() == domain_id
                    && successful_bundles.contains(&opaque_bundle.hash()) =>
            {
                Some(opaque_bundle)
            }
            _ => None,
        })
        .collect()
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
        frame_system::CheckWeight::<Runtime>::new(),
        // for unsigned extrinsic, transaction fee check will be skipped
        // so set a default value
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0u128),
        DisablePallets,
        pallet_subspace::extensions::SubspaceExtension::<Runtime>::new(),
        pallet_domains::extensions::DomainsExtension::<Runtime>::new(),
        pallet_messenger::extensions::MessengerExtension::<Runtime>::new(),
    );

    UncheckedExtrinsic::new_transaction(call, extra)
}

struct RewardAddress([u8; 32]);

impl From<PublicKey> for RewardAddress {
    #[inline]
    fn from(public_key: PublicKey) -> Self {
        Self(*public_key)
    }
}

impl From<RewardAddress> for AccountId32 {
    #[inline]
    fn from(reward_address: RewardAddress) -> Self {
        reward_address.0.into()
    }
}

pub struct StorageKeyProvider;
impl FraudProofStorageKeyProvider<NumberFor<Block>> for StorageKeyProvider {
    fn storage_key(req: FraudProofStorageKeyRequest<NumberFor<Block>>) -> Vec<u8> {
        match req {
            FraudProofStorageKeyRequest::InvalidInherentExtrinsicData => {
                pallet_domains::BlockInherentExtrinsicData::<Runtime>::hashed_key().to_vec()
            }
            FraudProofStorageKeyRequest::SuccessfulBundles(domain_id) => {
                pallet_domains::SuccessfulBundles::<Runtime>::hashed_key_for(domain_id)
            }
            FraudProofStorageKeyRequest::DomainAllowlistUpdates(domain_id) => {
                Messenger::domain_allow_list_update_storage_key(domain_id)
            }
            FraudProofStorageKeyRequest::DomainRuntimeUpgrades => {
                pallet_domains::DomainRuntimeUpgrades::<Runtime>::hashed_key().to_vec()
            }
            FraudProofStorageKeyRequest::RuntimeRegistry(runtime_id) => {
                pallet_domains::RuntimeRegistry::<Runtime>::hashed_key_for(runtime_id)
            }
            FraudProofStorageKeyRequest::DomainSudoCall(domain_id) => {
                pallet_domains::DomainSudoCalls::<Runtime>::hashed_key_for(domain_id)
            }
            FraudProofStorageKeyRequest::EvmDomainContractCreationAllowedByCall(domain_id) => {
                pallet_domains::EvmDomainContractCreationAllowedByCalls::<Runtime>::hashed_key_for(
                    domain_id,
                )
            }
            FraudProofStorageKeyRequest::MmrRoot(block_number) => {
                pallet_subspace_mmr::MmrRootHashes::<Runtime>::hashed_key_for(block_number)
            }
        }
    }
}

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block);
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

    impl sp_objects::ObjectsApi<Block> for Runtime {
        fn extract_block_object_mapping(block: Block) -> BlockObjectMapping {
            extract_block_object_mapping(block)
        }
    }

    impl sp_consensus_subspace::SubspaceApi<Block, PublicKey> for Runtime {
        fn pot_parameters() -> PotParameters {
            Subspace::pot_parameters()
        }

        fn solution_ranges() -> SolutionRanges {
            Subspace::solution_ranges()
        }

        fn submit_vote_extrinsic(
            signed_vote: SignedVote<NumberFor<Block>, BlockHashFor<Block>, PublicKey>,
        ) {
            let SignedVote { vote, signature } = signed_vote;
            let Vote::V0 {
                height,
                parent_hash,
                slot,
                solution,
                proof_of_time,
                future_proof_of_time,
            } = vote;

            Subspace::submit_vote(SignedVote {
                vote: Vote::V0 {
                    height,
                    parent_hash,
                    slot,
                    solution: solution.into_reward_address_format::<RewardAddress, AccountId32>(),
                    proof_of_time,
                    future_proof_of_time,
                },
                signature,
            })
        }

        fn history_size() -> HistorySize {
            <pallet_subspace::Pallet<Runtime>>::history_size()
        }

        fn max_pieces_in_sector() -> u16 {
            MAX_PIECES_IN_SECTOR
        }

        fn segment_commitment(segment_index: SegmentIndex) -> Option<SegmentCommitment> {
            Subspace::segment_commitment(segment_index)
        }

        fn extract_segment_headers(ext: &ExtrinsicFor<Block>) -> Option<Vec<SegmentHeader >> {
            extract_segment_headers(ext)
        }

        fn is_inherent(ext: &ExtrinsicFor<Block>) -> bool {
            match &ext.function {
                RuntimeCall::Subspace(call) => Subspace::is_inherent(call),
                RuntimeCall::Timestamp(call) => Timestamp::is_inherent(call),
                _ => false,
            }
        }

        fn root_plot_public_key() -> Option<PublicKey> {
            Subspace::root_plot_public_key()
        }

        fn should_adjust_solution_range() -> bool {
            Subspace::should_adjust_solution_range()
        }

        fn chain_constants() -> ChainConstants {
            ChainConstants::V0 {
                confirmation_depth_k: ConfirmationDepthK::get(),
                block_authoring_delay: Slot::from(BlockAuthoringDelay::get()),
                era_duration: EraDuration::get(),
                slot_probability: SlotProbability::get(),
                slot_duration: SlotDuration::from_millis(SLOT_DURATION),
                recent_segments: RecentSegments::get(),
                recent_history_fraction: RecentHistoryFraction::get(),
                min_sector_lifetime: MinSectorLifetime::get(),
            }
        }
    }

    impl sp_domains::DomainsApi<Block, DomainHeader> for Runtime {
        fn submit_bundle_unsigned(
            opaque_bundle: OpaqueBundle<NumberFor<Block>, BlockHashFor<Block>, DomainHeader, Balance>,
        ) {
            Domains::submit_bundle_unsigned(opaque_bundle)
        }

        fn submit_receipt_unsigned(
            singleton_receipt: sp_domains::SealedSingletonReceipt<NumberFor<Block>, BlockHashFor<Block>, DomainHeader, Balance>,
        ) {
            Domains::submit_receipt_unsigned(singleton_receipt)
        }

        fn extract_successful_bundles(
            domain_id: DomainId,
            extrinsics: Vec<ExtrinsicFor<Block>>,
        ) -> OpaqueBundles<Block, DomainHeader, Balance> {
            extract_successful_bundles(domain_id, extrinsics)
        }

        fn extrinsics_shuffling_seed() -> Randomness {
            Randomness::from(Domains::extrinsics_shuffling_seed().to_fixed_bytes())
        }

        fn domain_runtime_code(domain_id: DomainId) -> Option<Vec<u8>> {
            Domains::domain_runtime_code(domain_id)
        }

        fn runtime_id(domain_id: DomainId) -> Option<sp_domains::RuntimeId> {
            Domains::runtime_id(domain_id)
        }

        fn runtime_upgrades() -> Vec<sp_domains::RuntimeId> {
            Domains::runtime_upgrades()
        }

        fn domain_instance_data(domain_id: DomainId) -> Option<(DomainInstanceData, NumberFor<Block>)> {
            Domains::domain_instance_data(domain_id)
        }

        fn domain_timestamp() -> Moment {
            Domains::timestamp()
        }

        fn timestamp() -> Moment {
            Timestamp::now()
        }

        fn consensus_transaction_byte_fee() -> Balance {
            Domains::consensus_transaction_byte_fee()
        }

        fn consensus_chain_byte_fee() -> Balance {
            DOMAIN_STORAGE_FEE_MULTIPLIER * TransactionFees::transaction_byte_fee()
        }

        fn domain_tx_range(_: DomainId) -> U256 {
            U256::MAX
        }

        fn genesis_state_root(domain_id: DomainId) -> Option<H256> {
            Domains::genesis_state_root(domain_id)
        }

        fn head_receipt_number(domain_id: DomainId) -> DomainNumber {
            Domains::head_receipt_number(domain_id)
        }

        fn oldest_unconfirmed_receipt_number(domain_id: DomainId) -> Option<DomainNumber> {
            Domains::oldest_unconfirmed_receipt_number(domain_id)
        }

        fn domain_bundle_limit(domain_id: DomainId) -> Option<sp_domains::DomainBundleLimit> {
            Domains::domain_bundle_limit(domain_id).ok().flatten()
        }

        fn non_empty_er_exists(domain_id: DomainId) -> bool {
            Domains::non_empty_er_exists(domain_id)
        }

        fn domain_best_number(domain_id: DomainId) -> Option<DomainNumber> {
            Domains::domain_best_number(domain_id).ok()
        }

        fn execution_receipt(receipt_hash: DomainHash) -> Option<ExecutionReceiptFor<DomainHeader, Block, Balance>> {
            Domains::execution_receipt(receipt_hash)
        }

        fn domain_operators(domain_id: DomainId) -> Option<(BTreeMap<OperatorId, Balance>, Vec<OperatorId>)> {
            Domains::domain_staking_summary(domain_id).map(|summary| {
                let next_operators = summary.next_operators.into_iter().collect();
                (summary.current_operators, next_operators)
            })
        }

        fn receipt_hash(domain_id: DomainId, domain_number: DomainNumber) -> Option<DomainHash> {
            Domains::receipt_hash(domain_id, domain_number)
        }

        fn latest_confirmed_domain_block(domain_id: DomainId) -> Option<(DomainNumber, DomainHash)>{
            Domains::latest_confirmed_domain_block(domain_id)
        }

        fn is_bad_er_pending_to_prune(domain_id: DomainId, receipt_hash: DomainHash) -> bool {
            Domains::execution_receipt(receipt_hash).map(
                |er| Domains::is_bad_er_pending_to_prune(domain_id, er.domain_block_number)
            )
            .unwrap_or(false)
        }

        fn storage_fund_account_balance(operator_id: OperatorId) -> Balance {
            Domains::storage_fund_account_balance(operator_id)
        }

        fn is_domain_runtime_upgraded_since(domain_id: DomainId, at: NumberFor<Block>) -> Option<bool> {
            Domains::is_domain_runtime_upgraded_since(domain_id, at)
        }

        fn domain_sudo_call(domain_id: DomainId) -> Option<Vec<u8>> {
            Domains::domain_sudo_call(domain_id)
        }

        fn evm_domain_contract_creation_allowed_by_call(domain_id: DomainId) -> Option<PermissionedActionAllowedBy<EthereumAccountId>> {
            Domains::evm_domain_contract_creation_allowed_by_call(domain_id)
        }

        fn last_confirmed_domain_block_receipt(domain_id: DomainId) -> Option<ExecutionReceiptFor<DomainHeader, Block, Balance>>{
            Domains::latest_confirmed_domain_execution_receipt(domain_id)
        }
    }

    impl sp_domains::BundleProducerElectionApi<Block, Balance> for Runtime {
        fn bundle_producer_election_params(domain_id: DomainId) -> Option<BundleProducerElectionParams<Balance>> {
            Domains::bundle_producer_election_params(domain_id)
        }

        fn operator(operator_id: OperatorId) -> Option<(OperatorPublicKey, Balance)> {
            Domains::operator(operator_id)
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

    impl sp_messenger::MessengerApi<Block, BlockNumber, BlockHashFor<Block>> for Runtime {
        fn is_xdm_mmr_proof_valid(
            extrinsic: &ExtrinsicFor<Block>
        ) -> Option<bool> {
            is_xdm_mmr_proof_valid(extrinsic)
        }

        fn extract_xdm_mmr_proof(ext: &ExtrinsicFor<Block>) -> Option<ConsensusChainMmrLeafProof<BlockNumber, BlockHashFor<Block>, sp_core::H256>> {
            match &ext.function {
                RuntimeCall::Messenger(pallet_messenger::Call::relay_message { msg })
                | RuntimeCall::Messenger(pallet_messenger::Call::relay_message_response { msg }) => {
                    Some(msg.proof.consensus_mmr_proof())
                }
                _ => None,
            }
        }

        fn batch_extract_xdm_mmr_proof(extrinsics: &Vec<ExtrinsicFor<Block>>) -> BTreeMap<u32, ConsensusChainMmrLeafProof<BlockNumber, BlockHashFor<Block>, sp_core::H256>> {
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

        fn confirmed_domain_block_storage_key(domain_id: DomainId) -> Vec<u8> {
            Domains::confirmed_domain_block_storage_key(domain_id)
        }

        fn outbox_storage_key(message_key: MessageKey) -> Vec<u8> {
            Messenger::outbox_storage_key(message_key)
        }

        fn inbox_response_storage_key(message_key: MessageKey) -> Vec<u8> {
            Messenger::inbox_response_storage_key(message_key)
        }

        fn domain_chains_allowlist_update(domain_id: DomainId) -> Option<DomainAllowlistUpdates>{
            Messenger::domain_chains_allowlist_update(domain_id)
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

    impl sp_messenger::RelayerApi<Block, BlockNumber, BlockNumber, BlockHashFor<Block>> for Runtime {
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

    impl sp_domains_fraud_proof::FraudProofApi<Block, DomainHeader> for Runtime {
        fn submit_fraud_proof_unsigned(fraud_proof: FraudProof<NumberFor<Block>, BlockHashFor<Block>, DomainHeader, H256>) {
            Domains::submit_fraud_proof_unsigned(fraud_proof)
        }

        fn fraud_proof_storage_key(req: FraudProofStorageKeyRequest<NumberFor<Block>>) -> Vec<u8> {
            <StorageKeyProvider as FraudProofStorageKeyProvider<NumberFor<Block>>>::storage_key(req)
        }
    }

    impl mmr::MmrApi<Block, mmr::Hash, BlockNumber> for Runtime {
        fn mmr_root() -> Result<mmr::Hash, mmr::Error> {
            Ok(Mmr::mmr_root())
        }

        fn mmr_leaf_count() -> Result<mmr::LeafIndex, mmr::Error> {
            Ok(Mmr::mmr_leaves())
        }

        fn generate_proof(
            block_numbers: Vec<BlockNumber>,
            best_known_block_number: Option<BlockNumber>,
        ) -> Result<(Vec<mmr::EncodableOpaqueLeaf>, mmr::LeafProof<mmr::Hash>), mmr::Error> {
            Mmr::generate_proof(block_numbers, best_known_block_number).map(
                |(leaves, proof)| {
                    (
                        leaves
                            .into_iter()
                            .map(|leaf| mmr::EncodableOpaqueLeaf::from_leaf(&leaf))
                            .collect(),
                        proof,
                    )
                },
            )
        }

        fn verify_proof(leaves: Vec<mmr::EncodableOpaqueLeaf>, proof: mmr::LeafProof<mmr::Hash>)
            -> Result<(), mmr::Error>
        {
            let leaves = leaves.into_iter().map(|leaf|
                leaf.into_opaque_leaf()
                .try_decode()
                .ok_or(mmr::Error::Verify)).collect::<Result<Vec<mmr::Leaf>, mmr::Error>>()?;
            Mmr::verify_leaves(leaves, proof)
        }

        fn verify_proof_stateless(
            root: mmr::Hash,
            leaves: Vec<mmr::EncodableOpaqueLeaf>,
            proof: mmr::LeafProof<mmr::Hash>
        ) -> Result<(), mmr::Error> {
            let nodes = leaves.into_iter().map(|leaf|mmr::DataOrHash::Data(leaf.into_opaque_leaf())).collect();
            pallet_mmr::verify_leaves_proof::<mmr::Hashing, _>(root, nodes, proof)
        }
    }

    impl subspace_test_primitives::OnchainStateApi<Block, AccountId, Balance> for Runtime {
        fn free_balance(account_id: AccountId) -> Balance {
            Balances::free_balance(account_id)
        }

        fn get_open_channel_for_chain(dst_chain_id: ChainId) -> Option<ChannelId> {
            Messenger::get_open_channel_for_chain(dst_chain_id)
        }

        fn verify_proof_and_extract_leaf(mmr_leaf_proof: ConsensusChainMmrLeafProof<NumberFor<Block>, BlockHashFor<Block>, H256>) -> Option<mmr::Leaf> {
            <MmrProofVerifier as sp_subspace_mmr::MmrProofVerifier<_, _, _,>>::verify_proof_and_extract_leaf(mmr_leaf_proof)
        }

        fn domain_balance(domain_id: DomainId) -> Balance {
            Transporter::domain_balances(domain_id)
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
            build_state::<RuntimeGenesisConfig>(config)
        }

        fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
            get_preset::<RuntimeGenesisConfig>(id, |_| None)
        }

        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            vec![]
        }
    }
}

/// Disable balance transfers, if configured in the runtime.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, Default, TypeInfo)]
pub struct DisablePallets;

impl DisablePallets {
    fn do_validate_unsigned(call: &RuntimeCall) -> TransactionValidity {
        if matches!(call, RuntimeCall::Domains(_)) && !RuntimeConfigs::enable_domains() {
            InvalidTransaction::Call.into()
        } else {
            Ok(ValidTransaction::default())
        }
    }

    fn do_validate_signed(call: &RuntimeCall) -> TransactionValidity {
        // Disable normal balance transfers.
        if !RuntimeConfigs::enable_balance_transfers() && contains_balance_transfer(call) {
            Err(InvalidTransaction::Call.into())
        } else {
            Ok(ValidTransaction::default())
        }
    }
}

impl TransactionExtension<RuntimeCall> for DisablePallets {
    const IDENTIFIER: &'static str = "DisablePallets";
    type Implicit = ();
    type Val = ();
    type Pre = ();

    // TODO: calculate weight for extension
    fn weight(&self, _call: &RuntimeCall) -> Weight {
        // there is always one storage read
        <Runtime as frame_system::Config>::DbWeight::get().reads(1)
    }

    fn validate(
        &self,
        origin: OriginFor<Runtime>,
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Encode,
        _source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCallFor<Runtime>> {
        let validity = if origin.as_system_origin_signer().is_some() {
            Self::do_validate_signed(call)?
        } else {
            ValidTransaction::default()
        };

        Ok((validity, (), origin))
    }

    impl_tx_ext_default!(RuntimeCallFor<Runtime>; prepare);

    fn bare_validate(
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> TransactionValidity {
        Self::do_validate_unsigned(call)
    }

    fn bare_validate_and_prepare(
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> Result<(), TransactionValidityError> {
        Self::do_validate_unsigned(call)?;
        Ok(())
    }
}

fn contains_balance_transfer(call: &RuntimeCall) -> bool {
    for call in nested_call_iter::<Runtime>(call) {
        // Any other calls might contain nested calls, so we can only return early if we find a
        // balance transfer call.
        if let RuntimeCall::Balances(
            pallet_balances::Call::transfer_allow_death { .. }
            | pallet_balances::Call::transfer_keep_alive { .. }
            | pallet_balances::Call::transfer_all { .. },
        ) = call
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use crate::Runtime;
    use pallet_domains::bundle_storage_fund::AccountType;
    use sp_domains::OperatorId;
    use sp_runtime::traits::AccountIdConversion;

    #[test]
    fn test_bundle_storage_fund_account_uniqueness() {
        let _: <Runtime as frame_system::Config>::AccountId = <Runtime as pallet_domains::Config>::PalletId::get()
            .try_into_sub_account((AccountType::StorageFund, OperatorId::MAX))
            .expect(
                "The `AccountId` type must be large enough to fit the seed of the bundle storage fund account",
            );
    }
}
