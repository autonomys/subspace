use crate::block_tree::BlockTreeNode;
use crate::domain_registry::{calculate_max_bundle_weight_and_size, DomainConfig, DomainObject};
use crate::staking::Operator;
use crate::{
    self as pallet_domains, BalanceOf, BlockSlot, BlockTree, BlockTreeNodes, BundleError, Config,
    ConsensusBlockHash, DomainBlockNumberFor, DomainHashingFor, DomainRegistry, ExecutionInbox,
    ExecutionReceiptOf, FraudProofError, FungibleHoldId, HeadReceiptNumber, NextDomainId,
    Operators, ReceiptHashFor,
};
use codec::{Decode, Encode, MaxEncodedLen};
use core::mem;
use domain_runtime_primitives::opaque::Header as DomainHeader;
use domain_runtime_primitives::BlockNumber as DomainBlockNumber;
use frame_support::dispatch::{DispatchInfo, RawOrigin};
use frame_support::traits::{ConstU16, ConstU32, ConstU64, Currency, Hooks, VariantCount};
use frame_support::weights::constants::ParityDbWeight;
use frame_support::weights::{IdentityFee, Weight};
use frame_support::{assert_err, assert_ok, parameter_types, PalletId};
use frame_system::mocking::MockUncheckedExtrinsic;
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_core::crypto::Pair;
use sp_core::storage::{StateVersion, StorageKey};
use sp_core::{Get, H256, U256};
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::proof_provider_and_verifier::StorageProofProvider;
use sp_domains::storage::RawGenesis;
use sp_domains::{
    BundleHeader, ChainId, DomainId, DomainsHoldIdentifier, ExecutionReceipt, ExtrinsicDigest,
    InboxedBundle, InvalidBundleType, OpaqueBundle, OperatorAllowList, OperatorId, OperatorPair,
    ProofOfElection, RuntimeType, SealedBundleHeader, StakingHoldIdentifier,
};
use sp_domains_fraud_proof::fraud_proof::{
    FraudProof, InvalidBlockFeesProof, InvalidBundlesFraudProof, InvalidDomainBlockHashProof,
    InvalidExtrinsicsRootProof, ValidBundleDigest,
};
use sp_domains_fraud_proof::{
    FraudProofExtension, FraudProofHostFunctions, FraudProofVerificationInfoRequest,
    FraudProofVerificationInfoResponse, SetCodeExtrinsic,
};
use sp_runtime::traits::{
    AccountIdConversion, BlakeTwo256, BlockNumberProvider, Hash as HashT, IdentityLookup, One,
};
use sp_runtime::{BuildStorage, Digest, OpaqueExtrinsic, Saturating};
use sp_state_machine::backend::AsTrieBackend;
use sp_state_machine::{prove_read, Backend, TrieBackendBuilder};
use sp_std::sync::Arc;
use sp_trie::trie_types::TrieDBMutBuilderV1;
use sp_trie::{LayoutV1, PrefixedMemoryDB, StorageProof, TrieMut};
use sp_version::RuntimeVersion;
use subspace_core_primitives::{Randomness, U256 as P256};
use subspace_runtime_primitives::{Moment, StorageFee, SSC};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;
type Balance = u128;

// TODO: Remove when DomainRegistry is usable.
const DOMAIN_ID: DomainId = DomainId::new(0);

// Operator id used for testing
const OPERATOR_ID: OperatorId = 0u64;

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Balances: pallet_balances,
        Domains: pallet_domains,
        DomainExecutive: domain_pallet_executive,
        BlockFees: pallet_block_fees,
    }
);

type BlockNumber = u64;
type Hash = H256;
type AccountId = u128;

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ParityDbWeight;
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type RuntimeTask = RuntimeTask;
    type Nonce = u64;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<2>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const MaximumReceiptDrift: BlockNumber = 128;
    pub const InitialDomainTxRange: u64 = 3;
    pub const DomainTxRangeAdjustmentInterval: u64 = 100;
    pub const DomainRuntimeUpgradeDelay: BlockNumber = 100;
    pub const MaxBundlesPerBlock: u32 = 10;
    pub const MaxDomainBlockSize: u32 = 1024 * 1024;
    pub const MaxDomainBlockWeight: Weight = Weight::from_parts(1024 * 1024, 0);
    pub const DomainInstantiationDeposit: Balance = 100;
    pub const MaxDomainNameLength: u32 = 16;
    pub const BlockTreePruningDepth: u32 = 16;
    pub const SlotProbability: (u64, u64) = (1, 6);
}

pub struct ConfirmationDepthK;

impl Get<BlockNumber> for ConfirmationDepthK {
    fn get() -> BlockNumber {
        10
    }
}

#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub enum HoldIdentifier {
    Domains(DomainsHoldIdentifier),
}

impl pallet_domains::HoldIdentifier<Test> for HoldIdentifier {
    fn staking_staked(operator_id: OperatorId) -> FungibleHoldId<Test> {
        Self::Domains(DomainsHoldIdentifier::Staking(
            StakingHoldIdentifier::Staked(operator_id),
        ))
    }

    fn domain_instantiation_id(domain_id: DomainId) -> FungibleHoldId<Test> {
        Self::Domains(DomainsHoldIdentifier::DomainInstantiation(domain_id))
    }

    fn storage_fund_withdrawal(operator_id: OperatorId) -> Self {
        Self::Domains(DomainsHoldIdentifier::StorageFund(operator_id))
    }
}

impl VariantCount for HoldIdentifier {
    const VARIANT_COUNT: u32 = mem::variant_count::<Self>() as u32;
}

parameter_types! {
    pub const MaxHolds: u32 = 10;
    pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = HoldIdentifier;
    type MaxHolds = MaxHolds;
}

parameter_types! {
    pub const MinOperatorStake: Balance = 100 * SSC;
    pub const MinNominatorStake: Balance = SSC;
    pub const StakeWithdrawalLockingPeriod: DomainBlockNumber = 5;
    pub const StakeEpochDuration: DomainBlockNumber = 5;
    pub TreasuryAccount: u128 = PalletId(*b"treasury").into_account_truncating();
    pub const BlockReward: Balance = 10 * SSC;
    pub const MaxPendingStakingOperation: u32 = 100;
    pub const MaxNominators: u32 = 5;
    pub const DomainsPalletId: PalletId = PalletId(*b"domains_");
    pub const DomainChainByteFee: Balance = 1;
    pub const MaxInitialDomainAccounts: u32 = 5;
    pub const MinInitialDomainAccountBalance: Balance = SSC;
}

pub struct MockRandomness;

impl frame_support::traits::Randomness<Hash, BlockNumber> for MockRandomness {
    fn random(_: &[u8]) -> (Hash, BlockNumber) {
        (Default::default(), Default::default())
    }
}

const SLOT_DURATION: u64 = 1000;

impl pallet_timestamp::Config for Test {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = Moment;
    type OnTimestampSet = ();
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = ();
}

pub struct DummyStorageFee;

impl StorageFee<Balance> for DummyStorageFee {
    fn transaction_byte_fee() -> Balance {
        SSC
    }
    fn note_storage_fees(_fee: Balance) {}
}

pub struct DummyBlockSlot;

impl BlockSlot for DummyBlockSlot {
    fn current_slot() -> sp_consensus_slots::Slot {
        0u64.into()
    }

    fn future_slot() -> sp_consensus_slots::Slot {
        0u64.into()
    }
}

pub struct MockDomainsTransfersTracker;

impl sp_domains::DomainsTransfersTracker<Balance> for MockDomainsTransfersTracker {
    type Error = ();

    fn initialize_domain_balance(
        _domain_id: DomainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn note_transfer(
        _from_chain_id: ChainId,
        _to_chain_id: ChainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn confirm_transfer(
        _from_chain_id: ChainId,
        _to_chain_id: ChainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_rejected_transfer(
        _from_chain_id: ChainId,
        _to_chain_id: ChainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reject_transfer(
        _from_chain_id: ChainId,
        _to_chain_id: ChainId,
        _amount: Balance,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn reduce_domain_balance(_domain_id: DomainId, _amount: Balance) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl pallet_domains::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type DomainHash = sp_core::H256;
    type DomainHeader = DomainHeader;
    type ConfirmationDepthK = ConfirmationDepthK;
    type DomainRuntimeUpgradeDelay = DomainRuntimeUpgradeDelay;
    type Currency = Balances;
    type HoldIdentifier = HoldIdentifier;
    type WeightInfo = pallet_domains::weights::SubstrateWeight<Test>;
    type InitialDomainTxRange = InitialDomainTxRange;
    type DomainTxRangeAdjustmentInterval = DomainTxRangeAdjustmentInterval;
    type MinOperatorStake = MinOperatorStake;
    type MinNominatorStake = MinNominatorStake;
    type MaxDomainBlockSize = MaxDomainBlockSize;
    type MaxDomainBlockWeight = MaxDomainBlockWeight;
    type MaxBundlesPerBlock = MaxBundlesPerBlock;
    type DomainInstantiationDeposit = DomainInstantiationDeposit;
    type MaxDomainNameLength = MaxDomainNameLength;
    type Share = Balance;
    type BlockTreePruningDepth = BlockTreePruningDepth;
    type StakeWithdrawalLockingPeriod = StakeWithdrawalLockingPeriod;
    type StakeEpochDuration = StakeEpochDuration;
    type TreasuryAccount = TreasuryAccount;
    type MaxPendingStakingOperation = MaxPendingStakingOperation;
    type MaxNominators = MaxNominators;
    type Randomness = MockRandomness;
    type SudoId = ();
    type PalletId = DomainsPalletId;
    type StorageFee = DummyStorageFee;
    type BlockSlot = DummyBlockSlot;
    type DomainsTransfersTracker = MockDomainsTransfersTracker;
    type MaxInitialDomainAccounts = MaxInitialDomainAccounts;
    type MinInitialDomainAccountBalance = MinInitialDomainAccountBalance;
    type ConsensusSlotProbability = SlotProbability;
    type DomainBundleSubmitted = ();
}

pub struct ExtrinsicStorageFees;

impl domain_pallet_executive::ExtrinsicStorageFees<Test> for ExtrinsicStorageFees {
    fn extract_signer(_xt: MockUncheckedExtrinsic<Test>) -> (Option<AccountId>, DispatchInfo) {
        (None, DispatchInfo::default())
    }

    fn on_storage_fees_charged(_charged_fees: Balance, _tx_size: u32) {}
}

impl domain_pallet_executive::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type Currency = Balances;
    type LengthToFee = IdentityFee<Balance>;
    type ExtrinsicStorageFees = ExtrinsicStorageFees;
}

impl pallet_block_fees::Config for Test {
    type Balance = Balance;
    type DomainChainByteFee = DomainChainByteFee;
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    t.into()
}

pub(crate) struct MockDomainFraudProofExtension {
    block_randomness: Randomness,
    timestamp: Moment,
    runtime_code: Vec<u8>,
    tx_range: bool,
    is_inherent: bool,
    is_decodable: bool,
    domain_total_stake: Balance,
    bundle_slot_probability: (u64, u64),
    operator_stake: Balance,
    maybe_illegal_extrinsic_index: Option<u32>,
    is_valid_xdm: Option<bool>,
}

impl FraudProofHostFunctions for MockDomainFraudProofExtension {
    fn get_fraud_proof_verification_info(
        &self,
        _consensus_block_hash: H256,
        fraud_proof_verification_info_req: FraudProofVerificationInfoRequest,
    ) -> Option<FraudProofVerificationInfoResponse> {
        let response = match fraud_proof_verification_info_req {
            FraudProofVerificationInfoRequest::BlockRandomness => {
                FraudProofVerificationInfoResponse::BlockRandomness(self.block_randomness)
            }
            FraudProofVerificationInfoRequest::DomainTimestampExtrinsic(_) => {
                FraudProofVerificationInfoResponse::DomainTimestampExtrinsic(
                    UncheckedExtrinsic::new_unsigned(
                        pallet_timestamp::Call::<Test>::set {
                            now: self.timestamp,
                        }
                        .into(),
                    )
                    .encode(),
                )
            }
            FraudProofVerificationInfoRequest::ConsensusChainByteFeeExtrinsic(_) => {
                FraudProofVerificationInfoResponse::ConsensusChainByteFeeExtrinsic(
                    UncheckedExtrinsic::new_unsigned(
                        pallet_block_fees::Call::<Test>::set_next_consensus_chain_byte_fee {
                            transaction_byte_fee: Default::default(),
                        }
                        .into(),
                    )
                    .encode(),
                )
            }
            FraudProofVerificationInfoRequest::DomainBundleBody { .. } => {
                FraudProofVerificationInfoResponse::DomainBundleBody(Default::default())
            }
            FraudProofVerificationInfoRequest::DomainRuntimeCode(_) => {
                FraudProofVerificationInfoResponse::DomainRuntimeCode(Default::default())
            }
            FraudProofVerificationInfoRequest::DomainSetCodeExtrinsic(_) => {
                FraudProofVerificationInfoResponse::DomainSetCodeExtrinsic(
                    SetCodeExtrinsic::EncodedExtrinsic(
                        UncheckedExtrinsic::new_unsigned(
                            domain_pallet_executive::Call::<Test>::set_code {
                                code: self.runtime_code.clone(),
                            }
                            .into(),
                        )
                        .encode(),
                    ),
                )
            }
            FraudProofVerificationInfoRequest::TxRangeCheck { .. } => {
                FraudProofVerificationInfoResponse::TxRangeCheck(self.tx_range)
            }
            FraudProofVerificationInfoRequest::InherentExtrinsicCheck { .. } => {
                FraudProofVerificationInfoResponse::InherentExtrinsicCheck(self.is_inherent)
            }
            FraudProofVerificationInfoRequest::ExtrinsicDecodableCheck { .. } => {
                FraudProofVerificationInfoResponse::ExtrinsicDecodableCheck(self.is_decodable)
            }
            FraudProofVerificationInfoRequest::DomainElectionParams { .. } => {
                FraudProofVerificationInfoResponse::DomainElectionParams {
                    domain_total_stake: self.domain_total_stake,
                    bundle_slot_probability: self.bundle_slot_probability,
                }
            }
            FraudProofVerificationInfoRequest::OperatorStake { .. } => {
                FraudProofVerificationInfoResponse::OperatorStake(self.operator_stake)
            }
            FraudProofVerificationInfoRequest::CheckExtrinsicsInSingleContext { .. } => {
                FraudProofVerificationInfoResponse::CheckExtrinsicsInSingleContext(
                    self.maybe_illegal_extrinsic_index,
                )
            }
            FraudProofVerificationInfoRequest::StorageKey { .. } => {
                FraudProofVerificationInfoResponse::StorageKey(None)
            }
            FraudProofVerificationInfoRequest::XDMValidationCheck { .. } => {
                FraudProofVerificationInfoResponse::XDMValidationCheck(self.is_valid_xdm)
            }
        };

        Some(response)
    }

    fn derive_bundle_digest(
        &self,
        _consensus_block_hash: H256,
        _domain_id: DomainId,
        _bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256> {
        Some(H256::random())
    }

    fn execution_proof_check(
        &self,
        _domain_id: (u32, H256),
        _pre_state_root: H256,
        _encoded_proof: Vec<u8>,
        _execution_method: &str,
        _call_data: &[u8],
        _domain_runtime_code: Vec<u8>,
    ) -> Option<Vec<u8>> {
        None
    }
}

pub(crate) fn new_test_ext_with_extensions() -> sp_io::TestExternalities {
    let version = RuntimeVersion {
        spec_name: "test".into(),
        impl_name: Default::default(),
        authoring_version: 0,
        spec_version: 1,
        impl_version: 1,
        apis: Default::default(),
        transaction_version: 1,
        state_version: 0,
        extrinsic_state_version: 0,
    };

    let mut ext = new_test_ext();
    ext.register_extension(sp_core::traits::ReadRuntimeVersionExt::new(
        ReadRuntimeVersion(version.encode()),
    ));
    ext
}

pub(crate) fn create_dummy_receipt(
    block_number: BlockNumber,
    consensus_block_hash: Hash,
    parent_domain_block_receipt_hash: H256,
    block_extrinsics_roots: Vec<H256>,
) -> ExecutionReceipt<BlockNumber, Hash, DomainBlockNumber, H256, u128> {
    let (execution_trace, execution_trace_root) = if block_number == 0 {
        (Vec::new(), Default::default())
    } else {
        let execution_trace = vec![H256::random(), H256::random()];
        let trace: Vec<[u8; 32]> = execution_trace
            .iter()
            .map(|r| r.encode().try_into().expect("H256 must fit into [u8; 32]"))
            .collect();
        let execution_trace_root = MerkleTree::from_leaves(trace.as_slice())
            .root()
            .expect("Compute merkle root of trace should success")
            .into();
        (execution_trace, execution_trace_root)
    };
    let inboxed_bundles = block_extrinsics_roots
        .into_iter()
        .map(InboxedBundle::dummy)
        .collect();
    ExecutionReceipt {
        domain_block_number: block_number as DomainBlockNumber,
        domain_block_hash: H256::random(),
        domain_block_extrinsic_root: Default::default(),
        parent_domain_block_receipt_hash,
        consensus_block_number: block_number,
        consensus_block_hash,
        inboxed_bundles,
        final_state_root: *execution_trace.last().unwrap_or(&Default::default()),
        execution_trace,
        execution_trace_root,
        block_fees: Default::default(),
        transfers: Default::default(),
    }
}

fn create_dummy_bundle(
    domain_id: DomainId,
    block_number: BlockNumber,
    consensus_block_hash: Hash,
) -> OpaqueBundle<BlockNumber, Hash, DomainHeader, u128> {
    let execution_receipt = create_dummy_receipt(
        block_number,
        consensus_block_hash,
        Default::default(),
        vec![],
    );
    create_dummy_bundle_with_receipts(
        domain_id,
        OPERATOR_ID,
        Default::default(),
        execution_receipt,
    )
}

pub(crate) fn create_dummy_bundle_with_receipts(
    domain_id: DomainId,
    operator_id: OperatorId,
    bundle_extrinsics_root: H256,
    receipt: ExecutionReceipt<BlockNumber, Hash, DomainBlockNumber, H256, u128>,
) -> OpaqueBundle<BlockNumber, Hash, DomainHeader, u128> {
    let pair = OperatorPair::from_seed(&U256::from(0u32).into());

    let header = BundleHeader::<_, _, DomainHeader, _> {
        proof_of_election: ProofOfElection::dummy(domain_id, operator_id),
        receipt,
        estimated_bundle_weight: Default::default(),
        bundle_extrinsics_root,
    };

    let signature = pair.sign(header.hash().as_ref());

    OpaqueBundle {
        sealed_header: SealedBundleHeader::new(header, signature),
        extrinsics: Vec::new(),
    }
}

pub(crate) struct ReadRuntimeVersion(pub Vec<u8>);

impl sp_core::traits::ReadRuntimeVersion for ReadRuntimeVersion {
    fn read_runtime_version(
        &self,
        _wasm_code: &[u8],
        _ext: &mut dyn sp_externalities::Externalities,
    ) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }
}

pub(crate) fn run_to_block<T: Config>(block_number: BlockNumberFor<T>, parent_hash: T::Hash) {
    // Finalize previous block
    <crate::Pallet<T> as Hooks<BlockNumberFor<T>>>::on_finalize(
        block_number.saturating_sub(One::one()),
    );
    frame_system::Pallet::<T>::finalize();

    // Initialize current block
    frame_system::Pallet::<T>::set_block_number(block_number);
    frame_system::Pallet::<T>::initialize(&block_number, &parent_hash, &Default::default());
    <crate::Pallet<T> as Hooks<BlockNumberFor<T>>>::on_initialize(block_number);
}

pub(crate) fn register_genesis_domain(creator: u128, operator_ids: Vec<OperatorId>) -> DomainId {
    let raw_genesis_storage = RawGenesis::dummy(vec![1, 2, 3, 4]).encode();
    assert_ok!(crate::Pallet::<Test>::register_domain_runtime(
        RawOrigin::Root.into(),
        "evm".to_owned(),
        RuntimeType::Evm,
        raw_genesis_storage,
    ));

    let domain_id = NextDomainId::<Test>::get();
    <Test as Config>::Currency::make_free_balance_be(
        &creator,
        <Test as Config>::DomainInstantiationDeposit::get()
            + <Test as pallet_balances::Config>::ExistentialDeposit::get(),
    );
    crate::Pallet::<Test>::instantiate_domain(
        RawOrigin::Root.into(),
        DomainConfig {
            domain_name: "evm-domain".to_owned(),
            runtime_id: 0,
            max_block_size: 1u32,
            max_block_weight: Weight::from_parts(1, 0),
            bundle_slot_probability: (1, 1),
            target_bundles_per_block: 1,
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: Default::default(),
        },
    )
    .unwrap();

    let pair = OperatorPair::from_seed(&U256::from(0u32).into());
    for operator_id in operator_ids {
        Operators::<Test>::insert(operator_id, Operator::dummy(domain_id, pair.public(), SSC));
    }

    domain_id
}

// Submit new head receipt to extend the block tree from the genesis block
pub(crate) fn extend_block_tree_from_zero(
    domain_id: DomainId,
    operator_id: u64,
    to: DomainBlockNumberFor<Test>,
) -> ExecutionReceiptOf<Test> {
    let genesis_receipt = get_block_tree_node_at::<Test>(domain_id, 0)
        .unwrap()
        .execution_receipt;
    extend_block_tree(domain_id, operator_id, to, genesis_receipt)
}

// Submit new head receipt to extend the block tree
pub(crate) fn extend_block_tree(
    domain_id: DomainId,
    operator_id: u64,
    to: DomainBlockNumberFor<Test>,
    mut latest_receipt: ExecutionReceiptOf<Test>,
) -> ExecutionReceiptOf<Test> {
    let current_block_number = frame_system::Pallet::<Test>::current_block_number();
    assert!(current_block_number < to as u64);

    for block_number in (current_block_number + 1)..to as u64 {
        // Finilize parent block and initialize block at `block_number`
        run_to_block::<Test>(block_number, latest_receipt.consensus_block_hash);

        // Submit a bundle with the receipt of the last block
        let bundle_extrinsics_root = H256::random();
        let bundle = create_dummy_bundle_with_receipts(
            domain_id,
            operator_id,
            bundle_extrinsics_root,
            latest_receipt,
        );
        assert_ok!(crate::Pallet::<Test>::submit_bundle(
            RawOrigin::None.into(),
            bundle,
        ));

        // Construct a `NewHead` receipt of the just submitted bundle, which will be included in the next bundle
        let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
        let parent_block_tree_node =
            get_block_tree_node_at::<Test>(domain_id, head_receipt_number).unwrap();
        latest_receipt = create_dummy_receipt(
            block_number,
            H256::random(),
            parent_block_tree_node
                .execution_receipt
                .hash::<DomainHashingFor<Test>>(),
            vec![bundle_extrinsics_root],
        );
    }

    // Finilize parent block and initialize block at `to`
    run_to_block::<Test>(to as u64, latest_receipt.consensus_block_hash);

    latest_receipt
}

#[allow(clippy::type_complexity)]
pub(crate) fn get_block_tree_node_at<T: Config>(
    domain_id: DomainId,
    block_number: DomainBlockNumberFor<T>,
) -> Option<
    BlockTreeNode<BlockNumberFor<T>, T::Hash, DomainBlockNumberFor<T>, T::DomainHash, BalanceOf<T>>,
> {
    BlockTree::<T>::get(domain_id, block_number).and_then(BlockTreeNodes::<T>::get)
}

#[test]
fn test_calculate_tx_range() {
    let cur_tx_range = P256::from(400_u64);

    assert_eq!(
        cur_tx_range,
        pallet_domains::calculate_tx_range(cur_tx_range, 0, 1000)
    );
    assert_eq!(
        cur_tx_range,
        pallet_domains::calculate_tx_range(cur_tx_range, 1000, 0)
    );

    // Lower bound of 1/4 * current range
    assert_eq!(
        cur_tx_range.checked_div(&P256::from(4_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 10, 1000)
    );

    // Upper bound of 4 * current range
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(4_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 8000, 1000)
    );

    // For anything else in the [0.25, 4.0] range, the change ratio should be same as
    // actual / expected
    assert_eq!(
        cur_tx_range.checked_div(&P256::from(4_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 250, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_div(&P256::from(2_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 500, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(1_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 1000, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(2_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 2000, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(3_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 3000, 1000)
    );
    assert_eq!(
        cur_tx_range.checked_mul(&P256::from(4_u64)).unwrap(),
        pallet_domains::calculate_tx_range(cur_tx_range, 4000, 1000)
    );
}

#[test]
fn test_bundle_fromat_verification() {
    let opaque_extrinsic = |dest: u128, value: u128| -> OpaqueExtrinsic {
        UncheckedExtrinsic {
            signature: None,
            function: RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death {
                dest,
                value,
            }),
        }
        .into()
    };
    new_test_ext().execute_with(|| {
        let domain_id = DomainId::new(0);
        let max_extrincis_count = 10;
        let max_block_size = opaque_extrinsic(0, 0).encoded_size() as u32 * max_extrincis_count;
        let domain_config = DomainConfig {
            domain_name: "test-domain".to_owned(),
            runtime_id: 0u32,
            max_block_size,
            max_block_weight: Weight::MAX,
            bundle_slot_probability: (1, 1),
            target_bundles_per_block: 1,
            operator_allow_list: OperatorAllowList::Anyone,
            initial_balances: Default::default(),
        };
        let domain_obj = DomainObject {
            owner_account_id: Default::default(),
            created_at: Default::default(),
            genesis_receipt_hash: Default::default(),
            domain_config,
            domain_runtime_info: Default::default(),
        };
        DomainRegistry::<Test>::insert(domain_id, domain_obj);

        let mut valid_bundle = create_dummy_bundle(DOMAIN_ID, 0, System::parent_hash());
        valid_bundle.extrinsics.push(opaque_extrinsic(1, 1));
        valid_bundle.extrinsics.push(opaque_extrinsic(2, 2));
        valid_bundle.sealed_header.header.bundle_extrinsics_root = BlakeTwo256::ordered_trie_root(
            valid_bundle
                .extrinsics
                .iter()
                .map(|xt| xt.encode())
                .collect(),
            sp_core::storage::StateVersion::V1,
        );
        assert_ok!(pallet_domains::Pallet::<Test>::check_extrinsics_root(
            &valid_bundle
        ));

        // Bundle exceed max size
        let mut too_large_bundle = valid_bundle.clone();
        for i in 0..max_extrincis_count {
            too_large_bundle
                .extrinsics
                .push(opaque_extrinsic(i as u128, i as u128));
        }
        assert!(too_large_bundle.size() > max_block_size);

        // Bundle with wrong value of `bundle_extrinsics_root`
        let mut invalid_extrinsic_root_bundle = valid_bundle.clone();
        invalid_extrinsic_root_bundle
            .sealed_header
            .header
            .bundle_extrinsics_root = H256::random();
        assert_err!(
            pallet_domains::Pallet::<Test>::check_extrinsics_root(&invalid_extrinsic_root_bundle),
            BundleError::InvalidExtrinsicRoot
        );

        // Bundle with wrong value of `extrinsics`
        let mut invalid_extrinsic_root_bundle = valid_bundle.clone();
        invalid_extrinsic_root_bundle.extrinsics[0] = opaque_extrinsic(3, 3);
        assert_err!(
            pallet_domains::Pallet::<Test>::check_extrinsics_root(&invalid_extrinsic_root_bundle),
            BundleError::InvalidExtrinsicRoot
        );

        // Bundle with addtional extrinsic
        let mut invalid_extrinsic_root_bundle = valid_bundle.clone();
        invalid_extrinsic_root_bundle
            .extrinsics
            .push(opaque_extrinsic(4, 4));
        assert_err!(
            pallet_domains::Pallet::<Test>::check_extrinsics_root(&invalid_extrinsic_root_bundle),
            BundleError::InvalidExtrinsicRoot
        );

        // Bundle with missing extrinsic
        let mut invalid_extrinsic_root_bundle = valid_bundle;
        invalid_extrinsic_root_bundle.extrinsics.pop();
        assert_err!(
            pallet_domains::Pallet::<Test>::check_extrinsics_root(&invalid_extrinsic_root_bundle),
            BundleError::InvalidExtrinsicRoot
        );
    });
}

#[test]
fn test_invalid_fraud_proof() {
    let creator = 0u128;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree_from_zero(domain_id, operator_id, head_domain_number + 2);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        // Fraud proof target the genesis ER is invalid
        let bad_receipt_at = 0;
        let bad_receipt_hash = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at)
            .unwrap()
            .execution_receipt
            .hash::<DomainHashingFor<Test>>();
        let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, bad_receipt_hash);
        assert_eq!(
            Domains::validate_fraud_proof(&fraud_proof),
            Err(FraudProofError::ChallengingGenesisReceipt)
        );

        // Fraud proof target unknown ER is invalid
        let bad_receipt_hash = H256::random();
        let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, bad_receipt_hash);
        assert_eq!(
            Domains::validate_fraud_proof(&fraud_proof),
            Err(FraudProofError::BadReceiptNotFound)
        );
    });
}

#[test]
fn test_invalid_block_fees_fraud_proof() {
    let creator = 0u128;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree_from_zero(domain_id, operator_id, head_domain_number + 2);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        let bad_receipt_at = 8;
        let mut domain_block = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at).unwrap();

        let bad_receipt_hash = domain_block
            .execution_receipt
            .hash::<DomainHashingFor<Test>>();
        let (fraud_proof, root) = generate_invalid_block_fees_fraud_proof::<Test>(
            domain_id,
            bad_receipt_hash,
            // set different reward in the storage and generate proof for that value
            sp_domains::BlockFees::new(
                domain_block
                    .execution_receipt
                    .block_fees
                    .domain_execution_fee
                    + 1,
                domain_block
                    .execution_receipt
                    .block_fees
                    .consensus_storage_fee
                    + 1,
                domain_block.execution_receipt.block_fees.burned_balance + 1,
            ),
        );
        domain_block.execution_receipt.final_state_root = root;
        BlockTreeNodes::<Test>::insert(bad_receipt_hash, domain_block);
        assert_ok!(Domains::validate_fraud_proof(&fraud_proof),);
    });
}

type FraudProofFor<T> =
    FraudProof<BlockNumberFor<T>, <T as frame_system::Config>::Hash, <T as Config>::DomainHeader>;

fn generate_invalid_block_fees_fraud_proof<T: Config>(
    domain_id: DomainId,
    bad_receipt_hash: ReceiptHashFor<T>,
    block_fees: sp_domains::BlockFees<BalanceOf<T>>,
) -> (FraudProofFor<T>, T::Hash) {
    let storage_key = sp_domains_fraud_proof::fraud_proof::operator_block_fees_final_key();
    let mut root = T::Hash::default();
    let mut mdb = PrefixedMemoryDB::<T::Hashing>::default();
    {
        let mut trie = TrieDBMutBuilderV1::new(&mut mdb, &mut root).build();
        trie.insert(&storage_key, &block_fees.encode()).unwrap();
    };

    let backend = TrieBackendBuilder::new(mdb, root).build();
    let (root, storage_proof) = storage_proof_for_key::<T, _>(backend, StorageKey(storage_key));
    (
        FraudProof::InvalidBlockFees(InvalidBlockFeesProof {
            domain_id,
            bad_receipt_hash,
            storage_proof,
        }),
        root,
    )
}

fn storage_proof_for_key<T: Config, B: Backend<T::Hashing> + AsTrieBackend<T::Hashing>>(
    backend: B,
    key: StorageKey,
) -> (T::Hash, StorageProof) {
    let state_version = sp_runtime::StateVersion::default();
    let root = backend.storage_root(std::iter::empty(), state_version).0;
    let proof = StorageProof::new(prove_read(backend, &[key]).unwrap().iter_nodes().cloned());
    (root, proof)
}

#[test]
fn test_invalid_domain_extrinsic_root_proof() {
    let creator = 0u128;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    let fraud_proof = ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree_from_zero(domain_id, operator_id, head_domain_number + 2);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        let bad_receipt_at = 8;
        let valid_bundle_digests = [ValidBundleDigest {
            bundle_index: 0,
            bundle_digest: vec![(Some(vec![1, 2, 3]), ExtrinsicDigest::Data(vec![4, 5, 6]))],
        }];
        let mut domain_block = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at).unwrap();
        let bad_receipt = &mut domain_block.execution_receipt;
        bad_receipt.inboxed_bundles = {
            valid_bundle_digests
                .iter()
                .map(|vbd| {
                    InboxedBundle::valid(BlakeTwo256::hash_of(&vbd.bundle_digest), H256::random())
                })
                .collect()
        };
        bad_receipt.domain_block_extrinsic_root = H256::random();

        let bad_receipt_hash = bad_receipt.hash::<DomainHashingFor<Test>>();
        let fraud_proof =
            generate_invalid_domain_extrinsic_root_fraud_proof::<Test>(domain_id, bad_receipt_hash);
        let (consensus_block_number, consensus_block_hash) = (
            bad_receipt.consensus_block_number,
            bad_receipt.consensus_block_hash,
        );
        ConsensusBlockHash::<Test>::insert(domain_id, consensus_block_number, consensus_block_hash);
        BlockTreeNodes::<Test>::insert(bad_receipt_hash, domain_block);
        fraud_proof
    });

    let fraud_proof_ext = FraudProofExtension::new(Arc::new(MockDomainFraudProofExtension {
        block_randomness: Randomness::from([1u8; 32]),
        timestamp: 1000,
        runtime_code: vec![1, 2, 3, 4],
        tx_range: true,
        is_inherent: true,
        is_decodable: true,
        domain_total_stake: 100 * SSC,
        operator_stake: 10 * SSC,
        bundle_slot_probability: (0, 0),
        maybe_illegal_extrinsic_index: None,
        is_valid_xdm: None,
    }));
    ext.register_extension(fraud_proof_ext);

    ext.execute_with(|| {
        assert_ok!(Domains::validate_fraud_proof(&fraud_proof),);
    })
}

fn generate_invalid_domain_extrinsic_root_fraud_proof<T: Config + pallet_timestamp::Config>(
    domain_id: DomainId,
    bad_receipt_hash: ReceiptHashFor<T>,
) -> FraudProof<BlockNumberFor<T>, T::Hash, T::DomainHeader> {
    let valid_bundle_digests = vec![ValidBundleDigest {
        bundle_index: 0,
        bundle_digest: vec![(Some(vec![1, 2, 3]), ExtrinsicDigest::Data(vec![4, 5, 6]))],
    }];

    FraudProof::InvalidExtrinsicsRoot(InvalidExtrinsicsRootProof {
        domain_id,
        bad_receipt_hash,
        valid_bundle_digests,
    })
}

#[test]
fn test_true_invalid_bundles_inherent_extrinsic_proof() {
    let creator = 0u128;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    let fraud_proof = ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree_from_zero(domain_id, operator_id, head_domain_number + 2);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        let inherent_extrinsic = vec![1, 2, 3].encode();
        let extrinsics = vec![inherent_extrinsic];
        let bundle_extrinsic_root =
            BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);

        let bad_receipt_at = 8;
        let mut domain_block = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at).unwrap();
        let bad_receipt = &mut domain_block.execution_receipt;
        // bad receipt marks this particular bundle as valid even though bundle contains inherent extrinsic
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];
        bad_receipt.domain_block_extrinsic_root = H256::random();

        let bad_receipt_hash = bad_receipt.hash::<DomainHashingFor<Test>>();
        let fraud_proof = generate_invalid_bundle_inherent_extrinsic_fraud_proof::<Test>(
            domain_id,
            bad_receipt_hash,
            0,
            0,
            extrinsics,
            true,
        );
        let (consensus_block_number, consensus_block_hash) = (
            bad_receipt.consensus_block_number,
            bad_receipt.consensus_block_hash,
        );
        ConsensusBlockHash::<Test>::insert(domain_id, consensus_block_number, consensus_block_hash);
        BlockTreeNodes::<Test>::insert(bad_receipt_hash, domain_block);
        fraud_proof
    });

    let fraud_proof_ext = FraudProofExtension::new(Arc::new(MockDomainFraudProofExtension {
        block_randomness: Randomness::from([1u8; 32]),
        timestamp: 1000,
        runtime_code: vec![1, 2, 3, 4],
        tx_range: true,
        // return `true` indicating this is an inherent extrinsic
        is_inherent: true,
        is_decodable: true,
        domain_total_stake: 100 * SSC,
        operator_stake: 10 * SSC,
        bundle_slot_probability: (0, 0),
        maybe_illegal_extrinsic_index: None,
        is_valid_xdm: None,
    }));
    ext.register_extension(fraud_proof_ext);

    ext.execute_with(|| {
        assert_ok!(Domains::validate_fraud_proof(&fraud_proof),);
    })
}

#[test]
fn test_false_invalid_bundles_inherent_extrinsic_proof() {
    let creator = 0u128;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    let fraud_proof = ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree_from_zero(domain_id, operator_id, head_domain_number + 2);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        let non_inherent_extrinsic = vec![1, 2, 3].encode();
        let extrinsics = vec![non_inherent_extrinsic];
        let bundle_extrinsic_root =
            BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);

        let bad_receipt_at = 8;
        let mut domain_block = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at).unwrap();
        let bad_receipt = &mut domain_block.execution_receipt;
        // bad receipt marks this bundle as invalid even though bundle do not contain inherent extrinsic.
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::InherentExtrinsic(0),
            bundle_extrinsic_root,
        )];
        bad_receipt.domain_block_extrinsic_root = H256::random();

        let bad_receipt_hash = bad_receipt.hash::<DomainHashingFor<Test>>();
        let fraud_proof = generate_invalid_bundle_inherent_extrinsic_fraud_proof::<Test>(
            domain_id,
            bad_receipt_hash,
            0,
            0,
            extrinsics,
            false,
        );
        let (consensus_block_number, consensus_block_hash) = (
            bad_receipt.consensus_block_number,
            bad_receipt.consensus_block_hash,
        );
        ConsensusBlockHash::<Test>::insert(domain_id, consensus_block_number, consensus_block_hash);
        BlockTreeNodes::<Test>::insert(bad_receipt_hash, domain_block);
        fraud_proof
    });

    let fraud_proof_ext = FraudProofExtension::new(Arc::new(MockDomainFraudProofExtension {
        block_randomness: Randomness::from([1u8; 32]),
        timestamp: 1000,
        runtime_code: vec![1, 2, 3, 4],
        tx_range: true,
        // return `false` indicating this is not an inherent extrinsic
        is_inherent: false,
        is_decodable: true,
        domain_total_stake: 100 * SSC,
        operator_stake: 10 * SSC,
        bundle_slot_probability: (0, 0),
        maybe_illegal_extrinsic_index: None,
        is_valid_xdm: None,
    }));
    ext.register_extension(fraud_proof_ext);

    ext.execute_with(|| {
        assert_ok!(Domains::validate_fraud_proof(&fraud_proof),);
    })
}

fn generate_invalid_bundle_inherent_extrinsic_fraud_proof<T: Config>(
    domain_id: DomainId,
    bad_receipt_hash: ReceiptHashFor<T>,
    bundle_index: u32,
    bundle_extrinsic_index: u32,
    bundle_extrinsics: Vec<Vec<u8>>,
    is_true_invalid_fraud_proof: bool,
) -> FraudProof<BlockNumberFor<T>, T::Hash, T::DomainHeader> {
    let extrinsic_inclusion_proof =
        StorageProofProvider::<LayoutV1<BlakeTwo256>>::generate_enumerated_proof_of_inclusion(
            bundle_extrinsics.as_slice(),
            bundle_extrinsic_index,
        )
        .unwrap();
    FraudProof::InvalidBundles(InvalidBundlesFraudProof {
        domain_id,
        bad_receipt_hash,
        bundle_index,
        invalid_bundle_type: InvalidBundleType::InherentExtrinsic(bundle_extrinsic_index),
        proof_data: extrinsic_inclusion_proof,
        is_true_invalid_fraud_proof,
    })
}

#[test]
fn test_invalid_domain_block_hash_fraud_proof() {
    let creator = 0u128;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree_from_zero(domain_id, operator_id, head_domain_number + 2);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        let bad_receipt_at = 8;
        let mut domain_block = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at).unwrap();
        let (root, digest_storage_proof) =
            generate_invalid_domain_block_hash_fraud_proof::<Test>(Digest::default());
        domain_block.execution_receipt.final_state_root = root;
        domain_block.execution_receipt.domain_block_hash = H256::random();
        let bad_receipt_hash = domain_block
            .execution_receipt
            .hash::<DomainHashingFor<Test>>();
        BlockTreeNodes::<Test>::insert(bad_receipt_hash, domain_block);
        let fraud_proof = FraudProof::InvalidDomainBlockHash(InvalidDomainBlockHashProof {
            domain_id,
            bad_receipt_hash,
            digest_storage_proof,
        });
        assert_ok!(Domains::validate_fraud_proof(&fraud_proof),);
    });
}

fn generate_invalid_domain_block_hash_fraud_proof<T: Config>(
    digest: Digest,
) -> (T::Hash, StorageProof) {
    let digest_storage_key = sp_domains_fraud_proof::fraud_proof::system_digest_final_key();
    let mut root = T::Hash::default();
    let mut mdb = PrefixedMemoryDB::<T::Hashing>::default();
    {
        let mut trie = TrieDBMutBuilderV1::new(&mut mdb, &mut root).build();
        trie.insert(&digest_storage_key, &digest.encode()).unwrap();
    };

    let backend = TrieBackendBuilder::new(mdb, root).build();
    storage_proof_for_key::<T, _>(backend, StorageKey(digest_storage_key))
}

#[test]
fn test_basic_fraud_proof_processing() {
    let creator = 0u128;
    let malicious_operator = 1u64;
    let honest_operator = 2u64;
    let head_domain_number = BlockTreePruningDepth::get() - 1;
    let test_cases = vec![
        1,
        2,
        head_domain_number - BlockTreePruningDepth::get() / 2,
        head_domain_number - 1,
        head_domain_number,
    ];
    for bad_receipt_at in test_cases {
        let mut ext = new_test_ext_with_extensions();
        ext.execute_with(|| {
            let domain_id =
                register_genesis_domain(creator, vec![malicious_operator, honest_operator]);
            extend_block_tree_from_zero(domain_id, malicious_operator, head_domain_number + 2);
            assert_eq!(
                HeadReceiptNumber::<Test>::get(domain_id),
                head_domain_number
            );

            // Construct and submit fraud proof that target ER at `head_domain_number - BlockTreePruningDepth::get() / 2`
            let bad_receipt = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at)
                .unwrap()
                .execution_receipt;
            let bad_receipt_hash = bad_receipt.hash::<DomainHashingFor<Test>>();
            let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, bad_receipt_hash);
            assert_ok!(Domains::submit_fraud_proof(
                RawOrigin::None.into(),
                Box::new(fraud_proof)
            ));

            // The head receipt number should be reverted to `bad_receipt_at - 1`
            let head_receipt_number_after_fraud_proof = HeadReceiptNumber::<Test>::get(domain_id);
            assert_eq!(head_receipt_number_after_fraud_proof, bad_receipt_at - 1);

            for block_number in bad_receipt_at..=head_domain_number {
                if block_number == bad_receipt_at {
                    // The targetted ER should be removed from the block tree
                    assert!(BlockTree::<Test>::get(domain_id, block_number).is_none());
                } else {
                    // All the bad ER's descendants should be marked as pending to prune and the submitter
                    // should be marked as pending to slash
                    assert!(BlockTree::<Test>::get(domain_id, block_number).is_some());
                    assert!(Domains::is_bad_er_pending_to_prune(domain_id, block_number));
                    let submitter = get_block_tree_node_at::<Test>(domain_id, block_number)
                        .unwrap()
                        .operator_ids;
                    for operator_id in submitter {
                        assert!(Domains::is_operator_pending_to_slash(
                            domain_id,
                            operator_id
                        ));
                    }
                }

                // The other data that used to verify ER should not be removed, such that the honest
                // operator can re-submit the valid ER
                assert!(!ExecutionInbox::<Test>::get((
                    domain_id,
                    block_number,
                    block_number as u64
                ))
                .is_empty());
                assert!(ConsensusBlockHash::<Test>::get(domain_id, block_number as u64).is_some());
            }

            // Re-submit the valid ER
            let resubmit_receipt = bad_receipt;
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                honest_operator,
                H256::random(),
                resubmit_receipt,
            );
            assert_ok!(Domains::submit_bundle(RawOrigin::None.into(), bundle,));
            assert_eq!(
                HeadReceiptNumber::<Test>::get(domain_id),
                head_receipt_number_after_fraud_proof + 1
            );

            // Submit one more ER, the bad ER at the same domain block should be pruned
            let next_block_number = frame_system::Pallet::<Test>::current_block_number() + 1;
            run_to_block::<Test>(next_block_number, H256::random());
            if let Some(receipt_hash) = BlockTree::<Test>::get(domain_id, bad_receipt_at + 1) {
                let mut receipt = BlockTreeNodes::<Test>::get(receipt_hash)
                    .unwrap()
                    .execution_receipt;
                receipt.final_state_root = H256::random();
                let bundle = create_dummy_bundle_with_receipts(
                    domain_id,
                    honest_operator,
                    H256::random(),
                    receipt.clone(),
                );
                assert_ok!(Domains::submit_bundle(RawOrigin::None.into(), bundle));

                assert_eq!(
                    HeadReceiptNumber::<Test>::get(domain_id),
                    head_receipt_number_after_fraud_proof + 2
                );
                assert!(BlockTreeNodes::<Test>::get(receipt_hash).is_none());
                assert!(!Domains::is_bad_er_pending_to_prune(
                    domain_id,
                    receipt.domain_block_number
                ));
            }
        });
    }
}

#[test]
fn test_bundle_limit_calculation() {
    let table = vec![
        ((1500, 1599), (1, 6), (1, 1), (136, 145)),
        ((1501, 1598), (2, 7), (2, 99), (1501, 1598)),
        ((1502, 1597), (3, 8), (3, 98), (1502, 1597)),
        ((1503, 1596), (4, 9), (4, 97), (1503, 1596)),
        ((1504, 1595), (5, 10), (5, 96), (1504, 1595)),
        ((1505, 1594), (6, 11), (6, 95), (1505, 1594)),
        ((1506, 1593), (7, 12), (7, 94), (1506, 1593)),
        ((1507, 1592), (8, 13), (8, 93), (1507, 1592)),
        ((1508, 1591), (9, 14), (9, 92), (1508, 1591)),
        ((1509, 1590), (10, 15), (10, 91), (1509, 1590)),
        ((1510, 1589), (11, 16), (11, 90), (1510, 1589)),
        ((1511, 1588), (12, 17), (12, 89), (1511, 1588)),
        ((1512, 1587), (13, 18), (13, 88), (1512, 1587)),
        ((1513, 1586), (14, 19), (14, 87), (1513, 1586)),
        ((1514, 1585), (15, 20), (15, 86), (1514, 1585)),
        ((1515, 1584), (16, 21), (16, 85), (1515, 1584)),
        ((1516, 1583), (17, 22), (17, 84), (1516, 1583)),
        ((1517, 1582), (18, 23), (18, 83), (1517, 1582)),
        ((1518, 1581), (19, 24), (19, 82), (1518, 1581)),
        ((1519, 1580), (20, 25), (20, 81), (1519, 1580)),
        ((1520, 1579), (21, 26), (21, 80), (1520, 1579)),
        ((1521, 1578), (22, 27), (22, 79), (1521, 1578)),
        ((1522, 1577), (23, 28), (23, 78), (1522, 1577)),
        ((1523, 1576), (24, 29), (24, 77), (1523, 1576)),
        ((1524, 1575), (25, 30), (25, 76), (1524, 1575)),
        ((1525, 1574), (26, 31), (26, 75), (1525, 1574)),
        ((1526, 1573), (27, 32), (27, 74), (1526, 1573)),
        ((1527, 1572), (28, 33), (28, 73), (1527, 1572)),
        ((1528, 1571), (29, 34), (29, 72), (1528, 1571)),
        ((1529, 1570), (30, 35), (30, 71), (1529, 1570)),
        ((1530, 1569), (31, 36), (31, 70), (1530, 1569)),
        ((1531, 1568), (32, 37), (32, 69), (1531, 1568)),
        ((1532, 1567), (33, 38), (33, 68), (1532, 1567)),
        ((1533, 1566), (34, 39), (34, 67), (1533, 1566)),
        ((1534, 1565), (35, 40), (35, 66), (1534, 1565)),
        ((1535, 1564), (36, 41), (36, 65), (1535, 1564)),
        ((1536, 1563), (37, 42), (37, 64), (1536, 1563)),
        ((1537, 1562), (38, 43), (38, 63), (1537, 1562)),
        ((1538, 1561), (39, 44), (39, 62), (1538, 1561)),
        ((1539, 1560), (40, 45), (40, 61), (1539, 1560)),
        ((1540, 1559), (41, 46), (41, 60), (1540, 1559)),
        ((1541, 1558), (42, 47), (42, 59), (1541, 1558)),
        ((1542, 1557), (43, 48), (43, 58), (1542, 1557)),
        ((1543, 1556), (44, 49), (44, 57), (1543, 1556)),
        ((1544, 1555), (45, 50), (45, 56), (1544, 1555)),
        ((1545, 1554), (46, 51), (46, 55), (1545, 1554)),
        ((1546, 1553), (47, 52), (47, 54), (1546, 1553)),
        ((1547, 1552), (48, 53), (48, 53), (386, 388)),
        ((1548, 1551), (49, 54), (49, 52), (387, 387)),
        ((1549, 1550), (50, 55), (50, 51), (387, 387)),
        ((1550, 1549), (51, 56), (51, 50), (387, 387)),
        ((1551, 1548), (52, 57), (52, 49), (387, 387)),
        ((1552, 1547), (53, 58), (53, 48), (388, 386)),
        ((1553, 1546), (54, 59), (54, 47), (388, 386)),
        ((1554, 1545), (55, 60), (55, 46), (388, 386)),
        ((1555, 1544), (56, 61), (56, 45), (388, 386)),
        ((1556, 1543), (57, 62), (57, 44), (389, 385)),
        ((1557, 1542), (58, 63), (58, 43), (389, 385)),
        ((1558, 1541), (59, 64), (59, 42), (389, 385)),
        ((1559, 1540), (60, 65), (60, 41), (389, 385)),
        ((1560, 1539), (61, 66), (61, 40), (390, 384)),
        ((1561, 1538), (62, 67), (62, 39), (390, 384)),
        ((1562, 1537), (63, 68), (63, 38), (390, 384)),
        ((1563, 1536), (64, 69), (64, 37), (390, 384)),
        ((1564, 1535), (65, 70), (65, 36), (391, 383)),
        ((1565, 1534), (66, 71), (66, 35), (313, 306)),
        ((1566, 1533), (67, 72), (67, 34), (313, 306)),
        ((1567, 1532), (68, 73), (68, 33), (313, 306)),
        ((1568, 1531), (69, 74), (69, 32), (313, 306)),
        ((1569, 1530), (70, 75), (70, 31), (313, 306)),
        ((1570, 1529), (71, 76), (71, 30), (314, 305)),
        ((1571, 1528), (72, 77), (72, 29), (314, 305)),
        ((1572, 1527), (73, 78), (73, 28), (314, 305)),
        ((1573, 1526), (74, 79), (74, 27), (314, 305)),
        ((1574, 1525), (75, 80), (75, 26), (262, 254)),
        ((1575, 1524), (76, 81), (76, 25), (262, 254)),
        ((1576, 1523), (77, 82), (77, 24), (262, 253)),
        ((1577, 1522), (78, 83), (78, 23), (262, 253)),
        ((1578, 1521), (79, 84), (79, 22), (263, 253)),
        ((1579, 1520), (80, 85), (80, 21), (175, 168)),
        ((1580, 1519), (81, 86), (81, 20), (175, 168)),
        ((1581, 1518), (82, 87), (82, 19), (175, 168)),
        ((1582, 1517), (83, 88), (83, 18), (175, 168)),
        ((1583, 1516), (84, 89), (84, 17), (158, 151)),
        ((1584, 1515), (85, 90), (85, 16), (158, 151)),
        ((1585, 1514), (86, 91), (86, 15), (144, 137)),
        ((1586, 1513), (87, 92), (87, 14), (144, 137)),
        ((1587, 1512), (88, 93), (88, 13), (132, 126)),
        ((1588, 1511), (89, 94), (89, 12), (132, 125)),
        ((1589, 1510), (90, 95), (90, 11), (122, 116)),
        ((1590, 1509), (91, 96), (91, 10), (99, 94)),
        ((1591, 1508), (92, 97), (92, 9), (93, 88)),
        ((1592, 1507), (93, 98), (93, 8), (83, 79)),
        ((1593, 1506), (94, 99), (94, 7), (75, 71)),
        ((1594, 1505), (95, 100), (95, 6), (63, 60)),
        ((1595, 1504), (96, 101), (96, 5), (55, 51)),
        ((1596, 1503), (97, 102), (97, 4), (44, 41)),
        ((1597, 1502), (98, 103), (98, 3), (35, 33)),
        ((1598, 1501), (99, 104), (99, 2), (23, 22)),
        ((1599, 1500), (100, 105), (100, 1), (12, 11)),
    ];

    for row in table {
        let block_max_weight = row.0 .0;
        let block_max_size = row.0 .1;
        let consensus_slot_numerator = row.1 .0;
        let consensus_slot_denominator = row.1 .1;
        let bundle_probability_numerator = row.2 .0;
        let bundle_probability_denominator = row.2 .1;
        let expected_bundle_max_weight = row.3 .0;
        let expected_bundle_max_size = row.3 .1;

        let domain_bundle_limit = calculate_max_bundle_weight_and_size(
            block_max_size,
            Weight::from_all(block_max_weight),
            (consensus_slot_numerator, consensus_slot_denominator),
            (bundle_probability_numerator, bundle_probability_denominator),
        )
        .unwrap();

        assert_eq!(
            domain_bundle_limit.max_bundle_size,
            expected_bundle_max_size
        );
        assert_eq!(
            domain_bundle_limit.max_bundle_weight,
            Weight::from_all(expected_bundle_max_weight)
        );
    }
}
