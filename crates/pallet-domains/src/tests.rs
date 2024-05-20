use crate::block_tree::BlockTreeNode;
use crate::domain_registry::{DomainConfig, DomainObject};
use crate::staking::Operator;
use crate::{
    self as pallet_domains, BalanceOf, BlockSlot, BlockTree, BlockTreeNodes, BundleError, Config,
    ConsensusBlockHash, DomainBlockNumberFor, DomainHashingFor, DomainRegistry, ExecutionInbox,
    ExecutionReceiptOf, FraudProofError, FungibleHoldId, HeadReceiptNumber, NextDomainId,
    Operators, ReceiptHashFor,
};
use codec::{Decode, Encode, MaxEncodedLen};
use domain_runtime_primitives::opaque::Header as DomainHeader;
use domain_runtime_primitives::BlockNumber as DomainBlockNumber;
use frame_support::dispatch::{DispatchInfo, RawOrigin};
use frame_support::traits::{ConstU64, Currency, Hooks, VariantCount};
use frame_support::weights::constants::ParityDbWeight;
use frame_support::weights::{IdentityFee, Weight};
use frame_support::{assert_err, assert_ok, derive_impl, parameter_types, PalletId};
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
    DomainChainAllowlistUpdateExtrinsic, DomainInherentExtrinsic, DomainInherentExtrinsicData,
    DomainStorageKeyRequest, FraudProofExtension, FraudProofHostFunctions,
    FraudProofVerificationInfoRequest, FraudProofVerificationInfoResponse, SetCodeExtrinsic,
    StatelessDomainRuntimeCall,
};
use sp_runtime::traits::{
    AccountIdConversion, BlakeTwo256, BlockNumberProvider, Hash as HashT, IdentityLookup, One,
};
use sp_runtime::transaction_validity::TransactionValidityError;
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

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type Hash = Hash;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = pallet_balances::AccountData<Balance>;
    type DbWeight = ParityDbWeight;
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
    // TODO: HACK this is not the actual variant count but it is required see
    // https://github.com/subspace/subspace/issues/2674 for more details. It
    // will be resolved as https://github.com/paritytech/polkadot-sdk/issues/4033.
    const VARIANT_COUNT: u32 = 10;
}

parameter_types! {
    pub const ExistentialDeposit: Balance = 1;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for Test {
    type Balance = Balance;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type RuntimeHoldReason = HoldIdentifier;
    type DustRemoval = ();
}

parameter_types! {
    pub const MinOperatorStake: Balance = 100 * SSC;
    pub const MinNominatorStake: Balance = SSC;
    pub const StakeWithdrawalLockingPeriod: DomainBlockNumber = 5;
    pub const StakeEpochDuration: DomainBlockNumber = 5;
    pub TreasuryAccount: u128 = PalletId(*b"treasury").into_account_truncating();
    pub const BlockReward: Balance = 10 * SSC;
    pub const MaxPendingStakingOperation: u32 = 512;
    pub const MaxNominators: u32 = 5;
    pub const DomainsPalletId: PalletId = PalletId(*b"domains_");
    pub const DomainChainByteFee: Balance = 1;
    pub const MaxInitialDomainAccounts: u32 = 5;
    pub const MinInitialDomainAccountBalance: Balance = SSC;
    pub const BundleLongevity: u32 = 5;
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

impl BlockSlot<Test> for DummyBlockSlot {
    fn future_slot(_block_number: BlockNumberFor<Test>) -> Option<sp_consensus_slots::Slot> {
        Some(0u64.into())
    }

    fn slot_produced_after(_slot: sp_consensus_slots::Slot) -> Option<BlockNumberFor<Test>> {
        Some(0u64)
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
    type PalletId = DomainsPalletId;
    type StorageFee = DummyStorageFee;
    type BlockSlot = DummyBlockSlot;
    type DomainsTransfersTracker = MockDomainsTransfersTracker;
    type MaxInitialDomainAccounts = MaxInitialDomainAccounts;
    type MinInitialDomainAccountBalance = MinInitialDomainAccountBalance;
    type BundleLongevity = BundleLongevity;
    type ConsensusSlotProbability = SlotProbability;
    type DomainBundleSubmitted = ();
    type OnDomainInstantiated = ();
    type Balance = Balance;
}

pub struct ExtrinsicStorageFees;

impl domain_pallet_executive::ExtrinsicStorageFees<Test> for ExtrinsicStorageFees {
    fn extract_signer(_xt: MockUncheckedExtrinsic<Test>) -> (Option<AccountId>, DispatchInfo) {
        (None, DispatchInfo::default())
    }

    fn on_storage_fees_charged(
        _charged_fees: Balance,
        _tx_size: u32,
    ) -> Result<(), TransactionValidityError> {
        Ok(())
    }
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
            FraudProofVerificationInfoRequest::DomainChainsAllowlistUpdateExtrinsic(_) => {
                FraudProofVerificationInfoResponse::DomainChainAllowlistUpdateExtrinsic(
                    DomainChainAllowlistUpdateExtrinsic::None,
                )
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

    fn derive_bundle_digest_v2(
        &self,
        _domain_runtime_code: Vec<u8>,
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

    fn check_extrinsics_in_single_context(
        &self,
        _domain_runtime_code: Vec<u8>,
        _domain_block_id: (u32, H256),
        _domain_block_state_root: H256,
        _bundle_extrinsics: Vec<OpaqueExtrinsic>,
        _encoded_proof: Vec<u8>,
    ) -> Option<Option<u32>> {
        None
    }

    fn construct_domain_inherent_extrinsic(
        &self,
        _domain_runtime_code: Vec<u8>,
        _domain_inherent_extrinsic_data: DomainInherentExtrinsicData,
    ) -> Option<DomainInherentExtrinsic> {
        None
    }

    fn domain_storage_key(
        &self,
        _domain_runtime_code: Vec<u8>,
        _req: DomainStorageKeyRequest,
    ) -> Option<Vec<u8>> {
        None
    }

    fn domain_runtime_call(
        &self,
        _domain_runtime_code: Vec<u8>,
        _call: StatelessDomainRuntimeCall,
    ) -> Option<bool> {
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
    assert_ok!(crate::Pallet::<Test>::set_permissioned_action_allowed_by(
        RawOrigin::Root.into(),
        sp_domains::PermissionedActionAllowedBy::Anyone
    ));
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
        RawOrigin::Signed(creator).into(),
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
    let storage_key = sp_domains::operator_block_fees_final_key();
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
    let digest_storage_key = sp_domains::system_digest_final_key();
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
