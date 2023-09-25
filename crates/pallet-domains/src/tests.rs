use crate::block_tree::DomainBlock;
use crate::domain_registry::{DomainConfig, DomainObject};
use crate::{
    self as pallet_domains, BalanceOf, BlockTree, BundleError, Config, ConsensusBlockInfo,
    DomainBlocks, DomainRegistry, ExecutionInbox, ExecutionReceiptOf, FraudProofError,
    FungibleHoldId, HeadReceiptNumber, NextDomainId, Operator, OperatorStatus, Operators,
};
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::dispatch::RawOrigin;
use frame_support::storage::generator::StorageValue;
use frame_support::traits::{ConstU16, ConstU32, ConstU64, Currency, Hooks};
use frame_support::weights::Weight;
use frame_support::{assert_err, assert_ok, parameter_types, PalletId};
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;
use sp_core::crypto::Pair;
use sp_core::storage::{StateVersion, StorageKey};
use sp_core::{Get, H256, U256};
use sp_domains::fraud_proof::{
    ExtrinsicDigest, FraudProof, InvalidExtrinsicsRootProof, InvalidTotalRewardsProof,
    ValidBundleDigest,
};
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{
    BundleHeader, DomainId, DomainInstanceData, DomainsHoldIdentifier, ExecutionReceipt,
    GenerateGenesisStateRoot, GenesisReceiptExtension, OpaqueBundle, OperatorId, OperatorPair,
    ProofOfElection, ReceiptHash, RuntimeType, SealedBundleHeader, StakingHoldIdentifier,
};
use sp_runtime::traits::{AccountIdConversion, BlakeTwo256, Hash as HashT, IdentityLookup, Zero};
use sp_runtime::{BuildStorage, OpaqueExtrinsic};
use sp_state_machine::backend::AsTrieBackend;
use sp_state_machine::{prove_read, Backend, TrieBackendBuilder};
use sp_trie::trie_types::TrieDBMutBuilderV1;
use sp_trie::{PrefixedMemoryDB, StorageProof, TrieMut};
use sp_version::RuntimeVersion;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use subspace_core_primitives::{Randomness, U256 as P256};
use subspace_runtime_primitives::{Moment, SSC};

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
    }
);

type BlockNumber = u64;
type Hash = H256;

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
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
    type ExtrinsicsRootStateVersion = ExtrinsicsRootStateVersion;
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
    pub const ExtrinsicsRootStateVersion: StateVersion = StateVersion::V0;
}

static CONFIRMATION_DEPTH_K: AtomicU64 = AtomicU64::new(10);

pub struct ConfirmationDepthK;

impl ConfirmationDepthK {
    fn set(new: BlockNumber) {
        CONFIRMATION_DEPTH_K.store(new, Ordering::SeqCst);
    }

    fn get() -> BlockNumber {
        CONFIRMATION_DEPTH_K.load(Ordering::SeqCst)
    }
}

impl Get<BlockNumber> for ConfirmationDepthK {
    fn get() -> BlockNumber {
        Self::get()
    }
}

#[derive(
    PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
)]
pub enum HoldIdentifier {
    Domains(DomainsHoldIdentifier),
}

impl pallet_domains::HoldIdentifier<Test> for HoldIdentifier {
    fn staking_pending_deposit(operator_id: OperatorId) -> FungibleHoldId<Test> {
        Self::Domains(DomainsHoldIdentifier::Staking(
            StakingHoldIdentifier::PendingDeposit(operator_id),
        ))
    }

    fn staking_staked(operator_id: OperatorId) -> FungibleHoldId<Test> {
        Self::Domains(DomainsHoldIdentifier::Staking(
            StakingHoldIdentifier::Staked(operator_id),
        ))
    }

    fn staking_pending_unlock(operator_id: OperatorId) -> FungibleHoldId<Test> {
        Self::Domains(DomainsHoldIdentifier::Staking(
            StakingHoldIdentifier::PendingUnlock(operator_id),
        ))
    }

    fn domain_instantiation_id(domain_id: DomainId) -> FungibleHoldId<Test> {
        Self::Domains(DomainsHoldIdentifier::DomainInstantiation(domain_id))
    }
}

parameter_types! {
    pub const MaxHolds: u32 = 10;
    pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
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
    pub const StakeWithdrawalLockingPeriod: BlockNumber = 5;
    pub const StakeEpochDuration: BlockNumber = 5;
    pub TreasuryAccount: u64 = PalletId(*b"treasury").into_account_truncating();
    pub const BlockReward: Balance = 10 * SSC;
    pub const MaxPendingStakingOperation: u32 = 100;
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

pub struct DeriveExtrinsics;
impl sp_domains::fraud_proof::DeriveExtrinsics<Moment> for DeriveExtrinsics {
    fn timestamp_storage_key() -> StorageKey {
        StorageKey(pallet_timestamp::pallet::Now::<Test>::storage_value_final_key().to_vec())
    }

    fn derive_timestamp_extrinsic(now: Moment) -> Vec<u8> {
        pallet_timestamp::Call::<Test>::set { now }.encode()
    }
}

impl pallet_domains::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type DomainNumber = BlockNumber;
    type DomainHash = sp_core::H256;
    type ConfirmationDepthK = ConfirmationDepthK;
    type DomainRuntimeUpgradeDelay = DomainRuntimeUpgradeDelay;
    type Currency = Balances;
    type HoldIdentifier = HoldIdentifier;
    type WeightInfo = pallet_domains::weights::SubstrateWeight<Test>;
    type InitialDomainTxRange = InitialDomainTxRange;
    type DomainTxRangeAdjustmentInterval = DomainTxRangeAdjustmentInterval;
    type MinOperatorStake = MinOperatorStake;
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
    type SudoId = ();
    type Randomness = MockRandomness;
    type DeriveExtrinsics = DeriveExtrinsics;
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    t.into()
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
    };

    let mut ext = new_test_ext();
    ext.register_extension(sp_core::traits::ReadRuntimeVersionExt::new(
        ReadRuntimeVersion(version.encode()),
    ));
    ext.register_extension(GenesisReceiptExtension::new(Arc::new(
        GenesisStateRootGenerater,
    )));

    ext
}

pub(crate) fn create_dummy_receipt(
    block_number: BlockNumber,
    consensus_block_hash: Hash,
    parent_domain_block_receipt_hash: H256,
    block_extrinsics_roots: Vec<H256>,
) -> ExecutionReceipt<BlockNumber, Hash, BlockNumber, H256, u128> {
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
    ExecutionReceipt {
        domain_block_number: block_number,
        domain_block_hash: H256::random(),
        domain_block_extrinsic_root: Default::default(),
        parent_domain_block_receipt_hash,
        consensus_block_number: block_number,
        consensus_block_hash,
        valid_bundles: Vec::new(),
        invalid_bundles: Vec::new(),
        block_extrinsics_roots,
        final_state_root: Default::default(),
        execution_trace,
        execution_trace_root,
        total_rewards: 0,
    }
}

fn create_dummy_bundle(
    domain_id: DomainId,
    block_number: BlockNumber,
    consensus_block_hash: Hash,
) -> OpaqueBundle<BlockNumber, Hash, BlockNumber, H256, u128> {
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
    receipt: ExecutionReceipt<BlockNumber, Hash, BlockNumber, H256, u128>,
) -> OpaqueBundle<BlockNumber, Hash, BlockNumber, H256, u128> {
    let pair = OperatorPair::from_seed(&U256::from(0u32).into());

    let header = BundleHeader {
        proof_of_election: ProofOfElection::dummy(domain_id, operator_id),
        receipt,
        bundle_size: 0u32,
        estimated_bundle_weight: Default::default(),
        bundle_extrinsics_root,
    };

    let signature = pair.sign(header.hash().as_ref());

    OpaqueBundle {
        sealed_header: SealedBundleHeader::new(header, signature),
        extrinsics: Vec::new(),
    }
}

pub(crate) struct GenesisStateRootGenerater;

impl GenerateGenesisStateRoot for GenesisStateRootGenerater {
    fn generate_genesis_state_root(
        &self,
        _domain_id: DomainId,
        _domain_instance_data: DomainInstanceData,
    ) -> Option<H256> {
        Some(Default::default())
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
    frame_system::Pallet::<T>::set_block_number(block_number);
    frame_system::Pallet::<T>::initialize(&block_number, &parent_hash, &Default::default());
    <crate::Pallet<T> as Hooks<BlockNumberFor<T>>>::on_initialize(block_number);
    frame_system::Pallet::<T>::finalize();
}

pub(crate) fn register_genesis_domain(creator: u64, operator_ids: Vec<OperatorId>) -> DomainId {
    assert_ok!(crate::Pallet::<Test>::register_domain_runtime(
        RawOrigin::Root.into(),
        b"evm".to_vec(),
        RuntimeType::Evm,
        vec![1, 2, 3, 4],
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
            domain_name: b"evm-domain".to_vec(),
            runtime_id: 0,
            max_block_size: 1u32,
            max_block_weight: Weight::from_parts(1, 0),
            bundle_slot_probability: (1, 1),
            target_bundles_per_block: 1,
        },
        vec![],
    )
    .unwrap();

    let pair = OperatorPair::from_seed(&U256::from(0u32).into());
    for operator_id in operator_ids {
        Operators::<Test>::insert(
            operator_id,
            Operator {
                signing_key: pair.public(),
                current_domain_id: domain_id,
                next_domain_id: domain_id,
                minimum_nominator_stake: SSC,
                nomination_tax: Default::default(),
                current_total_stake: Zero::zero(),
                current_epoch_rewards: Zero::zero(),
                total_shares: Zero::zero(),
                status: OperatorStatus::Registered,
            },
        );
    }

    domain_id
}

// Submit new head receipt to extend the block tree
pub(crate) fn extend_block_tree(
    domain_id: DomainId,
    operator_id: u64,
    to: u64,
) -> ExecutionReceiptOf<Test> {
    let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
    assert!(head_receipt_number < to);

    let head_node = get_block_tree_node_at::<Test>(domain_id, head_receipt_number).unwrap();
    let mut receipt = head_node.execution_receipt;
    for block_number in (head_receipt_number + 1)..=to {
        // Finilize parent block and initialize block at `block_number`
        run_to_block::<Test>(block_number, receipt.consensus_block_hash);

        // Submit a bundle with the receipt of the last block
        let bundle_extrinsics_root = H256::random();
        let bundle = create_dummy_bundle_with_receipts(
            domain_id,
            operator_id,
            bundle_extrinsics_root,
            receipt,
        );
        assert_ok!(crate::Pallet::<Test>::submit_bundle(
            RawOrigin::None.into(),
            bundle,
        ));

        // Construct a `NewHead` receipt of the just submitted bundle, which will be included in the next bundle
        let head_receipt_number = HeadReceiptNumber::<Test>::get(domain_id);
        let parent_block_tree_node =
            get_block_tree_node_at::<Test>(domain_id, head_receipt_number).unwrap();
        receipt = create_dummy_receipt(
            block_number,
            H256::random(),
            parent_block_tree_node.execution_receipt.hash(),
            vec![bundle_extrinsics_root],
        );
    }

    receipt
}

#[allow(clippy::type_complexity)]
pub(crate) fn get_block_tree_node_at<T: Config>(
    domain_id: DomainId,
    block_number: T::DomainNumber,
) -> Option<DomainBlock<BlockNumberFor<T>, T::Hash, T::DomainNumber, T::DomainHash, BalanceOf<T>>> {
    BlockTree::<T>::get(domain_id, block_number)
        .first()
        .and_then(DomainBlocks::<T>::get)
}

// TODO: Unblock once bundle producer election v2 is finished.
#[test]
#[ignore]
fn test_stale_bundle_should_be_rejected() {
    // Small macro in order to be more readable.
    //
    // We only care about whether the error type is `StaleBundle`.
    macro_rules! assert_stale {
        ($validate_bundle_result:expr) => {
            assert_eq!(
                $validate_bundle_result,
                Err(pallet_domains::BundleError::StaleBundle)
            )
        };
    }

    macro_rules! assert_not_stale {
        ($validate_bundle_result:expr) => {
            assert_ne!(
                $validate_bundle_result,
                Err(pallet_domains::BundleError::StaleBundle)
            )
        };
    }

    ConfirmationDepthK::set(1);
    new_test_ext().execute_with(|| {
        // Create a bundle at genesis block -> #1
        let bundle0 = create_dummy_bundle(DOMAIN_ID, 0, System::parent_hash());
        System::initialize(&1, &System::parent_hash(), &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(1);
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));

        // Create a bundle at block #1 -> #2
        let block_hash1 = Hash::random();
        let bundle1 = create_dummy_bundle(DOMAIN_ID, 1, block_hash1);
        System::initialize(&2, &block_hash1, &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(2);
        assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle1));
    });

    ConfirmationDepthK::set(2);
    new_test_ext().execute_with(|| {
        // Create a bundle at genesis block -> #1
        let bundle0 = create_dummy_bundle(DOMAIN_ID, 0, System::parent_hash());
        System::initialize(&1, &System::parent_hash(), &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(1);
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));

        // Create a bundle at block #1 -> #2
        let block_hash1 = Hash::random();
        let bundle1 = create_dummy_bundle(DOMAIN_ID, 1, block_hash1);
        System::initialize(&2, &block_hash1, &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(2);
        assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle1));

        // Create a bundle at block #2 -> #3
        let block_hash2 = Hash::random();
        let bundle2 = create_dummy_bundle(DOMAIN_ID, 2, block_hash2);
        System::initialize(&3, &block_hash2, &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(3);
        assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle0));
        assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle1));
        assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(&bundle2));
    });

    ConfirmationDepthK::set(10);
    let confirmation_depth_k = ConfirmationDepthK::get();
    let (dummy_bundles, block_hashes): (Vec<_>, Vec<_>) = (1..=confirmation_depth_k + 2)
        .map(|n| {
            let consensus_block_hash = Hash::random();
            (
                create_dummy_bundle(DOMAIN_ID, n, consensus_block_hash),
                consensus_block_hash,
            )
        })
        .unzip();

    let run_to_block = |n: BlockNumber, block_hashes: Vec<Hash>| {
        System::initialize(&1, &System::parent_hash(), &Default::default());
        <Domains as Hooks<BlockNumber>>::on_initialize(1);
        System::finalize();

        for b in 2..=n {
            System::set_block_number(b);
            System::initialize(&b, &block_hashes[b as usize - 2], &Default::default());
            <Domains as Hooks<BlockNumber>>::on_initialize(b);
            System::finalize();
        }
    };

    new_test_ext().execute_with(|| {
        run_to_block(confirmation_depth_k + 2, block_hashes);
        for bundle in dummy_bundles.iter().take(2) {
            assert_stale!(pallet_domains::Pallet::<Test>::validate_bundle(bundle));
        }
        for bundle in dummy_bundles.iter().skip(2) {
            assert_not_stale!(pallet_domains::Pallet::<Test>::validate_bundle(bundle));
        }
    });
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
    let opaque_extrinsic = |dest: u64, value: u128| -> OpaqueExtrinsic {
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
            domain_name: b"test-domain".to_vec(),
            runtime_id: 0u32,
            max_block_size,
            max_block_weight: Weight::MAX,
            bundle_slot_probability: (1, 1),
            target_bundles_per_block: 1,
        };
        let domain_obj = DomainObject {
            owner_account_id: Default::default(),
            created_at: Default::default(),
            genesis_receipt_hash: Default::default(),
            domain_config,
            raw_genesis_config: None,
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
        assert_ok!(pallet_domains::Pallet::<Test>::check_bundle_size(
            &valid_bundle,
            max_block_size
        ));
        assert_ok!(pallet_domains::Pallet::<Test>::check_extrinsics_root(
            &valid_bundle
        ));

        // Bundle exceed max size
        let mut too_large_bundle = valid_bundle.clone();
        for i in 0..max_extrincis_count {
            too_large_bundle
                .extrinsics
                .push(opaque_extrinsic(i as u64, i as u128));
        }
        assert_err!(
            pallet_domains::Pallet::<Test>::check_bundle_size(&too_large_bundle, max_block_size),
            BundleError::BundleTooLarge
        );

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
    let creator = 0u64;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree(domain_id, operator_id, head_domain_number + 1);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        // Fraud proof target the genesis ER is invalid
        let bad_receipt_at = 0;
        let bad_receipt_hash = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at)
            .unwrap()
            .execution_receipt
            .hash();
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
fn test_invalid_total_rewards_fraud_proof() {
    let creator = 0u64;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree(domain_id, operator_id, head_domain_number + 1);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        let bad_receipt_at = 8;
        let mut domain_block = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at).unwrap();

        let bad_receipt_hash = domain_block.execution_receipt.hash();
        let (fraud_proof, root) = generate_invalid_total_rewards_fraud_proof::<Test>(
            domain_id,
            bad_receipt_hash,
            // set different reward in the storage and generate proof for that value
            domain_block.execution_receipt.total_rewards + 1,
        );
        domain_block.execution_receipt.final_state_root = root;
        DomainBlocks::<Test>::insert(bad_receipt_hash, domain_block);
        assert_ok!(Domains::validate_fraud_proof(&fraud_proof),);
    });
}

fn generate_invalid_total_rewards_fraud_proof<T: Config>(
    domain_id: DomainId,
    bad_receipt_hash: ReceiptHash,
    rewards: BalanceOf<T>,
) -> (FraudProof<BlockNumberFor<T>, T::Hash>, T::Hash) {
    let storage_key = sp_domains::fraud_proof::operator_block_rewards_final_key();
    let mut root = T::Hash::default();
    let mut mdb = PrefixedMemoryDB::<T::Hashing>::default();
    {
        let mut trie = TrieDBMutBuilderV1::new(&mut mdb, &mut root).build();
        trie.insert(&storage_key, &rewards.encode()).unwrap();
    };

    let backend = TrieBackendBuilder::new(mdb, root).build();
    let (root, storage_proof) = storage_proof_for_key::<T, _>(backend, StorageKey(storage_key));
    (
        FraudProof::InvalidTotalRewards(InvalidTotalRewardsProof {
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
    let creator = 0u64;
    let operator_id = 1u64;
    let head_domain_number = 10;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree(domain_id, operator_id, head_domain_number + 1);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        let bad_receipt_at = 8;
        let domain_block = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at).unwrap();

        let bad_receipt_hash = domain_block.execution_receipt.hash();
        let (fraud_proof, root) = generate_invalid_domain_extrinsic_root_fraud_proof::<Test>(
            domain_id,
            bad_receipt_hash,
            Randomness::from([1u8; 32]),
            1000,
        );
        let (consensus_block_number, consensus_block_hash) = (
            domain_block.execution_receipt.consensus_block_number,
            domain_block.execution_receipt.consensus_block_hash,
        );
        ConsensusBlockInfo::<Test>::insert(
            domain_id,
            consensus_block_number,
            (consensus_block_hash, root),
        );
        DomainBlocks::<Test>::insert(bad_receipt_hash, domain_block);
        assert_ok!(Domains::validate_fraud_proof(&fraud_proof),);
    });
}

fn generate_invalid_domain_extrinsic_root_fraud_proof<T: Config + pallet_timestamp::Config>(
    domain_id: DomainId,
    bad_receipt_hash: ReceiptHash,
    randomness: Randomness,
    moment: Moment,
) -> (FraudProof<BlockNumberFor<T>, T::Hash>, T::Hash) {
    let randomness_storage_key = sp_domains::fraud_proof::block_randomness_final_key();
    let timestamp_key = pallet_timestamp::pallet::Now::<T>::storage_value_final_key().to_vec();
    let mut root = T::Hash::default();
    let mut mdb = PrefixedMemoryDB::<T::Hashing>::default();
    {
        let mut trie = TrieDBMutBuilderV1::new(&mut mdb, &mut root).build();
        trie.insert(&randomness_storage_key, &randomness.encode())
            .unwrap();
        trie.insert(&timestamp_key, &moment.encode()).unwrap();
    };

    let backend = TrieBackendBuilder::new(mdb, root).build();
    let (_, randomness_proof) =
        storage_proof_for_key::<T, _>(backend.clone(), StorageKey(randomness_storage_key));
    let (root, timestamp_proof) = storage_proof_for_key::<T, _>(backend, StorageKey(timestamp_key));
    let valid_bundle_digests = vec![ValidBundleDigest {
        bundle_index: 0,
        bundle_digest: vec![(Some(vec![1, 2, 3]), ExtrinsicDigest::Data(vec![4, 5, 6]))],
    }];
    (
        FraudProof::InvalidExtrinsicsRoot(InvalidExtrinsicsRootProof {
            domain_id,
            bad_receipt_hash,
            randomness_proof,
            valid_bundle_digests,
            timestamp_proof,
        }),
        root,
    )
}

#[test]
fn test_basic_fraud_proof_processing() {
    let creator = 0u64;
    let operator_id = 1u64;
    let head_domain_number = BlockTreePruningDepth::get() as u64 * 2;
    let bad_receipt_at = head_domain_number - BlockTreePruningDepth::get() as u64 / 2;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree(domain_id, operator_id, head_domain_number + 1);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        // Construct and submit fraud proof that target ER at `head_domain_number - BlockTreePruningDepth::get() / 2`
        let bad_receipt = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at)
            .unwrap()
            .execution_receipt;
        let bad_receipt_hash = bad_receipt.hash();
        let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, bad_receipt_hash);
        assert_ok!(Domains::submit_fraud_proof(
            RawOrigin::None.into(),
            Box::new(fraud_proof)
        ));

        // The head receipt number should be reverted to `bad_receipt_at - 1`
        let head_receipt_number_after_fraud_proof = HeadReceiptNumber::<Test>::get(domain_id);
        assert_eq!(head_receipt_number_after_fraud_proof, bad_receipt_at - 1);

        for block_number in bad_receipt_at..=head_domain_number {
            // The targetted ER and all its descendants should be removed from the block tree
            assert!(BlockTree::<Test>::get(domain_id, block_number).is_empty());

            // The other data that used to verify ER should not be removed, such that the honest
            // operator can re-submit the valid ER
            assert!(
                !ExecutionInbox::<Test>::get((domain_id, block_number, block_number)).is_empty()
            );
            assert!(ConsensusBlockInfo::<Test>::get(domain_id, block_number).is_some());
        }

        // Re-submit the valid ER
        let resubmit_receipt = bad_receipt;
        let bundle = create_dummy_bundle_with_receipts(
            domain_id,
            operator_id,
            H256::random(),
            resubmit_receipt,
        );
        assert_ok!(Domains::submit_bundle(RawOrigin::None.into(), bundle,));
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_receipt_number_after_fraud_proof + 1
        );
    });
}

#[test]
fn test_fraud_proof_prune_fraudulent_branch_of_receipt() {
    let creator = 0u64;
    let operator_id = 1u64;
    let head_domain_number = BlockTreePruningDepth::get() as u64 * 2;
    let bad_receipt_start_at = head_domain_number - BlockTreePruningDepth::get() as u64 / 2;
    let mut ext = new_test_ext_with_extensions();
    ext.execute_with(|| {
        let domain_id = register_genesis_domain(creator, vec![operator_id]);
        extend_block_tree(domain_id, operator_id, head_domain_number + 1);
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );

        // Construct a fraudulent branch of ER in the block tree start at `head_domain_number - BlockTreePruningDepth::get() / 2`
        let mut bad_receipts = vec![];
        for i in 0..3 {
            let bad_receipt_at = bad_receipt_start_at + i;
            let bad_receipt = {
                let mut er = get_block_tree_node_at::<Test>(domain_id, bad_receipt_at)
                    .unwrap()
                    .execution_receipt;
                er.final_state_root = H256::random();
                if let Some(h) = bad_receipts.last() {
                    er.parent_domain_block_receipt_hash = *h;
                }
                er
            };
            let bad_receipt_hash = bad_receipt.hash();
            let bundle = create_dummy_bundle_with_receipts(
                domain_id,
                operator_id,
                H256::random(),
                bad_receipt,
            );
            assert_ok!(Domains::submit_bundle(RawOrigin::None.into(), bundle));
            bad_receipts.push(bad_receipt_hash);

            assert_eq!(BlockTree::<Test>::get(domain_id, bad_receipt_at).len(), 2);
            assert!(DomainBlocks::<Test>::get(bad_receipt_hash).is_some());
        }

        // Construct and submit a fraud proof for the fraudulent branch of ER
        let fraud_proof = FraudProof::dummy_fraud_proof(domain_id, bad_receipts[0]);
        assert_ok!(Domains::submit_fraud_proof(
            RawOrigin::None.into(),
            Box::new(fraud_proof)
        ));

        // The head receipt number should be unchanged since the best branch of ER is valid
        // and only the fraudulent branch of ER should be removed from the block tree
        assert_eq!(
            HeadReceiptNumber::<Test>::get(domain_id),
            head_domain_number
        );
        for i in 0..3 {
            let bad_receipt_at = bad_receipt_start_at + i;
            assert_eq!(BlockTree::<Test>::get(domain_id, bad_receipt_at).len(), 1);
            assert!(DomainBlocks::<Test>::get(bad_receipts[i as usize]).is_none());
        }
    });
}
