pub mod execution_receipt_v0;

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::InboxedBundle;
use crate::execution_receipt::execution_receipt_v0::ExecutionReceiptV0;
use crate::runtime_decl_for_bundle_producer_election_api::HashT;
use crate::{
    ChainId, DomainId, HeaderHashFor, HeaderHashingFor, HeaderNumberFor, OperatorId,
    OperatorSignature, ProofOfElection,
};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::traits::{CheckedAdd, Header as HeaderT, NumberFor, Zero};
use sp_std::collections::btree_map::BTreeMap;
use subspace_runtime_primitives::BlockHashFor;

/// Execution Receipt Versions.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Copy)]
pub enum ExecutionReceiptVersion {
    /// V0 execution receipt.
    V0,
}

#[derive(Clone, Debug, Decode, Default, Encode, Eq, PartialEq, TypeInfo)]
pub struct BlockFees<Balance> {
    /// The consensus chain storage fee
    pub consensus_storage_fee: Balance,
    /// The domain execution fee including the storage and compute fee on domain chain,
    /// tip, and the XDM reward.
    pub domain_execution_fee: Balance,
    /// Burned balances on domain chain
    pub burned_balance: Balance,
    /// Rewards for the chain.
    pub chain_rewards: BTreeMap<ChainId, Balance>,
}

impl<Balance> BlockFees<Balance>
where
    Balance: CheckedAdd + Zero,
{
    pub fn new(
        domain_execution_fee: Balance,
        consensus_storage_fee: Balance,
        burned_balance: Balance,
        chain_rewards: BTreeMap<ChainId, Balance>,
    ) -> Self {
        BlockFees {
            consensus_storage_fee,
            domain_execution_fee,
            burned_balance,
            chain_rewards,
        }
    }

    /// Returns the total fees that was collected and burned on the Domain.
    pub fn total_fees(&self) -> Option<Balance> {
        let total_chain_reward = self
            .chain_rewards
            .values()
            .try_fold(Zero::zero(), |acc: Balance, cr| acc.checked_add(cr))?;
        self.consensus_storage_fee
            .checked_add(&self.domain_execution_fee)
            .and_then(|balance| balance.checked_add(&self.burned_balance))
            .and_then(|balance| balance.checked_add(&total_chain_reward))
    }
}

/// Type that holds the transfers(in/out) for a given chain.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, Default)]
pub struct Transfers<Balance> {
    /// Total transfers that came into the domain.
    pub transfers_in: BTreeMap<ChainId, Balance>,
    /// Total transfers that went out of the domain.
    pub transfers_out: BTreeMap<ChainId, Balance>,
    /// Total transfers from this domain that were reverted.
    pub rejected_transfers_claimed: BTreeMap<ChainId, Balance>,
    /// Total transfers to this domain that were rejected.
    pub transfers_rejected: BTreeMap<ChainId, Balance>,
}

impl<Balance> Transfers<Balance> {
    pub fn is_valid(&self, chain_id: ChainId) -> bool {
        !self.transfers_rejected.contains_key(&chain_id)
            && !self.transfers_in.contains_key(&chain_id)
            && !self.transfers_out.contains_key(&chain_id)
            && !self.rejected_transfers_claimed.contains_key(&chain_id)
    }
}

/// Receipt for execution of Domain Bundle holding the reference to various ER versions.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Copy, Clone)]
pub enum ExecutionReceiptRef<'a, Number, Hash, DomainNumber, DomainHash, Balance> {
    V0(&'a ExecutionReceiptV0<Number, Hash, DomainNumber, DomainHash, Balance>),
}

impl<'a, Number, Hash, DomainNumber, DomainHash, Balance>
    ExecutionReceiptRef<'a, Number, Hash, DomainNumber, DomainHash, Balance>
where
    Number: Encode + Clone,
    Hash: Encode + Clone,
    DomainNumber: Encode + Clone,
    DomainHash: Encode + Clone,
    Balance: Encode + Clone,
{
    pub fn hash<DomainHashing: HashT<Output = DomainHash>>(&self) -> DomainHash {
        match self {
            // for v0, we need hash of inner execution receipt v0
            ExecutionReceiptRef::V0(receipt) => receipt.hash::<DomainHashing>(),
        }
    }

    /// Returns a cloned ER. Used in tests.
    pub fn to_owned_er(self) -> ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
        match self {
            ExecutionReceiptRef::V0(er) => ExecutionReceipt::V0(er.clone()),
        }
    }

    /// Returns the consensus block number at which ER is derived.
    pub fn consensus_block_number(&self) -> &Number {
        match self {
            ExecutionReceiptRef::V0(er) => &er.consensus_block_number,
        }
    }

    /// Return the execution receipt version.
    pub fn version(&self) -> ExecutionReceiptVersion {
        match self {
            ExecutionReceiptRef::V0(_) => ExecutionReceiptVersion::V0,
        }
    }
}

/// Receipt for execution of Domain Bundle holding the mutable reference to various ER versions.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq)]
pub enum ExecutionReceiptMutRef<'a, Number, Hash, DomainNumber, DomainHash, Balance> {
    V0(&'a mut ExecutionReceiptV0<Number, Hash, DomainNumber, DomainHash, Balance>),
}

/// Receipt for execution of Domain Bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
    V0(ExecutionReceiptV0<Number, Hash, DomainNumber, DomainHash, Balance>),
}

impl<Number, Hash, DomainNumber, DomainHash, Balance>
    ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>
where
    Number: Encode + Zero,
    Hash: Encode + Default,
    DomainNumber: Encode + Zero,
    DomainHash: Clone + Encode + Default + Copy,
    Balance: Encode + Zero + Default,
{
    /// Returns the domain block number.
    pub fn domain_block_number(&self) -> &DomainNumber {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.domain_block_number
    }

    /// Returns the domain block hash.
    pub fn domain_block_hash(&self) -> &DomainHash {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.domain_block_hash
    }

    /// Returns the final state root of the execution.
    pub fn final_state_root(&self) -> &DomainHash {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.final_state_root
    }

    /// Returns the parent's receipt hash.
    pub fn parent_domain_block_receipt_hash(&self) -> &DomainHash {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.parent_domain_block_receipt_hash
    }

    /// Returns the consensus block number.
    pub fn consensus_block_number(&self) -> &Number {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.consensus_block_number
    }

    /// Returns the consensus block hash.
    pub fn consensus_block_hash(&self) -> &Hash {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.consensus_block_hash
    }

    /// Returns the inboxed bundles.
    pub fn inboxed_bundles(&self) -> &[InboxedBundle<DomainHash>] {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.inboxed_bundles
    }

    /// Returns the execution traces of the execution.
    pub fn execution_traces(&self) -> &[DomainHash] {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.execution_trace
    }

    /// Returns Domain block extrinsics root.
    pub fn domain_block_extrinsics_root(&self) -> &DomainHash {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.domain_block_extrinsic_root
    }

    /// Returns the Block fees of the Execution.
    pub fn block_fees(&self) -> &BlockFees<Balance> {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.block_fees
    }

    /// Returns the transfers of the Execution.
    pub fn transfers(&self) -> &Transfers<Balance> {
        let ExecutionReceipt::V0(receipt) = self;
        &receipt.transfers
    }

    /// Returns the valid bundle digests in the ER.
    pub fn valid_bundle_digests(&self) -> Vec<DomainHash> {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.valid_bundle_digests()
    }

    /// Returns extrinsics roots of each bundle.
    pub fn bundles_extrinsics_roots(&self) -> Vec<&DomainHash> {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.bundles_extrinsics_roots()
    }

    /// Returns indexes of valid bundles.
    pub fn valid_bundle_indexes(&self) -> Vec<u32> {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.valid_bundle_indexes()
    }

    /// Returns a valid bundle digest at specific index in the ER.
    pub fn valid_bundle_digest_at(&self, idx: usize) -> Option<DomainHash> {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.valid_bundle_digest_at(idx)
    }

    /// Sets final state root on ER
    pub fn set_final_state_root(&mut self, final_state_root: DomainHash) {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.final_state_root = final_state_root;
    }

    /// Sets inboxed bundles on Er
    pub fn set_inboxed_bundles(&mut self, inboxed_bundles: Vec<InboxedBundle<DomainHash>>) {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.inboxed_bundles = inboxed_bundles;
    }

    /// Sets domain block number on ER
    pub fn set_domain_block_number(&mut self, domain_block_number: DomainNumber) {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.domain_block_number = domain_block_number;
    }

    /// Sets consensus block number on ER
    pub fn set_consensus_block_number(&mut self, consensus_block_number: Number) {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.consensus_block_number = consensus_block_number;
    }

    /// Sets consensus block hash on ER
    pub fn set_consensus_block_hash(&mut self, consensus_block_hash: Hash) {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.consensus_block_hash = consensus_block_hash;
    }

    /// Sets parent receipt hash on ER
    pub fn set_parent_receipt_hash(&mut self, receipt_hash: DomainHash) {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.parent_domain_block_receipt_hash = receipt_hash;
    }

    pub fn set_execution_traces(&mut self, execution_traces: Vec<DomainHash>) {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.execution_trace = execution_traces;
    }

    pub fn set_execution_trace_root(&mut self, execution_trace_root: H256) {
        let ExecutionReceipt::V0(receipt) = self;
        receipt.execution_trace_root = execution_trace_root;
    }

    /// Returns the Execution receipt as a ref.
    pub fn as_execution_receipt_ref(
        &self,
    ) -> ExecutionReceiptRef<Number, Hash, DomainNumber, DomainHash, Balance> {
        let ExecutionReceipt::V0(receipt) = self;
        ExecutionReceiptRef::V0(receipt)
    }

    /// Returns the hash of this execution receipt.
    pub fn hash<DomainHashing: HashT<Output = DomainHash>>(&self) -> DomainHash {
        match self {
            // for v0,we need hash of inner execution receipt v0
            ExecutionReceipt::V0(receipt) => receipt.hash::<DomainHashing>(),
        }
    }

    /// Return the execution receipt version.
    pub fn version(&self) -> ExecutionReceiptVersion {
        match self {
            ExecutionReceipt::V0(_) => ExecutionReceiptVersion::V0,
        }
    }

    /// Returns the genesis ER.
    pub fn genesis(
        genesis_state_root: DomainHash,
        genesis_extrinsic_root: DomainHash,
        genesis_domain_block_hash: DomainHash,
        execution_receipt_version: ExecutionReceiptVersion,
    ) -> Self {
        match execution_receipt_version {
            ExecutionReceiptVersion::V0 => ExecutionReceipt::V0(ExecutionReceiptV0 {
                domain_block_number: Zero::zero(),
                domain_block_hash: genesis_domain_block_hash,
                domain_block_extrinsic_root: genesis_extrinsic_root,
                parent_domain_block_receipt_hash: Default::default(),
                consensus_block_hash: Default::default(),
                consensus_block_number: Zero::zero(),
                inboxed_bundles: Vec::new(),
                final_state_root: genesis_state_root,
                execution_trace: sp_std::vec![genesis_state_root],
                execution_trace_root: Default::default(),
                block_fees: Default::default(),
                transfers: Default::default(),
            }),
        }
    }

    #[cfg(any(feature = "std", feature = "runtime-benchmarks"))]
    pub fn dummy<DomainHashing>(
        consensus_block_number: Number,
        consensus_block_hash: Hash,
        domain_block_number: DomainNumber,
        parent_domain_block_receipt_hash: DomainHash,
    ) -> ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>
    where
        DomainHashing: HashT<Output = DomainHash>,
    {
        let execution_trace = sp_std::vec![Default::default(), Default::default()];
        let execution_trace_root = {
            let trace: Vec<[u8; 32]> = execution_trace
                .iter()
                .map(|r: &DomainHash| r.encode().try_into().expect("H256 must fit into [u8; 32]"))
                .collect();
            crate::merkle_tree::MerkleTree::from_leaves(trace.as_slice())
                .root()
                .expect("Compute merkle root of trace should success")
                .into()
        };
        ExecutionReceipt::V0(ExecutionReceiptV0 {
            domain_block_number,
            domain_block_hash: Default::default(),
            domain_block_extrinsic_root: Default::default(),
            parent_domain_block_receipt_hash,
            consensus_block_number,
            consensus_block_hash,
            inboxed_bundles: sp_std::vec![InboxedBundle::dummy(Default::default())],
            final_state_root: Default::default(),
            execution_trace,
            execution_trace_root,
            block_fees: Default::default(),
            transfers: Default::default(),
        })
    }
}

/// Singleton receipt submit along when there is a gap between `domain_best_number`
/// and `HeadReceiptNumber`
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SingletonReceipt<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Proof of receipt producer election.
    pub proof_of_election: ProofOfElection,
    /// The receipt to submit
    pub receipt: ExecutionReceipt<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
}

impl<Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    SingletonReceipt<Number, Hash, DomainHeader, Balance>
{
    pub fn hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash_of(&self)
    }
}

/// Singleton receipt with operator signature.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SealedSingletonReceipt<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// A collection of the receipt.
    pub singleton_receipt: SingletonReceipt<Number, Hash, DomainHeader, Balance>,
    /// Signature of the receipt bundle.
    pub signature: OperatorSignature,
}

impl<Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    SealedSingletonReceipt<Number, Hash, DomainHeader, Balance>
{
    /// Returns the `domain_id`
    pub fn domain_id(&self) -> DomainId {
        self.singleton_receipt.proof_of_election.domain_id
    }

    /// Return the `operator_id`
    pub fn operator_id(&self) -> OperatorId {
        self.singleton_receipt.proof_of_election.operator_id
    }

    /// Return the `slot_number` of the `proof_of_election`
    pub fn slot_number(&self) -> u64 {
        self.singleton_receipt.proof_of_election.slot_number
    }

    /// Return the receipt
    pub fn receipt(
        &self,
    ) -> &ExecutionReceipt<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    > {
        &self.singleton_receipt.receipt
    }

    /// Consume this `SealedSingletonReceipt` and return the receipt
    pub fn into_receipt(
        self,
    ) -> ExecutionReceipt<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    > {
        self.singleton_receipt.receipt
    }

    /// Returns the hash of `SingletonReceipt`
    pub fn pre_hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash_of(&self.singleton_receipt)
    }

    /// Return the encode size of `SealedSingletonReceipt`
    pub fn size(&self) -> u32 {
        self.encoded_size() as u32
    }
}

pub type ExecutionReceiptFor<DomainHeader, CBlock, Balance> = ExecutionReceipt<
    NumberFor<CBlock>,
    BlockHashFor<CBlock>,
    <DomainHeader as HeaderT>::Number,
    <DomainHeader as HeaderT>::Hash,
    Balance,
>;
