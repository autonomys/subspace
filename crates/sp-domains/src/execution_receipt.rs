#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::{BundleValidity, InboxedBundle};
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
use sp_runtime::traits::{CheckedAdd, Hash as HashT, Header as HeaderT, NumberFor, Zero};
use sp_std::collections::btree_map::BTreeMap;
use subspace_runtime_primitives::BlockHashFor;

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

/// Receipt of a domain block execution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// The index of the current domain block that forms the basis of this ER.
    pub domain_block_number: DomainNumber,
    /// The block hash corresponding to `domain_block_number`.
    pub domain_block_hash: DomainHash,
    /// Extrinsic root field of the header of domain block referenced by this ER.
    pub domain_block_extrinsic_root: DomainHash,
    /// The hash of the ER for the last domain block.
    pub parent_domain_block_receipt_hash: DomainHash,
    /// A pointer to the consensus block index which contains all of the bundles that were used to derive and
    /// order all extrinsics executed by the current domain block for this ER.
    pub consensus_block_number: Number,
    /// The block hash corresponding to `consensus_block_number`.
    pub consensus_block_hash: Hash,
    /// All the bundles that being included in the consensus block.
    pub inboxed_bundles: Vec<InboxedBundle<DomainHash>>,
    /// The final state root for the current domain block reflected by this ER.
    ///
    /// Used for verifying storage proofs for domains.
    pub final_state_root: DomainHash,
    /// List of storage roots collected during the domain block execution.
    pub execution_trace: Vec<DomainHash>,
    /// The Merkle root of the execution trace for the current domain block.
    ///
    /// Used for verifying fraud proofs.
    pub execution_trace_root: H256,
    /// Compute and Domain storage fees are shared across operators and Consensus
    /// storage fees are given to the consensus block author.
    pub block_fees: BlockFees<Balance>,
    /// List of transfers from this Domain to other chains
    pub transfers: Transfers<Balance>,
}

impl<Number, Hash, DomainNumber, DomainHash, Balance>
    ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>
{
    pub fn bundles_extrinsics_roots(&self) -> Vec<&DomainHash> {
        self.inboxed_bundles
            .iter()
            .map(|b| &b.extrinsics_root)
            .collect()
    }

    pub fn valid_bundle_digest_at(&self, index: usize) -> Option<DomainHash>
    where
        DomainHash: Copy,
    {
        match self.inboxed_bundles.get(index).map(|ib| &ib.bundle) {
            Some(BundleValidity::Valid(bundle_digest_hash)) => Some(*bundle_digest_hash),
            _ => None,
        }
    }

    pub fn valid_bundle_digests(&self) -> Vec<DomainHash>
    where
        DomainHash: Copy,
    {
        self.inboxed_bundles
            .iter()
            .filter_map(|b| match b.bundle {
                BundleValidity::Valid(bundle_digest_hash) => Some(bundle_digest_hash),
                BundleValidity::Invalid(_) => None,
            })
            .collect()
    }

    pub fn valid_bundle_indexes(&self) -> Vec<u32> {
        self.inboxed_bundles
            .iter()
            .enumerate()
            .filter_map(|(index, b)| match b.bundle {
                BundleValidity::Valid(_) => Some(index as u32),
                BundleValidity::Invalid(_) => None,
            })
            .collect()
    }
}

impl<
    Number: Encode + Zero,
    Hash: Encode + Default,
    DomainNumber: Encode + Zero,
    DomainHash: Clone + Encode + Default,
    Balance: Encode + Zero + Default,
> ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Returns the hash of this execution receipt.
    pub fn hash<DomainHashing: HashT<Output = DomainHash>>(&self) -> DomainHash {
        DomainHashing::hash_of(self)
    }

    pub fn genesis(
        genesis_state_root: DomainHash,
        genesis_extrinsic_root: DomainHash,
        genesis_domain_block_hash: DomainHash,
    ) -> Self {
        ExecutionReceipt {
            domain_block_number: Zero::zero(),
            domain_block_hash: genesis_domain_block_hash,
            domain_block_extrinsic_root: genesis_extrinsic_root,
            parent_domain_block_receipt_hash: Default::default(),
            consensus_block_hash: Default::default(),
            consensus_block_number: Zero::zero(),
            inboxed_bundles: Vec::new(),
            final_state_root: genesis_state_root.clone(),
            execution_trace: sp_std::vec![genesis_state_root],
            execution_trace_root: Default::default(),
            block_fees: Default::default(),
            transfers: Default::default(),
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
        ExecutionReceipt {
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
        }
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
