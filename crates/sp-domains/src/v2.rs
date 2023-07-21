// Domain primitives for the v2 architecture
// TODO: the v1 primitives can be removed and replaced by them after the domain client side
// retired all of the v1 usage.

use crate::{
    DomainId, ExtrinsicsRoot, OperatorId, OperatorSignature, ProofOfElection, ReceiptHash,
};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_api::HashT;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, NumberFor, Zero};
use sp_runtime::OpaqueExtrinsic;
use sp_std::vec::Vec;
use sp_weights::Weight;

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct BundleHeader<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// The consensus chain's best block number when the bundle is created. Used for detect stale
    /// bundle and prevent attacker from reusing them to occupy the block space without cost.
    pub consensus_block_number: Number,
    /// Proof of bundle producer election.
    pub proof_of_election: ProofOfElection<DomainHash>,
    /// Execution receipt that should extend the receipt chain or add confirmations
    /// to the head receipt.
    pub receipt: ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// The size of the bundle body in bytes. Used to calculate the storage cost.
    pub bundle_size: u32,
    /// The total (estimated) weight of all extrinsics in the bundle. Used to prevent overloading
    /// the bundle with compute.
    pub estimated_bundle_weight: Weight,
    /// The Merkle root of all new extrinsics included in this bundle.
    pub bundle_extrinsics_root: ExtrinsicsRoot,
}

impl<Number: Encode, Hash: Encode, DomainNumber: Encode, DomainHash: Encode, Balance: Encode>
    BundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Returns the hash of this header.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }
}

/// Header of bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct SealedBundleHeader<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// Unsealed header.
    pub header: BundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// Signature of the bundle.
    pub signature: OperatorSignature,
}

impl<Number: Encode, Hash: Encode, DomainNumber: Encode, DomainHash: Encode, Balance: Encode>
    SealedBundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Constructs a new instance of [`SealedBundleHeader`].
    pub fn new(
        header: BundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>,
        signature: OperatorSignature,
    ) -> Self {
        Self { header, signature }
    }

    /// Returns the hash of the inner unsealed header.
    pub fn pre_hash(&self) -> H256 {
        self.header.hash()
    }

    /// Returns the hash of this header.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }

    pub fn slot_number(&self) -> u64 {
        self.header.proof_of_election.slot_number
    }
}

/// Domain bundle.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct Bundle<Extrinsic, Number, Hash, DomainNumber, DomainHash, Balance> {
    /// Sealed bundle header.
    pub sealed_header: SealedBundleHeader<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// The accompanying extrinsics.
    pub extrinsics: Vec<Extrinsic>,
}

impl<
        Extrinsic: Encode,
        Number: Encode,
        Hash: Encode,
        DomainNumber: Encode,
        DomainHash: Encode,
        Balance: Encode,
    > Bundle<Extrinsic, Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Returns the hash of this bundle.
    pub fn hash(&self) -> H256 {
        BlakeTwo256::hash_of(self)
    }

    /// Returns the domain_id of this bundle.
    pub fn domain_id(&self) -> DomainId {
        self.sealed_header.header.proof_of_election.domain_id
    }

    // Return the `bundle_extrinsics_root`
    pub fn extrinsics_root(&self) -> ExtrinsicsRoot {
        self.sealed_header.header.bundle_extrinsics_root
    }

    // Return the `operator_id`
    pub fn operator_id(&self) -> OperatorId {
        self.sealed_header.header.proof_of_election.operator_id
    }

    /// Return a reference of the execution receipt.
    pub fn receipt(&self) -> &ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
        &self.sealed_header.header.receipt
    }

    /// Consumes [`Bundle`] to extract the execution receipt.
    pub fn into_receipt(self) -> ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
        self.sealed_header.header.receipt
    }
}

/// Bundle with opaque extrinsics.
pub type OpaqueBundle<Number, Hash, DomainNumber, DomainHash, Balance> =
    Bundle<OpaqueExtrinsic, Number, Hash, DomainNumber, DomainHash, Balance>;

/// List of [`OpaqueBundle`].
pub type OpaqueBundles<Block, DomainNumber, DomainHash, Balance> =
    Vec<OpaqueBundle<NumberFor<Block>, <Block as BlockT>::Hash, DomainNumber, DomainHash, Balance>>;

impl<Extrinsic: Encode, Number, Hash, DomainNumber, DomainHash, Balance>
    Bundle<Extrinsic, Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Convert a bundle with generic extrinsic to a bundle with opaque extrinsic.
    pub fn into_opaque_bundle(
        self,
    ) -> OpaqueBundle<Number, Hash, DomainNumber, DomainHash, Balance> {
        let Bundle {
            sealed_header,
            extrinsics,
        } = self;
        let opaque_extrinsics = extrinsics
            .into_iter()
            .map(|xt| {
                OpaqueExtrinsic::from_bytes(&xt.encode())
                    .expect("We have just encoded a valid extrinsic; qed")
            })
            .collect();
        OpaqueBundle {
            sealed_header,
            extrinsics: opaque_extrinsics,
        }
    }
}

/// Receipt of a domain block execution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance> {
    // The index of the current domain block that forms the basis of this ER.
    pub domain_block_number: DomainNumber,
    // The block hash correspond to `domain_block_number`.
    pub domain_block_hash: DomainHash,
    // A pointer to the hash of the ER for the last domain block.
    pub parent_domain_block_receipt_hash: ReceiptHash,
    // A pointer to the consensus block index which contains all of the bundles that were used to derive and
    // order all extrinsics executed by the current domain block for this ER.
    pub consensus_block_number: Number,
    // The block hash correspond to `consensus_block_number`.
    pub consensus_block_hash: Hash,
    // All `extrinsics_roots` for all bundles being executed by this block. Used to ensure these are contained
    // within the state of the `execution_inbox`.
    pub block_extrinsics_roots: Vec<ExtrinsicsRoot>,
    // The final state root for the current domain block reflected by this ER. Used for verifying storage proofs
    // for domains.
    pub final_state_root: DomainHash,
    /// List of storage roots collected during the domain block execution.
    pub execution_trace: Vec<DomainHash>,
    // The Merkle root of the execution trace for the current domain block. Used for verifying fraud proofs.
    pub execution_trace_root: H256,
    // All SSC rewards for this ER to be shared across operators.
    pub total_rewards: Balance,
}

impl<
        Number: Encode + Zero,
        Hash: Encode + Default,
        DomainNumber: Encode + Zero,
        DomainHash: Clone + Encode + Default,
        Balance: Encode + Zero,
    > ExecutionReceipt<Number, Hash, DomainNumber, DomainHash, Balance>
{
    /// Returns the hash of this execution receipt.
    pub fn hash(&self) -> ReceiptHash {
        BlakeTwo256::hash_of(self)
    }

    pub fn genesis(consensus_genesis_hash: Hash, genesis_state_root: DomainHash) -> Self {
        ExecutionReceipt {
            domain_block_number: Zero::zero(),
            domain_block_hash: Default::default(),
            parent_domain_block_receipt_hash: Default::default(),
            consensus_block_hash: consensus_genesis_hash,
            consensus_block_number: Zero::zero(),
            block_extrinsics_roots: sp_std::vec![],
            final_state_root: genesis_state_root.clone(),
            execution_trace: sp_std::vec![genesis_state_root],
            execution_trace_root: Default::default(),
            total_rewards: Zero::zero(),
        }
    }
}
