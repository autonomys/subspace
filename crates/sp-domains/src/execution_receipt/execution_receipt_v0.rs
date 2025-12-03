#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::bundle::{BundleValidity, InboxedBundle};
use crate::execution_receipt::{BlockFees, Transfers};
use crate::{HeaderHashFor, HeaderHashingFor, HeaderNumberFor, OperatorSignature, ProofOfElection};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::traits::{Hash as HashT, Header as HeaderT, NumberFor};
use subspace_runtime_primitives::BlockHashFor;

/// Receipt V0 of a domain block execution.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, DecodeWithMemTracking)]
pub struct ExecutionReceiptV0<Number, Hash, DomainNumber, DomainHash, Balance> {
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
    ExecutionReceiptV0<Number, Hash, DomainNumber, DomainHash, Balance>
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

impl<Number, Hash, DomainNumber, DomainHash, Balance>
    ExecutionReceiptV0<Number, Hash, DomainNumber, DomainHash, Balance>
where
    Number: Encode,
    Hash: Encode,
    DomainNumber: Encode,
    DomainHash: Encode,
    Balance: Encode,
{
    pub fn hash<DomainHashing: HashT<Output = DomainHash>>(&self) -> DomainHash {
        DomainHashing::hash_of(self)
    }
}

/// Singleton receipt submit along when there is a gap between `domain_best_number`
/// and `HeadReceiptNumber`
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, DecodeWithMemTracking)]
pub struct SingletonReceiptV0<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// Proof of receipt producer election.
    pub proof_of_election: ProofOfElection,
    /// The receipt to submit
    pub receipt: ExecutionReceiptV0<
        Number,
        Hash,
        HeaderNumberFor<DomainHeader>,
        HeaderHashFor<DomainHeader>,
        Balance,
    >,
}

impl<Number: Encode, Hash: Encode, DomainHeader: HeaderT, Balance: Encode>
    SingletonReceiptV0<Number, Hash, DomainHeader, Balance>
{
    pub fn hash(&self) -> HeaderHashFor<DomainHeader> {
        HeaderHashingFor::<DomainHeader>::hash_of(&self)
    }
}

#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone, DecodeWithMemTracking)]
pub struct SealedSingletonReceiptV0<Number, Hash, DomainHeader: HeaderT, Balance> {
    /// A collection of the receipt.
    pub singleton_receipt: SingletonReceiptV0<Number, Hash, DomainHeader, Balance>,
    /// Signature of the receipt bundle.
    pub signature: OperatorSignature,
}

pub type ExecutionReceiptV0For<DomainHeader, CBlock, Balance> = ExecutionReceiptV0<
    NumberFor<CBlock>,
    BlockHashFor<CBlock>,
    <DomainHeader as HeaderT>::Number,
    <DomainHeader as HeaderT>::Hash,
    Balance,
>;
