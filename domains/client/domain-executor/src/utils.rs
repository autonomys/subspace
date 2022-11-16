use sc_consensus::ForkChoiceStrategy;
use sp_consensus_slots::Slot;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::convert::TryInto;
use std::fmt::Debug;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber};

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub(super) struct ExecutorSlotInfo {
    /// Slot
    pub(super) slot: Slot,
    /// Global challenge
    pub(super) global_challenge: Blake2b256Hash,
}

/// An event telling the `Overseer` on the particular block
/// that has been imported or finalized.
///
/// This structure exists solely for the purposes of decoupling
/// `Overseer` code from the client code and the necessity to call
/// `HeaderBackend::block_number_from_id()`.
#[derive(Debug, Clone)]
pub struct BlockInfo<Block>
where
    Block: BlockT,
{
    /// hash of the block.
    pub hash: Block::Hash,
    /// hash of the parent block.
    pub parent_hash: Block::Hash,
    /// block's number.
    pub number: NumberFor<Block>,
    /// Fork choice of the block.
    pub fork_choice: ForkChoiceStrategy,
}

/// Converts the block number from the generic type `N1` to `N2`.
pub(crate) fn translate_number_type<N1, N2>(block_number: N1) -> N2
where
    N1: TryInto<BlockNumber>,
    N2: From<BlockNumber>,
{
    let concrete_block_number: BlockNumber = block_number
        .try_into()
        .unwrap_or_else(|_| panic!("Block number must fit into u32; qed"));

    N2::from(concrete_block_number)
}
