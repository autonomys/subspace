use parking_lot::Mutex;
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender};
use sp_consensus_slots::Slot;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::convert::TryInto;
use std::sync::Arc;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber};

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub(super) struct ExecutorSlotInfo {
    /// Slot
    pub(super) slot: Slot,
    /// Global challenge
    pub(super) global_challenge: Blake2b256Hash,
}

#[derive(Debug, Clone)]
pub(crate) struct BlockInfo<Block>
where
    Block: BlockT,
{
    /// hash of the block.
    pub hash: Block::Hash,
    /// hash of the parent block.
    pub parent_hash: Block::Hash,
    /// block's number.
    pub number: NumberFor<Block>,
}

/// Converts a generic block number to a concrete primitive block number.
pub(crate) fn to_number_primitive<N>(block_number: N) -> BlockNumber
where
    N: TryInto<BlockNumber>,
{
    block_number
        .try_into()
        .unwrap_or_else(|_| panic!("Block number must fit into u32; qed"))
}

pub type DomainImportNotificationSinks<Block, PBlock> =
    Arc<Mutex<Vec<TracingUnboundedSender<DomainBlockImportNotification<Block, PBlock>>>>>;

pub type DomainImportNotifications<Block, PBlock> =
    TracingUnboundedReceiver<DomainBlockImportNotification<Block, PBlock>>;

#[derive(Clone, Debug)]
pub struct DomainBlockImportNotification<Block: BlockT, PBlock: BlockT> {
    pub domain_block_hash: Block::Hash,
    pub primary_block_hash: PBlock::Hash,
}
