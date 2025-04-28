use parking_lot::Mutex;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_consensus_slots::Slot;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;
use subspace_core_primitives::pot::PotOutput;

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub struct OperatorSlotInfo {
    /// Slot
    pub slot: Slot,
    /// The PoT output for `slot`
    pub proof_of_time: PotOutput,
}

#[derive(Debug, Clone)]
pub(crate) struct BlockInfo<Block>
where
    Block: BlockT,
{
    /// hash of the block.
    pub hash: Block::Hash,
    /// block's number.
    pub number: NumberFor<Block>,
    /// Is this the new best block.
    pub is_new_best: bool,
}

pub type DomainImportNotificationSinks<Block, CBlock> =
    Arc<Mutex<Vec<TracingUnboundedSender<DomainBlockImportNotification<Block, CBlock>>>>>;

#[derive(Clone, Debug)]
pub struct DomainBlockImportNotification<Block: BlockT, CBlock: BlockT> {
    pub domain_block_hash: Block::Hash,
    pub consensus_block_hash: CBlock::Hash,
}
