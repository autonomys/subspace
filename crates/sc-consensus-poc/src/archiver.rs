use sp_runtime::traits::{Block as BlockT, NumberFor};

/// State associated with archiving process of Subspace blockchain (permanent storage of
/// blocks).
#[derive(Debug)]
struct RecordingHistoryState<Block: BlockT> {
    /// Last block that was included into recorded history, used to determine what blocks should be
    /// included next.
    ///
    /// NOTE: This block might be included partially if it was large enough to be split over into
    /// the next segment.
    last_recorded_block: Option<NumberFor<Block>>,
    /// How much data from `last_recorded_block` was spilled over into the next segment, such that
    /// we can extract it and prepend to the next segment.
    spill_over_offset: u32,
    /// Total amount of buffered data in bytes that is pending to be included into the next segment,
    /// will include data of the last block spilled over into the next segment.
    buffered_data: u32,
}

impl<Block: BlockT> Default for RecordingHistoryState<Block> {
    fn default() -> Self {
        Self {
            last_recorded_block: None,
            spill_over_offset: 0,
            buffered_data: 0,
        }
    }
}

#[derive(Debug)]
pub(super) struct Archiver<Block: BlockT> {
    recorded_history_segment_size: u32,
    state: RecordingHistoryState<Block>,
}

impl<Block: BlockT> Archiver<Block> {
    pub(super) fn new(recorded_history_segment_size: u32) -> Self {
        Self {
            recorded_history_segment_size,
            state: RecordingHistoryState::default(),
        }
    }

    pub(super) fn add_block(&self, block: Block) {
        // TODO
    }
}
