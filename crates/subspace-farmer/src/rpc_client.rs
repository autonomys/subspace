use async_trait::async_trait;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::BlockNumber;
use subspace_rpc_primitives::{
    BlockSignature, BlockSigningInfo, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::{
    sync::mpsc::{self, Receiver},
    time::Instant,
};

/// To become error type agnostic
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub enum SegmentPipelineEventSender {
    Some(mpsc::UnboundedSender<SegmentPipelineEvent>),
    None,
}

impl SegmentPipelineEventSender {
    pub fn send(&self, event: SegmentPipelineEvent) {
        if let Self::Some(sender) = self {
            let _ = sender.send(event);
        }
    }
}

/// Event of benchmarking of archiving
pub enum SegmentPipelineEvent {
    /// Segment was received
    Received {
        /// Starting index of pieces
        pieces_start_index: u64,
        /// Amount of pieces created
        pieces_amount: u64,
        /// Moment of time at which some stage was finished
        at: Instant,
    },
    /// Last mentioned segment pieces were encoded
    Encoded {
        /// Starting index of pieces
        pieces_start_index: u64,
        /// Amount of pieces created
        pieces_amount: u64,
        at: Instant,
    },
    /// Last mentioned segment pieces were written to plot
    WritenToPlot {
        /// Starting index of pieces
        pieces_start_index: u64,
        /// Amount of pieces created
        pieces_amount: u64,
        at: Instant,
    },
    /// Evicted pieces were removed
    EvictedPieces {
        /// Starting index of pieces
        pieces_start_index: u64,
        /// Amount of pieces created
        pieces_amount: u64,
        at: Instant,
    },
    /// New commitments were created
    CreatedCommitments {
        /// Starting index of pieces
        pieces_start_index: u64,
        /// Amount of pieces created
        pieces_amount: u64,
        at: Instant,
    },
    /// Segment passed all stages
    Done {
        /// Starting index of pieces
        pieces_start_index: u64,
        /// Amount of pieces created
        pieces_amount: u64,
        /// Moment of time at which some stage was finished
        at: Instant,
    },
}

impl SegmentPipelineEvent {
    pub fn received(pieces_start_index: u64, pieces_amount: u64) -> Self {
        Self::Received {
            pieces_start_index,
            pieces_amount,
            at: Instant::now(),
        }
    }

    pub fn encoded(pieces_start_index: u64, pieces_amount: u64) -> Self {
        Self::Encoded {
            pieces_start_index,
            pieces_amount,
            at: Instant::now(),
        }
    }

    pub fn writen_to_plot(pieces_start_index: u64, pieces_amount: u64) -> Self {
        Self::WritenToPlot {
            pieces_start_index,
            pieces_amount,
            at: Instant::now(),
        }
    }

    pub fn evicted_pieces(pieces_start_index: u64, pieces_amount: u64) -> Self {
        Self::EvictedPieces {
            pieces_start_index,
            pieces_amount,
            at: Instant::now(),
        }
    }

    pub fn created_commitments(pieces_start_index: u64, pieces_amount: u64) -> Self {
        Self::CreatedCommitments {
            pieces_start_index,
            pieces_amount,
            at: Instant::now(),
        }
    }

    pub fn done(pieces_start_index: u64, pieces_amount: u64) -> Self {
        Self::Done {
            pieces_start_index,
            pieces_amount,
            at: Instant::now(),
        }
    }
}

/// Abstraction of the Remote Procedure Call Client
#[async_trait]
pub trait RpcClient: Clone + Send + Sync + 'static {
    /// Get farmer metadata
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, Error>;

    /// Get a block by number
    async fn best_block_number(&self) -> Result<BlockNumber, Error>;

    /// Subscribe to slot
    async fn subscribe_slot_info(&self) -> Result<Receiver<SlotInfo>, Error>;

    /// Submit a slot solution
    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), Error>;

    /// Subscribe to block signing request
    async fn subscribe_block_signing(&self) -> Result<Receiver<BlockSigningInfo>, Error>;

    /// Submit a block signature
    async fn submit_block_signature(&self, block_signature: BlockSignature) -> Result<(), Error>;

    /// Subscribe to archived segments
    async fn subscribe_archived_segments(&self) -> Result<Receiver<ArchivedSegment>, Error>;

    /// Acknowledge receiving of archived segments
    async fn acknowledge_archived_segment(&self, segment_index: u64) -> Result<(), Error>;

    /// Returns sender for segment pipeline event
    fn segment_pipeline_event_sender(&self) -> SegmentPipelineEventSender {
        SegmentPipelineEventSender::None
    }
}
