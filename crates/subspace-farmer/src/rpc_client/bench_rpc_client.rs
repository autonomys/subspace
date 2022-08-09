use crate::rpc_client::{Error, RpcClient};
use crate::utils::AbortingJoinHandle;
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::{stream, SinkExt, Stream, StreamExt};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{RecordsRoot, SegmentIndex};
use subspace_rpc_primitives::{
    FarmerProtocolInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};
use tokio::sync::Mutex;

/// Client mock for benching purpose
#[derive(Clone, Debug)]
pub struct BenchRpcClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct Inner {
    farmer_protocol_info: FarmerProtocolInfo,
    slot_info_receiver: Arc<Mutex<mpsc::Receiver<SlotInfo>>>,
    acknowledge_archived_segment_sender: mpsc::Sender<SegmentIndex>,
    archived_segments_receiver: Arc<Mutex<mpsc::Receiver<ArchivedSegment>>>,
    _segment_producer_handle: AbortingJoinHandle<()>,
}

/// Default farmer metadata for benchmarking
pub const BENCH_FARMER_PROTOCOL_INFO: FarmerProtocolInfo = FarmerProtocolInfo {
    genesis_hash: [0; 32],
    // PIECE_SIZE - WITNESS_SIZE
    record_size: NonZeroU32::new(3840).expect("We must set non-zero integer here."),
    recorded_history_segment_size: 491520, // RECORD_SIZE * MERKLE_NUM_LEAVES / 2
    max_plot_size: 100 * 1024 * 1024 * 1024, // 100G
    // Doesn't matter, as we don't start sync
    total_pieces: 0,
};

impl BenchRpcClient {
    /// Create a new instance of [`BenchRpcClient`].
    pub fn new(
        farmer_protocol_info: FarmerProtocolInfo,
        slot_info_receiver: mpsc::Receiver<SlotInfo>,
        mut archived_segments_receiver: mpsc::Receiver<ArchivedSegment>,
        acknowledge_archived_segment_sender: mpsc::Sender<SegmentIndex>,
    ) -> Self {
        let (mut inner_archived_segments_sender, inner_archived_segments_receiver) =
            mpsc::channel(10);

        let segment_producer_handle = tokio::spawn({
            async move {
                while let Some(segment) = archived_segments_receiver.next().await {
                    if inner_archived_segments_sender.send(segment).await.is_err() {
                        break;
                    }
                }
            }
        });

        Self {
            inner: Arc::new(Inner {
                farmer_protocol_info,
                slot_info_receiver: Arc::new(Mutex::new(slot_info_receiver)),
                archived_segments_receiver: Arc::new(Mutex::new(inner_archived_segments_receiver)),
                acknowledge_archived_segment_sender,
                _segment_producer_handle: AbortingJoinHandle::new(segment_producer_handle),
            }),
        }
    }
}

#[async_trait]
impl RpcClient for BenchRpcClient {
    async fn farmer_protocol_info(&self) -> Result<FarmerProtocolInfo, Error> {
        Ok(self.inner.farmer_protocol_info)
    }

    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, Error> {
        let (mut sender, receiver) = mpsc::channel(10);
        let slot_receiver = self.inner.slot_info_receiver.clone();
        tokio::spawn(async move {
            while let Some(slot_info) = slot_receiver.lock().await.next().await {
                if sender.send(slot_info).await.is_err() {
                    break;
                }
            }
        });

        Ok(Box::pin(receiver))
    }

    async fn submit_solution_response(
        &self,
        _solution_response: SolutionResponse,
    ) -> Result<(), Error> {
        // Bench RPC client doesn't care
        Ok(())
    }

    async fn subscribe_reward_signing(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, Error> {
        Ok(Box::pin(stream::empty()))
    }

    async fn submit_reward_signature(
        &self,
        _reward_signature: RewardSignatureResponse,
    ) -> Result<(), Error> {
        unreachable!("Unreachable, as we don't start farming for benchmarking")
    }

    async fn subscribe_archived_segments(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = ArchivedSegment> + Send + 'static>>, Error> {
        let (mut sender, receiver) = mpsc::channel(0);
        let archived_segments_receiver = self.inner.archived_segments_receiver.clone();
        tokio::spawn(async move {
            while let Some(archived_segment) = archived_segments_receiver.lock().await.next().await
            {
                if sender.send(archived_segment).await.is_err() {
                    break;
                }
            }
        });

        Ok(Box::pin(receiver))
    }

    async fn acknowledge_archived_segment(&self, segment_index: SegmentIndex) -> Result<(), Error> {
        self.inner
            .acknowledge_archived_segment_sender
            .clone()
            .send(segment_index)
            .await?;
        Ok(())
    }

    async fn records_roots(&self, _: Vec<SegmentIndex>) -> Result<Vec<Option<RecordsRoot>>, Error> {
        Ok(Default::default())
    }
}
