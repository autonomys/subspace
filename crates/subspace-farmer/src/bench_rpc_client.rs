use crate::rpc_client::{Error, RpcClient};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::NPieces;
use subspace_rpc_primitives::{
    FarmerMetadata, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Client mock for benching purpose
#[derive(Clone, Debug)]
pub struct BenchRpcClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct Inner {
    metadata: FarmerMetadata,
    acknowledge_archived_segment_sender: mpsc::Sender<u64>,
    archived_segments_receiver: Arc<Mutex<mpsc::Receiver<ArchivedSegment>>>,
    segment_producer_handle: Mutex<JoinHandle<()>>,
}

/// Default farmer metadata for benchmarking
pub const BENCH_FARMER_METADATA: FarmerMetadata = FarmerMetadata {
    record_size: 3840,                     // PIECE_SIZE - WITNESS_SIZE
    recorded_history_segment_size: 491520, // RECORD_SIZE * MERKLE_NUM_LEAVES / 2
    max_plot_size: NPieces::from_bytes(100 * 1024 * 1024 * 1024), // 100G
    // Doesn't matter, as we don't start sync
    total_pieces: NPieces::from_bytes(0),
};

impl BenchRpcClient {
    /// Create a new instance of [`BenchRpcClient`].
    pub fn new(
        metadata: FarmerMetadata,
        mut archived_segments_receiver: mpsc::Receiver<ArchivedSegment>,
    ) -> Self {
        let (mut inner_archived_segments_sender, inner_archived_segments_receiver) =
            mpsc::channel(10);
        let (acknowledge_archived_segment_sender, mut acknowledge_archived_segment_receiver) =
            mpsc::channel(1);

        let segment_producer_handle = tokio::spawn({
            async move {
                while let Some(segment) = archived_segments_receiver.next().await {
                    if inner_archived_segments_sender.send(segment).await.is_err() {
                        break;
                    }
                    if acknowledge_archived_segment_receiver.next().await.is_none() {
                        break;
                    }
                }
            }
        });

        Self {
            inner: Arc::new(Inner {
                metadata,
                archived_segments_receiver: Arc::new(Mutex::new(inner_archived_segments_receiver)),
                acknowledge_archived_segment_sender,
                segment_producer_handle: Mutex::new(segment_producer_handle),
            }),
        }
    }

    pub async fn stop(self) {
        self.inner.segment_producer_handle.lock().await.abort();
    }
}

#[async_trait]
impl RpcClient for BenchRpcClient {
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, Error> {
        Ok(self.inner.metadata)
    }

    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, Error> {
        unreachable!("Unreachable, as we don't start farming for benchmarking")
    }

    async fn submit_solution_response(
        &self,
        _solution_response: SolutionResponse,
    ) -> Result<(), Error> {
        unreachable!("Unreachable, as we don't start farming for benchmarking")
    }

    async fn subscribe_reward_signing(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, Error> {
        unreachable!("Unreachable, as we don't start farming for benchmarking")
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
        let (mut sender, receiver) = mpsc::channel(10);
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

    async fn acknowledge_archived_segment(&self, segment_index: u64) -> Result<(), Error> {
        self.inner
            .acknowledge_archived_segment_sender
            .clone()
            .send(segment_index)
            .await?;
        Ok(())
    }
}
