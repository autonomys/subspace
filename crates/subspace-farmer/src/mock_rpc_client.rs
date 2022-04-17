use crate::rpc_client::{Error as MockError, RpcClient};
use async_trait::async_trait;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::BlockNumber;
use subspace_rpc_primitives::{
    BlockSignature, BlockSigningInfo, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, Mutex};

/// `MockRpc` wrapper.
#[derive(Clone, Debug)]
pub struct MockRpcClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct Inner {
    metadata_sender: mpsc::Sender<FarmerMetadata>,
    metadata_receiver: Arc<Mutex<mpsc::Receiver<FarmerMetadata>>>,
    slot_into_sender: Mutex<Option<mpsc::Sender<SlotInfo>>>,
    slot_info_receiver: Arc<Mutex<mpsc::Receiver<SlotInfo>>>,
    solution_sender: mpsc::Sender<SolutionResponse>,
    solution_receiver: Arc<Mutex<mpsc::Receiver<SolutionResponse>>>,
    // TODO: Use this
    #[allow(dead_code)]
    block_signing_info_sender: Mutex<Option<mpsc::Sender<BlockSigningInfo>>>,
    block_signing_info_receiver: Arc<Mutex<mpsc::Receiver<BlockSigningInfo>>>,
    block_signature_sender: mpsc::Sender<BlockSignature>,
    // TODO: Use this
    #[allow(dead_code)]
    block_signature_receiver: Arc<Mutex<mpsc::Receiver<BlockSignature>>>,
    archived_segments_sender: Mutex<Option<mpsc::Sender<ArchivedSegment>>>,
    archived_segments_receiver: Arc<Mutex<mpsc::Receiver<ArchivedSegment>>>,
    acknowledge_archived_segment_sender: mpsc::Sender<u64>,
    // TODO: Use this
    #[allow(dead_code)]
    acknowledge_archived_segment_receiver: Arc<Mutex<mpsc::Receiver<u64>>>,
}

impl MockRpcClient {
    /// Create a new instance of [`MockRPC`].
    pub(crate) fn new() -> Self {
        // channels for MockRPC to communicate with the environment
        let (metadata_sender, metadata_receiver) = mpsc::channel(10);
        let (slot_info_sender, slot_info_receiver) = mpsc::channel(10);
        let (solution_sender, solution_receiver) = mpsc::channel(1);
        let (block_signing_info_sender, block_signing_info_receiver) = mpsc::channel(10);
        let (block_signature_sender, block_signature_receiver) = mpsc::channel(1);
        let (archived_segments_sender, archived_segments_receiver) = mpsc::channel(10);
        let (acknowledge_archived_segment_sender, acknowledge_archived_segment_receiver) =
            mpsc::channel(1);

        Self {
            inner: Arc::new(Inner {
                metadata_sender,
                metadata_receiver: Arc::new(Mutex::new(metadata_receiver)),
                slot_into_sender: Mutex::new(Some(slot_info_sender)),
                slot_info_receiver: Arc::new(Mutex::new(slot_info_receiver)),
                solution_sender,
                solution_receiver: Arc::new(Mutex::new(solution_receiver)),
                block_signing_info_sender: Mutex::new(Some(block_signing_info_sender)),
                block_signing_info_receiver: Arc::new(Mutex::new(block_signing_info_receiver)),
                block_signature_sender,
                block_signature_receiver: Arc::new(Mutex::new(block_signature_receiver)),
                archived_segments_sender: Mutex::new(Some(archived_segments_sender)),
                archived_segments_receiver: Arc::new(Mutex::new(archived_segments_receiver)),
                acknowledge_archived_segment_sender,
                acknowledge_archived_segment_receiver: Arc::new(Mutex::new(
                    acknowledge_archived_segment_receiver,
                )),
            }),
        }
    }

    pub(crate) async fn send_metadata(&self, metadata: FarmerMetadata) {
        self.inner.metadata_sender.send(metadata).await.unwrap();
    }

    pub(crate) async fn send_slot_info(&self, slot_info: SlotInfo) {
        self.inner
            .slot_into_sender
            .lock()
            .await
            .as_ref()
            .unwrap()
            .send(slot_info)
            .await
            .unwrap();
    }

    pub(crate) async fn receive_solution(&self) -> Option<SolutionResponse> {
        self.inner.solution_receiver.lock().await.recv().await
    }

    pub(crate) async fn drop_slot_sender(&self) {
        self.inner.slot_into_sender.lock().await.take().unwrap();
    }

    pub(crate) async fn send_archived_segment(&self, archived_segment: ArchivedSegment) {
        self.inner
            .archived_segments_sender
            .lock()
            .await
            .as_ref()
            .unwrap()
            .send(archived_segment)
            .await
            .unwrap();
    }

    pub(crate) async fn drop_archived_segment_sender(&self) {
        self.inner
            .archived_segments_sender
            .lock()
            .await
            .take()
            .unwrap();
    }
}

#[async_trait]
impl RpcClient for MockRpcClient {
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, MockError> {
        Ok(self.inner.metadata_receiver.lock().await.try_recv()?)
    }

    async fn best_block_number(&self) -> Result<BlockNumber, MockError> {
        // Doesn't matter for tests (at least yet)
        Ok(0)
    }

    async fn subscribe_slot_info(&self) -> Result<mpsc::Receiver<SlotInfo>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let slot_receiver = self.inner.slot_info_receiver.clone();
        tokio::spawn(async move {
            while let Some(slot_info) = slot_receiver.lock().await.recv().await {
                sender.send(slot_info).await.unwrap();
            }
        });

        Ok(receiver)
    }

    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), MockError> {
        self.inner
            .solution_sender
            .send(solution_response)
            .await
            .unwrap();
        Ok(())
    }

    async fn subscribe_block_signing(&self) -> Result<Receiver<BlockSigningInfo>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let block_signing_receiver = self.inner.block_signing_info_receiver.clone();
        tokio::spawn(async move {
            while let Some(block_signing_info) = block_signing_receiver.lock().await.recv().await {
                sender.send(block_signing_info).await.unwrap();
            }
        });

        Ok(receiver)
    }

    async fn submit_block_signature(
        &self,
        block_signature: BlockSignature,
    ) -> Result<(), MockError> {
        self.inner
            .block_signature_sender
            .send(block_signature)
            .await
            .unwrap();
        Ok(())
    }

    async fn subscribe_archived_segments(&self) -> Result<Receiver<ArchivedSegment>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let archived_segments_receiver = self.inner.archived_segments_receiver.clone();
        tokio::spawn(async move {
            while let Some(archived_segment) = archived_segments_receiver.lock().await.recv().await
            {
                sender.send(archived_segment).await.unwrap();
            }
        });

        Ok(receiver)
    }

    async fn acknowledge_archived_segment(&self, segment_index: u64) -> Result<(), MockError> {
        self.inner
            .acknowledge_archived_segment_sender
            .send(segment_index)
            .await
            .unwrap();
        Ok(())
    }
}
