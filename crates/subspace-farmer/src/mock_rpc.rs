use crate::rpc::{Error as MockError, NewHead, RpcClient};
use async_trait::async_trait;
use std::sync::Arc;
use subspace_rpc_primitives::{
    EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::{mpsc, Mutex};

/// `MockRpc` wrapper.
#[derive(Clone, Debug)]
pub struct MockRpc {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct Inner {
    metadata_sender: mpsc::Sender<FarmerMetadata>,
    metadata_recv: Arc<Mutex<mpsc::Receiver<FarmerMetadata>>>,
    block_sender: mpsc::Sender<EncodedBlockWithObjectMapping>,
    block_recv: Arc<Mutex<mpsc::Receiver<EncodedBlockWithObjectMapping>>>,
    new_head_sender: Mutex<Option<mpsc::Sender<NewHead>>>,
    new_head_recv: Arc<Mutex<mpsc::Receiver<NewHead>>>,
    slot_sender: Mutex<Option<mpsc::Sender<SlotInfo>>>,
    slot_recv: Arc<Mutex<mpsc::Receiver<SlotInfo>>>,
    solution_sender: mpsc::Sender<SolutionResponse>,
    solution_recv: Arc<Mutex<mpsc::Receiver<SolutionResponse>>>,
}

impl MockRpc {
    /// Create a new instance of [`MockRPC`].
    pub(crate) fn new() -> Self {
        // channels for MockRPC to communicate with the environment
        let (metadata_sender, metadata_recv) = mpsc::channel(10);
        let (block_sender, block_recv) = mpsc::channel(10);
        let (new_head_sender, new_head_recv) = mpsc::channel(10);
        let (slot_sender, slot_recv) = mpsc::channel(10);
        let (solution_sender, solution_recv) = mpsc::channel(1);

        MockRpc {
            inner: Arc::new(Inner {
                metadata_sender,
                metadata_recv: Arc::new(Mutex::new(metadata_recv)),
                block_sender,
                block_recv: Arc::new(Mutex::new(block_recv)),
                new_head_sender: Mutex::new(Some(new_head_sender)),
                new_head_recv: Arc::new(Mutex::new(new_head_recv)),
                slot_sender: Mutex::new(Some(slot_sender)),
                slot_recv: Arc::new(Mutex::new(slot_recv)),
                solution_sender,
                solution_recv: Arc::new(Mutex::new(solution_recv)),
            }),
        }
    }

    pub(crate) async fn send_metadata(&self, metadata: FarmerMetadata) {
        self.inner.metadata_sender.send(metadata).await.unwrap();
    }

    pub(crate) async fn send_block(&self, block: EncodedBlockWithObjectMapping) {
        self.inner
            .block_sender
            .send(block)
            .await
            .expect("Mock RPC could not send the block:");
    }

    pub(crate) async fn send_new_head(&self, new_head: NewHead) {
        self.inner
            .new_head_sender
            .lock()
            .await
            .as_ref()
            .unwrap()
            .send(new_head)
            .await
            .unwrap();
    }

    pub(crate) async fn send_slot(&self, slot: SlotInfo) {
        self.inner
            .slot_sender
            .lock()
            .await
            .as_ref()
            .unwrap()
            .send(slot)
            .await
            .unwrap();
    }

    pub(crate) async fn receive_solution(&self) -> Option<SolutionResponse> {
        self.inner.solution_recv.lock().await.recv().await
    }

    pub(crate) async fn drop_slot_sender(&self) {
        self.inner.slot_sender.lock().await.take().unwrap();
    }

    pub(crate) async fn drop_new_head_sender(&self) {
        self.inner.new_head_sender.lock().await.take().unwrap();
    }
}

#[async_trait]
impl RpcClient for MockRpc {
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, MockError> {
        Ok(self.inner.metadata_recv.lock().await.try_recv()?)
    }

    async fn block_by_number(
        &self,
        _block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, MockError> {
        Ok(Some(self.inner.block_recv.lock().await.try_recv()?))
    }

    async fn subscribe_new_head(&self) -> Result<mpsc::Receiver<NewHead>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let new_head_r = self.inner.new_head_recv.clone();
        tokio::spawn(async move {
            while let Some(new_head) = new_head_r.lock().await.recv().await {
                sender.send(new_head).await.unwrap();
            }
        });

        Ok(receiver)
    }

    async fn subscribe_slot_info(&self) -> Result<mpsc::Receiver<SlotInfo>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let slot_r = self.inner.slot_recv.clone();
        tokio::spawn(async move {
            while let Some(slot_info) = slot_r.lock().await.recv().await {
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
}
