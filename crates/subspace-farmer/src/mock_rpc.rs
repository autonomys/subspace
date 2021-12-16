use crate::rpc::{Error as MockError, NewHead, RpcClient};
use async_trait::async_trait;
use std::sync::Arc;
use subspace_rpc_primitives::{
    BlockSignature, EncodedBlockWithObjectMapping, FarmerMetadata, SignBlockInfo, SlotInfo,
    SolutionResponse,
};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, Mutex};

/// `MockRpc` wrapper.
#[derive(Clone, Debug)]
pub struct MockRpc {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct Inner {
    metadata_sender: mpsc::Sender<FarmerMetadata>,
    metadata_receiver: Arc<Mutex<mpsc::Receiver<FarmerMetadata>>>,
    block_sender: mpsc::Sender<EncodedBlockWithObjectMapping>,
    block_receiver: Arc<Mutex<mpsc::Receiver<EncodedBlockWithObjectMapping>>>,
    new_head_sender: Mutex<Option<mpsc::Sender<NewHead>>>,
    new_head_receiver: Arc<Mutex<mpsc::Receiver<NewHead>>>,
    slot_into_sender: Mutex<Option<mpsc::Sender<SlotInfo>>>,
    slot_info_receiver: Arc<Mutex<mpsc::Receiver<SlotInfo>>>,
    solution_sender: mpsc::Sender<SolutionResponse>,
    solution_receiver: Arc<Mutex<mpsc::Receiver<SolutionResponse>>>,
    // TODO: Use this
    #[allow(dead_code)]
    sign_block_info_sender: Mutex<Option<mpsc::Sender<SignBlockInfo>>>,
    sign_block_info_receiver: Arc<Mutex<mpsc::Receiver<SignBlockInfo>>>,
    block_signature_sender: mpsc::Sender<BlockSignature>,
    // TODO: Use this
    #[allow(dead_code)]
    block_signature_receiver: Arc<Mutex<mpsc::Receiver<BlockSignature>>>,
}

impl MockRpc {
    /// Create a new instance of [`MockRPC`].
    pub(crate) fn new() -> Self {
        // channels for MockRPC to communicate with the environment
        let (metadata_sender, metadata_receiver) = mpsc::channel(10);
        let (block_sender, block_receiver) = mpsc::channel(10);
        let (new_head_sender, new_head_receiver) = mpsc::channel(10);
        let (slot_info_sender, slot_info_receiver) = mpsc::channel(10);
        let (solution_sender, solution_receiver) = mpsc::channel(1);
        let (sign_block_info_sender, sign_block_info_receiver) = mpsc::channel(10);
        let (block_signature_sender, block_signature_receiver) = mpsc::channel(1);

        MockRpc {
            inner: Arc::new(Inner {
                metadata_sender,
                metadata_receiver: Arc::new(Mutex::new(metadata_receiver)),
                block_sender,
                block_receiver: Arc::new(Mutex::new(block_receiver)),
                new_head_sender: Mutex::new(Some(new_head_sender)),
                new_head_receiver: Arc::new(Mutex::new(new_head_receiver)),
                slot_into_sender: Mutex::new(Some(slot_info_sender)),
                slot_info_receiver: Arc::new(Mutex::new(slot_info_receiver)),
                solution_sender,
                solution_receiver: Arc::new(Mutex::new(solution_receiver)),
                sign_block_info_sender: Mutex::new(Some(sign_block_info_sender)),
                sign_block_info_receiver: Arc::new(Mutex::new(sign_block_info_receiver)),
                block_signature_sender,
                block_signature_receiver: Arc::new(Mutex::new(block_signature_receiver)),
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

    pub(crate) async fn drop_new_head_sender(&self) {
        self.inner.new_head_sender.lock().await.take().unwrap();
    }
}

#[async_trait]
impl RpcClient for MockRpc {
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, MockError> {
        Ok(self.inner.metadata_receiver.lock().await.try_recv()?)
    }

    async fn block_by_number(
        &self,
        _block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, MockError> {
        Ok(Some(self.inner.block_receiver.lock().await.try_recv()?))
    }

    async fn subscribe_new_head(&self) -> Result<mpsc::Receiver<NewHead>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let new_head_receiver = self.inner.new_head_receiver.clone();
        tokio::spawn(async move {
            while let Some(new_head) = new_head_receiver.lock().await.recv().await {
                sender.send(new_head).await.unwrap();
            }
        });

        Ok(receiver)
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

    async fn subscribe_sign_block(&self) -> Result<Receiver<SignBlockInfo>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let sign_block_receiver = self.inner.sign_block_info_receiver.clone();
        tokio::spawn(async move {
            while let Some(sign_block_info) = sign_block_receiver.lock().await.recv().await {
                sender.send(sign_block_info).await.unwrap();
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
}
