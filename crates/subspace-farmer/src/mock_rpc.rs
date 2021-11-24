use crate::rpc::{Error as MockError, NewHead, RpcClient};
use async_trait::async_trait;
use log::info;
use std::sync::Arc;
use subspace_core_primitives::Tag;
use subspace_rpc_primitives::{
    EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::{mpsc, Mutex};

/// `MockRpc` wrapper.
#[derive(Debug)]
pub struct MockRpc {
    metadata_recv: Arc<Mutex<mpsc::Receiver<FarmerMetadata>>>,
    block_recv: Arc<Mutex<mpsc::Receiver<EncodedBlockWithObjectMapping>>>,
    new_head_recv: Arc<Mutex<mpsc::Receiver<NewHead>>>,
    slot_recv: Arc<Mutex<mpsc::Receiver<SlotInfo>>>,
    tag_recv: Arc<Mutex<mpsc::Receiver<Tag>>>,
    signal_sender: mpsc::Sender<()>,
}

impl MockRpc {
    /// Create a new instance of [`MockRPC`].
    pub(crate) fn new(
        metadata_recv: mpsc::Receiver<FarmerMetadata>,
        block_recv: mpsc::Receiver<EncodedBlockWithObjectMapping>,
        new_head_recv: mpsc::Receiver<NewHead>,
        slot_recv: mpsc::Receiver<SlotInfo>,
        tag_recv: mpsc::Receiver<Tag>,
        signal_sender: mpsc::Sender<()>,
    ) -> Self {
        MockRpc {
            metadata_recv: Arc::new(Mutex::new(metadata_recv)),
            block_recv: Arc::new(Mutex::new(block_recv)),
            new_head_recv: Arc::new(Mutex::new(new_head_recv)),
            slot_recv: Arc::new(Mutex::new(slot_recv)),
            tag_recv: Arc::new(Mutex::new(tag_recv)),
            signal_sender,
        }
    }
}

#[async_trait]
impl RpcClient for MockRpc {
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, MockError> {
        Ok(self.metadata_recv.lock().await.try_recv()?)
    }

    async fn block_by_number(
        &self,
        _block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, MockError> {
        Ok(Some(self.block_recv.lock().await.try_recv()?))
    }

    async fn subscribe_new_head(&self) -> Result<mpsc::Receiver<NewHead>, MockError> {
        let (sender, receiver) = mpsc::channel(10);

        // sends only a single new_head, after a solution is submitted
        let new_head_r = self.new_head_recv.clone();
        tokio::spawn(async move {
            while let Some(new_head) = new_head_r.lock().await.recv().await {
                let _ = sender.send(new_head);
            }
        });

        Ok(receiver)
    }

    async fn subscribe_slot_info(&self) -> Result<mpsc::Receiver<SlotInfo>, MockError> {
        let (sender, receiver) = mpsc::channel(10);

        // sends only a single challenge, after a solution is submitted
        let slot_r = self.slot_recv.clone();
        tokio::spawn(async move {
            while let Some(slot_info) = slot_r.lock().await.recv().await {
                let _ = sender.send(slot_info).await;
            }
        });

        Ok(receiver)
    }

    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), MockError> {
        if let Some(correct_tag) = self.tag_recv.lock().await.recv().await {
            let received_tag = solution_response.maybe_solution.unwrap().tag;
            if received_tag == correct_tag {
                let _ = self.signal_sender.send(()).await;
                Ok(())
            } else {
                info!("expected value was: {:?}", correct_tag);
                Err("Wrong Tag!".into())
            }
        } else {
            Err("Cannot receive the correct tag from channel".into())
        }
    }
}
