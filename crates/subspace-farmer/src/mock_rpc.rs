use crate::rpc::{Error as MockError, NewHead, RpcClient};
use async_trait::async_trait;
use log::info;
use subspace_core_primitives::Tag;
use subspace_rpc_primitives::{
    EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::mpsc;

/// `MockRpc` wrapper.
#[derive(Debug)]
pub struct MockRpc {
    metadata_recv: mpsc::Receiver<FarmerMetadata>,
    block_recv: mpsc::Receiver<EncodedBlockWithObjectMapping>,
    newhead_recv: mpsc::Receiver<NewHead>,
    slot_recv: mpsc::Receiver<SlotInfo>,
    tag_recv: mpsc::Receiver<Tag>,
}

impl MockRpc {
    /// Create a new instance of [`MockRPC`].
    pub(crate) fn new(
        metadata_recv: mpsc::Receiver<FarmerMetadata>,
        block_recv: mpsc::Receiver<EncodedBlockWithObjectMapping>,
        newhead_recv: mpsc::Receiver<NewHead>,
        slot_recv: mpsc::Receiver<SlotInfo>,
        tag_recv: mpsc::Receiver<Tag>,
    ) -> Self {
        MockRpc {
            metadata_recv,
            block_recv,
            newhead_recv,
            slot_recv,
            tag_recv,
        }
    }
}

#[async_trait]
impl RpcClient for MockRpc {
    async fn farmer_metadata(&mut self) -> Result<FarmerMetadata, MockError> {
        Ok(self.metadata_recv.try_recv()?)
    }

    async fn block_by_number(
        &mut self,
        _block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, MockError> {
        Ok(Some(self.block_recv.try_recv()?))
    }

    async fn subscribe_new_head(&mut self) -> Result<mpsc::Receiver<NewHead>, MockError> {
        let (sender, receiver) = mpsc::channel(1);
        while let Ok(new_head) = self.newhead_recv.try_recv() {
            sender.send(new_head).await?;
        }

        Ok(receiver)
    }

    async fn subscribe_slot_info(&mut self) -> Result<mpsc::Receiver<SlotInfo>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        while let Ok(slot_info) = self.slot_recv.try_recv() {
            sender.send(slot_info).await?;
        }

        Ok(receiver)
    }

    async fn submit_solution_response(
        &mut self,
        solution_response: SolutionResponse,
    ) -> Result<(), MockError> {
        if let Ok(correct_tag) = self.tag_recv.try_recv() {
            let received_tag = solution_response.maybe_solution.unwrap().tag;
            if received_tag == correct_tag {
                Ok(())
            } else {
                info!("expected value was: {:?}", received_tag);
                Err("Wrong Tag!".into())
            }
        } else {
            Err("Cannot receive the correct tag from channel".into())
        }
    }
}
