use crate::rpc_client::{Error as MockError, RpcClient};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::{SinkExt, Stream, StreamExt};
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_rpc_primitives::{
    FarmerProtocolInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};
use tokio::sync::Mutex;

/// `MockRpc` wrapper.
#[derive(Clone, Debug)]
pub struct MockRpcClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct Inner {
    farmer_protocol_info_sender: mpsc::Sender<FarmerProtocolInfo>,
    farmer_protocol_info_receiver: Arc<Mutex<mpsc::Receiver<FarmerProtocolInfo>>>,
    slot_into_sender: Mutex<Option<mpsc::Sender<SlotInfo>>>,
    slot_info_receiver: Arc<Mutex<mpsc::Receiver<SlotInfo>>>,
    solution_sender: mpsc::Sender<SolutionResponse>,
    solution_receiver: Arc<Mutex<mpsc::Receiver<SolutionResponse>>>,
    // TODO: Use this
    #[allow(dead_code)]
    reward_signing_info_sender: Mutex<Option<mpsc::Sender<RewardSigningInfo>>>,
    reward_signing_info_receiver: Arc<Mutex<mpsc::Receiver<RewardSigningInfo>>>,
    reward_signature_sender: mpsc::Sender<RewardSignatureResponse>,
    // TODO: Use this
    #[allow(dead_code)]
    reward_signature_receiver: Arc<Mutex<mpsc::Receiver<RewardSignatureResponse>>>,
    archived_segments_sender: Mutex<Option<mpsc::Sender<ArchivedSegment>>>,
    archived_segments_receiver: Arc<Mutex<mpsc::Receiver<ArchivedSegment>>>,
    acknowledge_archived_segment_sender: mpsc::Sender<u64>,
    acknowledge_archived_segment_receiver: Arc<Mutex<mpsc::Receiver<u64>>>,
}

impl MockRpcClient {
    /// Create a new instance of [`MockRPC`].
    pub(crate) fn new() -> Self {
        // channels for MockRPC to communicate with the environment
        let (farmer_protocol_info_sender, farmer_protocol_info_receiver) = mpsc::channel(10);
        let (slot_info_sender, slot_info_receiver) = mpsc::channel(10);
        let (solution_sender, solution_receiver) = mpsc::channel(1);
        let (reward_signing_info_sender, reward_signing_info_receiver) = mpsc::channel(10);
        let (reward_signature_sender, reward_signature_receiver) = mpsc::channel(1);
        let (archived_segments_sender, archived_segments_receiver) = mpsc::channel(10);
        let (acknowledge_archived_segment_sender, acknowledge_archived_segment_receiver) =
            mpsc::channel(1);

        Self {
            inner: Arc::new(Inner {
                farmer_protocol_info_sender,
                farmer_protocol_info_receiver: Arc::new(Mutex::new(farmer_protocol_info_receiver)),
                slot_into_sender: Mutex::new(Some(slot_info_sender)),
                slot_info_receiver: Arc::new(Mutex::new(slot_info_receiver)),
                solution_sender,
                solution_receiver: Arc::new(Mutex::new(solution_receiver)),
                reward_signing_info_sender: Mutex::new(Some(reward_signing_info_sender)),
                reward_signing_info_receiver: Arc::new(Mutex::new(reward_signing_info_receiver)),
                reward_signature_sender,
                reward_signature_receiver: Arc::new(Mutex::new(reward_signature_receiver)),
                archived_segments_sender: Mutex::new(Some(archived_segments_sender)),
                archived_segments_receiver: Arc::new(Mutex::new(archived_segments_receiver)),
                acknowledge_archived_segment_sender,
                acknowledge_archived_segment_receiver: Arc::new(Mutex::new(
                    acknowledge_archived_segment_receiver,
                )),
            }),
        }
    }

    pub(crate) async fn send_farmer_protocol_info(&self, farmer_protocol_info: FarmerProtocolInfo) {
        self.inner
            .farmer_protocol_info_sender
            .clone()
            .send(farmer_protocol_info)
            .await
            .unwrap();
    }

    pub(crate) async fn send_slot_info(&self, slot_info: SlotInfo) {
        self.inner
            .slot_into_sender
            .lock()
            .await
            .as_mut()
            .unwrap()
            .send(slot_info)
            .await
            .unwrap();
    }

    pub(crate) async fn receive_solution(&self) -> Option<SolutionResponse> {
        self.inner.solution_receiver.lock().await.next().await
    }

    pub(crate) async fn drop_slot_sender(&self) {
        self.inner.slot_into_sender.lock().await.take().unwrap();
    }

    pub(crate) async fn send_archived_segment(&self, archived_segment: ArchivedSegment) {
        self.inner
            .archived_segments_sender
            .lock()
            .await
            .as_mut()
            .unwrap()
            .send(archived_segment)
            .await
            .unwrap();

        // Receive one acknowledgement in the background
        let acknowledge_archived_segment_receiver =
            self.inner.acknowledge_archived_segment_receiver.clone();
        tokio::spawn(async move {
            acknowledge_archived_segment_receiver
                .lock()
                .await
                .next()
                .await;
        });
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
    async fn farmer_protocol_info(&self) -> Result<FarmerProtocolInfo, MockError> {
        Ok(self
            .inner
            .farmer_protocol_info_receiver
            .lock()
            .await
            .try_next()?
            .unwrap())
    }

    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, MockError> {
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
        solution_response: SolutionResponse,
    ) -> Result<(), MockError> {
        self.inner
            .solution_sender
            .clone()
            .send(solution_response)
            .await
            .unwrap();
        Ok(())
    }

    async fn subscribe_reward_signing(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, MockError> {
        let (mut sender, receiver) = mpsc::channel(10);
        let reward_signing_receiver = self.inner.reward_signing_info_receiver.clone();
        tokio::spawn(async move {
            while let Some(reward_signing_info) = reward_signing_receiver.lock().await.next().await
            {
                if sender.send(reward_signing_info).await.is_err() {
                    break;
                }
            }
        });

        Ok(Box::pin(receiver))
    }

    async fn submit_reward_signature(
        &self,
        signature: RewardSignatureResponse,
    ) -> Result<(), MockError> {
        self.inner
            .reward_signature_sender
            .clone()
            .send(signature)
            .await
            .unwrap();
        Ok(())
    }

    async fn subscribe_archived_segments(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = ArchivedSegment> + Send + 'static>>, MockError> {
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

    async fn acknowledge_archived_segment(&self, segment_index: u64) -> Result<(), MockError> {
        self.inner
            .acknowledge_archived_segment_sender
            .clone()
            .send(segment_index)
            .await
            .unwrap();
        Ok(())
    }
}
