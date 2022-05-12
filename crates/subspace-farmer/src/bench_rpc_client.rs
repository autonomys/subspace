use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::prelude::*;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::objects::{PieceObject, PieceObjectMapping};
use subspace_core_primitives::{
    ArchivedBlockProgress, BlockNumber, FlatPieces, LastArchivedBlock, RootBlock, Sha256Hash,
};
use subspace_rpc_primitives::{
    BlockSignature, BlockSigningInfo, FarmerMetadata, SlotInfo, SolutionResponse,
};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::rpc_client::{Error as MockError, RpcClient};

/// Client mock for benching purpose
#[derive(Clone, Debug)]
pub struct BenchRpcClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct Inner {
    metadata: FarmerMetadata,
    slot_info_receiver: Arc<Mutex<mpsc::Receiver<SlotInfo>>>,
    acknowledge_archived_segment_sender: mpsc::Sender<u64>,
    archived_segments_receiver: Arc<Mutex<mpsc::Receiver<ArchivedSegment>>>,
    slot_info_handler: Mutex<JoinHandle<()>>,
    segment_producer_handle: Mutex<JoinHandle<()>>,
    writen_piece_count: Arc<AtomicU64>,
}

impl BenchRpcClient {
    /// Create a new instance of [`BenchRpcClient`].
    pub fn new(metadata: FarmerMetadata) -> Self {
        let (slot_info_sender, slot_info_receiver) = mpsc::channel(10);
        let (archived_segments_sender, archived_segments_receiver) = mpsc::channel(10);
        let (acknowledge_archived_segment_sender, mut acknowledge_archived_segment_receiver) =
            mpsc::channel(1);
        let writen_piece_count = Arc::new(AtomicU64::new(0));

        let slot_info_handler = tokio::spawn(async move {
            let mut slot_number = 0;
            let mut next_salt = rand::random();
            loop {
                let global_challenge = rand::random();
                next_salt = {
                    let (salt, next_salt) = (next_salt, rand::random());
                    let slot_info = SlotInfo {
                        slot_number,
                        global_challenge,
                        salt: next_salt,
                        next_salt: salt,
                        solution_range: rand::random(),
                    };
                    if slot_info_sender.send(slot_info).await.is_err() {
                        break;
                    };
                    Some(next_salt)
                };

                tokio::time::sleep(Duration::from_secs(2 * 60)).await;

                slot_number += 1;
            }
        });

        let segment_producer_handle = tokio::spawn({
            let writen_piece_count = Arc::clone(&writen_piece_count);
            async move {
                let mut segment_index = 0;
                let mut last_archived_block = LastArchivedBlock {
                    number: 0,
                    archived_progress: ArchivedBlockProgress::Partial(0),
                };
                loop {
                    last_archived_block
                        .archived_progress
                        .set_partial(segment_index as u32);

                    let archived_segment = {
                        let root_block = RootBlock::V0 {
                            segment_index,
                            records_root: Sha256Hash::default(),
                            prev_root_block_hash: Sha256Hash::default(),
                            last_archived_block,
                        };

                        let mut pieces = FlatPieces::new(100);
                        rand::thread_rng().fill(pieces.as_mut());

                        let objects = std::iter::repeat_with(|| PieceObject::V0 {
                            hash: rand::random(),
                            offset: rand::random(),
                        })
                        .take(100)
                        .collect();

                        ArchivedSegment {
                            root_block,
                            pieces,
                            object_mapping: vec![PieceObjectMapping { objects }],
                        }
                    };

                    if archived_segments_sender
                        .send(archived_segment)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if acknowledge_archived_segment_receiver.recv().await.is_none() {
                        break;
                    }

                    segment_index += 1;
                    writen_piece_count.fetch_add(100, Ordering::AcqRel);
                }
            }
        });

        Self {
            inner: Arc::new(Inner {
                metadata,
                slot_info_receiver: Arc::new(Mutex::new(slot_info_receiver)),
                archived_segments_receiver: Arc::new(Mutex::new(archived_segments_receiver)),
                acknowledge_archived_segment_sender,
                slot_info_handler: Mutex::new(slot_info_handler),
                segment_producer_handle: Mutex::new(segment_producer_handle),
                writen_piece_count,
            }),
        }
    }

    pub fn writen_piece_count(&self) -> u64 {
        self.inner.writen_piece_count.load(Ordering::Relaxed)
    }

    pub async fn stop(self) {
        self.inner.slot_info_handler.lock().await.abort();
        self.inner.segment_producer_handle.lock().await.abort();
    }
}

#[async_trait]
impl RpcClient for BenchRpcClient {
    async fn farmer_metadata(&self) -> Result<FarmerMetadata, MockError> {
        Ok(self.inner.metadata.clone())
    }

    async fn best_block_number(&self) -> Result<BlockNumber, MockError> {
        // Doesn't matter for tests (at least yet)
        Ok(BlockNumber::MAX)
    }

    async fn subscribe_slot_info(&self) -> Result<mpsc::Receiver<SlotInfo>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let slot_receiver = self.inner.slot_info_receiver.clone();
        tokio::spawn(async move {
            while let Some(slot_info) = slot_receiver.lock().await.recv().await {
                if sender.send(slot_info).await.is_err() {
                    break;
                }
            }
        });

        Ok(receiver)
    }

    async fn submit_solution_response(
        &self,
        _solution_response: SolutionResponse,
    ) -> Result<(), MockError> {
        unreachable!("Unreachable, as we don't start farming for benchmarking")
    }

    async fn subscribe_block_signing(&self) -> Result<Receiver<BlockSigningInfo>, MockError> {
        unreachable!("Unreachable, as we don't start farming for benchmarking")
    }

    async fn submit_block_signature(
        &self,
        _block_signature: BlockSignature,
    ) -> Result<(), MockError> {
        unreachable!("Unreachable, as we don't start farming for benchmarking")
    }

    async fn subscribe_archived_segments(&self) -> Result<Receiver<ArchivedSegment>, MockError> {
        let (sender, receiver) = mpsc::channel(10);
        let archived_segments_receiver = self.inner.archived_segments_receiver.clone();
        tokio::spawn(async move {
            while let Some(archived_segment) = archived_segments_receiver.lock().await.recv().await
            {
                if sender.send(archived_segment).await.is_err() {
                    break;
                }
            }
        });

        Ok(receiver)
    }

    async fn acknowledge_archived_segment(&self, segment_index: u64) -> Result<(), MockError> {
        self.inner
            .acknowledge_archived_segment_sender
            .send(segment_index)
            .await?;
        Ok(())
    }
}
