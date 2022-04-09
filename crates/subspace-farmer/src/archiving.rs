use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use log::{debug, error, info};
use subspace_archiving::archiver::{ArchivedSegment, Archiver};
use subspace_rpc_primitives::EncodedBlockWithObjectMapping;

use crate::RpcClient;

pub struct Archiving<T> {
    archiver: Archiver,
    new_block_to_archive_receiver: std::sync::mpsc::Receiver<Arc<AtomicU32>>,
    archived_segments_sender: tokio::sync::broadcast::Sender<Vec<ArchivedSegment>>,
    client: T,
}

impl<T> Archiving<T> {
    pub fn new(
        archiver: Archiver,
        client: T,
    ) -> (
        Self,
        std::sync::mpsc::SyncSender<Arc<AtomicU32>>,
        tokio::sync::broadcast::Sender<Vec<ArchivedSegment>>,
    ) {
        let (new_block_to_archive_sender, new_block_to_archive_receiver) =
            std::sync::mpsc::sync_channel::<Arc<AtomicU32>>(0);
        let (archived_segments_sender, _) = tokio::sync::broadcast::channel(1);

        (
            Self {
                archiver,
                client,
                new_block_to_archive_receiver,
                archived_segments_sender: archived_segments_sender.clone(),
            },
            new_block_to_archive_sender,
            archived_segments_sender,
        )
    }

    pub fn archive(mut self)
    where
        T: RpcClient + Clone + Send + 'static,
    {
        // Process blocks since last fully archived block (or genesis) up to the current head minus K
        let mut blocks_to_archive_from = self
            .archiver
            .last_archived_block_number()
            .map(|n| n + 1)
            .unwrap_or_default();

        let runtime_handle = tokio::runtime::Handle::current();
        info!("Archiving new blocks in the background");

        'outer: for blocks_to_archive_to in self.new_block_to_archive_receiver.into_iter() {
            let blocks_to_archive_to = blocks_to_archive_to.load(Ordering::Relaxed);
            if blocks_to_archive_to >= blocks_to_archive_from {
                debug!(
                    "Archiving blocks {}..={}",
                    blocks_to_archive_from, blocks_to_archive_to,
                );
            }

            #[allow(clippy::mut_range_bound)]
            for block_to_archive in blocks_to_archive_from..=blocks_to_archive_to {
                let EncodedBlockWithObjectMapping {
                    block,
                    object_mapping,
                } = match runtime_handle.block_on(self.client.block_by_number(block_to_archive)) {
                    Ok(Some(block)) => block,
                    Ok(None) => {
                        error!(
                            "Failed to get block #{} from RPC: Block not found",
                            block_to_archive,
                        );

                        blocks_to_archive_from = block_to_archive;
                        continue 'outer;
                    }
                    Err(error) => {
                        error!(
                            "Failed to get block #{} from RPC: {}",
                            block_to_archive, error,
                        );

                        blocks_to_archive_from = block_to_archive;
                        continue 'outer;
                    }
                };

                let _ = self
                    .archived_segments_sender
                    .send(self.archiver.add_block(block, object_mapping));
            }

            blocks_to_archive_from = blocks_to_archive_to + 1;
        }
    }
}
