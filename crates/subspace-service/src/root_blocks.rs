use futures::{Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sc_consensus_subspace::ArchivedSegmentNotification;
use sc_consensus_subspace_rpc::RootBlockProvider;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{RootBlock, SegmentIndex};
use tracing::{debug, error, trace};

/// Start an archiver that will listen for archived segments and send root block to the storage
pub(crate) async fn start_root_block_archiver<AS: AuxStore>(
    mut root_block_cache: RootBlockCache<AS>,
    mut archived_segment_notification_stream: impl Stream<Item = ArchivedSegmentNotification> + Unpin,
) {
    trace!("Subspace root block archiver started.");

    while let Some(ArchivedSegmentNotification {
        archived_segment, ..
    }) = archived_segment_notification_stream.next().await
    {
        let segment_index = archived_segment.root_block.segment_index();
        let result = root_block_cache.add_root_block(archived_segment.root_block);

        if let Err(err) = result {
            error!(%segment_index, ?err, "Root block archiving failed.");
        } else {
            debug!(%segment_index, "Root block archived.");
        }
    }
}

/// Cache of recently produced root blocks in aux storage
pub struct RootBlockCache<AS> {
    aux_store: Arc<AS>,
}

impl<AS> Clone for RootBlockCache<AS> {
    fn clone(&self) -> Self {
        Self {
            aux_store: self.aux_store.clone(),
        }
    }
}

impl<AS> RootBlockCache<AS>
where
    AS: AuxStore,
{
    const KEY_PREFIX: &[u8] = b"segment-headers-cache";

    /// Create new instance.
    pub fn new(aux_store: Arc<AS>) -> Self {
        Self { aux_store }
    }

    /// Add root block to cache (likely as the result of archiving)
    pub fn add_root_block(&mut self, root_block: RootBlock) -> Result<(), Box<dyn Error>> {
        let key = Self::key(root_block.segment_index());
        let value = root_block.encode();
        let insert_data = vec![(key.as_slice(), value.as_slice())];

        self.aux_store.insert_aux(&insert_data, &Vec::new())?;

        Ok(())
    }

    fn key(segment_index: SegmentIndex) -> Vec<u8> {
        Self::key_from_bytes(&u64::to_be_bytes(segment_index))
    }

    fn key_from_bytes(bytes: &[u8]) -> Vec<u8> {
        (Self::KEY_PREFIX, bytes).encode()
    }
}

impl<AS: AuxStore> RootBlockProvider for RootBlockCache<AS> {
    /// Get root block from storage
    fn get_root_block(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<Option<RootBlock>, Box<dyn Error>> {
        Ok(self
            .aux_store
            .get_aux(&Self::key(segment_index))?
            .map(|root_block| {
                RootBlock::decode(&mut root_block.as_slice())
                    .expect("Always correct root block unless DB is corrupted; qed")
            }))
    }
}
