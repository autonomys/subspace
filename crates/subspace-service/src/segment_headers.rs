use futures::{Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sc_consensus_subspace::ArchivedSegmentNotification;
use sc_consensus_subspace_rpc::SegmentHeaderProvider;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use subspace_core_primitives::{SegmentHeader, SegmentIndex};
use tracing::{debug, error, trace};

/// Start an archiver that will listen for archived segments and send segment header to the storage
pub(crate) async fn start_segment_header_archiver<AS: AuxStore>(
    mut segment_header_cache: SegmentHeaderCache<AS>,
    mut archived_segment_notification_stream: impl Stream<Item = ArchivedSegmentNotification> + Unpin,
) {
    trace!("Subspace segment header archiver started.");

    while let Some(ArchivedSegmentNotification {
        archived_segment, ..
    }) = archived_segment_notification_stream.next().await
    {
        let segment_index = archived_segment.segment_header.segment_index();
        let result = segment_header_cache.add_segment_header(archived_segment.segment_header);

        if let Err(err) = result {
            error!(%segment_index, ?err, "Segment header archiving failed.");
        } else {
            debug!(%segment_index, "Segment header archived.");
        }
    }
}

/// Cache of recently produced segment headers in aux storage
pub struct SegmentHeaderCache<AS> {
    aux_store: Arc<AS>,
    // TODO: Consider introducing and using global in-memory segment header cache (this comment is
    //  in multiple files)
    max_segment_index: Arc<AtomicU64>,
}

impl<AS> Clone for SegmentHeaderCache<AS> {
    fn clone(&self) -> Self {
        Self {
            aux_store: self.aux_store.clone(),
            max_segment_index: self.max_segment_index.clone(),
        }
    }
}

impl<AS> SegmentHeaderCache<AS>
where
    AS: AuxStore,
{
    const KEY_PREFIX: &[u8] = b"segment-headers-cache";

    /// Create new instance.
    pub fn new(aux_store: Arc<AS>) -> Self {
        Self {
            aux_store,
            max_segment_index: Default::default(),
        }
    }

    /// Returns last observed segment index.
    pub fn max_segment_index(&self) -> SegmentIndex {
        SegmentIndex::from(self.max_segment_index.load(Ordering::Relaxed))
    }

    /// Add segment header to cache (likely as the result of archiving)
    pub fn add_segment_header(
        &mut self,
        segment_header: SegmentHeader,
    ) -> Result<(), Box<dyn Error>> {
        let key = Self::key(segment_header.segment_index());
        let value = segment_header.encode();
        let insert_data = vec![(key.as_slice(), value.as_slice())];

        self.aux_store.insert_aux(&insert_data, &Vec::new())?;
        self.max_segment_index
            .store(u64::from(segment_header.segment_index()), Ordering::Relaxed);

        Ok(())
    }

    fn key(segment_index: SegmentIndex) -> Vec<u8> {
        Self::key_from_bytes(&u64::from(segment_index).to_le_bytes())
    }

    fn key_from_bytes(bytes: &[u8]) -> Vec<u8> {
        (Self::KEY_PREFIX, bytes).encode()
    }
}

impl<AS: AuxStore> SegmentHeaderProvider for SegmentHeaderCache<AS> {
    /// Get segment header from storage
    fn get_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<Option<SegmentHeader>, Box<dyn Error>> {
        Ok(self
            .aux_store
            .get_aux(&Self::key(segment_index))?
            .map(|segment_header| {
                SegmentHeader::decode(&mut segment_header.as_slice())
                    .expect("Always correct segment header unless DB is corrupted; qed")
            }))
    }
}
