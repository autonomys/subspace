use cuckoofilter::CuckooFilter;
use parking_lot::Mutex;
use std::collections::hash_map::DefaultHasher;
use std::sync::Arc;
use subspace_core_primitives::PieceIndex;
use subspace_networking::{PeerInfo, PeerInfoProvider, PeerRole};

pub const DEFAULT_CAPACITY: usize = (1 << 20) - 1;

#[derive(Clone)]
pub struct ArchivalStoragePieces {
    cuckoo_filter: Arc<Mutex<CuckooFilter<DefaultHasher>>>,
}

impl Default for ArchivalStoragePieces {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl ArchivalStoragePieces {
    pub fn new(capacity: usize) -> Self {
        Self {
            cuckoo_filter: Arc::new(Mutex::new(CuckooFilter::with_capacity(capacity))),
        }
    }

    pub fn add_pieces(&self, piece_indexes: &[PieceIndex]) -> Result<(), anyhow::Error> {
        for piece_index in piece_indexes {
            self.cuckoo_filter
                .lock()
                .add(piece_index)
                .map_err(|err| anyhow::anyhow!("Cuckoo filter error: {}", err,))?;
        }

        Ok(())
    }
}

impl PeerInfoProvider for ArchivalStoragePieces {
    fn peer_info(&self) -> PeerInfo {
        let exported_filter = self.cuckoo_filter.lock().export();
        let data = serde_scale::to_vec(&exported_filter).expect("Serialization always works.");

        PeerInfo {
            role: PeerRole::Farmer,
            data: Some(data),
        }
    }
}
