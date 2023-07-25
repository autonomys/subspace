use cuckoofilter::{CuckooFilter, ExportedCuckooFilter};
use parking_lot::Mutex;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use subspace_core_primitives::PieceIndex;
use subspace_networking::libp2p::PeerId;
use subspace_networking::CuckooFilterDTO;

#[derive(Clone, Default)]
pub struct ArchivalStorageInfo {
    peers: Arc<Mutex<HashMap<PeerId, CuckooFilter<DefaultHasher>>>>,
}

impl Debug for ArchivalStorageInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchivalStorageInfo")
            .field("peers (len)", &self.peers.lock().len())
            .finish()
    }
}

impl ArchivalStorageInfo {
    pub fn update_cuckoo_filter(&self, peer_id: PeerId, cuckoo_filter_dto: Arc<CuckooFilterDTO>) {
        let exported_filter = ExportedCuckooFilter {
            values: cuckoo_filter_dto.values.clone(),
            length: cuckoo_filter_dto.length as usize,
        };

        let cuckoo_filter = CuckooFilter::from(exported_filter);

        self.peers.lock().insert(peer_id, cuckoo_filter);
    }

    pub fn remove_peer_filter(&self, peer_id: &PeerId) -> bool {
        self.peers.lock().remove(peer_id).is_some()
    }

    pub fn peers_contain_piece(&self, piece_index: &PieceIndex) -> Vec<PeerId> {
        let mut result = Vec::new();
        for (peer_id, cuckoo_filter) in self.peers.lock().iter() {
            if cuckoo_filter.contains(piece_index) {
                result.push(*peer_id)
            }
        }

        result
    }
}
