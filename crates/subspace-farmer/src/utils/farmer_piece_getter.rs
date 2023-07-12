use crate::utils::archival_storage_info::ArchivalStorageInfo;
use crate::utils::piece_cache::PieceCache;
use async_trait::async_trait;
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_farmer_components::plotting::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator, RetryPolicy};
use subspace_networking::Node;

pub struct FarmerPieceGetter<PV, PC> {
    node: Node,
    piece_provider: PieceProvider<PV>,
    piece_cache: Arc<tokio::sync::Mutex<PC>>,
    archival_storage_info: ArchivalStorageInfo,
}

impl<PV, PC> FarmerPieceGetter<PV, PC> {
    pub fn new(
        node: Node,
        piece_provider: PieceProvider<PV>,
        piece_cache: Arc<tokio::sync::Mutex<PC>>,
        archival_storage_info: ArchivalStorageInfo,
    ) -> Self {
        Self {
            node,
            piece_provider,
            piece_cache,
            archival_storage_info,
        }
    }

    fn convert_retry_policy(retry_policy: PieceGetterRetryPolicy) -> RetryPolicy {
        match retry_policy {
            PieceGetterRetryPolicy::Limited(retries) => RetryPolicy::Limited(retries),
            PieceGetterRetryPolicy::Unlimited => RetryPolicy::Unlimited,
        }
    }
}

#[async_trait]
impl<PV, PC> PieceGetter for FarmerPieceGetter<PV, PC>
where
    PV: PieceValidator + Send + 'static,
    PC: PieceCache + Send + 'static,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let piece_index_hash = piece_index.hash();
        let key = piece_index_hash.to_multihash().into();

        if let Some(piece) = self.piece_cache.lock().await.get_piece(&key) {
            return Ok(Some(piece));
        }

        // L2 piece acquisition
        let maybe_piece = self
            .piece_provider
            .get_piece(piece_index, Self::convert_retry_policy(retry_policy))
            .await?;

        if maybe_piece.is_some() {
            return Ok(maybe_piece);
        }

        // L1 piece acquisition
        // TODO: consider using not connected peers as well
        // TODO: consider using retry policy for L1 lookups as well.
        let connected_peers =
            HashSet::<PeerId>::from_iter(self.node.connected_peers().await?.into_iter());

        for peer_id in self
            .archival_storage_info
            .peers_contain_piece(&piece_index)
            .iter()
        {
            if connected_peers.contains(peer_id) {
                let maybe_piece = self
                    .piece_provider
                    .get_piece_from_peer(*peer_id, piece_index)
                    .await;

                if maybe_piece.is_some() {
                    return Ok(maybe_piece);
                }
            }
        }

        Ok(None)
    }
}
