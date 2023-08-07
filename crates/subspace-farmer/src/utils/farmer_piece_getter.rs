use crate::piece_cache::PieceCache;
use crate::utils::archival_storage_info::ArchivalStorageInfo;
use crate::utils::readers_and_pieces::ReadersAndPieces;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndex};
use subspace_farmer_components::plotting::{PieceGetter, PieceGetterRetryPolicy};
use subspace_networking::libp2p::kad::RecordKey;
use subspace_networking::libp2p::PeerId;
use subspace_networking::utils::multihash::ToMultihash;
use subspace_networking::utils::piece_provider::{PieceProvider, PieceValidator, RetryPolicy};
use subspace_networking::Node;

pub struct FarmerPieceGetter<PV> {
    node: Node,
    piece_provider: PieceProvider<PV>,
    piece_cache: PieceCache,
    archival_storage_info: ArchivalStorageInfo,
    readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
}

impl<PV> FarmerPieceGetter<PV> {
    pub fn new(
        node: Node,
        piece_provider: PieceProvider<PV>,
        piece_cache: PieceCache,
        archival_storage_info: ArchivalStorageInfo,
        readers_and_pieces: Arc<Mutex<Option<ReadersAndPieces>>>,
    ) -> Self {
        Self {
            node,
            piece_provider,
            piece_cache,
            archival_storage_info,
            readers_and_pieces,
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
impl<PV> PieceGetter for FarmerPieceGetter<PV>
where
    PV: PieceValidator + Send + 'static,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        let piece_index_hash = piece_index.hash();
        let key = RecordKey::from(piece_index_hash.to_multihash());

        if let Some(piece) = self.piece_cache.get_piece(key).await {
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

        let maybe_read_piece_fut = self
            .readers_and_pieces
            .lock()
            .as_ref()
            .and_then(|readers_and_pieces| readers_and_pieces.read_piece(&piece_index_hash));

        if let Some(read_piece_fut) = maybe_read_piece_fut {
            if let Some(piece) = read_piece_fut.await {
                return Ok(Some(piece));
            }
        }

        // L1 piece acquisition
        // TODO: consider using retry policy for L1 lookups as well.
        let connected_peers = HashSet::<PeerId>::from_iter(self.node.connected_peers().await?);

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
