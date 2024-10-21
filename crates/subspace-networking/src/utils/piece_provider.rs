//! Provides methods to retrieve pieces from DSN.

use crate::protocols::request_response::handlers::cached_piece_by_index::{
    CachedPieceByIndexRequest, CachedPieceByIndexResponse, PieceResult,
};
use crate::protocols::request_response::handlers::piece_by_index::{
    PieceByIndexRequest, PieceByIndexResponse,
};
use crate::utils::multihash::ToMultihash;
use crate::{Multihash, Node};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::FusedFuture;
use futures::stream::FuturesUnordered;
use futures::task::noop_waker_ref;
use futures::{stream, FutureExt, Stream, StreamExt};
use libp2p::kad::store::RecordStore;
use libp2p::kad::{store, Behaviour as Kademlia, KBucketKey, ProviderRecord, Record, RecordKey};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use rand::prelude::*;
use std::any::type_name;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::iter::Empty;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, iter, mem};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use tokio_stream::StreamMap;
use tracing::{debug, trace, warn};

/// Validates piece against using its commitment.
#[async_trait]
pub trait PieceValidator: Sync + Send {
    /// Validates piece against using its commitment.
    async fn validate_piece(
        &self,
        source_peer_id: PeerId,
        piece_index: PieceIndex,
        piece: Piece,
    ) -> Option<Piece>;
}

/// Stub implementation for piece validation.
#[derive(Debug, Clone, Copy)]
pub struct NoPieceValidator;

#[async_trait]
impl PieceValidator for NoPieceValidator {
    async fn validate_piece(&self, _: PeerId, _: PieceIndex, piece: Piece) -> Option<Piece> {
        Some(piece)
    }
}

/// Piece provider with cancellation and piece validator.
/// Use `NoPieceValidator` to disable validation.
pub struct PieceProvider<PV> {
    node: Node,
    piece_validator: PV,
}

impl<PV> fmt::Debug for PieceProvider<PV> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(&format!("PieceProvider<{}>", type_name::<PV>()))
            .finish_non_exhaustive()
    }
}

impl<PV> PieceProvider<PV>
where
    PV: PieceValidator,
{
    /// Creates new piece provider.
    pub fn new(node: Node, piece_validator: PV) -> Self {
        Self {
            node,
            piece_validator,
        }
    }

    /// Get pieces with provided indices from cache.
    ///
    /// Number of elements in returned stream is the same as number of unique `piece_indices`.
    pub async fn get_from_cache<'a, PieceIndices>(
        &'a self,
        piece_indices: PieceIndices,
    ) -> impl Stream<Item = (PieceIndex, Option<Piece>)> + Unpin + 'a
    where
        PieceIndices: IntoIterator<Item = PieceIndex> + 'a,
    {
        let (tx, mut rx) = mpsc::unbounded();
        let fut = get_from_cache_inner(
            piece_indices.into_iter(),
            &self.node,
            &self.piece_validator,
            tx,
        );
        let mut fut = Box::pin(fut.fuse());

        // Drive above future and stream back any pieces that were downloaded so far
        stream::poll_fn(move |cx| {
            if !fut.is_terminated() {
                // Result doesn't matter, we'll need to poll stream below anyway
                let _ = fut.poll_unpin(cx);
            }

            if let Poll::Ready(maybe_result) = rx.poll_next_unpin(cx) {
                return Poll::Ready(maybe_result);
            }

            // Exit will be done by the stream above
            Poll::Pending
        })
    }

    /// Returns piece by its index from farmer's piece cache (L2)
    pub async fn get_piece_from_cache(&self, piece_index: PieceIndex) -> Option<Piece> {
        let key = RecordKey::from(piece_index.to_multihash());

        let mut request_batch = self.node.get_requests_batch_handle().await;
        let get_providers_result = request_batch.get_providers(key.clone()).await;

        match get_providers_result {
            Ok(mut get_providers_stream) => {
                while let Some(provider_id) = get_providers_stream.next().await {
                    trace!(
                        %piece_index,
                        key = hex::encode(&key),
                        %provider_id,
                        "get_providers returned an item"
                    );

                    let request_result = request_batch
                        .send_generic_request(
                            provider_id,
                            Vec::new(),
                            PieceByIndexRequest {
                                piece_index,
                                cached_pieces: Arc::default(),
                            },
                        )
                        .await;

                    match request_result {
                        Ok(PieceByIndexResponse {
                            piece: Some(piece),
                            cached_pieces: _,
                        }) => {
                            trace!(
                                %piece_index,
                                key = hex::encode(&key),
                                %provider_id,
                                "Piece request succeeded"
                            );

                            return self
                                .piece_validator
                                .validate_piece(provider_id, piece_index, piece)
                                .await;
                        }
                        Ok(PieceByIndexResponse {
                            piece: None,
                            cached_pieces: _,
                        }) => {
                            debug!(
                                %piece_index,
                                key = hex::encode(&key),
                                %provider_id,
                                "Piece request returned empty piece"
                            );
                        }
                        Err(error) => {
                            debug!(
                                %piece_index,
                                key = hex::encode(&key),
                                %provider_id,
                                ?error,
                                "Piece request failed"
                            );
                        }
                    }
                }
            }
            Err(err) => {
                warn!(%piece_index,?key, ?err, "get_providers returned an error");
            }
        }

        None
    }

    /// Get piece from a particular peer.
    pub async fn get_piece_from_peer(
        &self,
        peer_id: PeerId,
        piece_index: PieceIndex,
    ) -> Option<Piece> {
        // TODO: Take advantage of `cached_pieces`
        let request_result = self
            .node
            .send_generic_request(
                peer_id,
                Vec::new(),
                PieceByIndexRequest {
                    piece_index,
                    cached_pieces: Arc::default(),
                },
            )
            .await;

        match request_result {
            Ok(PieceByIndexResponse {
                piece: Some(piece),
                cached_pieces: _,
            }) => {
                trace!(%peer_id, %piece_index, "Piece request succeeded");

                return self
                    .piece_validator
                    .validate_piece(peer_id, piece_index, piece)
                    .await;
            }
            Ok(PieceByIndexResponse {
                piece: None,
                cached_pieces: _,
            }) => {
                debug!(%peer_id, %piece_index, "Piece request returned empty piece");
            }
            Err(error) => {
                debug!(%peer_id, %piece_index, ?error, "Piece request failed");
            }
        }

        None
    }

    /// Get piece from archival storage (L1). The algorithm tries to get a piece from currently
    /// connected peers and falls back to random walking.
    pub async fn get_piece_from_archival_storage(
        &self,
        piece_index: PieceIndex,
        max_random_walking_rounds: usize,
    ) -> Option<Piece> {
        // TODO: consider using retry policy for L1 lookups as well.
        trace!(%piece_index, "Getting piece from archival storage..");

        let connected_peers = {
            let connected_peers = match self.node.connected_peers().await {
                Ok(connected_peers) => connected_peers,
                Err(err) => {
                    debug!(%piece_index, ?err, "Cannot get connected peers (DSN L1 lookup)");

                    Default::default()
                }
            };

            HashSet::<PeerId>::from_iter(connected_peers)
        };

        if connected_peers.is_empty() {
            debug!(%piece_index, "Cannot acquire piece from no connected peers (DSN L1 lookup)");
        } else {
            for peer_id in connected_peers.iter() {
                let maybe_piece = self.get_piece_from_peer(*peer_id, piece_index).await;

                if maybe_piece.is_some() {
                    trace!(%piece_index, %peer_id, "DSN L1 lookup from connected peers succeeded");

                    return maybe_piece;
                }
            }
        }

        trace!(%piece_index, "Getting piece from DSN L1 using random walk.");
        let random_walk_result = self
            .get_piece_by_random_walking(piece_index, max_random_walking_rounds)
            .await;

        if random_walk_result.is_some() {
            trace!(%piece_index, "DSN L1 lookup via random walk succeeded");

            return random_walk_result;
        } else {
            debug!(
                %piece_index,
                %max_random_walking_rounds,
                "Cannot acquire piece from DSN L1: random walk failed"
            );
        }

        None
    }

    /// Get piece from L1 by random walking
    async fn get_piece_by_random_walking(
        &self,
        piece_index: PieceIndex,
        walking_rounds: usize,
    ) -> Option<Piece> {
        for round in 0..walking_rounds {
            debug!(%piece_index, round, "Random walk round");

            let result = self
                .get_piece_by_random_walking_from_single_round(piece_index, round)
                .await;

            if result.is_some() {
                return result;
            }
        }

        debug!(%piece_index, "Random walking piece retrieval failed.");

        None
    }

    /// Get piece from L1 by random walking (single round)
    async fn get_piece_by_random_walking_from_single_round(
        &self,
        piece_index: PieceIndex,
        round: usize,
    ) -> Option<Piece> {
        // TODO: Take advantage of `cached_pieces`
        trace!(%piece_index, "get_piece_by_random_walking round");

        // Random walk key
        let key = PeerId::random();

        let mut request_batch = self.node.get_requests_batch_handle().await;
        let get_closest_peers_result = request_batch.get_closest_peers(key.into()).await;

        match get_closest_peers_result {
            Ok(mut get_closest_peers_stream) => {
                while let Some(peer_id) = get_closest_peers_stream.next().await {
                    trace!(%piece_index, %peer_id, %round, "get_closest_peers returned an item");

                    let request_result = request_batch
                        .send_generic_request(
                            peer_id,
                            Vec::new(),
                            PieceByIndexRequest {
                                piece_index,
                                cached_pieces: Arc::default(),
                            },
                        )
                        .await;

                    match request_result {
                        Ok(PieceByIndexResponse {
                            piece: Some(piece),
                            cached_pieces: _,
                        }) => {
                            trace!(%peer_id, %piece_index, ?key, %round,  "Piece request succeeded.");

                            return self
                                .piece_validator
                                .validate_piece(peer_id, piece_index, piece)
                                .await;
                        }
                        Ok(PieceByIndexResponse {
                            piece: None,
                            cached_pieces: _,
                        }) => {
                            debug!(%peer_id, %piece_index, ?key, %round, "Piece request returned empty piece.");
                        }
                        Err(error) => {
                            debug!(%peer_id, %piece_index, ?key, %round, ?error, "Piece request failed.");
                        }
                    }
                }
            }
            Err(err) => {
                warn!(%piece_index, ?key, ?err, %round, "get_closest_peers returned an error");
            }
        }

        None
    }
}

struct DummyRecordStore;

impl RecordStore for DummyRecordStore {
    type RecordsIter<'a>
        = Empty<Cow<'a, Record>>
    where
        Self: 'a;
    type ProvidedIter<'a>
        = Empty<Cow<'a, ProviderRecord>>
    where
        Self: 'a;

    fn get(&self, _key: &RecordKey) -> Option<Cow<'_, Record>> {
        // Not supported
        None
    }

    fn put(&mut self, _record: Record) -> store::Result<()> {
        // Not supported
        Ok(())
    }

    fn remove(&mut self, _key: &RecordKey) {
        // Not supported
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        // Not supported
        iter::empty()
    }

    fn add_provider(&mut self, _record: ProviderRecord) -> store::Result<()> {
        // Not supported
        Ok(())
    }

    fn providers(&self, _key: &RecordKey) -> Vec<ProviderRecord> {
        // Not supported
        Vec::new()
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        // Not supported
        iter::empty()
    }

    fn remove_provider(&mut self, _key: &RecordKey, _provider: &PeerId) {
        // Not supported
    }
}

/// Kademlia wrapper to take advantage of its internal logic of selecting closest peers
struct KademliaWrapper {
    local_peer_id: PeerId,
    kademlia: Kademlia<DummyRecordStore>,
}

impl KademliaWrapper {
    fn new(local_peer_id: PeerId) -> Self {
        Self {
            local_peer_id,
            kademlia: Kademlia::new(local_peer_id, DummyRecordStore),
        }
    }

    fn add_peer(&mut self, peer_id: &PeerId, addresses: Vec<Multiaddr>) {
        for address in addresses {
            self.kademlia.add_address(peer_id, address);
        }
        while self
            .kademlia
            .poll(&mut Context::from_waker(noop_waker_ref()))
            .is_ready()
        {
            // Simply drain useless events generated by above calls
        }
    }

    /// Returned peers are already sorted in ascending distance order
    fn closest_peers(
        &mut self,
        key: &KBucketKey<Multihash>,
    ) -> impl Iterator<Item = (PeerId, Vec<Multiaddr>)> + 'static {
        let mut closest_peers = self
            .kademlia
            .find_closest(key, &self.local_peer_id)
            .into_iter()
            .map(|peer| {
                (
                    KBucketKey::from(peer.node_id).distance(key),
                    peer.node_id,
                    peer.multiaddrs,
                )
            })
            .collect::<Vec<_>>();

        closest_peers.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        closest_peers
            .into_iter()
            .map(|(_distance, peer_id, addresses)| (peer_id, addresses))
    }
}

async fn get_from_cache_inner<PV, PieceIndices>(
    piece_indices: PieceIndices,
    node: &Node,
    piece_validator: &PV,
    results: mpsc::UnboundedSender<(PieceIndex, Option<Piece>)>,
) where
    PV: PieceValidator,
    PieceIndices: Iterator<Item = PieceIndex>,
{
    // Download from connected peers first
    let pieces_to_download =
        download_cached_pieces_from_connected_peers(piece_indices, node, piece_validator, &results)
            .await;

    if pieces_to_download.is_empty() {
        return;
    }

    // Download from iteratively closer peers according to Kademlia rules
    download_cached_pieces_from_closest_peers(pieces_to_download, node, piece_validator, &results)
        .await;
}

/// Takes pieces to download as an input, sends results with pieces that were downloaded
/// successfully and returns those that were not downloaded from connected peer with addresses of
/// potential candidates
async fn download_cached_pieces_from_connected_peers<PV, PieceIndices>(
    piece_indices: PieceIndices,
    node: &Node,
    piece_validator: &PV,
    results: &mpsc::UnboundedSender<(PieceIndex, Option<Piece>)>,
) -> HashMap<PieceIndex, HashMap<PeerId, Vec<Multiaddr>>>
where
    PV: PieceValidator,
    PieceIndices: Iterator<Item = PieceIndex>,
{
    // Make sure every piece index has an entry since this will be the primary container for
    // tracking pieces to download going forward.
    //
    // At the end pieces that were not downloaded will remain with a collection of known closest
    // peers for them.
    let mut pieces_to_download = piece_indices
        .map(|piece_index| (piece_index, HashMap::new()))
        .collect::<HashMap<PieceIndex, HashMap<PeerId, Vec<Multiaddr>>>>();
    let mut checked_connected_peers = HashSet::new();

    // The loop is in order to check peers that might be connected after the initial loop has
    // started.
    loop {
        let Ok(connected_peers) = node.connected_peers().await else {
            break;
        };

        if connected_peers.is_empty() || pieces_to_download.is_empty() {
            break;
        }

        let num_pieces = pieces_to_download.len();
        let step = num_pieces / connected_peers.len().min(num_pieces);

        // Dispatch initial set of requests to peers
        let mut downloading_stream = connected_peers
            .into_iter()
            .take(num_pieces)
            .enumerate()
            .filter_map(|(peer_index, peer_id)| {
                if !checked_connected_peers.insert(peer_id) {
                    return None;
                }

                // Take unique first piece index for each connected peer and the rest just to check
                // cached pieces up to recommended limit
                let mut peer_piece_indices = pieces_to_download
                    .keys()
                    .cycle()
                    .skip(step * peer_index)
                    .take(num_pieces.min(CachedPieceByIndexRequest::RECOMMENDED_LIMIT))
                    .copied()
                    .collect::<Vec<_>>();
                // Pick first piece index as the piece we want to download
                let piece_index = peer_piece_indices.swap_remove(0);

                let fut = download_cached_piece_from_peer(
                    node,
                    piece_validator,
                    peer_id,
                    Vec::new(),
                    Arc::new(peer_piece_indices),
                    piece_index,
                    HashSet::new(),
                    HashSet::new(),
                );

                Some((piece_index, Box::pin(fut.into_stream())))
            })
            .collect::<StreamMap<_, _>>();

        // Process every response and potentially schedule follow-up request to the same peer
        while let Some((piece_index, result)) = downloading_stream.next().await {
            let DownloadedPieceFromPeer {
                peer_id,
                result,
                mut cached_pieces,
                not_cached_pieces,
            } = result;

            let Some(result) = result else {
                // Downloading failed, ignore peer
                continue;
            };

            match result {
                PieceResult::Piece(piece) => {
                    // Downloaded successfully
                    pieces_to_download.remove(&piece_index);

                    results
                        .unbounded_send((piece_index, Some(piece)))
                        .expect("This future isn't polled after receiver is dropped; qed");

                    if pieces_to_download.is_empty() {
                        return HashMap::new();
                    }
                }
                PieceResult::ClosestPeers(closest_peers) => {
                    // Store closer peers in case piece index was not downloaded yet
                    if let Some(peers) = pieces_to_download.get_mut(&piece_index) {
                        peers.extend(Vec::from(closest_peers));
                    }
                }
            }

            let mut maybe_piece_index_to_download_next = None;
            // Clear useless entries in cached pieces and find something to download next
            cached_pieces.retain(|piece_index| {
                // Clear downloaded pieces
                if !pieces_to_download.contains_key(piece_index) {
                    return false;
                }

                // Try to pick a piece to download that is not being downloaded already
                if maybe_piece_index_to_download_next.is_none()
                    && !downloading_stream.contains_key(piece_index)
                {
                    maybe_piece_index_to_download_next.replace(*piece_index);
                    // We'll not need to download it after this attempt
                    return false;
                }

                // Retain everything else
                true
            });

            let piece_index_to_download_next =
                if let Some(piece_index) = maybe_piece_index_to_download_next {
                    piece_index
                } else {
                    // Nothing left to do with this peer
                    continue;
                };

            let fut = download_cached_piece_from_peer(
                node,
                piece_validator,
                peer_id,
                Vec::new(),
                // Sample more random cached piece indices for connected peer, algorithm can be
                // improved, but has to be something simple and this should do it for now
                Arc::new(
                    pieces_to_download
                        .keys()
                        // Do a bit of work to filter-out piece indices we already know remote peer
                        // has or doesn't to decrease burden on them
                        .filter_map(|piece_index| {
                            if piece_index == &piece_index_to_download_next
                                || cached_pieces.contains(piece_index)
                                || not_cached_pieces.contains(piece_index)
                            {
                                None
                            } else {
                                Some(*piece_index)
                            }
                        })
                        .choose_multiple(
                            &mut thread_rng(),
                            CachedPieceByIndexRequest::RECOMMENDED_LIMIT,
                        ),
                ),
                piece_index_to_download_next,
                cached_pieces,
                not_cached_pieces,
            );
            downloading_stream.insert(piece_index, Box::pin(fut.into_stream()));
        }

        if pieces_to_download.len() == num_pieces {
            // Nothing was downloaded, we're done here
            break;
        }
    }

    pieces_to_download
}

/// Takes pieces to download with potential peer candidates as an input, sends results with pieces
/// that were downloaded successfully and returns those that were not downloaded
async fn download_cached_pieces_from_closest_peers<PV>(
    maybe_pieces_to_download: HashMap<PieceIndex, HashMap<PeerId, Vec<Multiaddr>>>,
    node: &Node,
    piece_validator: &PV,
    results: &mpsc::UnboundedSender<(PieceIndex, Option<Piece>)>,
) where
    PV: PieceValidator,
{
    let kademlia = &Mutex::new(KademliaWrapper::new(node.id()));
    // Collection of pieces to download and already connected peers that claim to have them
    let connected_peers_with_piece = &Mutex::new(
        maybe_pieces_to_download
            .keys()
            .map(|&piece_index| (piece_index, HashSet::<PeerId>::new()))
            .collect::<HashMap<_, _>>(),
    );

    let mut downloaded_pieces = maybe_pieces_to_download
        .into_iter()
        .map(|(piece_index, collected_peers)| async move {
            let key = piece_index.to_multihash();
            let kbucket_key = KBucketKey::from(key);
            let mut checked_closest_peers = HashSet::<PeerId>::new();

            {
                let local_closest_peers = node
                    .get_closest_local_peers(key, None)
                    .await
                    .unwrap_or_default();
                let mut kademlia = kademlia.lock();

                for (peer_id, addresses) in collected_peers {
                    kademlia.add_peer(&peer_id, addresses);
                }
                for (peer_id, addresses) in local_closest_peers {
                    kademlia.add_peer(&peer_id, addresses);
                }
            }

            loop {
                // Collect pieces that still need to be downloaded and connected peers that claim to
                // have them
                let (pieces_to_download, connected_peers) = {
                    let mut connected_peers_with_piece = connected_peers_with_piece.lock();

                    (
                        Arc::new(
                            connected_peers_with_piece
                                .keys()
                                .filter(|&candidate| candidate != &piece_index)
                                .take(CachedPieceByIndexRequest::RECOMMENDED_LIMIT)
                                .copied()
                                .collect::<Vec<_>>(),
                        ),
                        connected_peers_with_piece
                            .get_mut(&piece_index)
                            .map(mem::take)
                            .unwrap_or_default(),
                    )
                };

                // Check connected peers that claim to have the piece index first
                for peer_id in connected_peers {
                    let fut = download_cached_piece_from_peer(
                        node,
                        piece_validator,
                        peer_id,
                        Vec::new(),
                        Arc::default(),
                        piece_index,
                        HashSet::new(),
                        HashSet::new(),
                    );

                    match fut.await.result {
                        Some(PieceResult::Piece(piece)) => {
                            return (piece_index, Some(piece));
                        }
                        Some(PieceResult::ClosestPeers(closest_peers)) => {
                            let mut kademlia = kademlia.lock();

                            // Store additional closest peers reported by the peer
                            for (peer_id, addresses) in Vec::from(closest_peers) {
                                kademlia.add_peer(&peer_id, addresses);
                            }
                        }
                        None => {
                            checked_closest_peers.insert(peer_id);
                        }
                    }
                }

                // Find the closest peers that were not queried yet
                let closest_peers_to_check = kademlia.lock().closest_peers(&kbucket_key);
                let closest_peers_to_check = closest_peers_to_check
                    .filter(|(peer_id, _addresses)| checked_closest_peers.insert(*peer_id))
                    .collect::<Vec<_>>();

                if closest_peers_to_check.is_empty() {
                    // No new closest peers found, nothing left to do here
                    break;
                }

                for (peer_id, addresses) in closest_peers_to_check {
                    let fut = download_cached_piece_from_peer(
                        node,
                        piece_validator,
                        peer_id,
                        addresses,
                        Arc::clone(&pieces_to_download),
                        piece_index,
                        HashSet::new(),
                        HashSet::new(),
                    );

                    let DownloadedPieceFromPeer {
                        peer_id: _,
                        result,
                        cached_pieces,
                        not_cached_pieces: _,
                    } = fut.await;

                    if !cached_pieces.is_empty() {
                        let mut connected_peers_with_piece = connected_peers_with_piece.lock();

                        // Remember that this peer has some pieces that need to be downloaded here
                        for cached_piece_index in cached_pieces {
                            if let Some(peers) =
                                connected_peers_with_piece.get_mut(&cached_piece_index)
                            {
                                peers.insert(peer_id);
                            }
                        }
                    }

                    match result {
                        Some(PieceResult::Piece(piece)) => {
                            return (piece_index, Some(piece));
                        }
                        Some(PieceResult::ClosestPeers(closest_peers)) => {
                            let mut kademlia = kademlia.lock();

                            // Store additional closest peers
                            for (peer_id, addresses) in Vec::from(closest_peers) {
                                kademlia.add_peer(&peer_id, addresses);
                            }
                        }
                        None => {
                            checked_closest_peers.insert(peer_id);
                        }
                    }
                }
            }

            (piece_index, None)
        })
        .collect::<FuturesUnordered<_>>();

    while let Some((piece_index, maybe_piece)) = downloaded_pieces.next().await {
        connected_peers_with_piece.lock().remove(&piece_index);

        results
            .unbounded_send((piece_index, maybe_piece))
            .expect("This future isn't polled after receiver is dropped; qed");
    }
}

struct DownloadedPieceFromPeer {
    peer_id: PeerId,
    result: Option<PieceResult>,
    cached_pieces: HashSet<PieceIndex>,
    not_cached_pieces: HashSet<PieceIndex>,
}

#[allow(clippy::too_many_arguments)]
async fn download_cached_piece_from_peer<PV>(
    node: &Node,
    piece_validator: &PV,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    peer_piece_indices: Arc<Vec<PieceIndex>>,
    piece_index: PieceIndex,
    mut cached_pieces: HashSet<PieceIndex>,
    mut not_cached_pieces: HashSet<PieceIndex>,
) -> DownloadedPieceFromPeer
where
    PV: PieceValidator,
{
    let result = match node
        .send_generic_request(
            peer_id,
            addresses,
            CachedPieceByIndexRequest {
                piece_index,
                cached_pieces: peer_piece_indices,
            },
        )
        .await
    {
        Ok(response) => {
            let CachedPieceByIndexResponse {
                result,
                cached_pieces,
            } = response;

            match result {
                PieceResult::Piece(piece) => piece_validator
                    .validate_piece(peer_id, piece_index, piece)
                    .await
                    .map(|piece| CachedPieceByIndexResponse {
                        result: PieceResult::Piece(piece),
                        cached_pieces,
                    }),
                PieceResult::ClosestPeers(closest_peers) => Some(CachedPieceByIndexResponse {
                    result: PieceResult::ClosestPeers(closest_peers),
                    cached_pieces,
                }),
            }
        }
        Err(error) => {
            debug!(%error, %peer_id, %piece_index, "Failed to download cached piece from peer");

            None
        }
    };

    match result {
        Some(result) => DownloadedPieceFromPeer {
            peer_id,
            result: Some(result.result),
            cached_pieces: {
                cached_pieces.extend(result.cached_pieces);
                cached_pieces
            },
            not_cached_pieces,
        },
        None => {
            not_cached_pieces.insert(piece_index);

            DownloadedPieceFromPeer {
                peer_id,
                result: None,
                cached_pieces,
                not_cached_pieces,
            }
        }
    }
}
