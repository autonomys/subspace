//! Provides methods to retrieve pieces from DSN.

use crate::protocols::request_response::handlers::cached_piece_by_index::{
    CachedPieceByIndexRequest, CachedPieceByIndexResponse, PieceResult,
};
use crate::protocols::request_response::handlers::piece_by_index::{
    PieceByIndexRequest, PieceByIndexResponse,
};
use crate::utils::multihash::ToMultihash;
use crate::{Multihash, Node};
use async_lock::{Semaphore, SemaphoreGuard};
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
use rand::prelude::*;
use std::any::type_name;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::iter::Empty;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, iter};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use tokio_stream::StreamMap;
use tracing::{debug, trace, warn, Instrument};

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
    piece_downloading_semaphore: Semaphore,
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
    pub fn new(node: Node, piece_validator: PV, piece_downloading_semaphore: Semaphore) -> Self {
        Self {
            node,
            piece_validator,
            piece_downloading_semaphore,
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
            &self.piece_downloading_semaphore,
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
    piece_downloading_semaphore: &Semaphore,
) where
    PV: PieceValidator,
    PieceIndices: Iterator<Item = PieceIndex>,
{
    let download_id = random::<u64>();

    let fut = async move {
        // Download from connected peers first
        let pieces_to_download = download_cached_pieces(
            piece_indices,
            node,
            piece_validator,
            &results,
            piece_downloading_semaphore,
        )
        .await;

        if pieces_to_download.is_empty() {
            debug!("Done");
            return;
        }

        for (piece_index, _closest_peers) in pieces_to_download {
            results
                .unbounded_send((piece_index, None))
                .expect("This future isn't polled after receiver is dropped; qed");
        }

        debug!("Done #2");
    };

    fut.instrument(tracing::info_span!("", %download_id)).await;
}

/// Takes pieces to download as an input, sends results with pieces that were downloaded
/// successfully and returns those that were not downloaded from connected peer with addresses of
/// potential candidates
async fn download_cached_pieces<PV, PieceIndices>(
    piece_indices: PieceIndices,
    node: &Node,
    piece_validator: &PV,
    results: &mpsc::UnboundedSender<(PieceIndex, Option<Piece>)>,
    semaphore: &Semaphore,
) -> HashMap<PieceIndex, KademliaWrapper>
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
        .map(|piece_index| async move {
            let mut kademlia = KademliaWrapper::new(node.id());
            let key = piece_index.to_multihash();

            let local_closest_peers = node
                .get_closest_local_peers(key, None)
                .await
                .unwrap_or_default();

            // Seed with local closest peers
            for (peer_id, addresses) in local_closest_peers {
                kademlia.add_peer(&peer_id, addresses);
            }

            (piece_index, kademlia)
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<HashMap<_, _>>()
        .await;

    let num_pieces = pieces_to_download.len();
    debug!(%num_pieces, "Starting");

    let mut checked_peers = HashSet::new();

    let Ok(connected_peers) = node.connected_peers().await else {
        trace!("Connected peers error");
        return pieces_to_download;
    };

    let num_connected_peers = connected_peers.len();
    debug!(
        %num_connected_peers,
        %num_pieces,
        "Starting downloading"
    );

    // Dispatch initial set of requests to peers with checked pieces distributed uniformly
    let mut downloading_stream = connected_peers
        .into_iter()
        .take(num_pieces)
        .enumerate()
        .map(|(peer_index, peer_id)| {
            checked_peers.insert(peer_id);

            // Inside to avoid division by zero in case there are no connected peers or pieces
            let step = num_pieces / num_connected_peers.min(num_pieces);

            // Take unique first piece index for each connected peer and the rest just to check
            // cached pieces up to recommended limit
            let mut check_cached_pieces = pieces_to_download
                .keys()
                .cycle()
                .skip(step * peer_index)
                // + 1 because one index below is removed below
                .take(num_pieces.min(CachedPieceByIndexRequest::RECOMMENDED_LIMIT + 1))
                .copied()
                .collect::<Vec<_>>();
            // Pick first piece index as the piece we want to download
            let piece_index = check_cached_pieces.swap_remove(0);

            trace!(%peer_id, %piece_index, "Downloading piece from initially connected peer");

            let permit = semaphore.try_acquire();

            let fut = async move {
                let permit = match permit {
                    Some(permit) => permit,
                    None => semaphore.acquire().await,
                };

                download_cached_piece_from_peer(
                    node,
                    piece_validator,
                    peer_id,
                    Vec::new(),
                    Arc::new(check_cached_pieces),
                    piece_index,
                    HashSet::new(),
                    HashSet::new(),
                    permit,
                )
                .await
            };

            (piece_index, Box::pin(fut.into_stream()) as _)
        })
        .collect::<StreamMap<_, _>>();

    loop {
        // Process up to 50% of the pieces concurrently
        let mut additional_pieces_to_download =
            (num_pieces / 2).saturating_sub(downloading_stream.len());
        if additional_pieces_to_download > 0 {
            trace!(
                %additional_pieces_to_download,
                num_pieces,
                currently_downloading = %downloading_stream.len(),
                "Downloading additional pieces from closest peers"
            );
            // Pick up any newly connected peers (if any)
            'outer: for peer_id in node
                .connected_peers()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|peer_id| checked_peers.insert(*peer_id))
                .take(additional_pieces_to_download)
            {
                let permit = if downloading_stream.is_empty() {
                    semaphore.acquire().await
                } else if let Some(permit) = semaphore.try_acquire() {
                    permit
                } else {
                    break;
                };

                for &piece_index in pieces_to_download.keys() {
                    if downloading_stream.contains_key(&piece_index) {
                        continue;
                    }

                    trace!(%peer_id, %piece_index, "Downloading piece from newly connected peer");

                    let check_cached_pieces = sample_cached_piece_indices(
                        pieces_to_download.keys(),
                        &HashSet::new(),
                        &HashSet::new(),
                        piece_index,
                    );
                    let fut = download_cached_piece_from_peer(
                        node,
                        piece_validator,
                        peer_id,
                        Vec::new(),
                        Arc::new(check_cached_pieces),
                        piece_index,
                        HashSet::new(),
                        HashSet::new(),
                        permit,
                    );

                    downloading_stream.insert(piece_index, Box::pin(fut.into_stream()) as _);
                    additional_pieces_to_download -= 1;

                    continue 'outer;
                }

                break;
            }

            // Pick up more pieces to download from the closest peers
            // Ideally we'd not allocate here, but it is hard to explain to the compiler that
            // entries are not removed otherwise
            let pieces_indices_to_download = pieces_to_download.keys().copied().collect::<Vec<_>>();
            for piece_index in pieces_indices_to_download {
                if additional_pieces_to_download == 0 {
                    break;
                }
                if downloading_stream.contains_key(&piece_index) {
                    continue;
                }
                let permit = if downloading_stream.is_empty() {
                    semaphore.acquire().await
                } else if let Some(permit) = semaphore.try_acquire() {
                    permit
                } else {
                    break;
                };

                let kbucket_key = KBucketKey::from(piece_index.to_multihash());
                let closest_peers_to_check = pieces_to_download
                    .get_mut(&piece_index)
                    .expect("Entries are not removed here; qed")
                    .closest_peers(&kbucket_key);
                for (peer_id, addresses) in closest_peers_to_check {
                    if !checked_peers.insert(peer_id) {
                        continue;
                    }

                    trace!(%peer_id, %piece_index, "Downloading piece from closest peer");

                    let check_cached_pieces = sample_cached_piece_indices(
                        pieces_to_download.keys(),
                        &HashSet::new(),
                        &HashSet::new(),
                        piece_index,
                    );
                    let fut = download_cached_piece_from_peer(
                        node,
                        piece_validator,
                        peer_id,
                        addresses,
                        Arc::new(check_cached_pieces),
                        piece_index,
                        HashSet::new(),
                        HashSet::new(),
                        permit,
                    );

                    downloading_stream.insert(piece_index, Box::pin(fut.into_stream()) as _);
                    additional_pieces_to_download -= 1;
                    break;
                }
            }

            trace!(
                pieces_left = %additional_pieces_to_download,
                "Initiated downloading additional pieces from closest peers"
            );
        }

        let Some((piece_index, result)) = downloading_stream.next().await else {
            if !pieces_to_download.is_empty() {
                debug!(
                    %num_pieces,
                    downloaded = %pieces_to_download.len(),
                    "Finished downloading early"
                );
                // Nothing was downloaded, we're done here
                break;
            }
            break;
        };
        process_downloading_result(
            piece_index,
            result,
            &mut pieces_to_download,
            &mut downloading_stream,
            node,
            piece_validator,
            results,
        );

        if pieces_to_download.is_empty() {
            break;
        }
    }

    pieces_to_download
}

fn process_downloading_result<'a, 'b, PV>(
    piece_index: PieceIndex,
    result: DownloadedPieceFromPeer<'a>,
    pieces_to_download: &'b mut HashMap<PieceIndex, KademliaWrapper>,
    downloading_stream: &'b mut StreamMap<
        PieceIndex,
        Pin<Box<dyn Stream<Item = DownloadedPieceFromPeer<'a>> + Send + 'a>>,
    >,
    node: &'a Node,
    piece_validator: &'a PV,
    results: &'a mpsc::UnboundedSender<(PieceIndex, Option<Piece>)>,
) where
    PV: PieceValidator,
{
    let DownloadedPieceFromPeer {
        peer_id,
        result,
        mut cached_pieces,
        not_cached_pieces,
        permit,
    } = result;
    trace!(%piece_index, %peer_id, result = %result.is_some(), "Piece response");

    let Some(result) = result else {
        // Downloading failed, ignore peer
        return;
    };

    match result {
        PieceResult::Piece(piece) => {
            trace!(%piece_index, %peer_id, "Got piece");

            // Downloaded successfully
            pieces_to_download.remove(&piece_index);

            results
                .unbounded_send((piece_index, Some(piece)))
                .expect("This future isn't polled after receiver is dropped; qed");

            if pieces_to_download.is_empty() {
                return;
            }

            cached_pieces.remove(&piece_index);
        }
        PieceResult::ClosestPeers(closest_peers) => {
            trace!(%piece_index, %peer_id, "Got closest peers");

            // Store closer peers in case piece index was not downloaded yet
            if let Some(kademlia) = pieces_to_download.get_mut(&piece_index) {
                for (peer_id, addresses) in Vec::from(closest_peers) {
                    kademlia.add_peer(&peer_id, addresses);
                }
            }

            // No need to ask this peer again if they claimed to have this piece index earlier
            if cached_pieces.remove(&piece_index) {
                return;
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
            // We'll check it later when receiving response
            return true;
        }

        // Retain everything else
        true
    });

    let piece_index_to_download_next = if let Some(piece_index) = maybe_piece_index_to_download_next
    {
        trace!(%piece_index, %peer_id, "Next piece to download from peer");
        piece_index
    } else {
        trace!(%peer_id, "Peer doesn't have anything else");
        // Nothing left to do with this peer
        return;
    };

    let fut = download_cached_piece_from_peer(
        node,
        piece_validator,
        peer_id,
        Vec::new(),
        // Sample more random cached piece indices for connected peer, algorithm can be
        // improved, but has to be something simple and this should do it for now
        Arc::new(sample_cached_piece_indices(
            pieces_to_download.keys(),
            &cached_pieces,
            &not_cached_pieces,
            piece_index_to_download_next,
        )),
        piece_index_to_download_next,
        cached_pieces,
        not_cached_pieces,
        permit,
    );
    downloading_stream.insert(piece_index_to_download_next, Box::pin(fut.into_stream()));
}

fn sample_cached_piece_indices<'a, I>(
    pieces_to_download: I,
    cached_pieces: &HashSet<PieceIndex>,
    not_cached_pieces: &HashSet<PieceIndex>,
    piece_index_to_download_next: PieceIndex,
) -> Vec<PieceIndex>
where
    I: Iterator<Item = &'a PieceIndex>,
{
    pieces_to_download
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
        )
}

struct DownloadedPieceFromPeer<'a> {
    peer_id: PeerId,
    result: Option<PieceResult>,
    cached_pieces: HashSet<PieceIndex>,
    not_cached_pieces: HashSet<PieceIndex>,
    permit: SemaphoreGuard<'a>,
}

#[allow(clippy::too_many_arguments)]
async fn download_cached_piece_from_peer<'a, PV>(
    node: &'a Node,
    piece_validator: &'a PV,
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    check_cached_pieces: Arc<Vec<PieceIndex>>,
    piece_index: PieceIndex,
    mut cached_pieces: HashSet<PieceIndex>,
    mut not_cached_pieces: HashSet<PieceIndex>,
    permit: SemaphoreGuard<'a>,
) -> DownloadedPieceFromPeer<'a>
where
    PV: PieceValidator,
{
    let result = match node
        .send_generic_request(
            peer_id,
            addresses,
            CachedPieceByIndexRequest {
                piece_index,
                cached_pieces: check_cached_pieces,
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
            permit,
        },
        None => {
            not_cached_pieces.insert(piece_index);

            DownloadedPieceFromPeer {
                peer_id,
                result: None,
                cached_pieces,
                not_cached_pieces,
                permit,
            }
        }
    }
}
