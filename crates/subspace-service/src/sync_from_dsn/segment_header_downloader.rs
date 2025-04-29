use crate::sync_from_dsn::LOG_TARGET;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::pin::pin;
use std::sync::Arc;
use subspace_core_primitives::segments::{SegmentHeader, SegmentIndex};
use subspace_networking::libp2p::PeerId;
use subspace_networking::protocols::request_response::handlers::segment_header::{
    SegmentHeaderRequest, SegmentHeaderResponse,
};
use subspace_networking::Node;
use tracing::{debug, error, info, trace, warn};

const SEGMENT_HEADER_NUMBER_PER_REQUEST: u64 = 1000;

/// Initial number of peers to query for last segment header.
const SEGMENT_HEADER_CONSENSUS_INITIAL_NODES: usize = 20;

/// Initial number of peers to query for the rest of the segment headers.
const SEGMENT_HEADER_BATCH_NODES: usize = 4;

/// Number of retries for the last segment header peer checks, and the segment header batch
/// request. Each new segment index range resets the retry count.
const SEGMENT_HEADER_RETRIES: u32 = 5;

/// Helps downloader segment headers from DSN
pub struct SegmentHeaderDownloader<'a> {
    dsn_node: &'a Node,
}

impl<'a> SegmentHeaderDownloader<'a> {
    pub fn new(dsn_node: &'a Node) -> Self {
        Self { dsn_node }
    }

    /// Returns new segment headers known to DSN, ordered from 0 to the last known, but newer than
    /// `last_known_segment_index`
    pub async fn get_segment_headers(
        &self,
        last_known_segment_header: &SegmentHeader,
    ) -> Result<Vec<SegmentHeader>, Box<dyn Error>> {
        let last_known_segment_index = last_known_segment_header.segment_index();
        trace!(
            target: LOG_TARGET,
            %last_known_segment_index,
            "Searching for latest segment header"
        );

        let Some((last_segment_header, mut peers)) = self.get_last_segment_header().await? else {
            return Ok(Vec::new());
        };

        if last_segment_header.segment_index() <= last_known_segment_index {
            debug!(
                target: LOG_TARGET,
                %last_known_segment_index,
                last_found_segment_index = %last_segment_header.segment_index(),
                "No new segment headers found, nothing to download"
            );

            return Ok(Vec::new());
        }

        debug!(
            target: LOG_TARGET,
            %last_known_segment_index,
            last_segment_index = %last_segment_header.segment_index(),
            "Downloading segment headers"
        );

        let new_segment_headers_count = last_segment_header
            .segment_index()
            .checked_sub(last_known_segment_index)
            .expect("just checked last_segment_header is greater; qed");

        let mut new_segment_headers =
            Vec::with_capacity(u64::from(new_segment_headers_count) as usize);
        new_segment_headers.push(last_segment_header);
        let mut segment_to_download_to = last_segment_header;

        'new_peers: for segment_headers_batch_retry in 0..SEGMENT_HEADER_RETRIES {
            if segment_headers_batch_retry > 0 {
                info!(
                    target: LOG_TARGET,
                    %segment_headers_batch_retry,
                    %SEGMENT_HEADER_RETRIES,
                    %SEGMENT_HEADER_BATCH_NODES,
                    "Retrying segment header batch download with new peers...",
                );

                // Get a few new random peers, because the previous random peers didn't provide any
                // segment headers. We only get a few peers at a time, because the rest of the
                // peers will likely disconnect while we're querying the first few peers.
                peers = self.get_random_peers(SEGMENT_HEADER_BATCH_NODES).await?;
            }

            'next_peer: for peer in peers.iter() {
                let mut headers_batch_result = Err(());
                while segment_to_download_to.segment_index() - last_known_segment_index
                    > SegmentIndex::ONE
                {
                    let segment_indexes = (last_known_segment_index + SegmentIndex::ONE
                        ..segment_to_download_to.segment_index())
                        .rev()
                        .take(SEGMENT_HEADER_NUMBER_PER_REQUEST as usize)
                        .collect::<Vec<SegmentIndex>>();

                    let segment_indexes = Arc::new(segment_indexes);

                    headers_batch_result = self
                        .get_segment_headers_batch(*peer, segment_indexes.clone())
                        .await;
                    if headers_batch_result.is_ok() {
                        break;
                    }
                }

                let Ok((peer_id, segment_headers)) = headers_batch_result else {
                    debug!(
                        target: LOG_TARGET,
                        %peer,
                        ?last_known_segment_index,
                        segment_to_download_to = ?segment_to_download_to.segment_index(),
                        %segment_headers_batch_retry,
                        "Error getting segment headers from peer",
                    );

                    if segment_headers_batch_retry == 0 {
                        // Peers from the last segment header consensus check are in arbitrary
                        // order, so we can only assume if one fails, the rest have probably
                        // disconnected already.
                        continue 'new_peers;
                    } else {
                        // We only get a small number of peers for each retry, so it's worth trying
                        // them all.
                        continue 'next_peer;
                    }
                };

                for segment_header in segment_headers {
                    if segment_header.hash() != segment_to_download_to.prev_segment_header_hash() {
                        error!(
                            target: LOG_TARGET,
                            %peer_id,
                            segment_index=%segment_to_download_to.segment_index() - SegmentIndex::ONE,
                            actual_hash=?segment_header.hash(),
                            expected_hash=?segment_to_download_to.prev_segment_header_hash(),
                            "Segment header hash doesn't match expected hash from the last block"
                        );

                        return Err(
                            "Segment header hash doesn't match expected hash from the last block"
                                .into(),
                        );
                    }

                    segment_to_download_to = segment_header;
                    new_segment_headers.push(segment_header);
                }
            }
        }

        new_segment_headers.reverse();

        if new_segment_headers
            .first()
            .expect("Not empty; qed")
            .prev_segment_header_hash()
            != last_known_segment_header.hash()
        {
            return Err(
                "Downloaded segment headers do not match last known segment header, ignoring \
                downloaded headers"
                    .into(),
            );
        }

        Ok(new_segment_headers)
    }

    /// Return last segment header known to DSN and agreed on by majority of the peer set with
    /// minimum initial size of [`SEGMENT_HEADER_CONSENSUS_INITIAL_NODES`] peers.
    ///
    /// `Ok(None)` is returned when no peers were found.
    async fn get_last_segment_header(
        &self,
    ) -> Result<Option<(SegmentHeader, Vec<PeerId>)>, Box<dyn Error>> {
        let mut peer_segment_headers = HashMap::<PeerId, Vec<SegmentHeader>>::default();
        for (required_peers, retry_attempt) in (1..=SEGMENT_HEADER_CONSENSUS_INITIAL_NODES)
            .rev()
            .zip(1_usize..)
        {
            trace!(target: LOG_TARGET, %retry_attempt, "Downloading last segment headers");

            // Acquire segment headers from peers.
            let mut peers = self
                .get_random_peers(SEGMENT_HEADER_CONSENSUS_INITIAL_NODES)
                .await?;
            peers.retain(|peer_id| !peer_segment_headers.contains_key(peer_id));

            let new_last_known_segment_headers = peers
                .into_iter()
                .map(|peer_id| async move {
                    let request_result = self
                        .dsn_node
                        .send_generic_request(
                            peer_id,
                            Vec::new(),
                            SegmentHeaderRequest::LastSegmentHeaders {
                                // Request 2 top segment headers, accounting for situations when new
                                // segment header was just produced and not all nodes have it
                                limit: 2,
                            },
                        )
                        .await;

                    match request_result {
                        Ok(SegmentHeaderResponse { segment_headers }) => {
                            trace!(
                                target: LOG_TARGET,
                                %peer_id,
                                segment_headers_number=%segment_headers.len(),
                                "Last segment headers request succeeded"
                            );

                            if !self
                                .is_last_segment_headers_response_valid(peer_id, &segment_headers)
                            {
                                warn!(
                                    target: LOG_TARGET,
                                    %peer_id,
                                    "Received last segment headers response was invalid"
                                );

                                let _ = self.dsn_node.ban_peer(peer_id).await;
                                return None;
                            }

                            Some((peer_id, segment_headers))
                        }
                        Err(error) => {
                            debug!(target: LOG_TARGET, %peer_id, ?error, "Last segment headers request failed");
                            None
                        }
                    }
                })
                .collect::<FuturesUnordered<_>>()
                .filter_map(|maybe_result| async move { maybe_result });
            let mut new_last_known_segment_headers = pin!(new_last_known_segment_headers);

            let last_peers_count = peer_segment_headers.len();

            while let Some((peer_id, segment_headers)) = new_last_known_segment_headers.next().await
            {
                peer_segment_headers.insert(peer_id, segment_headers);
            }

            let peer_count = peer_segment_headers.len();

            if peer_count < required_peers {
                // If we've got nothing, we have to retry
                if last_peers_count == 0 {
                    debug!(
                        target: LOG_TARGET,
                        %peer_count,
                        %required_peers,
                        %retry_attempt,
                        "Segment headers consensus requires some peers, will retry"
                    );

                    continue;
                }
                // If there are still attempts left, do more attempts
                if required_peers > 1 {
                    debug!(
                        target: LOG_TARGET,
                        %peer_count,
                        %required_peers,
                        %retry_attempt,
                        "Segment headers consensus requires more peers, will retry"
                    );

                    continue;
                }

                debug!(
                    target: LOG_TARGET,
                    %peer_count,
                    %required_peers,
                    %retry_attempt,
                    "Segment headers consensus requires more peers, but no attempts left, so continue as is"
                );
            }

            // Calculate votes
            let mut segment_header_peers: HashMap<SegmentHeader, Vec<PeerId>> = HashMap::new();

            for (peer_id, segment_headers) in peer_segment_headers {
                for segment_header in segment_headers {
                    segment_header_peers
                        .entry(segment_header)
                        .and_modify(|peers| {
                            peers.push(peer_id);
                        })
                        .or_insert(vec![peer_id]);
                }
            }

            let mut segment_header_peers_iter = segment_header_peers.into_iter();
            let (mut best_segment_header, mut most_peers) =
                segment_header_peers_iter.next().expect(
                    "Not empty due to not empty list of peers with non empty list of segment \
                    headers each; qed",
                );

            for (segment_header, peers) in segment_header_peers_iter {
                if peers.len() > most_peers.len()
                    || (peers.len() == most_peers.len()
                        && segment_header.segment_index() > best_segment_header.segment_index())
                {
                    best_segment_header = segment_header;
                    most_peers = peers;
                }
            }

            return Ok(Some((best_segment_header, most_peers)));
        }

        Ok(None)
    }

    /// Validates segment headers and related segment indexes.
    /// We assume `segment_indexes` to be a sorted collection (we create it manually).
    fn is_segment_headers_response_valid(
        &self,
        peer_id: PeerId,
        segment_indexes: &[SegmentIndex],
        segment_headers: &[SegmentHeader],
    ) -> bool {
        if segment_headers.len() != segment_indexes.len() {
            warn!(target: LOG_TARGET, %peer_id, "Segment header and segment indexes collection differ");

            return false;
        }

        let returned_segment_indexes =
            BTreeSet::from_iter(segment_headers.iter().map(|rb| rb.segment_index()));
        if returned_segment_indexes.len() != segment_headers.len() {
            warn!(target: LOG_TARGET, %peer_id, "Peer banned: it returned collection with duplicated segment headers");

            return false;
        }

        let indexes_match = segment_indexes.iter().zip(segment_headers.iter()).all(
            |(segment_index, segment_header)| *segment_index == segment_header.segment_index(),
        );

        if !indexes_match {
            warn!(target: LOG_TARGET, %peer_id, "Segment header collection doesn't match segment indexes");

            return false;
        }

        true
    }

    fn is_last_segment_headers_response_valid(
        &self,
        peer_id: PeerId,
        segment_headers: &[SegmentHeader],
    ) -> bool {
        let segment_indexes = match segment_headers.last() {
            None => {
                // Empty collection is invalid, everyone has at least one segment header
                return false;
            }
            Some(last_segment_header) => {
                let last_segment_index = last_segment_header.segment_index();

                let mut segment_indices = (SegmentIndex::ZERO..=last_segment_index)
                    .rev()
                    .take(segment_headers.len())
                    .collect::<Vec<_>>();
                segment_indices.reverse();
                segment_indices
            }
        };

        self.is_segment_headers_response_valid(peer_id, &segment_indexes, segment_headers)
    }

    async fn get_segment_headers_batch(
        &self,
        peer_id: PeerId,
        segment_indexes: Arc<Vec<SegmentIndex>>,
    ) -> Result<(PeerId, Vec<SegmentHeader>), ()> {
        trace!(
            target: LOG_TARGET,
            %peer_id,
            segment_indexes_count = %segment_indexes.len(),
            first_segment_index = ?segment_indexes.first(),
            last_segment_index = ?segment_indexes.last(),
            "Getting segment header batch...",
        );

        let request_result = self
            .dsn_node
            .send_generic_request(
                peer_id,
                Vec::new(),
                SegmentHeaderRequest::SegmentIndexes {
                    segment_indexes: Arc::clone(&segment_indexes),
                },
            )
            .await;

        match request_result {
            Ok(SegmentHeaderResponse { segment_headers }) => {
                trace!(target: LOG_TARGET, %peer_id, ?segment_indexes, "Segment header request succeeded");

                if !self.is_segment_headers_response_valid(
                    peer_id,
                    &segment_indexes,
                    &segment_headers,
                ) {
                    warn!(target: LOG_TARGET, %peer_id, "Received segment headers were invalid");

                    let _ = self.dsn_node.ban_peer(peer_id).await;
                }

                return Ok((peer_id, segment_headers));
            }
            Err(error) => {
                debug!(target: LOG_TARGET, %peer_id, ?segment_indexes, ?error, "Segment header request failed");
            }
        };

        Err(())
    }

    // Get up to `limit` random peers. Some of them could be bootstrap nodes with no support for
    // request-response protocol for segment headers.
    async fn get_random_peers(&self, limit: usize) -> Result<Vec<PeerId>, Box<dyn Error>> {
        let get_peers_result = self
            .dsn_node
            .get_closest_peers(PeerId::random().into())
            .await;

        let peers = match get_peers_result {
            Ok(get_peers_stream) => get_peers_stream.take(limit).collect::<Vec<_>>().await,
            Err(err) => {
                warn!(target: LOG_TARGET, ?err, %limit, "get_closest_peers returned an error");

                return Err(err.into());
            }
        };

        trace!(target: LOG_TARGET, peers_count = %peers.len(), %limit, "Found closest peers");

        Ok(peers)
    }
}
