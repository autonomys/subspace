use futures::StreamExt;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::pin::pin;
use std::sync::Arc;
use subspace_core_primitives::segments::{SegmentHeader, SegmentIndex};
use subspace_networking::libp2p::PeerId;
use subspace_networking::protocols::request_response::handlers::segment_header::{
    SegmentHeaderRequest, SegmentHeaderResponse,
};
use subspace_networking::Node;
use tracing::{debug, error, trace, warn};

const SEGMENT_HEADER_NUMBER_PER_REQUEST: u64 = 1000;
/// Initial number of peers to query for last segment header.
const SEGMENT_HEADER_CONSENSUS_INITIAL_NODES: usize = 20;
/// How many distinct peers to try before giving up on downloading segment headers batches.
const SEGMENT_HEADER_PEERS_RETRIES: u32 = 20;

/// Helps downloader segment headers from DSN
pub struct SegmentHeaderDownloader {
    dsn_node: Node,
}

impl SegmentHeaderDownloader {
    pub fn new(dsn_node: &Node) -> Self {
        // TODO: Should not be necessary to store owned copy, but it results in confusing compiler
        //  errors otherwise
        Self {
            dsn_node: dsn_node.clone(),
        }
    }

    /// Returns new segment headers known to DSN, ordered from 0 to the last known, but newer than
    /// `last_known_segment_index`
    pub async fn get_segment_headers(
        &self,
        last_known_segment_header: &SegmentHeader,
    ) -> Result<Vec<SegmentHeader>, Box<dyn Error>> {
        let last_known_segment_index = last_known_segment_header.segment_index();
        trace!(
            %last_known_segment_index,
            "Searching for latest segment header"
        );

        let Some(last_segment_header) = self.get_last_segment_header().await? else {
            return Ok(Vec::new());
        };

        if last_segment_header.segment_index() <= last_known_segment_index {
            debug!(
                %last_known_segment_index,
                last_found_segment_index = %last_segment_header.segment_index(),
                "No new segment headers found, nothing to download"
            );

            return Ok(Vec::new());
        }

        debug!(
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

        let mut tried_peers = HashSet::<PeerId>::new();
        let mut segment_to_download_to = last_segment_header;
        'new_peer: for segment_headers_batch_retry in 0..SEGMENT_HEADER_PEERS_RETRIES {
            let maybe_connected_peer = self
                .dsn_node
                .connected_servers()
                .await?
                .into_iter()
                .find(|connected_peer| !tried_peers.contains(connected_peer));

            let peer_id = if let Some(peer_id) = maybe_connected_peer {
                peer_id
            } else {
                let random_peers = self
                    .dsn_node
                    .get_closest_peers(PeerId::random().into())
                    .await?
                    .filter(|connected_peer| {
                        let new_peer = !tried_peers.contains(connected_peer);

                        async move { new_peer }
                    });
                let mut random_peers = pin!(random_peers);

                if let Some(peer_id) = random_peers.next().await {
                    peer_id
                } else {
                    return Err("Can't find peers to download headers from".into());
                }
            };
            tried_peers.insert(peer_id);

            while segment_to_download_to.segment_index() - last_known_segment_index
                > SegmentIndex::ONE
            {
                let segment_indexes = (last_known_segment_index + SegmentIndex::ONE
                    ..segment_to_download_to.segment_index())
                    .rev()
                    .take(SEGMENT_HEADER_NUMBER_PER_REQUEST as usize)
                    .collect::<Vec<_>>();

                trace!(
                    %peer_id,
                    %segment_headers_batch_retry,
                    segment_indexes_count = %segment_indexes.len(),
                    first_segment_index = ?segment_indexes.first(),
                    last_segment_index = ?segment_indexes.last(),
                    "Getting segment header batch...",
                );

                let segment_indexes = Arc::new(segment_indexes);

                let segment_headers = match self
                    .dsn_node
                    .send_generic_request(
                        peer_id,
                        Vec::new(),
                        SegmentHeaderRequest::SegmentIndexes {
                            segment_indexes: Arc::clone(&segment_indexes),
                        },
                    )
                    .await
                {
                    Ok(response) => response.segment_headers,
                    Err(error) => {
                        debug!(
                            %peer_id,
                            %segment_headers_batch_retry,
                            %error,
                            %last_known_segment_index,
                            segment_to_download_to = %segment_to_download_to.segment_index(),
                            "Error getting segment headers from peer",
                        );

                        continue 'new_peer;
                    }
                };

                if !self.is_segment_headers_response_valid(
                    peer_id,
                    &segment_indexes,
                    &segment_headers,
                ) {
                    warn!(
                        %peer_id,
                        %segment_headers_batch_retry,
                        "Received segment headers were invalid"
                    );

                    let _ = self.dsn_node.ban_peer(peer_id).await;
                }

                for segment_header in segment_headers {
                    if segment_header.hash() != segment_to_download_to.prev_segment_header_hash() {
                        error!(
                            %peer_id,
                            %segment_headers_batch_retry,
                            segment_index = %segment_to_download_to.segment_index() - SegmentIndex::ONE,
                            actual_hash = ?segment_header.hash(),
                            expected_hash = ?segment_to_download_to.prev_segment_header_hash(),
                            "Segment header hash doesn't match expected hash of the previous \
                            segment"
                        );

                        return Err(
                            "Segment header hash doesn't match expected hash of the previous \
                            segment"
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
    async fn get_last_segment_header(&self) -> Result<Option<SegmentHeader>, Box<dyn Error>> {
        let mut peer_segment_headers = HashMap::<PeerId, Vec<SegmentHeader>>::default();
        for (required_peers, retry_attempt) in (1..=SEGMENT_HEADER_CONSENSUS_INITIAL_NODES)
            .rev()
            .zip(1_usize..)
        {
            trace!( %retry_attempt, "Downloading last segment headers");

            // Get random peers and acquire segments from them. Some of them could be bootstrap
            // nodes with no support for request-response protocol for segment commitment.
            let new_last_known_segment_headers = self
                .dsn_node
                .get_closest_peers(PeerId::random().into())
                .await
                .inspect_err(|error| {
                    warn!(?error, "get_closest_peers returned an error");
                })?
                .filter(|peer_id| {
                    let known_peer = peer_segment_headers.contains_key(peer_id);

                    async move { !known_peer }
                })
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
                                %peer_id,
                                segment_headers_number=%segment_headers.len(),
                                "Last segment headers request succeeded"
                            );

                            if !self
                                .is_last_segment_headers_response_valid(peer_id, &segment_headers)
                            {
                                warn!(
                                    %peer_id,
                                    "Received last segment headers response was invalid"
                                );

                                let _ = self.dsn_node.ban_peer(peer_id).await;
                                return None;
                            }

                            Some((peer_id, segment_headers))
                        }
                        Err(error) => {
                            debug!(
                                %peer_id,
                                ?error,
                                "Last segment headers request failed"
                            );
                            None
                        }
                    }
                })
                .take(SEGMENT_HEADER_CONSENSUS_INITIAL_NODES)
                .buffer_unordered(SEGMENT_HEADER_CONSENSUS_INITIAL_NODES)
                .filter_map(|maybe_result| async move { maybe_result })
                .collect::<Vec<(PeerId, Vec<SegmentHeader>)>>()
                .await;

            let last_peers_count = peer_segment_headers.len();
            peer_segment_headers.extend(new_last_known_segment_headers);

            let peer_count = peer_segment_headers.len();

            if peer_count < required_peers {
                // If we've got nothing, we have to retry
                if last_peers_count == 0 {
                    debug!(
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
                        %peer_count,
                        %required_peers,
                        %retry_attempt,
                        "Segment headers consensus requires more peers, will retry"
                    );

                    continue;
                }

                debug!(
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

            return Ok(Some(best_segment_header));
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
            warn!( %peer_id, "Segment header and segment indexes collection differ");

            return false;
        }

        let returned_segment_indexes =
            BTreeSet::from_iter(segment_headers.iter().map(|rb| rb.segment_index()));
        if returned_segment_indexes.len() != segment_headers.len() {
            warn!( %peer_id, "Peer banned: it returned collection with duplicated segment headers");

            return false;
        }

        let indexes_match = segment_indexes.iter().zip(segment_headers.iter()).all(
            |(segment_index, segment_header)| *segment_index == segment_header.segment_index(),
        );

        if !indexes_match {
            warn!( %peer_id, "Segment header collection doesn't match segment indexes");

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
}
