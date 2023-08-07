use futures::StreamExt;
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use subspace_core_primitives::{SegmentHeader, SegmentIndex};
use subspace_networking::libp2p::PeerId;
use subspace_networking::{Node, SegmentHeaderRequest, SegmentHeaderResponse};
use tracing::{debug, error, trace, warn};

const SEGMENT_HEADER_NUMBER_PER_REQUEST: u64 = 1000;
/// Initial number of peers to query for segment header
const SEGMENT_HEADER_CONSENSUS_INITIAL_NODES: usize = 20;

/// Helps gathering segment headers from DSN
pub struct SegmentHeaderHandler {
    dsn_node: Node,
}

impl SegmentHeaderHandler {
    pub fn new(dsn_node: Node) -> Self {
        Self { dsn_node }
    }

    /// Returns segment headers known to DSN, ordered from 0 to the last known.
    pub async fn get_segment_headers(&self) -> Result<Vec<SegmentHeader>, Box<dyn Error>> {
        trace!("Getting segment headers...");

        let Some((mut last_segment_header, peers)) = self.get_last_segment_header().await? else {
            return Ok(Vec::new());
        };
        debug!(
            "Getting segment headers starting from segment_index={}",
            last_segment_header.segment_index()
        );

        // TODO: Needs to statically require 64-bit environment or else u64->usize may cause
        //  problems in the future
        let mut all_segment_headers =
            Vec::with_capacity(u64::from(last_segment_header.segment_index()) as usize + 1);
        all_segment_headers.push(last_segment_header);

        while last_segment_header.segment_index() > SegmentIndex::ZERO {
            let segment_indexes: Vec<_> = (SegmentIndex::ZERO..last_segment_header.segment_index())
                .rev()
                .take(SEGMENT_HEADER_NUMBER_PER_REQUEST as usize)
                .collect();

            let (peer_id, segment_headers) = self
                .get_segment_headers_batch(&peers, segment_indexes)
                .await?;

            for segment_header in segment_headers {
                if segment_header.hash() != last_segment_header.prev_segment_header_hash() {
                    error!(
                        %peer_id,
                        segment_index=%last_segment_header.segment_index() - SegmentIndex::ONE,
                        actual_hash=?segment_header.hash(),
                        expected_hash=?last_segment_header.prev_segment_header_hash(),
                        "Segment header hash doesn't match expected hash from the last block."
                    );

                    return Err(
                        "Segment header hash doesn't match expected hash from the last block."
                            .into(),
                    );
                }

                last_segment_header = segment_header;
                all_segment_headers.push(segment_header);
            }
        }

        all_segment_headers.reverse();

        Ok(all_segment_headers)
    }

    /// Return last segment header known to DSN and agreed on by majority of the peer set with
    /// minimum initial size of [`SEGMENT_HEADER_CONSENSUS_INITIAL_NODES`] peers.
    ///
    /// `Ok(None)` is returned when no peers were found.
    async fn get_last_segment_header(
        &self,
    ) -> Result<Option<(SegmentHeader, Vec<PeerId>)>, Box<dyn Error>> {
        for (root_block_consensus_nodes, retry_attempt) in (1
            ..=SEGMENT_HEADER_CONSENSUS_INITIAL_NODES)
            .rev()
            .zip(1_usize..)
        {
            trace!(%retry_attempt, "Getting last segment header...");

            // Get random peers. Some of them could be bootstrap nodes with no support for
            // request-response protocol for segment commitment.
            let get_peers_result = self
                .dsn_node
                .get_closest_peers(PeerId::random().into())
                .await;

            // Acquire segment headers from peers.
            let get_peers_stream = match get_peers_result {
                Ok(get_peers_stream) => get_peers_stream,
                Err(err) => {
                    warn!(?err, "get_closest_peers returned an error");

                    return Err(err.into());
                }
            };

            // Hashmap here just to potentially peers
            let peer_blocks: HashMap<PeerId, Vec<SegmentHeader>> = get_peers_stream
                .filter_map(|peer_id| async move {
                    let request_result = self
                        .dsn_node
                        .send_generic_request(
                            peer_id,
                            SegmentHeaderRequest::LastSegmentHeaders {
                                // Request 2 top segment headers, accounting for situations when new
                                // segment header was just produced and not all nodes have it
                                segment_header_number: 2,
                            },
                        )
                        .await;

                    match request_result {
                        Ok(SegmentHeaderResponse { segment_headers }) => {
                            trace!(
                                %peer_id,
                                segment_headers_number=%segment_headers.len(),
                                "Last segment header request succeeded."
                            );

                            if !self.is_last_segment_headers_response_valid(peer_id, &segment_headers) {
                                warn!(%peer_id, "Received last segment headers response was invalid.");

                                let _ = self.dsn_node.ban_peer(peer_id).await;
                                return None;
                            }

                            Some((peer_id, segment_headers))
                        }
                        Err(error) => {
                            debug!(%peer_id, ?error, "Last segment header request failed.");
                            None
                        }
                    }
                })
                .collect()
                .await;

            let peer_count = peer_blocks.len();

            if peer_count < root_block_consensus_nodes {
                debug!(
                    %peer_count,
                    %root_block_consensus_nodes,
                    %retry_attempt,
                    "Segment header consensus requires more peers, will retry"
                );

                continue;
            }

            // Calculate votes
            let mut segment_header_peers: HashMap<SegmentHeader, Vec<PeerId>> = HashMap::new();

            for (peer_id, segment_headers) in peer_blocks {
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
            warn!(%peer_id, "Segment header and segment indexes collection differ.");

            return false;
        }

        let returned_segment_indexes =
            BTreeSet::from_iter(segment_headers.iter().map(|rb| rb.segment_index()));
        if returned_segment_indexes.len() != segment_headers.len() {
            warn!(%peer_id, "Peer banned: it returned collection with duplicated segment headers.");

            return false;
        }

        let indexes_match = segment_indexes.iter().zip(segment_headers.iter()).all(
            |(segment_index, segment_header)| *segment_index == segment_header.segment_index(),
        );

        if !indexes_match {
            warn!(%peer_id, "Segment header collection doesn't match segment indexes.");

            return false;
        }

        true
    }

    fn is_last_segment_headers_response_valid(
        &self,
        peer_id: PeerId,
        segment_headers: &[SegmentHeader],
    ) -> bool {
        let segment_indexes = match segment_headers.first() {
            None => {
                // Empty collection is invalid, everyone has at least one segment header
                return false;
            }
            Some(first_segment_header) => {
                // We expect the reverse order
                let last_segment_index = first_segment_header.segment_index();

                (SegmentIndex::ZERO..=last_segment_index)
                    .rev()
                    .take(segment_headers.len())
                    .collect::<Vec<_>>()
            }
        };

        self.is_segment_headers_response_valid(peer_id, &segment_indexes, segment_headers)
    }

    async fn get_segment_headers_batch(
        &self,
        peers: &[PeerId],
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<(PeerId, Vec<SegmentHeader>), Box<dyn Error>> {
        trace!(?segment_indexes, "Getting segment header batch...");

        for &peer_id in peers {
            trace!(%peer_id, "get_closest_peers returned an item");

            let request_result = self
                .dsn_node
                .send_generic_request(
                    peer_id,
                    SegmentHeaderRequest::SegmentIndexes {
                        segment_indexes: segment_indexes.clone(),
                    },
                )
                .await;

            match request_result {
                Ok(SegmentHeaderResponse { segment_headers }) => {
                    trace!(%peer_id, ?segment_indexes, "Segment header request succeeded.");

                    if !self.is_segment_headers_response_valid(
                        peer_id,
                        &segment_indexes,
                        &segment_headers,
                    ) {
                        warn!(%peer_id, "Received segment headers were invalid.");

                        let _ = self.dsn_node.ban_peer(peer_id).await;
                    }

                    return Ok((peer_id, segment_headers));
                }
                Err(error) => {
                    debug!(%peer_id, ?segment_indexes, ?error, "Segment header request failed.");
                }
            };
        }
        Err("No more peers for segment headers.".into())
    }
}
