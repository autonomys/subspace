use futures::StreamExt;
use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use subspace_core_primitives::{RootBlock, SegmentIndex};
use subspace_networking::libp2p::PeerId;
use subspace_networking::{Node, RootBlockRequest, RootBlockResponse};
use tracing::{debug, error, trace, warn};

const LAST_BLOCK_GET_RETRIES: u8 = 5;
const ROOT_BLOCK_NUMBER_PER_REQUEST: u64 = 1000;
/// Minimum peers number to participate in root block election.
const ROOT_BLOCK_CONSENSUS_MIN_SET: usize = 2; //TODO: change the value
/// Threshold for the root block election success (percentage).
const ROOT_BLOCK_CONSENSUS_THRESHOLD: u64 = 51; //TODO: change the value

/// Helps gathering root blocks from DSN
pub struct RootBlockHandler {
    dsn_node: Node,
}

impl RootBlockHandler {
    pub fn new(dsn_node: Node) -> Self {
        Self { dsn_node }
    }

    /// Returns root blocks known to DSN.
    pub async fn get_root_blocks(&self) -> Result<Vec<RootBlock>, Box<dyn Error>> {
        trace!("Getting root blocks...");

        let mut result = Vec::new();
        let (mut last_root_block, peers) = self.get_last_root_block().await?;
        debug!(
            "Getting root blocks starting from segment_index={}",
            last_root_block.segment_index()
        );

        result.push(last_root_block);

        while last_root_block.segment_index() > 0 {
            let segment_indexes: Vec<_> = (0..last_root_block.segment_index())
                .rev()
                .take(ROOT_BLOCK_NUMBER_PER_REQUEST as usize)
                .collect();

            let (peer_id, root_blocks) =
                self.get_root_blocks_batch(&peers, segment_indexes).await?;

            for root_block in root_blocks {
                if root_block.hash() != last_root_block.prev_root_block_hash() {
                    error!(
                        %peer_id,
                        hash=?root_block.hash(),
                        prev_hash=?last_root_block.prev_root_block_hash(),
                        "Root block hash doesn't match expected hash from the last block."
                    );

                    return Err(
                        "Root block hash doesn't match expected hash from the last block.".into(),
                    );
                }

                last_root_block = root_block;
                result.push(root_block);
            }
        }
        Ok(result)
    }

    /// Return last root block known to DSN and peers voted for it. We ask several peers for the
    /// highest root block known to them. Target root block should be known to at least
    /// ROOT_BLOCK_CONSENSUS_THRESHOLD among peer set with minimum size
    /// of ROOT_BLOCK_CONSENSUS_MIN_SET peers.
    async fn get_last_root_block(&self) -> Result<(RootBlock, Vec<PeerId>), Box<dyn Error>> {
        for retry_attempt in 1..=LAST_BLOCK_GET_RETRIES {
            trace!(%retry_attempt, "Getting last root block...");

            // Get random peers. Some of them could be bootstrap nodes with no support for
            // request-response protocol for records root.
            let get_peers_result = self
                .dsn_node
                .get_closest_peers(PeerId::random().into())
                .await;

            // Acquire root blocks from peers.
            let get_peers_stream = match get_peers_result {
                Ok(get_peers_stream) => get_peers_stream,
                Err(err) => {
                    warn!(?err, "get_closest_peers returned an error");

                    return Err(err.into());
                }
            };

            // Hashmap here just to potentially peers
            let peer_blocks: HashMap<PeerId, Vec<RootBlock>> = get_peers_stream
                .filter_map(|peer_id| async move {
                    let request_result = self
                        .dsn_node
                        .send_generic_request(
                            peer_id,
                            RootBlockRequest::LastRootBlocks {
                                root_block_number: ROOT_BLOCK_NUMBER_PER_REQUEST,
                            },
                        )
                        .await;

                    match request_result {
                        Ok(RootBlockResponse { root_blocks }) => {
                            trace!(
                                %peer_id,
                                root_blocks_number=%root_blocks.len(),
                                "Last root block request succeeded."
                            );

                            Some((peer_id, root_blocks))
                        }
                        Err(error) => {
                            debug!(%peer_id, ?error, "Last root block request failed.");
                            None
                        }
                    }
                })
                .collect()
                .await;

            // TODO: Consider adding attempts to increase the initial peer set.
            if peer_blocks.len() < ROOT_BLOCK_CONSENSUS_MIN_SET {
                debug!(
                    "Root block consensus failed: not enough peers ({}).",
                    peer_blocks.len()
                );

                continue;
            }

            // Calculate votes
            let mut root_block_score: HashMap<RootBlock, (u64, Vec<PeerId>)> = HashMap::new();

            for (peer_id, root_blocks) in &peer_blocks {
                if !self.validate_last_root_blocks(*peer_id, root_blocks) {
                    warn!(%peer_id, "Received last root blocks were invalid.");

                    let _ = self.dsn_node.ban_peer(*peer_id).await;
                    continue;
                }

                for root_block in root_blocks {
                    root_block_score
                        .entry(*root_block)
                        .and_modify(|(val, peers)| {
                            *val += 1;
                            peers.push(*peer_id);
                        })
                        .or_insert((1, vec![*peer_id]));
                }
            }

            // Sort the collection to get highest blocks first.
            let mut root_blocks = root_block_score.keys().collect::<Vec<_>>();
            root_blocks.sort_by_key(|rb| Reverse(rb.segment_index()));

            for root_block in root_blocks {
                let (score, peers) = root_block_score
                    .get(root_block)
                    .expect("Must be present because of the manual adding.");

                // peer_blocks.len() >= 1 because it's not less than ROOT_BLOCK_CONSENSUS_MIN_SET
                let peer_count = peer_blocks.len() as u64;
                let percentage = score * 100 / peer_count;

                trace!(%percentage, limit=%ROOT_BLOCK_CONSENSUS_THRESHOLD, "Root blocks voting ended.");

                if percentage >= ROOT_BLOCK_CONSENSUS_THRESHOLD {
                    return Ok((*root_block, peers.clone()));
                }
            }

            debug!(retry_attempt, "Failed attempt to get a root block.");
        }

        Err("Root block consensus failed: can't pass the threshold.".into())
    }

    /// Validates root blocks and related segment indexes.
    /// We assume `segment_indexes` to be a sorted collection (we create it manually).
    fn validate_root_blocks(
        &self,
        peer_id: PeerId,
        segment_indexes: &Vec<SegmentIndex>,
        root_blocks: &Vec<RootBlock>,
    ) -> bool {
        if root_blocks.len() != segment_indexes.len() {
            warn!(%peer_id, "Root block and segment indexes collection differ.");

            return false;
        }

        let returned_segment_indexes =
            BTreeSet::from_iter(root_blocks.iter().map(|rb| rb.segment_index()));
        if returned_segment_indexes.len() != root_blocks.len() {
            warn!(%peer_id, "Peer banned: it returned collection with duplicated root blocks.");

            return false;
        }

        let indexes_match = segment_indexes
            .iter()
            .zip(root_blocks.iter())
            .all(|(segment_index, root_block)| *segment_index == root_block.segment_index());

        if !indexes_match {
            warn!(%peer_id, "Root block collection doesn't match segment indexes.");

            return false;
        }

        true
    }

    fn validate_last_root_blocks(&self, peer_id: PeerId, root_blocks: &Vec<RootBlock>) -> bool {
        let segment_indexes = match root_blocks.first() {
            None => {
                // empty collection considered as valid
                return true;
            }
            Some(first_root_block) => {
                // we expect the reverse order
                let last_segment_index = first_root_block.segment_index();

                (0..=last_segment_index)
                    .rev()
                    .take(root_blocks.len())
                    .collect::<Vec<_>>()
            }
        };

        self.validate_root_blocks(peer_id, &segment_indexes, root_blocks)
    }

    async fn get_root_blocks_batch(
        &self,
        peers: &[PeerId],
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<(PeerId, Vec<RootBlock>), Box<dyn Error>> {
        trace!(?segment_indexes, "Getting root block batch...");

        for peer_id in peers {
            trace!(%peer_id, "get_closest_peers returned an item");

            let request_result = self
                .dsn_node
                .send_generic_request(
                    *peer_id,
                    RootBlockRequest::SegmentIndexes {
                        segment_indexes: segment_indexes.clone(),
                    },
                )
                .await;

            match request_result {
                Ok(RootBlockResponse { root_blocks }) => {
                    trace!(%peer_id, ?segment_indexes, "Root block request succeeded.");

                    if !self.validate_root_blocks(*peer_id, &segment_indexes, &root_blocks) {
                        warn!(%peer_id, "Received root blocks were invalid.");

                        let _ = self.dsn_node.ban_peer(*peer_id).await;
                    }

                    return Ok((*peer_id, root_blocks));
                }
                Err(error) => {
                    debug!(%peer_id, ?segment_indexes, ?error, "Root block request failed.");
                }
            };
        }
        Err("No more peers for root blocks.".into())
    }
}
