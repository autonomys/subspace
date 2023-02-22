use futures::StreamExt;
use parking_lot::Mutex;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;
use subspace_core_primitives::{Blake2b256Hash, RootBlock, SegmentIndex};
use subspace_networking::libp2p::PeerId;
use subspace_networking::{Node, RootBlockRequest, RootBlockResponse};
use tracing::{debug, error, trace, warn};

const ROOT_BLOCK_NUMBER_PER_REQUEST: u64 = 10;
/// Minimum peers number to participate in root block election.
const ROOT_BLOCK_CONSENSUS_MIN_SET: usize = 2; //TODO: change the value
/// Threshold for the root block election success (minimum peer number with the same root block).
const ROOT_BLOCK_CONSENSUS_THRESHOLD: u64 = 2; //TODO: change the value

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
        let mut last_root_block = self.get_last_root_block().await?;
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

            let mut root_blocks = self.get_root_blocks_batch(segment_indexes).await?;
            root_blocks.sort_by(|rb1, rb2| rb1.segment_index().cmp(&rb2.segment_index()).reverse());

            for root_block in root_blocks {
                if root_block.hash() != last_root_block.prev_root_block_hash() {
                    error!(
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

    /// Return last root block known to DSN. We ask several peers for the highest root block
    /// known to them. Target root block should be known to at least ROOT_BLOCK_CONSENSUS_THRESHOLD
    /// among peer set with minimum size of ROOT_BLOCK_CONSENSUS_MIN_SET peers.
    async fn get_last_root_block(&self) -> Result<RootBlock, Box<dyn Error>> {
        trace!("Getting last root block...");
        let peer_blocks = Arc::new(Mutex::new(BTreeMap::<PeerId, Vec<RootBlock>>::new()));

        // Get random peers. Some of them could be bootstrap nodes with no support for
        // request-response protocol for records root.
        let get_peers_result = self
            .dsn_node
            .get_closest_peers(PeerId::random().into())
            .await;

        let mut peer_handles = Vec::new();
        // Acquire root blocks from peers.
        match get_peers_result {
            Ok(mut get_peers_stream) => {
                while let Some(peer_id) = get_peers_stream.next().await {
                    let peer_blocks = peer_blocks.clone();
                    let dsn_node = self.dsn_node.clone();
                    let join_handle = tokio::spawn(async move {
                        trace!(%peer_id, "get_closest_peers returned an item");

                        let request_result = dsn_node
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

                                peer_blocks.lock().insert(peer_id, root_blocks);
                            }
                            Err(error) => {
                                debug!(%peer_id, ?error, "Last root block request failed.");
                            }
                        };
                    });

                    peer_handles.push(join_handle);
                }
            }
            Err(err) => {
                warn!(?err, "get_closest_peers returned an error");

                return Err(err.into());
            }
        }

        for handle in peer_handles {
            if let Err(err) = handle.await {
                error!(?err, "Task for root blocks returned an error");
            }
        }

        let peer_blocks = Arc::try_unwrap(peer_blocks)
            .expect("We manually waited for each other usage to be dropped.")
            .into_inner();

        // TODO: Consider adding attempts to increase the initial peer set.
        if peer_blocks.len() < ROOT_BLOCK_CONSENSUS_MIN_SET {
            return Err(format!(
                "Root block consensus failed: not enough peers ({}).",
                peer_blocks.len()
            )
            .into());
        }

        // Calculate votes
        let mut root_block_score: BTreeMap<Blake2b256Hash, u64> = BTreeMap::new();
        let mut root_block_dict: BTreeMap<Blake2b256Hash, RootBlock> = BTreeMap::new();

        for (peer_id, root_blocks) in peer_blocks {
            if !self.validate_root_blocks(peer_id, &root_blocks).await {
                continue;
            }

            for root_block in root_blocks {
                root_block_score
                    .entry(root_block.hash())
                    .and_modify(|val| *val += 1)
                    .or_insert(1);
                root_block_dict
                    .entry(root_block.hash())
                    .or_insert(root_block);
            }
        }

        // Sort the collection to get highest blocks first.
        let mut root_blocks = root_block_dict.values().collect::<Vec<_>>();
        root_blocks.sort_by_key(|rb| Reverse(rb.segment_index()));

        for root_block in root_blocks {
            let score = root_block_score
                .get(&root_block.hash())
                .expect("Must be present because of the manual adding.");

            if *score >= ROOT_BLOCK_CONSENSUS_THRESHOLD {
                return Ok(*root_block);
            }
        }

        Err("Root block consensus failed: can't pass the threshold.".into())
    }

    async fn validate_root_blocks(&self, peer_id: PeerId, root_blocks: &Vec<RootBlock>) -> bool {
        // check for duplicates
        let segment_indexes = BTreeSet::from_iter(root_blocks.iter().map(|rb| rb.segment_index()));
        if segment_indexes.len() != root_blocks.len() {
            warn!(%peer_id, "Peer banned: it returned collection with duplicated root blocks.");
            // We don't check the result here.
            let _ = self.dsn_node.ban_peer(peer_id).await;

            return false;
        }

        true
    }

    async fn get_root_blocks_batch(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<RootBlock>, Box<dyn Error>> {
        trace!(?segment_indexes, "Getting root block batch...");

        // Get random peers. Some of them could be bootstrap nodes with no support for
        // request-response protocol for records root.
        let get_peers_result = self
            .dsn_node
            .get_closest_peers(PeerId::random().into())
            .await;

        match get_peers_result {
            Ok(mut get_peers_stream) => {
                while let Some(peer_id) = get_peers_stream.next().await {
                    trace!(%peer_id, "get_closest_peers returned an item");

                    let request_result = self
                        .dsn_node
                        .send_generic_request(
                            peer_id,
                            RootBlockRequest::SegmentIndexes {
                                segment_indexes: segment_indexes.clone(),
                            },
                        )
                        .await;

                    match request_result {
                        Ok(RootBlockResponse { root_blocks }) => {
                            trace!(%peer_id, ?segment_indexes, "Root block request succeeded.");

                            return Ok(root_blocks);
                        }
                        Err(error) => {
                            debug!(%peer_id, ?segment_indexes, ?error, "Root block request failed.");
                        }
                    };
                }
                Err("No more peers for root blocks.".into())
            }
            Err(err) => {
                warn!(?err, "get_closest_peers returned an error");

                Err(err.into())
            }
        }
    }
}
