use futures::StreamExt;
use std::cmp::Ordering;
use std::error::Error;
use subspace_core_primitives::{RootBlock, SegmentIndex};
use subspace_networking::libp2p::PeerId;
use subspace_networking::{Node, RootBlockRequest, RootBlockResponse};
use tracing::{debug, trace, warn};

const ROOT_BLOCK_NUMBER_PER_REQUEST: u64 = 10;

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
            root_blocks.sort_by(|rb1, rb2| compare_optional_root_blocks(rb1, rb2).reverse());

            for root_block in root_blocks {
                match root_block {
                    None => {
                        warn!("Root block request returned None.");
                    }
                    Some(root_block) => {
                        last_root_block = root_block;
                        result.push(root_block);
                    }
                }
            }
        }

        Ok(result)
    }

    async fn get_last_root_block(&self) -> Result<RootBlock, Box<dyn Error>> {
        trace!("Getting last root block...");

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
                            RootBlockRequest::LastRootBlocks {
                                root_block_number: ROOT_BLOCK_NUMBER_PER_REQUEST,
                            },
                        )
                        .await;

                    match request_result {
                        Ok(RootBlockResponse { root_blocks }) => {
                            trace!(%peer_id, "Last root block request succeeded.");

                            let last_root_block = root_blocks
                                .iter()
                                .max_by(|rb1, rb2| compare_optional_root_blocks(rb1, rb2));

                            if let Some(Some(root_block)) = last_root_block {
                                trace!(
                                    %peer_id,
                                    segment_index=root_block.segment_index(),
                                    "Last root block was obtained."
                                );

                                return Ok(*root_block);
                            } else {
                                debug!(%peer_id, "Last root block was not received.");
                            }
                        }
                        Err(error) => {
                            debug!(%peer_id, ?error, "Last root block request failed.");
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

    async fn get_root_blocks_batch(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<RootBlock>>, Box<dyn Error>> {
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

/// Compares two root blocks by segment indexes. None are less then Some.
fn compare_optional_root_blocks(rb1: &Option<RootBlock>, rb2: &Option<RootBlock>) -> Ordering {
    match (rb1, rb2) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (Some(rb1), Some(rb2)) => rb1.segment_index().cmp(&rb2.segment_index()),
    }
}
