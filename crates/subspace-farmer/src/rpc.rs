use crate::common::{Salt, Tag};
use jsonrpsee::types::traits::{Client, SubscriptionClient};
use jsonrpsee::types::v2::params::JsonRpcParams;
use jsonrpsee::types::{Error, Subscription};
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subspace_core_primitives::objects::BlockObjectMapping;

type SlotNumber = u64;

/// Metadata necessary for farmer operation
#[derive(Debug, Deserialize)]
pub(super) struct FarmerMetadata {
    /// Depth `K` after which a block enters the recorded history (a global constant, as opposed
    /// to the client-dependent transaction confirmation depth `k`).
    pub confirmation_depth_k: u32,
    /// The size of data in one piece (in bytes).
    pub record_size: u32,
    /// Recorded history is encoded and plotted in segments of this size (in bytes).
    pub recorded_history_segment_size: u32,
    /// This constant defines the size (in bytes) of one pre-genesis object.
    pub pre_genesis_object_size: u32,
    /// This constant defines the number of a pre-genesis objects that will bootstrap the
    /// history.
    pub pre_genesis_object_count: u32,
    /// This constant defines the seed used for deriving pre-genesis objects that will bootstrap
    /// the history.
    pub pre_genesis_object_seed: Vec<u8>,
}

/// Encoded block with mapping of objects that it contains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct EncodedBlockWithObjectMapping {
    /// Encoded block
    pub block: Vec<u8>,
    /// Mapping of objects inside of the block
    pub object_mapping: BlockObjectMapping,
}

// There are more fields in this struct, but we only care about one
#[derive(Debug, Deserialize)]
pub(super) struct NewHead {
    pub number: String,
}

/// Proposed proof of space consisting of solution and farmer's secret key for block signing
#[derive(Debug, Serialize)]
pub(super) struct ProposedProofOfReplicationResponse {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Solution (if present) from farmer's plot corresponding to slot number above
    pub solution: Option<Solution>,
    /// Secret key, used for signing blocks on the client node
    pub secret_key: Vec<u8>,
}

/// Information about new slot that just arrived
#[derive(Debug, Deserialize)]
pub(super) struct SlotInfo {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Slot challenge
    pub challenge: [u8; 8],
    /// Salt
    pub salt: Salt,
    /// Salt for the next eon
    pub next_salt: Option<Salt>,
    /// Acceptable solution range
    pub solution_range: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct Solution {
    public_key: [u8; 32],
    piece_index: u64,
    encoding: Vec<u8>,
    signature: Vec<u8>,
    tag: Tag,
}

impl Solution {
    pub(super) fn new(
        public_key: [u8; 32],
        piece_index: u64,
        encoding: Vec<u8>,
        signature: Vec<u8>,
        tag: Tag,
    ) -> Self {
        Self {
            public_key,
            piece_index,
            encoding,
            signature,
            tag,
        }
    }
}

/// `WsClient` wrapper.
#[derive(Clone, Debug)]
pub struct RpcClient {
    client: Arc<WsClient>,
}

impl RpcClient {
    /// Create a new instance of [`RpcClient`].
    pub async fn new(url: &str) -> Result<Self, Error> {
        let client = Arc::new(WsClientBuilder::default().build(url).await?);
        Ok(Self { client })
    }

    /// Get farmer metadata.
    pub(super) async fn farmer_metadata(&self) -> Result<FarmerMetadata, Error> {
        self.client
            .request("subspace_getFarmerMetadata", JsonRpcParams::NoParams)
            .await
    }

    /// Get a block by number.
    pub(super) async fn block_by_number(
        &self,
        block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>, Error> {
        self.client
            .request(
                "subspace_getBlockByNumber",
                JsonRpcParams::Array(vec![serde_json::to_value(block_number)?]),
            )
            .await
    }

    /// Subscribe to chain head.
    pub(super) async fn subscribe_new_head(&self) -> Result<Subscription<NewHead>, Error> {
        self.client
            .subscribe(
                "chain_subscribeNewHead",
                JsonRpcParams::NoParams,
                "chain_unsubscribeNewHead",
            )
            .await
    }

    /// Subscribe to slot.
    pub(super) async fn subscribe_slot_info(&self) -> Result<Subscription<SlotInfo>, Error> {
        self.client
            .subscribe(
                "subspace_subscribeSlotInfo",
                JsonRpcParams::NoParams,
                "subspace_unsubscribeSlotInfo",
            )
            .await
    }

    /// Propose PoR.
    pub(super) async fn propose_proof_of_replication(
        &self,
        por: ProposedProofOfReplicationResponse,
    ) -> Result<(), Error> {
        self.client
            .request(
                "subspace_proposeProofOfReplication",
                JsonRpcParams::Array(vec![serde_json::to_value(&por)?]),
            )
            .await
    }
}
