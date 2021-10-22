use crate::commands::farm::{
    EncodedBlockWithObjectMapping, FarmerMetadata, NewHead, ProposedProofOfReplicationResponse,
    SlotInfo,
};
use anyhow::Result;
use jsonrpsee::types::traits::{Client, SubscriptionClient};
use jsonrpsee::types::v2::params::JsonRpcParams;
use jsonrpsee::types::Subscription;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::sync::Arc;

/// `WsClient` wrapper.
#[derive(Clone, Debug)]
pub struct RpcClient {
    client: Arc<WsClient>,
}

impl From<WsClient> for RpcClient {
    fn from(client: WsClient) -> Self {
        Self {
            client: Arc::new(client),
        }
    }
}

impl RpcClient {
    /// Create a new instance of [`RpcClient`].
    pub async fn new(url: &str) -> Result<Self> {
        let client = Arc::new(WsClientBuilder::default().build(url).await?);
        Ok(Self { client })
    }

    /// Get farmer metadata.
    pub async fn farmer_metadata(&self) -> Result<FarmerMetadata> {
        self.client
            .request("subspace_getFarmerMetadata", JsonRpcParams::NoParams)
            .await
            .map_err(Into::into)
    }

    /// Get a block by number.
    pub async fn block_by_number(
        &self,
        block_number: u32,
    ) -> Result<Option<EncodedBlockWithObjectMapping>> {
        self.client
            .request(
                "subspace_getBlockByNumber",
                JsonRpcParams::Array(vec![serde_json::to_value(block_number)?]),
            )
            .await
            .map_err(Into::into)
    }

    /// Subscribe to chain head.
    pub async fn subscribe_new_head(&self) -> Result<Subscription<NewHead>> {
        self.client
            .subscribe(
                "chain_subscribeNewHead",
                JsonRpcParams::NoParams,
                "chain_unsubscribeNewHead",
            )
            .await
            .map_err(Into::into)
    }

    /// Subscribe to slot.
    pub async fn subscribe_slot_info(&self) -> Result<Subscription<SlotInfo>> {
        self.client
            .subscribe(
                "subspace_subscribeSlotInfo",
                JsonRpcParams::NoParams,
                "subspace_unsubscribeSlotInfo",
            )
            .await
            .map_err(Into::into)
    }

    /// Propose PoR.
    pub async fn propose_proof_of_replication(
        &self,
        por: ProposedProofOfReplicationResponse,
    ) -> Result<()> {
        self.client
            .request(
                "subspace_proposeProofOfReplication",
                JsonRpcParams::Array(vec![serde_json::to_value(&por)?]),
            )
            .await
            .map_err(Into::into)
    }
}
