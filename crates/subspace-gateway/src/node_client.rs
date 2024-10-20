//! Node client implementation that connects to node via RPC (WebSockets)

use async_trait::async_trait;
use jsonrpsee::core::client::{ClientT, Error as JsonError};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use std::fmt;
use std::sync::Arc;
use subspace_core_primitives::segments::{SegmentHeader, SegmentIndex};
use subspace_rpc_primitives::FarmerAppInfo;

/// Node client implementation that connects to node via RPC (WebSockets).
///
/// This implementation is supposed to be used on local network and not via public Internet due to
/// sensitive contents.
#[derive(Debug, Clone)]
pub struct RpcNodeClient {
    client: Arc<WsClient>,
}

impl RpcNodeClient {
    /// Create a new instance of [`NodeClient`].
    pub async fn new(url: &str) -> Result<Self, JsonError> {
        let client = Arc::new(WsClientBuilder::default().build(url).await?);
        Ok(Self { client })
    }
}

/// Abstraction of the Node Client
#[async_trait]
pub trait NodeClient: fmt::Debug + Send + Sync + 'static {
    /// Get farmer app info
    async fn farmer_app_info(&self) -> anyhow::Result<FarmerAppInfo>;

    /// Get segment headers for the segments
    #[expect(dead_code, reason = "implementation is incomplete")]
    async fn segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> anyhow::Result<Vec<Option<SegmentHeader>>>;
}

#[async_trait]
impl NodeClient for RpcNodeClient {
    async fn farmer_app_info(&self) -> anyhow::Result<FarmerAppInfo> {
        Ok(self
            .client
            .request("subspace_getFarmerAppInfo", rpc_params![])
            .await?)
    }

    async fn segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> anyhow::Result<Vec<Option<SegmentHeader>>> {
        Ok(self
            .client
            .request("subspace_segmentHeaders", rpc_params![&segment_indices])
            .await?)
    }
}
