//! Node client abstraction
//!
//! During farmer operation it needs to communicate with node, for example to receive slot
//! notifications and send solutions to claim rewards.
//!
//! Implementation is abstracted away behind a trait to allow various implementation depending on
//! use case. Implementation may connect to node via RPC directly, through some kind of networked
//! middleware or even wired without network directly if node and farmer are both running in the
//! same process.

pub mod caching_proxy_node_client;
pub mod rpc_node_client;

use async_trait::async_trait;
use futures::Stream;
use std::fmt;
use std::pin::Pin;
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_core_primitives::segments::{SegmentHeader, SegmentIndex};
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};

/// Abstraction of the Node Client
#[async_trait]
pub trait NodeClient: fmt::Debug + Send + Sync + 'static {
    /// Get farmer app info
    async fn farmer_app_info(&self) -> anyhow::Result<FarmerAppInfo>;

    /// Subscribe to slot
    async fn subscribe_slot_info(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>>;

    /// Submit a slot solution
    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> anyhow::Result<()>;

    /// Subscribe to block signing request
    async fn subscribe_reward_signing(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>>;

    /// Submit a block signature
    async fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> anyhow::Result<()>;

    /// Subscribe to archived segment headers
    async fn subscribe_archived_segment_headers(
        &self,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>>;

    /// Get segment headers for the segments
    async fn segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> anyhow::Result<Vec<Option<SegmentHeader>>>;

    /// Get piece by index.
    async fn piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>>;

    /// Acknowledge segment header.
    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> anyhow::Result<()>;
}

/// Node Client extension methods that are not necessary for farmer as a library, but might be useful for an app
#[async_trait]
pub trait NodeClientExt: NodeClient {
    /// Get the cached segment headers for the given segment indices.
    /// If there is a cache, it is not updated, to avoid remote denial of service.
    ///
    /// Returns `None` for segment indices that are not in the cache.
    async fn cached_segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> anyhow::Result<Vec<Option<SegmentHeader>>>;

    /// Get up to `limit` most recent segment headers.
    /// If there is a cache, it is not updated, to avoid remote denial of service.
    ///
    /// If the node or cache has less than `limit` segment headers, the returned vector will be
    /// shorter. Each returned segment header is wrapped in `Some`.
    async fn last_segment_headers(&self, limit: u32) -> anyhow::Result<Vec<Option<SegmentHeader>>>;
}
