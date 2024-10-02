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
use subspace_core_primitives::segments::SegmentIndex;
use subspace_core_primitives::SegmentHeader;
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};

/// Erased error type
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Abstraction of the Node Client
#[async_trait]
pub trait NodeClient: fmt::Debug + Send + Sync + 'static {
    /// Get farmer app info
    async fn farmer_app_info(&self) -> Result<FarmerAppInfo, Error>;

    /// Subscribe to slot
    async fn subscribe_slot_info(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SlotInfo> + Send + 'static>>, Error>;

    /// Submit a slot solution
    async fn submit_solution_response(
        &self,
        solution_response: SolutionResponse,
    ) -> Result<(), Error>;

    /// Subscribe to block signing request
    async fn subscribe_reward_signing(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = RewardSigningInfo> + Send + 'static>>, Error>;

    /// Submit a block signature
    async fn submit_reward_signature(
        &self,
        reward_signature: RewardSignatureResponse,
    ) -> Result<(), Error>;

    /// Subscribe to archived segment headers
    async fn subscribe_archived_segment_headers(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = SegmentHeader> + Send + 'static>>, Error>;

    /// Get segment headers for the segments
    async fn segment_headers(
        &self,
        segment_indices: Vec<SegmentIndex>,
    ) -> Result<Vec<Option<SegmentHeader>>, Error>;

    /// Get piece by index.
    async fn piece(&self, piece_index: PieceIndex) -> Result<Option<Piece>, Error>;

    /// Acknowledge segment header.
    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<(), Error>;
}

/// Node Client extension methods that are not necessary for farmer as a library, but might be useful for an app
#[async_trait]
pub trait NodeClientExt: NodeClient {
    /// Get the last segment headers.
    async fn last_segment_headers(&self, limit: u32) -> Result<Vec<Option<SegmentHeader>>, Error>;
}
