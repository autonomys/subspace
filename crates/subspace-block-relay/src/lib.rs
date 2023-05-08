//! Block relay implementation.
//!
//! The components in the system:
//! 1. Relay users like consensus, execution. They implement the use case
//!    specific logic that drives the relay protocol. This has a client
//!    side stub, and a server side task to process incoming requests.
//! 2. Relay protocol that is agnostic to the relay user. The protocol
//!    is abstracted to be reused for different use cases. The protocol
//!    also has corresponding client/server side components.
//! 3. Protocol backend: relay user specific abstraction used by the relay
//!    protocol to populate the protocol messages
//!
//! Nodes advertise/exchange DownloadUnits with each other. DownloadUnit has
//! two parts:
//! - ProtocolUnits: the part fetched by the relay protocol. This is bulk of
//!   the data transfer that we would like to optimize
//! - Rest of the download unit, handled directly by the relay user
//!
//! Examples:
//! 1. Consensus
//!    DownloadUnit = Block, ProtocolUnit = extrinsics
//!    The extrinsics are handled by the protocol, remaining block
//!    fields are directly filled by the caller. The protocol backend
//!    helps fetch blocks/transactions from the substrate backend
//! 2. Execution
//!    TODO
//! 3. Other possible use cases (e.g) reconcile/sync the transaction pool
//!    between two nodes. In this case, DownloadUnit = transaction pool,
//!    ProtocolUnit = transaction
//!
//! The download has two phases:
//! -  Initial request/response
//!    Ideally, download of all the protocol units in the download unit should
//!    be completed during this phase
//! -  Reconcile phase
//!    If the initial phase could not complete the download, additional
//!    request/response messages are initiated by the protocol to fetch the
//!    protocol units
//!

#![feature(const_option)]

use crate::utils::RelayError;
use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::channel::oneshot::Canceled;
use sc_network::RequestFailure;
use std::sync::Arc;
use std::time::Duration;

mod consensus;
mod protocol;
mod utils;

pub use crate::consensus::build_consensus_relay;
pub use crate::utils::NetworkWrapper;

pub(crate) const LOG_TARGET: &str = "block_relay";

pub(crate) type EncoderFn<T> = Box<dyn Fn(T) -> Vec<u8> + Send>;

/// The downloaded entry and meta info
pub(crate) struct DownloadResult<DownloadUnitId> {
    /// Downloaded unit Id
    download_unit_id: DownloadUnitId,

    /// Downloaded entry
    download_unit: Vec<u8>,

    /// Total transactions (in bytes) that could not be resolved
    /// locally, and had to be fetched from the server
    local_miss: usize,

    /// Download latency
    latency: Duration,
}

/// The resolved protocol unit related info
pub(crate) struct Resolved<ProtocolUnitId, ProtocolUnit> {
    /// The protocol unit Id.
    pub(crate) protocol_unit_id: ProtocolUnitId,

    /// The protocol unit
    pub(crate) protocol_unit: ProtocolUnit,

    /// If it was resolved locally, or if it had to be
    /// fetched from the server (local miss)
    pub(crate) locally_resolved: bool,
}

/// The client side of the relay protocol
#[async_trait]
pub(crate) trait ProtocolClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>:
    Send + Sync
{
    type ProtocolReq: Send + Sync + Encode + Decode;
    type ProtocolRsp: Send + Sync + Encode + Decode;

    /// Builds the protocol portion of the initial request
    fn build_initial_request(&self) -> Self::ProtocolReq;

    /// Resolves the initial response to produce the protocol units.
    /// `encoder_fn` needs to be called to generate the request payload
    /// as part of request/response sequences initiated by the protocol.
    async fn resolve_initial_response(
        &self,
        response: Self::ProtocolRsp,
        encoder_fn: EncoderFn<Self::ProtocolReq>,
        network: Arc<dyn NetworkInterface>,
    ) -> Result<(DownloadUnitId, Vec<Resolved<ProtocolUnitId, ProtocolUnit>>), RelayError>;
}

/// The server side of the relay protocol
pub(crate) trait ProtocolServer<DownloadUnitId> {
    type ProtocolReq: Encode + Decode;
    type ProtocolRsp: Encode + Decode;

    /// Builds the protocol response to the initial request
    fn build_initial_response(
        &self,
        download_unit_id: &DownloadUnitId,
        initial_request: Self::ProtocolReq,
    ) -> Result<Self::ProtocolRsp, RelayError>;

    /// Handles the additional client messages during the reconcile phase
    fn on_request(&self, request: Self::ProtocolReq) -> Result<Self::ProtocolRsp, RelayError>;
}

/// The relay user specific backend interface
pub(crate) trait ProtocolBackend<DownloadUnitId, ProtocolUnitId, ProtocolUnit> {
    /// Returns all the protocol units for the given download unit
    fn download_unit_members(
        &self,
        id: &DownloadUnitId,
    ) -> Result<Vec<(ProtocolUnitId, ProtocolUnit)>, RelayError>;

    /// Returns the protocol unit for the given download/protocol unit
    fn protocol_unit(
        &self,
        download_unit_id: &DownloadUnitId,
        protocol_unit_id: &ProtocolUnitId,
    ) -> Result<Option<ProtocolUnit>, RelayError>;
}

/// Network interface helper
#[async_trait]
pub(crate) trait NetworkInterface: Send + Sync {
    /// Performs the request response and returns the result
    async fn request_response(
        &self,
        request: Vec<u8>,
    ) -> Result<Result<Vec<u8>, RequestFailure>, Canceled>;
}
