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

use crate::utils::{NetworkPeerHandle, RelayError};
use async_trait::async_trait;
use codec::{Decode, Encode};

mod consensus;
mod protocol;
mod utils;

pub use crate::consensus::build_consensus_relay;
pub use crate::utils::NetworkWrapper;

pub(crate) const LOG_TARGET: &str = "block_relay";

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
pub(crate) trait ProtocolClient<DownloadUnitId, ProtocolUnitId, ProtocolUnit>
where
    Self: Send + Sync,
{
    type Request: Send + Sync + Encode + Decode + 'static;
    type Response: Send + Sync + Encode + Decode + 'static;

    /// Builds the protocol portion of the initial request
    fn build_initial_request(&self) -> Self::Request;

    /// Resolves the initial response to produce the protocol units.
    async fn resolve_initial_response<Request>(
        &self,
        response: Self::Response,
        network_peer_handle: &NetworkPeerHandle,
    ) -> Result<(DownloadUnitId, Vec<Resolved<ProtocolUnitId, ProtocolUnit>>), RelayError>
    where
        Request: From<Self::Request> + Encode + Send + Sync;
}

/// The server side of the relay protocol
pub(crate) trait ProtocolServer<DownloadUnitId> {
    type Request: Encode + Decode;
    type Response: Encode + Decode;

    /// Builds the protocol response to the initial request
    fn build_initial_response(
        &self,
        download_unit_id: &DownloadUnitId,
        initial_request: Self::Request,
    ) -> Result<Self::Response, RelayError>;

    /// Handles the additional client messages during the reconcile phase
    fn on_request(&self, request: Self::Request) -> Result<Self::Response, RelayError>;
}

/// The relay user specific backend for the client side.
pub(crate) trait ClientBackend<ProtocolUnitId, ProtocolUnit> {
    /// Returns the protocol unit for the protocol unit id.
    fn protocol_unit(&self, protocol_unit_id: &ProtocolUnitId) -> Option<ProtocolUnit>;
}

/// The relay user specific backend for the server side.
pub(crate) trait ServerBackend<DownloadUnitId, ProtocolUnitId, ProtocolUnit> {
    /// Returns the protocol units for the given download unit, to be returned
    /// with the initial response. Some of the items may have the full entry
    /// along with the Id (e.g) consensus may choose to return the full
    /// transaction for inherents/small transactions in the block. And return
    /// only the Tx hash for the remaining extrinsics. Further protocol
    /// handshake would be used only for resolving these remaining items.
    fn download_unit_members(
        &self,
        id: &DownloadUnitId,
    ) -> Result<Vec<ProtocolUnitInfo<ProtocolUnitId, ProtocolUnit>>, RelayError>;

    /// Returns the protocol unit for the given download/protocol unit.
    fn protocol_unit(
        &self,
        download_unit_id: &DownloadUnitId,
        protocol_unit_id: &ProtocolUnitId,
    ) -> Option<ProtocolUnit>;
}

/// The protocol unit info carried in the initial response
#[derive(Encode, Decode)]
struct ProtocolUnitInfo<ProtocolUnitId, ProtocolUnit> {
    /// The protocol unit Id
    id: ProtocolUnitId,

    /// The server can optionally return the protocol unit
    /// as part of the initial response. No further
    /// action is needed on client side to resolve it
    unit: Option<ProtocolUnit>,
}
