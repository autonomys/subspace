//! Block relay implementation.

use async_trait::async_trait;
use codec::{Decode, Encode};
use libp2p::PeerId;
use sc_network::request_responses::IncomingRequest;
use sc_network_sync::service::network::NetworkServiceHandle;

mod consensus;
mod protocol;

/// Nodes advertise/exchange DownloadUnits with each other. DownloadUnit has
/// two parts:
/// 1. ProtocolUnits: the part fetched by the relay protocol
/// 2. Rest of the downloaded data
///
/// Examples:
/// - In the context of consensus gossip:
///   DownloadUnit = Block, ProtocolUnits = the transaction body/extrinsics
///   in the block
/// - In the context of execution, it would be something similar
/// - Other possible use case: sync of the transaction pool between nodes:
///   DownloadUnit = the complete transaction pool, ProtocolUnits are the
///   transactions
///
/// The relay protocols have roughly two phases:
/// 1. Initial request/response
///    Ideally, download of all the protocol units in the download unit should
///    be completed during this phase
/// 2. Reconcile phase
///    If the initial phase could not complete the download, the additional
///    request/response messages are exchanged to fetch the protocol units
///
/// The overall components:
/// 1. RelayClient: client side stub that initiates/manages the download
/// 2. RelayServer: server side task that handles the incoming download
///    requests and protocol messages
/// 3. ProtocolClient: client side processing of the relay protocol,
///    used by the RelayClient. It generate the initial request and
///    manages the reconcile protocol
/// 4. ProtocolServer: server side processing of the relay protocol,
///    used by the RelayServer. It handles the initial request and the
///    additional messages
///

pub(crate) const LOG_TARGET: &str = "block_relay";

/// The client to server message
#[derive(Encode, Decode)]
pub(crate) enum RelayServerMessage<T: Encode + Decode> {
    /// The initial request
    InitialRequest(T),

    /// The additional protocol specific messages
    ProtocolRequest(Vec<u8>),
}

type ProtocolInitialRequest = Option<Vec<u8>>;

/// The relay client stub
pub trait RelayClient {
    type Request;

    /// Fetches the download units from the peer
    fn download(&self, who: PeerId, request: &Self::Request, network: NetworkServiceHandle);
}

/// The client side of the protocol used by RelayClient
#[async_trait]
pub trait ProtocolClient<DownloadUnitId>
where
    DownloadUnitId: Encode + Decode,
{
    /// Builds the protocol portion of the initial request
    fn build_request(&self) -> ProtocolInitialRequest;

    /// Resolve the initial response to produce the protocol units.
    async fn resolve(&self) -> Vec<u8>;
}

/// The relay server
#[async_trait]
pub trait RelayServer {
    async fn on_request(&mut self, request: IncomingRequest);
}

/// The server side of the protocol used by RelayServer
pub trait ProtocolServer<DownloadUnitId>
where
    DownloadUnitId: Encode + Decode,
{
    /// Builds the protocol response for the request from the protocol client.
    fn build_response(
        &self,
        id: &DownloadUnitId,
        protocol_request: ProtocolInitialRequest,
    ) -> Result<Vec<u8>, RelayError>;

    /// Handles the additional client messages during the reconcile phase.
    fn on_message(&self);
}

/// The pool backend used by the protocol client/server sides.
pub trait PoolBackend<DownloadUnitId, ProtocolUnitId>
where
    DownloadUnitId: Encode + Decode,
    ProtocolUnitId: Encode + Decode,
{
    /// Returns all the protocol units for the given download unit.
    fn download_unit_members(
        &self,
        id: &DownloadUnitId,
    ) -> Result<Vec<(ProtocolUnitId, Vec<u8>)>, String>;

    /// Returns the protocol unit contents with the given Id.
    fn protocol_unit(&self, id: &ProtocolUnitId) -> Option<Vec<u8>>;
}

/// Errors returned by the server side.
#[derive(Encode, Decode)]
pub enum RelayError {
    /// Failed to decode the incoming request
    InvalidIncomingRequest(String),

    /// Invalid block hash in the block request
    InvalidBlockHash(String),
}
