//! Block relay implementation.

use async_trait::async_trait;
use codec::{Decode, Encode};
use libp2p::PeerId;
use sc_network_sync::service::network::NetworkServiceHandle;

mod consensus;

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

/// The messages exchanged between the relay client/server.
#[derive(Encode, Decode)]
pub(crate) enum RelayServerMessage<T: Encode + Decode> {
    /// The initial request
    InitialRequest(T),

    /// The additional protocol specific messages
    ProtocolRequest(Vec<u8>),
}

/// The client stub.
pub trait RelayClient {
    type Request;

    /// Fetches the download unit from the peer.
    fn download(&self, who: PeerId, request: &Self::Request, network: NetworkServiceHandle);
}

/// The relay server.
#[async_trait]
pub trait RelayServer {
    async fn on_message(&mut self);
}

/// The client side of the protocol.
#[async_trait]
pub trait ProtocolClient<DownloadUnitId>
where
    DownloadUnitId: Encode + Decode,
{
    /// Builds the initial request to be sent to the server side. This
    /// would be bundled by the caller with the overall request sent out.
    fn build_request(&self, download_unit: &DownloadUnitId) -> Vec<u8>;

    /// Resolve the initial response to produce the protocol units.
    async fn resolve(&self) -> Vec<u8>;
}

/// The server side of the protocol.
pub trait ProtocolServer {
    /// Builds the protocol response for the request from the protocol client.
    fn build_response(&self, protocol_request: Vec<u8>) -> Vec<u8>;

    /// Handles the additional client messages during the reconcile phase.
    fn on_message(&self);
}
