//! Block relay implementation.

use async_trait::async_trait;

/// Nodes advertise/exchange DownloadUnits with each other. DownloadUnit has
/// two parts:
/// 1. ProtocolSet: the part fetched by the relay protocol. This is made of
///    ProtocolUnits
/// 2. Rest of the downloaded data
///
/// Examples:
/// - In the context of consensus gossip:
///   DownloadUnit = Block, ProtocolSet = the transaction body in the block,
///   ProtocolUnit = transaction/extrinscic
/// - In the context of execution, it would be something similar
/// - Other possible use case: sync of the transaction pool between nodes:
///   DownloadUnit/ProtocolSet = transaction pool, ProtocolUnit = transaction
///
/// The relay protocols have roughly two phases:
/// 1. Initial request/response
///    Ideally, the protocol set download should be completed during this
///    phase
/// 2. Reconcile phase
///    If the initial phase could not complete the download, the additional
///    request/response messages are exchanged to fetch the protocol set
///
/// The overall components:
/// 1. RelayClient: client side stub that initiates/manages the download
/// 2. RelayServer: server side task that handles the incoming download
///    requests and protocol messages
/// 3. RelayProtocolClient: client side processing of the relay protocol,
///    used by the RelayClient. It generate the initial request and
///    manages the reconcile protocol
/// 4. RelayProtocolServer: server side processing of the relay protocol,
///    used by the RelayServer. It handles the initial request and the
///    additional messages
///

/// The client side of the protocol.
#[async_trait]
pub trait RelayProtocolClient {
    /// Builds the initial request to be sent to the server side. This
    /// would be bundled by the caller with the overall request sent out.
    fn build_request() -> Vec<u8>;

    /// Resolve the initial response to produce the download unit.
    async fn resolve() -> Vec<u8>;
}

/// The server side of the protocol.
pub trait RelayProtocolServer {
    /// Builds the initial response for the client request.
    fn build_response() -> Vec<u8>;

    /// Handles the additional client messages during the reconcile phase.
    fn on_message();
}
