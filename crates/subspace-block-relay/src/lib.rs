//! Block relay implementation.

use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::channel::oneshot;
use sc_network::request_responses::IncomingRequest;
use sc_network::{PeerId, RequestFailure};
use sc_network_sync::service::network::NetworkServiceHandle;

mod consensus;
mod protocol;
mod utils;

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

pub(crate) type RelayError = String;

/// The relay client stub
#[async_trait]
pub trait RelayClient {
    type Request;

    /// Fetches the download units from the peer
    async fn download(
        &self,
        who: PeerId,
        request: &Self::Request,
        network: NetworkServiceHandle,
    ) -> Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled>;
}

/// The relay server
#[async_trait]
pub trait RelayServer {
    async fn on_request(&mut self, request: IncomingRequest);
}
