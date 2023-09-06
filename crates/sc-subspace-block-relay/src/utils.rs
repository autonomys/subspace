//! Common utils.

use crate::types::{RelayVersion, RequestResponseErr, VersionEncodable};
use codec::Decode;
use futures::channel::oneshot;
use parking_lot::Mutex;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{NetworkRequest, PeerId};
use std::sync::Arc;

type NetworkRequestService = Arc<dyn NetworkRequest + Send + Sync + 'static>;

/// Wrapper to work around the circular dependency in substrate:
/// `build_network()` requires the block relay to be passed in,
/// which internally needs the network handle. `set()` is
/// used to fill in the network after the network is created.
pub struct NetworkWrapper {
    network: Mutex<Option<NetworkRequestService>>,
}

impl Default for NetworkWrapper {
    fn default() -> Self {
        Self {
            network: Mutex::new(None),
        }
    }
}

impl NetworkWrapper {
    pub fn set(&self, network: NetworkRequestService) {
        *self.network.lock() = Some(network);
    }

    pub(crate) fn network_peer_handle(
        &self,
        protocol_name: ProtocolName,
        who: PeerId,
    ) -> Result<NetworkPeerHandle, RequestResponseErr> {
        match self.network.lock().as_ref().cloned() {
            Some(network) => Ok(NetworkPeerHandle::new(protocol_name, who, network)),
            None => Err(RequestResponseErr::NetworkUninitialized),
        }
    }
}

/// Network handle that allows making requests to specific peer and protocol.
/// `Request` is the format of the request message sent on the wire.
#[derive(Clone)]
pub(crate) struct NetworkPeerHandle {
    protocol_name: ProtocolName,
    who: PeerId,
    network: NetworkRequestService,
}

impl NetworkPeerHandle {
    fn new(protocol_name: ProtocolName, who: PeerId, network: NetworkRequestService) -> Self {
        Self {
            protocol_name,
            who,
            network,
        }
    }

    /// Performs the request
    pub(crate) async fn request<Request, Response>(
        &self,
        request: Request,
        client_version: RelayVersion,
    ) -> Result<Response, RequestResponseErr>
    where
        Request: VersionEncodable,
        Response: Decode,
    {
        let (tx, rx) = oneshot::channel();
        self.network.start_request(
            self.who,
            self.protocol_name.clone(),
            request.encode(&client_version),
            tx,
            IfDisconnected::ImmediateError,
        );

        let response_bytes = rx
            .await
            .map_err(|_cancelled| RequestResponseErr::Canceled)?
            .map_err(RequestResponseErr::RequestFailure)?;

        let response_len = response_bytes.len();
        Response::decode(&mut response_bytes.as_ref())
            .map_err(|err| RequestResponseErr::DecodeFailed { response_len, err })
    }
}
