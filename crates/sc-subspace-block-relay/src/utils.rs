//! Common utils.

use crate::types::RequestResponseErr;
use futures::channel::oneshot;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{NetworkRequest, PeerId};
use std::collections::HashMap;
use std::sync::Arc;
use substrate_prometheus_endpoint::{
    register, Counter, CounterVec, Opts, PrometheusError, Registry, U64,
};

type NetworkRequestService = Arc<dyn NetworkRequest + Send + Sync + 'static>;

/// Wrapper to work around the circular dependency in substrate.
///
/// `build_network()` requires the block relay to be passed in, which internally needs the network
/// handle. `set()` is used to fill in the network after the network is created.
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
    ) -> Result<Response, RequestResponseErr>
    where
        Request: Encode,
        Response: Decode,
    {
        let (tx, rx) = oneshot::channel();
        self.network.start_request(
            self.who,
            self.protocol_name.clone(),
            request.encode(),
            None,
            tx,
            IfDisconnected::ImmediateError,
        );

        let (response_bytes, _protocol_name) = rx
            .await
            .map_err(|_cancelled| RequestResponseErr::Canceled)?
            .map_err(RequestResponseErr::RequestFailure)?;

        let response_len = response_bytes.len();
        Response::decode(&mut response_bytes.as_ref())
            .map_err(|err| RequestResponseErr::DecodeFailed { response_len, err })
    }
}

/// Convenience wrapper around prometheus counter, which can be optional.
pub(crate) struct RelayCounter(Option<Counter<U64>>);

impl RelayCounter {
    /// Creates the counter.
    pub(crate) fn new(
        name: &str,
        help: &str,
        registry: Option<&Registry>,
    ) -> Result<Self, PrometheusError> {
        let counter = if let Some(registry) = registry {
            Some(register(Counter::new(name, help)?, registry)?)
        } else {
            None
        };
        Ok(Self(counter))
    }

    /// Increments the counter.
    pub(crate) fn inc(&self) {
        if let Some(counter) = self.0.as_ref() {
            counter.inc()
        }
    }
}

/// Convenience wrapper around prometheus counter vec, which can be optional.
pub(crate) struct RelayCounterVec(Option<CounterVec<U64>>);

impl RelayCounterVec {
    /// Creates the counter vec.
    pub(crate) fn new(
        name: &str,
        help: &str,
        labels: &[&str],
        registry: Option<&Registry>,
    ) -> Result<Self, PrometheusError> {
        let counter_vec = if let Some(registry) = registry {
            Some(register(
                CounterVec::new(Opts::new(name, help), labels)?,
                registry,
            )?)
        } else {
            None
        };
        Ok(Self(counter_vec))
    }

    /// Increments the counter.
    pub(crate) fn inc(&self, label: &str, label_value: &str) {
        if let Some(counter) = self.0.as_ref() {
            let mut labels = HashMap::new();
            labels.insert(label, label_value);
            counter.with(&labels).inc()
        }
    }

    /// Increments the counter by specified value.
    pub(crate) fn inc_by(&self, label: &str, label_value: &str, v: u64) {
        if let Some(counter) = self.0.as_ref() {
            let mut labels = HashMap::new();
            labels.insert(label, label_value);
            counter.with(&labels).inc_by(v)
        }
    }
}
