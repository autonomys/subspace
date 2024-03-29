use crate::request_response::NoCodec;
use libp2p::request_response::{
    Behaviour as RequestResponse, Config as RequestResponseConfig, Event as RequestResponseEvent,
    ProtocolSupport,
};
use libp2p::swarm::NetworkBehaviour;
use libp2p::StreamProtocol;
use std::iter;
use std::time::Duration;

#[derive(Debug)]
pub(crate) enum Event {
    RequestResponse(RequestResponseEvent<Vec<u8>, Vec<u8>>),
}

impl From<RequestResponseEvent<Vec<u8>, Vec<u8>>> for Event {
    fn from(value: RequestResponseEvent<Vec<u8>, Vec<u8>>) -> Self {
        Self::RequestResponse(value)
    }
}

pub struct BehaviorConfig {
    pub request_response_protocol: &'static str,
    /// Maximum allowed size, in bytes, of a request.
    ///
    /// Any request larger than this value will be declined as a way to avoid allocating too
    /// much memory for it.
    pub max_request_size: u64,
    /// Maximum allowed size, in bytes, of a response.
    ///
    /// Any response larger than this value will be declined as a way to avoid allocating too
    /// much memory for it.
    pub max_response_size: u64,
    /// Timeout for inbound and outbound requests
    pub request_timeout: Duration,
    /// Upper bound for the number of concurrent inbound + outbound streams
    pub max_concurrent_streams: usize,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub(crate) struct Behavior {
    pub(crate) request_response: RequestResponse<NoCodec>,
}

impl Behavior {
    pub(crate) fn new(config: BehaviorConfig) -> Self {
        let request_response = RequestResponse::with_codec(
            NoCodec::new(config.max_request_size, config.max_response_size),
            iter::once((
                StreamProtocol::new(config.request_response_protocol),
                ProtocolSupport::Full,
            )),
            RequestResponseConfig::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(config.max_concurrent_streams),
        );

        Self { request_response }
    }
}
