use crate::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};

/// Peer-info protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct PeerInfoRequest;

/// Defines peer synchronization status.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub enum PeerSyncStatus {
    /// Synchronization is not supported for this peer.
    NotSupported,
    /// Peer is ready to provide data for synchronization.
    Ready,
    /// Peer is synchronizing itself.
    Syncing,
}

/// Defines peer current state.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PeerInfo {
    /// Synchronization status.
    pub status: PeerSyncStatus,
}

impl GenericRequest for PeerInfoRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/sync/peer-info/0.1.0";
    const LOG_TARGET: &'static str = "peer-info-request-response-handler";
    type Response = PeerInfoResponse;
}

/// Peer-info protocol response.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PeerInfoResponse {
    /// Returned data.
    pub peer_info: PeerInfo,
}

/// Create a new peer-info request handler.
pub type PeerInfoRequestHandler = GenericRequestHandler<PeerInfoRequest>;
