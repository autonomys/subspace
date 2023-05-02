//! Piece announcement request response protocol..
//!
//! Handle (i.e. answer) pieces announcement requests from a remote peer received via
//! `RequestResponsesBehaviour` with generic [`GenericRequestHandler`].

use crate::request_handlers::generic_request_handler::{GenericRequest, GenericRequestHandler};
use libp2p::Multiaddr;
use parity_scale_codec::{Decode, Encode};
use tracing::debug;

/// Piece announcement protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct PieceAnnouncementRequest {
    /// Request key - piece index multihash
    pub piece_key: Vec<u8>,

    /// External addresses of the peer
    pub addresses: Vec<Vec<u8>>,
}

impl PieceAnnouncementRequest {
    pub fn converted_addresses(&self) -> Vec<Multiaddr> {
        self
            .addresses
            .iter()
            .filter_map(|addr| {
                let converted_addr = Multiaddr::try_from(addr.clone());

                if let Err(err) = &converted_addr {
                    debug!(%err, "Failed to convert address from PieceAnnouncementRequest to Multiaddr.");
                }

                converted_addr.ok()
            })
            .collect()
    }
}

impl GenericRequest for PieceAnnouncementRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/piece-announcement/0.1.0";
    const LOG_TARGET: &'static str = "piece-announcement-request-response-handler";
    type Response = PieceAnnouncementResponse;
}

/// Piece announcement protocol response.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PieceAnnouncementResponse; // just an acknowledgement

//TODO: remove attribute on the first usage
#[allow(dead_code)]
/// Create a new piece announcement request handler.
pub type PieceAnnouncementRequestHandler = GenericRequestHandler<PieceAnnouncementRequest>;
