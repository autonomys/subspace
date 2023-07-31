//! Piece announcement request response protocol..
//!
//! Handle (i.e. answer) pieces announcement requests from a remote peer received via
//! `RequestResponsesBehaviour` with generic [`GenericRequestHandler`].

use crate::request_handlers::generic_request_handler::{GenericRequest, GenericRequestHandler};
use crate::utils::multihash::Multihash;
use libp2p::Multiaddr;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

/// Piece announcement protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PieceAnnouncementRequest {
    /// Request key - piece index multihash
    pub piece_index_hash: Multihash,

    /// External addresses of the peer
    pub addresses: Vec<Multiaddr>,
}

impl Encode for PieceAnnouncementRequest {
    fn size_hint(&self) -> usize {
        self.piece_index_hash.size() as usize
            + self
                .addresses
                .iter()
                .fold(0usize, |sum, item| sum + item.len())
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.piece_index_hash.to_bytes().encode_to(dest);
        for addr in &self.addresses {
            addr.to_vec().encode_to(dest);
        }
    }
}

impl Decode for PieceAnnouncementRequest {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let piece_index_hash = match Vec::decode(input) {
            Ok(bytes) => Multihash::from_bytes(&bytes).map_err(|_| {
                "Could not decode `PieceAnnouncementRequest.piece_index_hash`. Invalid multihash."
            })?,
            Err(error) => {
                return Err(
                    error.chain("Could not decode `PieceAnnouncementRequest.piece_index_hash`")
                );
            }
        };

        let mut addresses = Vec::new();
        loop {
            match input.remaining_len()? {
                Some(0) => {
                    break;
                }
                Some(_) => {
                    // Processing continues below
                }
                None => {
                    return Err(
                        "PieceAnnouncementRequest: Source doesn't report remaining length".into(),
                    );
                }
            }

            match Vec::decode(input) {
                Ok(bytes) => {
                    let addr = Multiaddr::try_from(bytes).map_err(|_| {
                        "Could not decode `PieceAnnouncementRequest.addresses`. Invalid multiaddr."
                    })?;

                    addresses.push(addr);
                }
                Err(error) => {
                    return Err(
                        error.chain("Could not decode `PieceAnnouncementRequest.addresses`")
                    );
                }
            }
        }

        Ok(PieceAnnouncementRequest {
            piece_index_hash,
            addresses,
        })
    }
}

impl GenericRequest for PieceAnnouncementRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/piece-announcement/0.1.0";
    const LOG_TARGET: &'static str = "piece-announcement-request-response-handler";
    type Response = PieceAnnouncementResponse;
}

/// Piece announcement protocol response.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub enum PieceAnnouncementResponse {
    /// Request acknowledgement
    Success,
}

/// Create a new piece announcement request handler.
pub type PieceAnnouncementRequestHandler = GenericRequestHandler<PieceAnnouncementRequest>;

#[cfg(test)]
mod test {
    use crate::PieceAnnouncementRequest;
    use libp2p::PeerId;
    use parity_scale_codec::{Decode, Encode};

    #[test]
    fn piece_announcement_request_encoding_works_as_expected() {
        let default = PieceAnnouncementRequest::default();
        let bytes = default.encode();
        let decoded_default_request: PieceAnnouncementRequest =
            Decode::decode(&mut bytes.as_slice()).unwrap();

        assert_eq!(default, decoded_default_request);

        let request = PieceAnnouncementRequest {
            piece_index_hash: PeerId::random().into(),
            addresses: vec![
                "/memory/0".parse().unwrap(),
                "/ip4/127.0.0.1/tcp/50000/p2p/12D3KooWGAjyJAZNNsHu8sV6MP6mXHzNXFQbadjVBFUr5deTiom2"
                    .parse()
                    .unwrap(),
            ],
        };
        let bytes = request.encode();
        let decoded_request: PieceAnnouncementRequest =
            Decode::decode(&mut bytes.as_slice()).unwrap();

        assert_eq!(request, decoded_request);
    }
}
