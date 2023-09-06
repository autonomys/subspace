//! Consensus related type definitions.

use crate::types::{RelayError, RelayVersion, VersionEncodable};
use codec::{Decode, Encode, Input};
use sc_network_common::sync::message::{BlockAttributes, BlockData, BlockRequest};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_runtime::Justifications;

pub(crate) type BlockHash<Block> = <Block as BlockT>::Hash;
pub(crate) type BlockHeader<Block> = <Block as BlockT>::Header;
pub(crate) type Extrinsic<Block> = <Block as BlockT>::Extrinsic;

/// Initial request for a single block.
#[derive(Encode, Decode)]
pub(crate) struct InitialRequest<Block: BlockT, ProtocolRequest> {
    /// Starting block
    pub(crate) from_block: BlockId<Block>,

    /// Requested block components
    pub(crate) block_attributes: BlockAttributes,

    /// The protocol specific part of the request
    pub(crate) protocol_request: ProtocolRequest,
}

/// The block details in the InitialResponse
#[derive(Encode, Decode)]
pub(crate) enum BlockResponse<Block: BlockT, ProtocolResponse> {
    /// Needs further protocol handshake to resolve the extrinsics.
    /// This is the normal path. This has:
    /// - The partial block, without the extrinsics.
    /// - The opaque protocol specific part of the response.
    ///   This is optional because BlockAttributes::BODY may not be set in
    ///   the BlockRequest, in which case we don't need to fetch the
    ///   extrinsics.
    Partial(PartialBlock<Block>, Option<ProtocolResponse>),

    /// Server returned the full block (e.g) version mismatch during
    /// protocol upgrade. No further need for protocol resolution.
    Complete(BlockData<Block>),
}

/// Initial response for a single block.
#[derive(Encode, Decode)]
pub(crate) struct InitialResponse<Block: BlockT, ProtocolResponse> {
    ///  Hash of the block being downloaded
    pub(crate) block_hash: BlockHash<Block>,

    /// The block details.
    pub(crate) response: BlockResponse<Block, ProtocolResponse>,
}

/// Request to download multiple/complete blocks, for scenarios like the
/// sync phase. This does not involve the protocol optimizations, as the
/// requesting node is just coming up and may not have the transactions
/// in its pool. So it does not make sense to send response with tx hash,
/// and the full blocks are sent back. This behaves like the default
/// substrate block downloader.
#[derive(Encode, Decode)]
pub(crate) struct FullDownloadRequest<Block: BlockT>(pub(crate) BlockRequest<Block>);

/// Response to the full download request.
#[derive(Encode, Decode)]
pub(crate) struct FullDownloadResponse<Block: BlockT>(pub(crate) Vec<BlockData<Block>>);

/// The message to the server
#[allow(clippy::enum_variant_names)]
#[derive(Encode, Decode)]
pub(crate) enum ServerMessage<Block: BlockT, ProtocolRequest: Encode> {
    /// Initial message, to be handled both by the client
    /// and the protocol
    InitialRequest(InitialRequest<Block, ProtocolRequest>),

    /// Message to be handled by the protocol
    ProtocolRequest(ProtocolRequest),

    /// Full download request.
    FullDownloadRequest(FullDownloadRequest<Block>),
}

impl<Block: BlockT, ProtocolRequest: Encode> From<ProtocolRequest>
    for ServerMessage<Block, ProtocolRequest>
{
    fn from(inner: ProtocolRequest) -> ServerMessage<Block, ProtocolRequest> {
        ServerMessage::ProtocolRequest(inner)
    }
}

/// `ServerMessage` is translated/encoded into two parts when it is sent
/// on the wire:
/// Prefix: client version + any version independent info. This is composed
/// of basic types like u32, usize. Data types like enum should not be
/// included which can fail to decode across versions.
/// Body: version dependent suffix
///
/// The server first decodes the prefix.
/// - If the client version in the prefix matches the server version,
/// it proceeds to decode the body and perform regular processing.
/// - If version mismatch, it takes necessary action to handle the
/// mismatch. The body is not decoded in this case. Otherwise, the
/// decoding of the version specific part may fail as they are from
/// different versions. And we won't be able to differentiate version
/// mismatch vs a garbled message. We want to be able to handle
/// the former gracefully, during scenarios like protocol upgrade.
///

/// Message prefix.
#[allow(clippy::enum_variant_names)]
#[derive(Encode, Decode)]
pub(crate) enum MessagePrefix<Block: BlockT> {
    /// Initial message, to be handled both by the client
    /// and the protocol
    InitialRequest(RelayVersion, BlockId<Block>, BlockAttributes),

    /// Message to be handled by the protocol
    ProtocolRequest(RelayVersion),

    /// Full download request.
    FullDownloadRequest(BlockRequest<Block>),
}

/// Message body.
#[allow(clippy::enum_variant_names)]
#[derive(Encode, Decode)]
pub(crate) enum MessageBody<ProtocolRequest>
where
    ProtocolRequest: Encode + Decode,
{
    /// Initial message, to be handled both by the client
    /// and the protocol
    InitialRequest(ProtocolRequest),

    /// Message to be handled by the protocol
    ProtocolRequest(ProtocolRequest),

    /// Full download request. No body, as this is protocol independent
    FullDownloadRequest,
}

impl<Block: BlockT, ProtocolRequest> VersionEncodable for ServerMessage<Block, ProtocolRequest>
where
    Block: BlockT,
    ProtocolRequest: Encode + Decode,
{
    fn encode(self, version: &RelayVersion) -> Vec<u8> {
        let (prefix, body) = match self {
            ServerMessage::InitialRequest(req) => (
                MessagePrefix::InitialRequest(*version, req.from_block, req.block_attributes),
                MessageBody::InitialRequest(req.protocol_request),
            ),
            ServerMessage::ProtocolRequest(req) => (
                MessagePrefix::ProtocolRequest(*version),
                MessageBody::ProtocolRequest(req),
            ),
            ServerMessage::FullDownloadRequest(req) => (
                MessagePrefix::FullDownloadRequest(req.0),
                MessageBody::FullDownloadRequest,
            ),
        };

        // Send the prefix followed by the body.
        let mut encoded = Vec::new();
        prefix.encode_to(&mut encoded);
        body.encode_to(&mut encoded);
        encoded
    }
}

/// Decoder on the server side.
pub(crate) struct ServerMessageDecoder<I: Input> {
    input: I,
}

impl<I: Input> ServerMessageDecoder<I> {
    /// Creates the decoder.
    pub(crate) fn new(input: I) -> Self {
        Self { input }
    }

    /// Decodes the message prefix.
    pub(crate) fn prefix<Block: BlockT>(&mut self) -> Result<MessagePrefix<Block>, RelayError> {
        Decode::decode(&mut self.input).map_err(RelayError::DecodeFailed)
    }

    /// Decodes the message body.
    pub(crate) fn body<ProtocolRequest: Encode + Decode>(
        &mut self,
    ) -> Result<MessageBody<ProtocolRequest>, RelayError> {
        Decode::decode(&mut self.input).map_err(RelayError::DecodeFailed)
    }
}

/// The partial block response from the server. It has all the fields
/// except the extrinsics(and some other meta info). The extrinsics
/// are handled by the protocol.
#[derive(Encode, Decode)]
pub(crate) struct PartialBlock<Block: BlockT> {
    pub(crate) parent_hash: BlockHash<Block>,
    pub(crate) block_number: NumberFor<Block>,
    pub(crate) block_header_hash: BlockHash<Block>,
    pub(crate) header: Option<BlockHeader<Block>>,
    pub(crate) indexed_body: Option<Vec<Vec<u8>>>,
    pub(crate) justifications: Option<Justifications>,
}

impl<Block: BlockT> PartialBlock<Block> {
    /// Builds the full block data.
    pub(crate) fn block_data(self, body: Option<Vec<Extrinsic<Block>>>) -> BlockData<Block> {
        BlockData::<Block> {
            hash: self.block_header_hash,
            header: self.header,
            body,
            indexed_body: self.indexed_body,
            receipt: None,
            message_queue: None,
            justification: None,
            justifications: self.justifications,
        }
    }
}
