//! Common utils.

use codec::{Decode, Encode, Input};
use futures::channel::oneshot;
use parking_lot::Mutex;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{NetworkRequest, PeerId, RequestFailure};
use sc_network_common::sync::message::BlockData;
use sp_runtime::traits::Block as BlockT;
use std::num::NonZeroUsize;
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

    /// Performs the request, returns the received bytes.
    pub(crate) async fn request_raw<Request>(
        &self,
        request: Request,
    ) -> Result<Vec<u8>, RequestResponseErr>
    where
        Request: Encode,
    {
        let (tx, rx) = oneshot::channel();
        self.network.start_request(
            self.who,
            self.protocol_name.clone(),
            request.encode(),
            tx,
            IfDisconnected::ImmediateError,
        );

        let response_bytes = rx
            .await
            .map_err(|_cancelled| RequestResponseErr::Canceled)?
            .map_err(RequestResponseErr::RequestFailure)?;

        Ok(response_bytes)
    }

    /// Performs the request, decodes the received bytes as
    /// into `Response` type.
    pub(crate) async fn request<Request, Response>(
        &self,
        request: Request,
    ) -> Result<Response, RequestResponseErr>
    where
        Request: Encode,
        Response: Decode,
    {
        let response_bytes = self.request_raw(request).await?;
        let response_len = response_bytes.len();
        Response::decode(&mut response_bytes.as_ref())
            .map_err(|err| RequestResponseErr::DecodeFailed { response_len, err })
    }
}

/// We want to be able to encode a Vec<Block> so that the total encoded size
/// doesn't exceed a max limit. The BlockEncoder/BlockDecoder wrappers
/// achieve this without repeated encoded_size() computation as the Vec<>
/// grows, and avoid expensive rollback of the last entry when the limit is
/// reached. Blocks are incrementally encoded/appended to the output, until
/// the limit is reached.
///
/// The encoding scheme is a simple prefix followed by the encoded entries:
///  Num entries ([u8; 4], big endian), Block_0 encoding, Block_1 encoding,...
type BlockDataPrefix = [u8; 4];

/// Incrementally encodes the block data until byte limit is reached, without having
/// to do any expensive rollback when the limit is reached.
pub(crate) struct BlockEncoder {
    /// Number of blocks accumulated so far.
    num_blocks: u32,

    /// Encoded blocks accumulated so far.
    block_data: Vec<u8>,

    /// Maximum allowed encoded data size.
    max_bytes: NonZeroUsize,
}

impl BlockEncoder {
    /// Creates the block encoder.
    pub(crate) fn new(max_bytes: NonZeroUsize) -> Self {
        Self {
            num_blocks: 0,
            block_data: Vec::new(),
            max_bytes,
        }
    }

    /// Adds the block to the serialized data, if the byte limit
    /// allows. Returns true if it could be appended, false otherwise.
    pub(crate) fn append<Block: BlockT>(&mut self, block: BlockData<Block>) -> bool {
        let mut block = block.encode();
        let new_len = std::mem::size_of::<BlockDataPrefix>() + self.block_data.len() + block.len();
        if self.num_blocks == 0 || new_len <= self.max_bytes.into() {
            self.block_data.append(&mut block);
            self.num_blocks += 1;
            true
        } else {
            false
        }
    }

    /// Returns the number of blocks.
    pub(crate) fn num_blocks(&self) -> u32 {
        self.num_blocks
    }

    /// Returns the encoded bytes.
    pub(crate) fn encode(mut self) -> Vec<u8> {
        let prefix: BlockDataPrefix = self.num_blocks.to_be_bytes();
        let mut encoded = prefix.to_vec();
        encoded.append(&mut self.block_data);
        encoded
    }
}

/// Decodes the block data.
pub(crate) struct BlockDecoder(Vec<u8>);

impl BlockDecoder {
    /// Creates the decoder.
    pub(crate) fn new(encoded: Vec<u8>) -> Self {
        Self(encoded)
    }

    /// Returns the decoded blocks.
    pub(crate) fn decode<Block: BlockT>(self) -> Result<Vec<BlockData<Block>>, RelayError> {
        let mut input = Box::new(self.0.as_slice());
        Self::decode_blocks::<_, Block>(input.as_mut())
    }

    /// Helper to decode.
    fn decode_blocks<I: Input, Block: BlockT>(
        input: &mut I,
    ) -> Result<Vec<BlockData<Block>>, RelayError> {
        let encoded_len = input.remaining_len();

        let mut prefix_bytes: BlockDataPrefix = [0; 4];
        input
            .read(&mut prefix_bytes)
            .map_err(|err| RelayError::BlockPrefixDecode {
                encoded_len: encoded_len.clone(),
                err,
            })?;
        let num_blocks = u32::from_be_bytes(prefix_bytes);

        let mut blocks = Vec::new();
        for i in 0..num_blocks {
            let block_data: BlockData<Block> =
                Decode::decode(input).map_err(|err| RelayError::BlockDecode {
                    encoded_len: encoded_len.clone(),
                    num_blocks,
                    failed_block: i,
                    err,
                })?;
            blocks.push(block_data)
        }
        Ok(blocks)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestResponseErr {
    #[error("RequestResponseErr::DecodeFailed: {response_len}/{err:?}")]
    DecodeFailed {
        response_len: usize,
        err: codec::Error,
    },

    #[error("RequestResponseErr::RequestFailure {0:?}")]
    RequestFailure(RequestFailure),

    #[error("Network not initialized")]
    NetworkUninitialized,

    #[error("RequestResponseErr::Canceled")]
    Canceled,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RelayError {
    #[error("Block header: {0}")]
    BlockHeader(String),

    #[error("Block indexed body: {0}")]
    BlockIndexedBody(String),

    #[error("Block justifications: {0}")]
    BlockJustifications(String),

    #[error("Block hash: {0}")]
    BlockHash(String),

    #[error("Block body: {0}")]
    BlockBody(String),

    #[error("Block extrinsics not found: {0}")]
    BlockExtrinsicsNotFound(String),

    #[error("Unexpected number of resolved entries: {expected}, {actual}")]
    ResolveMismatch { expected: usize, actual: usize },

    #[error("Resolved entry not found: {0}")]
    ResolvedNotFound(usize),

    #[error("Unexpected initial request")]
    UnexpectedInitialRequest,

    #[error("Unexpected initial response")]
    UnexpectedInitialResponse,

    #[error("Unexpected protocol request")]
    UnexpectedProtocolRequest,

    #[error("Unexpected protocol response")]
    UnexpectedProtocolRespone,

    #[error("Request/response error: {0}")]
    RequestResponse(#[from] RequestResponseErr),

    #[error("Block prefix decode failed: {encoded_len:?}/{err}")]
    BlockPrefixDecode {
        encoded_len: Result<Option<usize>, codec::Error>,
        err: codec::Error,
    },

    #[error("Block decode failed: {encoded_len:?}/{num_blocks}/{failed_block}/{err}")]
    BlockDecode {
        encoded_len: Result<Option<usize>, codec::Error>,
        num_blocks: u32,
        failed_block: u32,
        err: codec::Error,
    },
}
