use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use async_trait::async_trait;
use hex_buffer_serde::{Hex, HexForm};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::Error;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use subspace_core_primitives::{Piece, Sha256Hash, PIECE_SIZE};
use subspace_solving::SubspaceCodec;

/// Same as [`Piece`], but serializes/deserialized to/from hex string
#[derive(Debug, Serialize, Deserialize)]
pub struct HexPiece(#[serde(with = "HexForm")] [u8; PIECE_SIZE]);

impl From<Piece> for HexPiece {
    fn from(piece: Piece) -> Self {
        HexPiece(piece.into())
    }
}

impl From<HexPiece> for Piece {
    fn from(piece: HexPiece) -> Self {
        piece.0.into()
    }
}

impl Deref for HexPiece {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HexPiece {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for HexPiece {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for HexPiece {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Similar to [`Sha256Hash`], but serializes/deserialized to/from hex string
#[derive(Debug, Serialize, Deserialize)]
pub struct HexSha256Hash(#[serde(with = "HexForm")] Sha256Hash);

impl From<Sha256Hash> for HexSha256Hash {
    fn from(hash: Sha256Hash) -> Self {
        HexSha256Hash(hash)
    }
}

impl From<HexSha256Hash> for Sha256Hash {
    fn from(piece: HexSha256Hash) -> Self {
        piece.0
    }
}

impl Deref for HexSha256Hash {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HexSha256Hash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for HexSha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for HexSha256Hash {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Object stored inside in the history of the blockchain
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Object {
    /// Piece index where object is contained (at least its beginning, might not fit fully)
    piece_index: u64,
    /// Offset of the object
    offset: u16,
    /// The data object contains for convenience
    #[serde(with = "HexForm")]
    data: Vec<u8>,
}

#[rpc(server, client)]
pub trait Rpc {
    /// Get single piece by its index
    #[method(name = "getPiece")]
    async fn get_piece(&self, piece_index: u64) -> Result<Option<HexPiece>, Error>;

    /// Find object by its ID
    #[method(name = "findObject")]
    async fn find_object(&self, object_id: HexSha256Hash) -> Result<Option<Object>, Error>;
}

/// Farmer RPC server implementation.
///
/// Usage example:
/// ```rust
/// # async fn f() -> anyhow::Result<()> {
/// use jsonrpsee::ws_server::WsServerBuilder;
/// use subspace_farmer::{Identity, ObjectMappings, Plot};
/// use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
/// use subspace_solving::SubspaceCodec;
///
/// let base_directory = "/path/to/base/dir";
/// let ws_server_listen_addr = "127.0.0.1:0";
///
/// let identity = Identity::open_or_create(base_directory)?;
/// let plot = Plot::open_or_create(base_directory).await?;
/// let object_mappings = ObjectMappings::open_or_create(base_directory)?;
/// let ws_server = WsServerBuilder::default().build(ws_server_listen_addr).await?;
/// let rpc_server = RpcServerImpl::new(plot, object_mappings, SubspaceCodec::new(&[0]));
/// let stop_handle = ws_server.start(rpc_server.into_rpc())?;
///
/// // Keep server running
///
/// Ok(())
/// # }
/// ```
pub struct RpcServerImpl {
    plot: Plot,
    object_mappings: ObjectMappings,
    subspace_codec: SubspaceCodec,
}

impl RpcServerImpl {
    pub fn new(plot: Plot, object_mappings: ObjectMappings, subspace_codec: SubspaceCodec) -> Self {
        Self {
            plot,
            object_mappings,
            subspace_codec,
        }
    }
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn get_piece(&self, piece_index: u64) -> Result<Option<HexPiece>, Error> {
        let mut piece = match self.plot.read(piece_index).await {
            Ok(encoding) => encoding,
            Err(error) => {
                debug!("Failed to find piece with index {}: {}", piece_index, error);

                return Ok(None);
            }
        };

        self.subspace_codec
            .decode(piece_index, &mut piece)
            .map_err(|error| {
                debug!(
                    "Failed to decode piece with index {}: {}",
                    piece_index, error
                );

                Error::Custom("Failed to decode piece".to_string())
            })?;

        Ok(Some(piece.into()))
    }

    /// Find object by its ID
    async fn find_object(&self, object_id: HexSha256Hash) -> Result<Option<Object>, Error> {
        let global_object_handle = tokio::task::spawn_blocking({
            let object_mappings = self.object_mappings.clone();

            move || object_mappings.retrieve(&object_id.into())
        });
        let global_object = global_object_handle
            .await
            .map_err(|error| {
                error!("Object mapping retrieving panicked: {}", error);

                Error::Custom("Failed to find an object due to internal error".to_string())
            })?
            .map_err(|error| {
                error!("Object mapping retrieving failed: {}", error);

                Error::Custom("Failed to find an object due to internal error".to_string())
            })?;

        let global_object = match global_object {
            Some(global_object) => global_object,
            None => {
                return Ok(None);
            }
        };

        let piece_index = global_object.piece_index();
        let offset = global_object.offset();

        let mut piece = self.plot.read(piece_index).await.map_err(|error| {
            debug!("Failed to read piece with index {}: {}", piece_index, error);

            Error::Custom("Object mapping found, but reading piece failed".to_string())
        })?;

        self.subspace_codec
            .decode(piece_index, &mut piece)
            .map_err(|error| {
                debug!(
                    "Failed to decode piece with index {}: {}",
                    piece_index, error
                );

                Error::Custom("Failed to decode piece".to_string())
            })?;

        Ok(Some(Object {
            piece_index,
            offset,
            // TODO: Just offset is not enough, need to read and handle length properly too
            data: piece[offset as usize..].to_vec(),
        }))
    }
}
