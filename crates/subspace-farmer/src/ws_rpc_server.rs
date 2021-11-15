use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use async_trait::async_trait;
use hex_buffer_serde::{Hex, HexForm};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::Error;
use log::{debug, error};
use parity_scale_codec::{Compact, Decode};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use subspace_core_primitives::{Piece, Sha256Hash, PIECE_SIZE};
use subspace_solving::SubspaceCodec;

/// Same as [`Piece`], but serializes/deserialized to/from hex string
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
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
/// let rpc_server = RpcServerImpl::new(
///     3840,
///     3480 * 128,
///     plot,
///     object_mappings,
///     SubspaceCodec::new(&[0]),
/// );
/// let stop_handle = ws_server.start(rpc_server.into_rpc())?;
///
/// # Ok(())
/// # }
/// ```
pub struct RpcServerImpl {
    record_size: u32,
    merkle_num_leaves: u32,
    plot: Plot,
    object_mappings: ObjectMappings,
    subspace_codec: SubspaceCodec,
}

impl RpcServerImpl {
    pub fn new(
        record_size: u32,
        recorded_history_segment_size: u32,
        plot: Plot,
        object_mappings: ObjectMappings,
        subspace_codec: SubspaceCodec,
    ) -> Self {
        Self {
            record_size,
            merkle_num_leaves: recorded_history_segment_size / (record_size * 2),
            plot,
            object_mappings,
            subspace_codec,
        }
    }

    async fn assemble_object(&self, piece_index: u64, offset: u16) -> Result<Vec<u8>, Error> {
        // Try fast object assembling
        if let Some(data) = self.assemble_object_fast(piece_index, offset).await? {
            return Ok(data);
        }

        // TODO: Regular object retrieval

        todo!()
    }

    /// Fast object assembling in case object doesn't cross piece (super fast) or segment (just
    /// fast) boundary, returns `Ok(None)` if fast retrieval possibility is not guaranteed.
    async fn assemble_object_fast(
        &self,
        piece_index: u64,
        offset: u16,
    ) -> Result<Option<Vec<u8>>, Error> {
        // We care if the offset is before the last 2 bytes of a piece because if not we might be
        // able to do very fast object retrieval without assembling and processing the whole
        // segment. Last 2 bytes is because those 2 bytes might contain padding if a piece is the
        // last piece in the segment.
        let before_last_two_bytes = u32::from(offset) <= self.record_size - 1 - 2;

        // We care about whether piece index points to the last data piece in the segment because
        // if not we might be able to do very fast object retrieval without assembling and
        // processing the whole segment.
        let last_data_piece_in_segment = {
            let piece_position_in_segment = piece_index % u64::from(self.merkle_num_leaves);
            let last_piece_position_in_segment = u64::from(self.merkle_num_leaves) / 2 - 1;

            piece_position_in_segment >= last_piece_position_in_segment
        };

        // How much bytes are definitely available starting at `piece_index` and `offset` without
        // crossing segment boundary
        let bytes_available_in_segment = (u64::from(self.merkle_num_leaves)
            - piece_index % u64::from(self.merkle_num_leaves))
            * self.record_size as u64
            - offset as u64
            - 2;

        if last_data_piece_in_segment && !before_last_two_bytes {
            // Fast retrieval possibility is not guaranteed
            return Ok(None);
        }

        // Cache of read pieces that were already read, starting with piece at index `piece_index`
        let mut read_records_data = Vec::<u8>::new();
        let mut next_piece_index = piece_index;

        let piece = self.read_and_decode_piece(next_piece_index).await?;
        next_piece_index += 1;
        read_records_data.extend_from_slice(&piece[..self.record_size as usize]);

        // Let's see how many bytes encode compact length encoding of the data, see
        // https://docs.substrate.io/v3/advanced/scale-codec/#compactgeneral-integers for
        // details.
        let data_length_bytes_length: u32 = match read_records_data[offset as usize] % 4 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => {
                let error_string = format!(
                    "Invalid data length prefix found: 0x{:02x}",
                    read_records_data[offset as usize]
                );
                error!("{}", error_string);

                return Err(Error::Custom(error_string));
            }
        };

        // Same as `before_last_two_bytes`, but accounts for compact encoding of data length
        let length_before_last_two_bytes =
            u32::from(offset) + data_length_bytes_length < self.record_size - 1 - 2;
        // Similar to `length_before_last_two_bytes`, but uses the whole recordif needed
        let length_before_record_end =
            u32::from(offset) + data_length_bytes_length < self.record_size - 1;

        let data_length_result = if length_before_last_two_bytes {
            Compact::<u32>::decode(&mut &read_records_data[offset as usize..])
        } else if !last_data_piece_in_segment {
            if !length_before_record_end {
                // Need the next piece to read the length of data
                let piece = self.read_and_decode_piece(next_piece_index).await?;
                next_piece_index += 1;
                read_records_data.extend_from_slice(&piece[..self.record_size as usize]);
            }

            Compact::<u32>::decode(&mut &read_records_data[offset as usize..])
        } else {
            // Super fast read is not possible
            return Ok(None);
        };

        let Compact(data_length) = data_length_result.map_err(|error| {
            let error_string = format!("Failed to read object data length: {}", error);
            error!("{}", error_string);

            Error::Custom(error_string)
        })?;

        if (data_length_bytes_length + data_length) as u64 > bytes_available_in_segment {
            // Not enough data without crossing segment boundary
            return Ok(None);
        }

        let mut data =
            read_records_data[offset as usize + data_length_bytes_length as usize..].to_vec();
        drop(read_records_data);

        // Read more pieces until we have enough data
        while data.len() < data_length as usize {
            let piece = self.read_and_decode_piece(next_piece_index).await?;
            next_piece_index += 1;
            data.extend_from_slice(&piece[..self.record_size as usize]);
        }

        // Trim the excess
        data.truncate(data_length as usize);

        Ok(Some(data))
    }

    async fn read_and_decode_piece(&self, piece_index: u64) -> Result<Piece, Error> {
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

        Ok(piece)
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
                debug!("Object {} not found", hex::encode(object_id));

                return Ok(None);
            }
        };

        let piece_index = global_object.piece_index();
        let offset = global_object.offset();

        let data = self.assemble_object(piece_index, offset).await?;
        Ok(Some(Object {
            piece_index,
            offset,
            data,
        }))
    }
}
