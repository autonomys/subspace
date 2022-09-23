use crate::object_mappings::{ObjectMappingError, ObjectMappings};
use jsonrpsee::core::error::Error;
use jsonrpsee::proc_macros::rpc;
use parity_scale_codec::{Compact, CompactLen, Decode, Encode};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use subspace_archiving::archiver::{Segment, SegmentItem};
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::{Blake2b256Hash, Piece, PieceIndex, PieceIndexHash, SegmentIndex};
use tracing::{debug, error};

/// Maximum expected size of one object in bytes
const MAX_OBJECT_SIZE: usize = 5 * 1024 * 1024;

/// Something that can be used to get decoded pieces by index
pub trait PieceGetter {
    /// Get piece
    fn get_piece(&self, piece_index: PieceIndex, piece_index_hash: PieceIndexHash)
        -> Option<Piece>;
}

impl<PG> PieceGetter for Vec<PG>
where
    PG: PieceGetter,
{
    fn get_piece(
        &self,
        piece_index: PieceIndex,
        piece_index_hash: PieceIndexHash,
    ) -> Option<Piece> {
        self.iter()
            .find_map(|piece_getter| piece_getter.get_piece(piece_index, piece_index_hash))
    }
}

/// Same as [`Piece`], but serializes/deserialized to/from hex string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPiece(#[serde(with = "hex::serde")] Vec<u8>);

impl From<Piece> for HexPiece {
    fn from(piece: Piece) -> Self {
        HexPiece(piece.into())
    }
}

impl From<HexPiece> for Piece {
    fn from(piece: HexPiece) -> Self {
        piece
            .0
            .as_slice()
            .try_into()
            .expect("Internal piece is always has correct length; qed")
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

/// Similar to [`Blake2b256Hash`], but serializes/deserialized to/from hex string
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct HexBlake2b256Hash(#[serde(with = "hex::serde")] Blake2b256Hash);

impl From<Blake2b256Hash> for HexBlake2b256Hash {
    fn from(hash: Blake2b256Hash) -> Self {
        HexBlake2b256Hash(hash)
    }
}

impl From<HexBlake2b256Hash> for Blake2b256Hash {
    fn from(piece: HexBlake2b256Hash) -> Self {
        piece.0
    }
}

impl Deref for HexBlake2b256Hash {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for HexBlake2b256Hash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for HexBlake2b256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for HexBlake2b256Hash {
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
    offset: u32,
    /// The data object contains for convenience
    #[serde(with = "hex::serde")]
    data: Vec<u8>,
}

#[rpc(server, client)]
pub trait Rpc {
    /// Get single piece by its index
    #[method(name = "getPiece", blocking)]
    fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<HexPiece>, Error>;

    /// Find object by its ID
    #[method(name = "findObject", blocking)]
    fn find_object(&self, object_id: HexBlake2b256Hash) -> Result<Option<Object>, Error>;
}

/// Farmer RPC server implementation.
///
/// Usage example:
/// ```rust
///  async fn f() -> anyhow::Result<()> {
/// use jsonrpsee::ws_server::WsServerBuilder;
/// use subspace_farmer::{Identity, ObjectMappings, Plot};
/// use subspace_farmer::single_plot_farm::{SinglePlotPieceGetter, SinglePlotFarmId};
/// use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
/// use subspace_solving::SubspaceCodec;
/// use std::path::PathBuf;
/// use std::sync::Arc;
///
/// let base_directory = PathBuf::from("/path/to/base/dir");
/// let ws_server_listen_addr = "127.0.0.1:0";
///
/// let identity = Identity::open_or_create(&base_directory)?;
/// let public_key = identity.public_key().to_bytes().into();
/// let plot = Plot::open_or_create(
///     &SinglePlotFarmId::new(),
///     &base_directory,
///     &base_directory,
///     public_key,
///     u64::MAX,
/// )?;
/// let object_mappings = ObjectMappings::open_or_create(
///     &base_directory.join("object-mappings"),
///     public_key,
///     100 * 1024 * 1024,
/// )?;
/// let ws_server = WsServerBuilder::default().build(ws_server_listen_addr).await?;
/// let rpc_server = RpcServerImpl::new(
///     3840,
///     3480 * 128,
///     Arc::new(SinglePlotPieceGetter::new(SubspaceCodec::new(&public_key), plot)),
///     Arc::new(vec![object_mappings]),
/// );
/// let ws_server = ws_server.start(rpc_server.into_rpc())?;
///
/// # Ok(())
/// # }
/// ```
pub struct RpcServerImpl {
    record_size: u32,
    pieces_in_segment: u32,
    piece_getter: Arc<dyn PieceGetter + Send + Sync + 'static>,
    object_mappings: Arc<Vec<ObjectMappings>>,
}

impl RpcServerImpl {
    pub fn new(
        record_size: u32,
        recorded_history_segment_size: u32,
        piece_getter: Arc<dyn PieceGetter + Send + Sync + 'static>,
        object_mappings: Arc<Vec<ObjectMappings>>,
    ) -> Self {
        Self {
            record_size,
            pieces_in_segment: recorded_history_segment_size / record_size * 2,
            piece_getter,
            object_mappings,
        }
    }

    /// Assemble object that starts at `piece_index` at `offset` by reading necessary pieces from
    /// plot and putting necessary bytes together.
    fn assemble_object(
        &self,
        piece_index: PieceIndex,
        offset: u32,
        object_id: &str,
    ) -> Result<Vec<u8>, Error> {
        // Try fast object assembling
        if let Some(data) = self.assemble_object_fast(piece_index, offset)? {
            return Ok(data);
        }

        self.assemble_object_regular(piece_index, offset, object_id)
    }

    /// Fast object assembling in case object doesn't cross piece (super fast) or segment (just
    /// fast) boundary, returns `Ok(None)` if fast retrieval possibility is not guaranteed.
    fn assemble_object_fast(
        &self,
        piece_index: PieceIndex,
        offset: u32,
    ) -> Result<Option<Vec<u8>>, Error> {
        // We care if the offset is before the last 2 bytes of a piece because if not we might be
        // able to do very fast object retrieval without assembling and processing the whole
        // segment. `-2` is because last 2 bytes might contain padding if a piece is the last piece
        // in the segment.
        let before_last_two_bytes = offset <= self.record_size - 1 - 2;

        // We care about whether piece index points to the last data piece in the segment because
        // if not we might be able to do very fast object retrieval without assembling and
        // processing the whole segment.
        let last_data_piece_in_segment = {
            let piece_position_in_segment = piece_index % u64::from(self.pieces_in_segment);
            let last_piece_position_in_segment = u64::from(self.pieces_in_segment) / 2 - 1;

            piece_position_in_segment >= last_piece_position_in_segment
        };

        // How much bytes are definitely available starting at `piece_index` and `offset` without
        // crossing segment boundary
        let bytes_available_in_segment = {
            let data_shards = u64::from(self.pieces_in_segment / 2);
            let piece_position = piece_index % u64::from(self.pieces_in_segment);

            // `-2` is because last 2 bytes might contain padding if a piece is the last piece in
            // the segment.
            (data_shards - piece_position) * u64::from(self.record_size) - u64::from(offset) - 2
        };

        if last_data_piece_in_segment && !before_last_two_bytes {
            // Fast retrieval possibility is not guaranteed
            return Ok(None);
        }

        // Cache of read pieces that were already read, starting with piece at index `piece_index`
        let mut read_records_data = Vec::<u8>::with_capacity(self.record_size as usize * 2);
        let mut next_piece_index = piece_index;

        let piece = self.read_and_decode_piece(next_piece_index)?;
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
                error!(error = %error_string);

                return Err(Error::Custom(error_string));
            }
        };

        // Same as `before_last_two_bytes`, but accounts for compact encoding of data length
        let length_before_last_two_bytes =
            offset + data_length_bytes_length < self.record_size - 1 - 2;
        // Similar to `length_before_last_two_bytes`, but uses the whole recordif needed
        let length_before_record_end = offset + data_length_bytes_length < self.record_size - 1;

        let data_length_result = if length_before_last_two_bytes {
            Compact::<u32>::decode(&mut &read_records_data[offset as usize..])
        } else if !last_data_piece_in_segment {
            if !length_before_record_end {
                // Need the next piece to read the length of data
                let piece = self.read_and_decode_piece(next_piece_index)?;
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
            error!(error = %error_string);

            Error::Custom(error_string)
        })?;

        if u64::from(data_length_bytes_length + data_length) > bytes_available_in_segment {
            // Not enough data without crossing segment boundary
            return Ok(None);
        }

        let mut data =
            read_records_data[offset as usize + data_length_bytes_length as usize..].to_vec();
        drop(read_records_data);

        // Read more pieces until we have enough data
        while data.len() <= data_length as usize {
            let piece = self.read_and_decode_piece(next_piece_index)?;
            next_piece_index += 1;
            data.extend_from_slice(&piece[..self.record_size as usize]);
        }

        // Trim the excess
        data.truncate(data_length as usize);

        Ok(Some(data))
    }

    /// Assemble object that can cross segment boundary, which requires assembling and iterating
    /// over full segments.
    fn assemble_object_regular(
        &self,
        piece_index: PieceIndex,
        offset: u32,
        object_id: &str,
    ) -> Result<Vec<u8>, Error> {
        let segment_index = piece_index / u64::from(self.pieces_in_segment);
        let piece_position_in_segment = piece_index % u64::from(self.pieces_in_segment);
        let offset_in_segment =
            piece_position_in_segment * u64::from(self.record_size) + u64::from(offset);

        let mut data = {
            let Segment::V0 { items } = self.read_segment(segment_index)?;
            // Unconditional progress is enum variant + compact encoding of number of elements
            let mut progress = 1 + Compact::compact_len(&(items.len() as u64));
            let segment_item = items
                .into_iter()
                .find(|item| {
                    // Add number of bytes in encoded version of segment item
                    progress += item.encoded_size();

                    // Our data is within another segment item, which will have wrapping data
                    // structure, hence strictly `>` here
                    progress > offset_in_segment as usize
                })
                .ok_or_else(|| {
                    let error_string = format!(
                        "Failed to find item at offset {} in segment {} for object {}",
                        offset_in_segment, segment_index, object_id
                    );
                    error!(error = %error_string);

                    Error::Custom(error_string)
                })?;

            match segment_item {
                SegmentItem::Block { bytes, .. }
                | SegmentItem::BlockStart { bytes, .. }
                | SegmentItem::BlockContinuation { bytes, .. } => {
                    // Rewind back progress to the beginning of the number of bytes
                    progress -= bytes.len();
                    // Get a chunk of the bytes starting at the position we care about
                    Vec::from(&bytes[offset_in_segment as usize - progress..])
                }
                segment_item => {
                    error!(
                        ?segment_item,
                        offset_in_segment, segment_index, object_id, "Unexpected segment item",
                    );

                    return Err(Error::Custom(format!(
                        "Unexpected segment item at offset {} in segment {} for object {}",
                        offset_in_segment, segment_index, object_id
                    )));
                }
            }
        };

        if let Ok(data) = Vec::<u8>::decode(&mut data.as_slice()) {
            return Ok(data);
        }

        for segment_index in segment_index + 1.. {
            let Segment::V0 { items } = self.read_segment(segment_index)?;
            for segment_item in items {
                if let SegmentItem::BlockContinuation { bytes, .. } = segment_item {
                    data.extend_from_slice(&bytes);

                    if let Ok(data) = Vec::<u8>::decode(&mut data.as_slice()) {
                        return Ok(data);
                    }
                }
            }

            if data.len() >= MAX_OBJECT_SIZE {
                break;
            }
        }

        error!(object_id, "Read max object size for object without success",);

        Err(Error::Custom(
            "Read max object size for object without success".to_string(),
        ))
    }

    /// Read the whole segment by its index (just records, skipping witnesses)
    fn read_segment(&self, segment_index: SegmentIndex) -> Result<Segment, Error> {
        let first_piece_in_segment = segment_index * SegmentIndex::from(self.pieces_in_segment);
        let mut segment_bytes =
            Vec::<u8>::with_capacity((self.pieces_in_segment * self.record_size) as usize);

        for piece_index in (first_piece_in_segment..).take(self.pieces_in_segment as usize / 2) {
            let piece = self.read_and_decode_piece(piece_index)?;
            segment_bytes.extend_from_slice(&piece[..self.record_size as usize]);
        }

        let segment = Segment::decode(&mut segment_bytes.as_slice()).map_err(|error| {
            error!(
                index = segment_index,
                %error,
                "Failed to decode segment of archival history on retrieval",
            );

            Error::Custom(format!(
                "Failed to decode segment {} of archival history on retrieval",
                segment_index
            ))
        })?;

        Ok(segment)
    }

    /// Read and decode the whole piece
    fn read_and_decode_piece(&self, piece_index: PieceIndex) -> Result<Piece, Error> {
        let piece_getter = self.piece_getter.clone();
        piece_getter
            .get_piece(piece_index, PieceIndexHash::from_index(piece_index))
            .ok_or_else(|| {
                Error::Custom("Object mapping found, but reading piece failed".to_string())
            })
    }
}

impl RpcServer for RpcServerImpl {
    fn get_piece(&self, piece_index: PieceIndex) -> Result<Option<HexPiece>, Error> {
        let piece_getter = self.piece_getter.clone();
        piece_getter
            .get_piece(piece_index, PieceIndexHash::from_index(piece_index))
            .map(HexPiece::from)
            .map(Some)
            .ok_or_else(|| Error::Custom("Piece not found".to_string()))
    }

    /// Find object by its ID
    fn find_object(&self, object_id: HexBlake2b256Hash) -> Result<Option<Object>, Error> {
        let global_object_handle = || -> Result<Option<GlobalObject>, ObjectMappingError> {
            for object_mappings in self.object_mappings.iter() {
                let maybe_global_object = object_mappings.retrieve(&object_id.into())?;

                if let Some(global_object) = maybe_global_object {
                    return Ok(Some(global_object));
                }
            }

            Ok(None)
        };

        let object_id_string = hex::encode(object_id);

        let global_object = global_object_handle().map_err(|error| {
            error!(
                object_id = %object_id_string,
                %error,
                "Object mapping retrieving failed",
            );

            Error::Custom("Failed to find an object due to internal error".to_string())
        })?;

        let global_object = match global_object {
            Some(global_object) => global_object,
            None => {
                debug!(object_id = %object_id_string, "Object not found");

                return Ok(None);
            }
        };

        let piece_index = global_object.piece_index();
        let offset = global_object.offset();

        let data = self.assemble_object(piece_index, offset, &object_id_string)?;

        Ok(Some(Object {
            piece_index,
            offset,
            data,
        }))
    }
}
