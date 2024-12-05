// Copyright (C) 2024 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Fetching objects stored in the archived history of Subspace Network.

use crate::piece_fetcher::download_pieces;
use crate::piece_getter::PieceGetter;
use crate::segment_downloading::{download_segment, SegmentDownloadingError};
use parity_scale_codec::{Compact, CompactLen, Decode, Encode};
use std::sync::Arc;
use subspace_archiving::archiver::{Segment, SegmentItem};
use subspace_core_primitives::pieces::{Piece, PieceIndex, RawRecord};
use subspace_core_primitives::segments::{RecordedHistorySegment, SegmentIndex};
use subspace_erasure_coding::ErasureCoding;
use tracing::{debug, trace};

/// Object fetching errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Supplied piece index is not a source piece
    #[error("Piece index {piece_index} is not a source piece, offset: {piece_offset}")]
    NotSourcePiece {
        piece_index: PieceIndex,
        piece_offset: u32,
    },

    /// Supplied piece offset is too large
    #[error("Piece offset {piece_offset} is too large, must be less than {}, piece index: {piece_index}", RawRecord::SIZE)]
    PieceOffsetTooLarge {
        piece_index: PieceIndex,
        piece_offset: u32,
    },

    /// No item in segment at offset
    #[error("Offset {offset_in_segment} in segment {segment_index} is not an item, current progress: {progress}, object: {piece_index:?}, {piece_offset}")]
    NoSegmentItem {
        progress: usize,
        offset_in_segment: usize,
        segment_index: SegmentIndex,
        piece_index: PieceIndex,
        piece_offset: u32,
    },

    /// Unexpected item in first segment at offset
    #[error("Offset {offset_in_segment} in first segment {segment_index} has unexpected item, current progress: {segment_progress}, object: {piece_index:?}, {piece_offset}, item: {segment_item:?}")]
    UnexpectedFirstSegmentItem {
        segment_progress: usize,
        offset_in_segment: usize,
        segment_index: SegmentIndex,
        segment_item: Box<SegmentItem>,
        piece_index: PieceIndex,
        piece_offset: u32,
    },

    /// Unexpected item in continuing segment at offset
    #[error("Continuing segment {segment_index} has unexpected item, collected data: {collected_data}, object: {piece_index:?}, {piece_offset}, item: {segment_item:?}")]
    UnexpectedContinuingSegmentItem {
        collected_data: usize,
        segment_index: SegmentIndex,
        segment_item: Box<SegmentItem>,
        piece_index: PieceIndex,
        piece_offset: u32,
    },

    /// Object not found after downloading expected number of segments
    #[error("Object segment range {first_segment_index}..={last_segment_index} did not contain full object, object: {piece_index:?}, {piece_offset}")]
    TooManySegments {
        first_segment_index: SegmentIndex,
        last_segment_index: SegmentIndex,
        piece_index: PieceIndex,
        piece_offset: u32,
    },

    /// Object is too large error
    #[error(
        "Data length {data_length} exceeds maximum object size {max_object_len} for object: {piece_index:?}, {piece_offset}"
    )]
    ObjectTooLarge {
        data_length: usize,
        max_object_len: usize,
        piece_index: PieceIndex,
        piece_offset: u32,
    },

    /// Length prefix is too large error
    #[error(
        "Length prefix length {length_prefix_len} exceeds maximum object size {max_object_len} for object: {piece_index:?}, {piece_offset}"
    )]
    LengthPrefixTooLarge {
        length_prefix_len: usize,
        max_object_len: usize,
        piece_index: PieceIndex,
        piece_offset: u32,
    },

    /// Object decoding error
    #[error("Object data decoding error: {source:?}")]
    ObjectDecoding {
        #[from]
        source: parity_scale_codec::Error,
    },

    /// Segment getter error
    #[error("Getting segment failed: {source:?}")]
    SegmentGetter {
        #[from]
        source: SegmentDownloadingError,
    },

    /// Piece getter error
    #[error("Getting piece caused an error: {source:?}")]
    PieceGetterError {
        #[from]
        source: anyhow::Error,
    },

    /// Piece getter couldn't find the piece
    #[error("Piece {piece_index:?} was not found by piece getter")]
    PieceNotFound { piece_index: PieceIndex },
}

/// Object fetcher for the Subspace DSN.
pub struct ObjectFetcher<PG>
where
    PG: PieceGetter + Send + Sync,
{
    /// The piece getter used to fetch pieces.
    piece_getter: Arc<PG>,

    /// The erasure coding configuration of those pieces.
    erasure_coding: ErasureCoding,

    /// The maximum number of data bytes we'll read for a single object.
    max_object_len: usize,
}

impl<PG> ObjectFetcher<PG>
where
    PG: PieceGetter + Send + Sync,
{
    /// Create a new object fetcher with the given configuration.
    ///
    /// `max_object_len` is the amount of data bytes we'll read for a single object before giving
    /// up and returning an error, or `None` for no limit (`usize::MAX`).
    pub fn new(
        piece_getter: Arc<PG>,
        erasure_coding: ErasureCoding,
        max_object_len: Option<usize>,
    ) -> Self {
        Self {
            piece_getter,
            erasure_coding,
            max_object_len: max_object_len.unwrap_or(usize::MAX),
        }
    }

    /// Assemble the object in `piece_index` at `piece_offset` by fetching necessary pieces using
    /// the piece getter and putting the object's bytes together.
    ///
    /// The caller should check the object's hash to make sure the correct bytes are returned.
    pub async fn fetch_object(
        &self,
        piece_index: PieceIndex,
        piece_offset: u32,
    ) -> Result<Vec<u8>, Error> {
        // Validate parameters
        if !piece_index.is_source() {
            tracing::debug!(
                %piece_index,
                piece_offset,
                "Invalid piece index for object: must be a source piece",
            );

            // Parity pieces contain effectively random data, and can't be used to fetch objects
            return Err(Error::NotSourcePiece {
                piece_index,
                piece_offset,
            });
        }

        if piece_offset >= RawRecord::SIZE as u32 {
            tracing::debug!(
                %piece_index,
                piece_offset,
                RawRecord_SIZE = RawRecord::SIZE,
                "Invalid piece offset for object: must be less than the size of a raw record",
            );

            return Err(Error::PieceOffsetTooLarge {
                piece_index,
                piece_offset,
            });
        }

        // Try fast object assembling from individual pieces
        if let Some(data) = self.fetch_object_fast(piece_index, piece_offset).await? {
            tracing::debug!(
                %piece_index,
                piece_offset,
                len = %data.len(),
                "Fetched object using fast object assembling",
            );

            return Ok(data);
        }

        // Regular object assembling from segments
        let data = self.fetch_object_regular(piece_index, piece_offset).await?;

        tracing::debug!(
            %piece_index,
            piece_offset,
            len = %data.len(),
            "Fetched object using regular object assembling",
        );

        Ok(data)
    }

    /// Fast object fetching and assembling where the object doesn't cross piece (super fast) or
    /// segment (just fast) boundaries, returns `Ok(None)` if fast retrieval is not guaranteed.
    // TODO: return already downloaded pieces from fetch_object_fast() and pass them to fetch_object_regular()
    async fn fetch_object_fast(
        &self,
        piece_index: PieceIndex,
        piece_offset: u32,
    ) -> Result<Option<Vec<u8>>, Error> {
        // If the offset is before the last 2 bytes of a segment, we might be able to do very fast
        // object retrieval without assembling and processing the whole segment.
        //
        // The last 2 bytes might contain padding if a piece is the last piece in the segment.
        let before_last_two_bytes = piece_offset as usize <= RawRecord::SIZE - 1 - 2;
        let piece_position_in_segment = piece_index.source_position();
        let data_shards = RecordedHistorySegment::NUM_RAW_RECORDS as u32;
        let last_data_piece_in_segment = piece_position_in_segment >= data_shards - 1;

        if last_data_piece_in_segment && !before_last_two_bytes {
            trace!(
                piece_position_in_segment,
                %piece_index,
                piece_offset,
                "Fast object retrieval not possible: last source piece in segment, \
                and start of object length bytes is in potential segment padding",
            );

            // Fast retrieval possibility is not guaranteed
            return Ok(None);
        }

        // How much bytes are definitely available starting at `piece_index` and `offset` without
        // crossing a segment boundary.
        //
        // The last 2 bytes might contain padding if a piece is the last piece in the segment.
        let bytes_available_in_segment =
            (data_shards - piece_position_in_segment) * RawRecord::SIZE as u32 - piece_offset;
        let Some(bytes_available_in_segment) = bytes_available_in_segment.checked_sub(2) else {
            // We need to reconstruct the full segment and discard padding before reading the length.
            return Ok(None);
        };

        // Data from pieces that were already read, starting with piece at index `piece_index`
        let mut read_records_data = Vec::<u8>::with_capacity(RawRecord::SIZE * 2);
        let mut next_source_piece_index = piece_index;

        let piece = self
            .read_piece(next_source_piece_index, piece_index, piece_offset)
            .await?;
        next_source_piece_index = next_source_piece_index.next_source_index();
        read_records_data.extend(piece.record().to_raw_record_chunks().flatten().copied());

        if last_data_piece_in_segment {
            // The last 2 bytes might contain segment padding, so we can't use them for object length or object data.
            read_records_data.truncate(RawRecord::SIZE - 2);
        }

        let data_length = self.decode_data_length(
            &read_records_data[piece_offset as usize..],
            piece_index,
            piece_offset,
        )?;

        let data_length = if let Some(data_length) = data_length {
            data_length
        } else if !last_data_piece_in_segment {
            // Need the next piece to read the length of data, but we can only use it if there was
            // no segment padding
            trace!(
                %next_source_piece_index,
                piece_position_in_segment,
                bytes_available_in_segment,
                %piece_index,
                piece_offset,
                "Part of object length bytes is in next piece, fetching",
            );

            let piece = self
                .read_piece(next_source_piece_index, piece_index, piece_offset)
                .await?;
            next_source_piece_index = next_source_piece_index.next_source_index();
            read_records_data.extend(piece.record().to_raw_record_chunks().flatten().copied());

            self.decode_data_length(
                &read_records_data[piece_offset as usize..],
                piece_index,
                piece_offset,
            )?
            .expect("Extra RawRecord is larger than the length encoding; qed")
        } else {
            trace!(
                piece_position_in_segment,
                bytes_available_in_segment,
                %piece_index,
                piece_offset,
                "Fast object retrieval not possible: last source piece in segment, \
                and part of object length bytes is in potential segment padding",
            );

            // Super fast read is not possible, because we removed potential segment padding, so
            // the piece bytes are not guaranteed to be continuous
            return Ok(None);
        };

        if data_length > bytes_available_in_segment as usize {
            trace!(
                data_length,
                bytes_available_in_segment,
                piece_position_in_segment,
                %piece_index,
                piece_offset,
                "Fast object retrieval not possible: part of object data bytes is in \
                potential segment padding",
            );

            // Not enough data without crossing segment boundary
            return Ok(None);
        }

        // Discard piece data before the offset
        let mut data = read_records_data[piece_offset as usize..].to_vec();
        drop(read_records_data);

        // Read more pieces until we have enough data
        if data_length as usize > data.len() {
            let remaining_piece_count =
                (data_length as usize - data.len()).div_ceil(RawRecord::SIZE);
            let remaining_piece_indexes = (next_source_piece_index..)
                .filter(|i| i.is_source())
                .take(remaining_piece_count)
                .collect::<Vec<_>>();
            self.read_pieces(&remaining_piece_indexes)
                .await?
                .into_iter()
                .for_each(|piece| {
                    data.extend(piece.record().to_raw_record_chunks().flatten().copied())
                });
        }

        // Decode the data, and return it if it's valid
        let data = Vec::<u8>::decode(&mut data.as_slice())?;

        Ok(Some(data))
    }

    /// Fetch and assemble an object that can cross segment boundaries, which requires assembling
    /// and iterating over full segments.
    async fn fetch_object_regular(
        &self,
        piece_index: PieceIndex,
        piece_offset: u32,
    ) -> Result<Vec<u8>, Error> {
        let mut segment_index = piece_index.segment_index();
        let piece_position_in_segment = piece_index.source_position();
        // Used to access the data after it is converted to raw bytes
        let offset_in_segment =
            piece_position_in_segment as usize * RawRecord::SIZE + piece_offset as usize;

        tracing::trace!(
            %segment_index,
            offset_in_segment,
            piece_position_in_segment,
            %piece_index,
            piece_offset,
            "Fetching object from segment(s)",
        );

        let mut data = {
            let items = self.read_segment(segment_index).await?.into_items();
            // Go through the segment until we reach the offset.
            // Unconditional progress is enum variant + compact encoding of number of elements
            let mut progress = 1 + Compact::compact_len(&(items.len() as u64));
            let segment_item = items
                .into_iter()
                .find(|item| {
                    // Add number of bytes in encoded version of segment item
                    progress += item.encoded_size();

                    // Our data is within another segment item, which will have wrapping data
                    // structure, hence strictly `>` here
                    progress > offset_in_segment
                })
                .ok_or_else(|| {
                    debug!(
                        progress,
                        offset_in_segment,
                        ?segment_index,
                        %piece_index,
                        piece_offset,
                        "Failed to find item at offset in segment"
                    );

                    Error::NoSegmentItem {
                        progress,
                        offset_in_segment,
                        segment_index,
                        piece_index,
                        piece_offset,
                    }
                })?;

            tracing::trace!(
                progress,
                %segment_index,
                offset_in_segment,
                piece_position_in_segment,
                %piece_index,
                piece_offset,
                segment_item = format!("{segment_item:?}").chars().take(50).collect::<String>(),
                "Found item at offset in first segment",
            );

            // Look at the item after the offset, collecting block bytes
            match segment_item {
                SegmentItem::Block { bytes, .. }
                | SegmentItem::BlockStart { bytes, .. }
                | SegmentItem::BlockContinuation { bytes, .. } => {
                    // Rewind back progress to the beginning of this item
                    progress -= bytes.len();
                    // Get a chunk of the bytes starting at the offset in this item
                    Vec::from(&bytes[offset_in_segment - progress..])
                }
                segment_item @ SegmentItem::Padding
                | segment_item @ SegmentItem::ParentSegmentHeader(_) => {
                    // TODO: create a Display impl for SegmentItem that is shorter than the entire
                    // data contained in it
                    debug!(
                        segment_progress = progress,
                        offset_in_segment,
                        %segment_index,
                        %piece_index,
                        piece_offset,
                        segment_item = format!("{segment_item:?}").chars().take(50).collect::<String>(),
                        "Unexpected segment item in first segment",
                    );

                    return Err(Error::UnexpectedFirstSegmentItem {
                        segment_progress: progress,
                        offset_in_segment,
                        segment_index,
                        piece_index,
                        piece_offset,
                        segment_item: Box::new(segment_item),
                    });
                }
            }
        };

        tracing::trace!(
            %segment_index,
            offset_in_segment,
            piece_position_in_segment,
            %piece_index,
            piece_offset,
            data_len = data.len(),
            "Got data at offset in first segment",
        );

        // Return an error if the length is unreasonably large, before we get the next segment
        if let Some(data_length) =
            self.decode_data_length(data.as_slice(), piece_index, piece_offset)?
        {
            // If we have the whole object, decode and return it.
            // TODO: use tokio Bytes type to re-use the same allocation by stripping the length at the start
            if data.len() >= data_length {
                return Ok(Vec::<u8>::decode(&mut data.as_slice())?);
            }
        }

        // We need to read extra segments to get the object length, or the full object.
        // We don't attempt to calculate the number of segments needed, because it involves
        // headers and optional padding.
        loop {
            segment_index += SegmentIndex::ONE;
            let items = self.read_segment(segment_index).await?.into_items();
            for segment_item in items {
                match segment_item {
                    SegmentItem::BlockContinuation { bytes, .. } => {
                        data.extend_from_slice(&bytes);

                        if let Some(data_length) =
                            self.decode_data_length(data.as_slice(), piece_index, piece_offset)?
                        {
                            if data.len() >= data_length {
                                return Ok(Vec::<u8>::decode(&mut data.as_slice())?);
                            }
                        }
                    }

                    // Padding at the end of segments can be skipped, it's not part of the object data
                    SegmentItem::Padding => {}

                    // We should not see these items while collecting data for a single object
                    SegmentItem::Block { .. }
                    | SegmentItem::BlockStart { .. }
                    | SegmentItem::ParentSegmentHeader(_) => {
                        debug!(
                            collected_data = ?data.len(),
                            %segment_index,
                            %piece_index,
                            piece_offset,
                            segment_item = format!("{segment_item:?}").chars().take(50).collect::<String>(),
                            "Unexpected segment item in continuing segment",
                        );

                        return Err(Error::UnexpectedContinuingSegmentItem {
                            collected_data: data.len(),
                            segment_index,
                            piece_index,
                            piece_offset,
                            segment_item: Box::new(segment_item),
                        });
                    }
                }
            }
        }
    }

    /// Read the whole segment by its index (just records, skipping witnesses).
    async fn read_segment(&self, segment_index: SegmentIndex) -> Result<Segment, Error> {
        Ok(download_segment(
            segment_index,
            &self.piece_getter,
            self.erasure_coding.clone(),
        )
        .await?)
    }

    /// Concurrently read multiple pieces, and return them in the supplied order.
    async fn read_pieces(&self, piece_indexes: &[PieceIndex]) -> Result<Vec<Piece>, Error> {
        download_pieces(piece_indexes, &self.piece_getter)
            .await
            .map_err(|source| Error::PieceGetterError { source })
    }

    /// Read and return a single piece.
    ///
    /// The mapping piece index and offset are only used for error reporting.
    async fn read_piece(
        &self,
        piece_index: PieceIndex,
        mapping_piece_index: PieceIndex,
        mapping_piece_offset: u32,
    ) -> Result<Piece, Error> {
        let piece = self
            .piece_getter
            .get_piece(piece_index)
            .await
            .inspect_err(|source| {
                debug!(
                    %piece_index,
                    error = ?source,
                    %mapping_piece_index,
                    mapping_piece_offset,
                    "Error fetching piece during object assembling"
                );
            })?;

        if let Some(piece) = piece {
            trace!(
                %piece_index,
                %mapping_piece_index,
                mapping_piece_offset,
                "Fetched piece during object assembling"
            );

            Ok(piece)
        } else {
            debug!(
                %piece_index,
                %mapping_piece_index,
                mapping_piece_offset,
                "Piece not found during object assembling"
            );

            Err(Error::PieceNotFound {
                piece_index: mapping_piece_index,
            })?
        }
    }

    /// Validate and decode the encoded length of `data`, including the encoded length bytes.
    /// `data` may be incomplete.
    ///
    /// Returns `Ok(Some(data_length_encoded_length + data_length))` if the length is valid,
    /// `Ok(None)` if there aren't enough bytes to decode the length, otherwise an error.
    ///
    /// The mapping piece index and offset are only used for error reporting.
    fn decode_data_length(
        &self,
        mut data: &[u8],
        mapping_piece_index: PieceIndex,
        mapping_piece_offset: u32,
    ) -> Result<Option<usize>, Error> {
        let data_length = match Compact::<u64>::decode(&mut data) {
            Ok(Compact(data_length)) => {
                let data_length = data_length as usize;
                if data_length > self.max_object_len {
                    debug!(
                        data_length,
                        max_object_len = self.max_object_len,
                        %mapping_piece_index,
                        mapping_piece_offset,
                        "Data length exceeds object size limit for object fetcher"
                    );

                    return Err(Error::ObjectTooLarge {
                        data_length,
                        max_object_len: self.max_object_len,
                        piece_index: mapping_piece_index,
                        piece_offset: mapping_piece_offset,
                    });
                }

                data_length
            }
            Err(err) => {
                // Parity doesn't have an easily matched error enum, and all bit sequences are
                // valid compact encodings. So we assume we don't have enough bytes to decode the
                // length, unless we already have enough bytes to decode the maximum length.
                if data.len() >= Compact::<u64>::compact_len(&(self.max_object_len as u64)) {
                    debug!(
                        length_prefix_len = data.len(),
                        max_object_len = self.max_object_len,
                        %mapping_piece_index,
                        mapping_piece_offset,
                        "Length prefix exceeds object size limit for object fetcher"
                    );

                    return Err(Error::LengthPrefixTooLarge {
                        length_prefix_len: data.len(),
                        max_object_len: self.max_object_len,
                        piece_index: mapping_piece_index,
                        piece_offset: mapping_piece_offset,
                    });
                }

                debug!(
                    ?err,
                    %mapping_piece_index,
                    mapping_piece_offset,
                    "Not enough bytes to decode data length for object"
                );

                return Ok(None);
            }
        };

        let data_length_encoded_length = Compact::<u64>::compact_len(&(data_length as u64));

        trace!(
            data_length,
            data_length_encoded_length,
            %mapping_piece_index,
            mapping_piece_offset,
            "Decoded data length for object"
        );

        Ok(Some(data_length_encoded_length + data_length))
    }
}
