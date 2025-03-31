//! Object fetching internals for partial objects.
//!
//! Partial objects can contain potential segment padding at the start, middle, or end of the
//! object. They never contain segment headers, which are stripped before reconstruction.
//!
//! Objects are reconstructed from 3 kinds of pieces:
//! - pieces at the start of a segment, which have a variable-length segment header,
//! - pieces in the middle of a segment, which have no header or padding, and
//! - pieces at the end of a segment, which have variable-length padding.
//!
//! This module provides a uniform interface for handling these different kinds of pieces:
//! - `SegmentDataLength` is used to track the length of the partial object data before and in
//!   potential segment padding. It also tracks the presence of segment headers.
//! - `RawPieceData` is used to store the partial object data (including potential segment padding)
//!   before the object length is known, and before each new piece is added to the partial object.
//! - `PartialObject` is used to store the partial object data after the object length is known.

use crate::object_fetcher::segment_header::{strip_segment_header, MAX_SEGMENT_PADDING};
use crate::object_fetcher::{decode_data_length, Error, MAX_ENCODED_LENGTH_SIZE};
use parity_scale_codec::{Decode, Input};
use std::cmp::min;
use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Formatter;
use subspace_core_primitives::hashes::{blake3_hash, Blake3Hash};
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::pieces::{PieceIndex, RawRecord};
use subspace_core_primitives::segments::RecordedHistorySegment;
use tracing::{debug, trace};

/// The fixed value of every padding byte.
pub(crate) const PADDING_BYTE_VALUE: u8 = 0;

/// The data before an object's length is known.
#[derive(Clone, Eq, PartialEq)]
pub struct RawPieceData {
    /// The available data for the object in the current segment.
    segment_data_length: Option<usize>,

    /// The object data before segment padding, starting with the encoded object length.
    ///
    /// This can be empty for an object which starts in segment padding.
    prefix_data: Vec<u8>,

    /// The potential padding data. The bytes in this data can have any values.
    maybe_padding_data: Vec<u8>,

    /// The partial object data after segment padding.
    /// For objects which don't overlap the end of a segment, this is empty.
    ///
    /// The encoded object length might overlap with the start of the suffix data.
    suffix_data: Vec<u8>,
}

impl fmt::Debug for RawPieceData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawPieceData")
            .field("segment_data_length", &self.segment_data_length)
            .field("prefix_data", &hex::encode(&self.prefix_data))
            .field("maybe_padding_data", &hex::encode(&self.maybe_padding_data))
            .field("suffix_data", &hex::encode(&self.suffix_data))
            .finish()
    }
}

impl RawPieceData {
    /// Create a new empty `RawPieceData` object for the first piece in an object.
    pub fn new_for_first_piece(mapping: GlobalObject) -> Self {
        let GlobalObject {
            piece_index,
            offset,
            hash: _,
        } = mapping;

        let data_shards = RecordedHistorySegment::NUM_RAW_RECORDS;
        let source_position_in_segment = piece_index.source_position() as usize;

        // How much bytes are definitely available starting at `piece_index` and `offset` without
        // crossing a segment boundary.
        let bytes_available_in_segment =
            (data_shards - source_position_in_segment) * RawRecord::SIZE - offset as usize;

        Self {
            segment_data_length: Some(bytes_available_in_segment),
            prefix_data: Vec::new(),
            maybe_padding_data: Vec::new(),
            suffix_data: Vec::new(),
        }
    }

    /// Create a new empty `RawPieceData` object for the next piece in an object.
    pub fn new_for_next_piece(remaining_data_length: usize, piece_index: PieceIndex) -> Self {
        let source_position_in_segment = piece_index.source_position() as usize;
        let first_data_piece_in_segment = source_position_in_segment == 0;

        if first_data_piece_in_segment {
            Self {
                // We have to strip the segment header to work out the segment data length
                segment_data_length: None,
                prefix_data: Vec::new(),
                maybe_padding_data: Vec::new(),
                suffix_data: Vec::new(),
            }
        } else {
            let data_shards = RecordedHistorySegment::NUM_RAW_RECORDS;
            // How much bytes are definitely available starting at `piece_index` and `offset` without
            // crossing a segment boundary.
            let bytes_available_in_segment =
                (data_shards - source_position_in_segment) * RawRecord::SIZE;
            let remaining_data_length = min(remaining_data_length, bytes_available_in_segment);

            Self {
                segment_data_length: Some(remaining_data_length),
                prefix_data: Vec::new(),
                maybe_padding_data: Vec::new(),
                suffix_data: Vec::new(),
            }
        }
    }

    /// Adds the supplied `piece_data` to this `RawPieceData` object.
    pub fn add_piece_data(
        &mut self,
        piece_index: PieceIndex,
        mut piece_data: Vec<u8>,
        mapping: GlobalObject,
    ) -> Result<(), Error> {
        trace!(
            ?self,
            ?piece_index,
            ?mapping,
            piece_data_len = %piece_data.len(),
            "about to add piece data",
        );

        let data_shards = RecordedHistorySegment::NUM_RAW_RECORDS;
        let source_position_in_segment = piece_index.source_position() as usize;

        // The last few bytes might contain padding if a piece is the last piece in the segment
        let last_data_piece_in_segment = source_position_in_segment == data_shards - 1;

        if self.segment_data_length.is_none() {
            let (piece_data, max_remaining_object_bytes) =
                strip_segment_header(piece_data, piece_index.segment_index(), mapping)?;

            // Objects are currently much smaller than segments, so we know there's no further
            // headers or segment padding in an object that's near the start of a segment.
            // TODO: support objects that span multiple segments
            self.segment_data_length = Some(max_remaining_object_bytes);

            self.add_piece_data_without_padding(piece_data);
        } else if last_data_piece_in_segment {
            let segment_data_length = self
                .segment_data_length
                .expect("already checked for None; qed");

            // If the object starts outside the padding, the padding is only limited by the
            // archiving algorithm. Otherwise, if the object starts inside the padding, the
            // padding is limited to the remaining segment bytes.
            let maybe_padding_data_length = min(segment_data_length, MAX_SEGMENT_PADDING);

            // We only download whole pieces, and we only strip data off the front of pieces.
            // So if we have any padding, we have all remaining padding in the segment.
            assert_eq!(segment_data_length, piece_data.len());
            let maybe_padding_data =
                piece_data.split_off(piece_data.len().saturating_sub(maybe_padding_data_length));

            // Segment headers are variable length, so we don't know how much data is in the next
            // segment
            self.segment_data_length = None;

            self.add_piece_data_with_padding(&piece_data, &maybe_padding_data);
        } else {
            let segment_data_length = self
                .segment_data_length
                .as_mut()
                .expect("already checked for None; qed");

            // There's no header and no padding in this piece - the typical case.
            // (If we started at the first piece in a segment, the offset has already skipped the header.)
            piece_data.truncate(*segment_data_length);
            *segment_data_length -= piece_data.len();

            self.add_piece_data_without_padding(piece_data);
        }

        trace!(?self, ?piece_index, ?mapping, "added piece data");

        Ok(())
    }

    /// Add data with potential padding to the end of this partial data.
    /// This method can also handle data that doesn't actually have any padding.
    ///
    /// Panics if the object already has padding.
    fn add_piece_data_with_padding(
        &mut self,
        new_prefix_data: &[u8],
        new_maybe_padding_data: &[u8],
    ) {
        // Doesn't actually have padding
        if new_maybe_padding_data.is_empty() {
            self.add_piece_data_without_padding(new_prefix_data.to_vec());
            return;
        }

        trace!(
            new_prefix_data = ?hex::encode(new_prefix_data),
            maybe_padding_data = ?hex::encode(new_maybe_padding_data),
            "adding piece data with padding",
        );

        assert!(
            !self.has_padding(),
            "add_piece_data_with_padding() can only be called once: {self:?}, \
             {new_prefix_data:?}, {new_maybe_padding_data:?}"
        );

        self.prefix_data.extend_from_slice(new_prefix_data);
        // The padding was empty, so this does assignment (but without allocating another vector)
        self.maybe_padding_data
            .extend_from_slice(new_maybe_padding_data);
    }

    /// Add padding-less `piece_data` to the end of this partial object.
    fn add_piece_data_without_padding(&mut self, mut piece_data: Vec<u8>) {
        trace!(
            piece_data = ?hex::encode(&piece_data),
            "adding piece data without padding",
        );

        if self.has_padding() {
            // If there might be padding, or there is suffix data, new data must be added at the end
            // of the suffix data.
            self.suffix_data.append(&mut piece_data);
        } else {
            // Otherwise, the data belongs to the existing prefix data.
            self.prefix_data.append(&mut piece_data);
        }
    }

    /// Returns true if this object has padding, or might have padding.
    fn has_padding(&self) -> bool {
        !self.maybe_padding_data.is_empty() || !self.suffix_data.is_empty()
    }

    /// Returns the available object data in the current segment.
    pub fn segment_data_length(&self) -> Option<usize> {
        self.segment_data_length
    }
}

/// A possible data length and segment padding length for an object.
/// Sorts by data length first, then ignored padding length.
///
/// This sorting order allows us to check objects that contain all the potential padding bytes,
/// then download more pieces if needed.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ObjectLength {
    /// The length of the object data, including the encoded length.
    data_length: usize,

    /// The number of ignored zero-valued bytes at the end of the prefix data.
    /// These bytes could be segment padding, or part of the object data.
    ignored_padding_length: usize,
}

/// The state of a single object that is being fetched.
/// Each object is contained within a single block.
///
/// An object at the end of a segment needs to ignore any segment padding. To avoid reconstructing
/// the entire segment, we try each possible padding against the hash instead. We don't need to
/// store the padding bytes, because padding is always zero-valued.
///
/// Objects also need to ignore the parent segment header and `BlockContinuation` header at the
/// start of a segment.
#[derive(Clone, Eq, PartialEq)]
pub struct PartialObject {
    /// The object data, starting with the encoded object length, and maybe ending with segment
    /// padding.
    ///
    /// This can be empty for an object which starts in segment padding.
    /// (Such objects are always zero length, because padding is always zero-valued.)
    prefix_data: Vec<u8>,

    /// The partial object data after segment padding.
    /// For objects which don't overlap the end of a segment, this is empty.
    ///
    /// The encoded object length might overlap with the start of the suffix data.
    suffix_data: Vec<u8>,

    /// The possible object lengths and their corresponding padding lengths.
    /// For objects which aren't at the end of a segment, there is only one data length, and the
    /// padding length is zero.
    lengths: BTreeSet<ObjectLength>,
}

impl fmt::Debug for PartialObject {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartialObject")
            .field("prefix_data", &hex::encode(&self.prefix_data))
            .field("suffix_data", &hex::encode(&self.suffix_data))
            .field("lengths", &self.lengths)
            .finish()
    }
}

impl PartialObject {
    /// Given prefix data, potential padding data, and suffix data, returns a new `PartialObject`.
    /// Returns `Ok(None)` if more data is needed, or an error if object retrieval failed.
    ///
    /// This method can also handle data that doesn't actually have any padding.
    ///
    /// Panics if an object has a suffix, but no padding.
    pub fn new_with_padding(
        raw_data: &RawPieceData,
        max_object_len: usize,
        mapping: GlobalObject,
    ) -> Result<Option<Self>, Error> {
        let RawPieceData {
            segment_data_length,
            prefix_data,
            maybe_padding_data,
            suffix_data,
        } = raw_data;

        // No padding, so the data is continuous
        if maybe_padding_data.is_empty() {
            assert!(
                suffix_data.is_empty(),
                "suffix_data can only have bytes if there might be padding bytes"
            );
            return Self::new_without_padding(prefix_data, max_object_len, mapping);
        }

        trace!(
            ?max_object_len,
            ?mapping,
            ?segment_data_length,
            prefix_data = ?hex::encode(prefix_data),
            maybe_padding_data = ?hex::encode(maybe_padding_data),
            suffix_data = ?hex::encode(suffix_data),
            "trying to create new partial object with padding",
        );

        // Count the padding bytes
        let object_max_segment_padding_length = Self::count_padding_bytes(maybe_padding_data);

        trace!(?object_max_segment_padding_length, "analysed padding");

        // Keep the remaining non-padding and potential padding bytes
        let mut prefix_data = prefix_data.to_vec();
        prefix_data.extend_from_slice(maybe_padding_data);

        // Find the possible lengths for the object, for each potential padding byte.
        let mut lengths = BTreeSet::new();
        let mut last_error = None;

        for ignored_padding_length in 0..=object_max_segment_padding_length {
            let (length_prefix, length_suffix) = padded_data(
                &prefix_data,
                ignored_padding_length,
                suffix_data,
                MAX_ENCODED_LENGTH_SIZE,
            );
            let mut length_data = ObjectDataInput::new_from_parts(length_prefix, length_suffix);

            match decode_data_length(&length_data.remaining_data(), max_object_len, mapping) {
                // A valid length
                Ok(Some((length_prefix_len, data_length))) => {
                    lengths.insert(ObjectLength {
                        data_length: length_prefix_len + data_length,
                        ignored_padding_length,
                    });
                }
                // Not enough data to decode all the lengths yet (this is a rare edge case).
                Ok(None) => {
                    if lengths.is_empty() {
                        // We need more data to decode a length.
                        return Ok(None);
                    }

                    // Optimisation: try any lengths we already have.
                    // This optimisation avoids trying to fetch a useless piece if there is a
                    // zero-length object in potential segment padding.
                    let mut partial_object = Self {
                        prefix_data,
                        suffix_data: suffix_data.to_vec(),
                        lengths,
                    };

                    if let Ok(Some(_)) = partial_object.try_reconstruct_object(mapping) {
                        // The other lengths don't matter, because we've found the object.
                        // Return the completed object to the caller, so it can find that object.
                        return Ok(Some(partial_object));
                    } else {
                        // We need more data to decode the correct length.
                        return Ok(None);
                    }
                }
                Err(err) => {
                    // This length is invalid and needs to be skipped.
                    last_error = Some(err);
                    continue;
                }
            }
        }

        trace!(?lengths, ?last_error, "analysed possible lengths");

        if lengths.is_empty() {
            // All lengths were invalid
            Err(last_error.expect("last_error is set if lengths is empty; qed"))
        } else {
            Ok(Some(Self {
                prefix_data,
                suffix_data: suffix_data.to_vec(),
                lengths,
            }))
        }
    }

    /// Count the potential padding bytes in `maybe_padding_data`.
    /// These bytes have the padding byte value, but could still be part of the object.
    /// Returns the number of potential padding bytes.
    fn count_padding_bytes(maybe_padding_data: &[u8]) -> usize {
        maybe_padding_data
            .iter()
            .rev()
            .take_while(|byte| **byte == PADDING_BYTE_VALUE)
            .count()
    }

    /// Given the data for an object without any potential segment padding, returns a new
    /// `PartialObject`.
    ///
    /// Returns `Ok(None)` if more data is needed, or an error if object retrieval failed.
    ///
    /// The mapping is only used for error reporting.
    fn new_without_padding(
        data: &[u8],
        max_object_len: usize,
        mapping: GlobalObject,
    ) -> Result<Option<Self>, Error> {
        trace!(
            ?max_object_len,
            ?mapping,
            data = ?hex::encode(data),
            "trying to create new partial object without padding",
        );

        let Some((length_prefix_len, data_length)) =
            decode_data_length(data, max_object_len, mapping)?
        else {
            // Not enough data yet (this is a rare edge case).
            return Ok(None);
        };

        Ok(Some(Self {
            prefix_data: data.to_vec(),
            suffix_data: Vec::new(),
            lengths: [ObjectLength {
                data_length: length_prefix_len + data_length,
                ignored_padding_length: 0,
            }]
            .into(),
        }))
    }

    /// Add `piece_data` with padding to the end of this partial object.
    /// This method can also handle data that doesn't actually have any padding.
    pub fn add_piece_data_with_padding(&mut self, mut new_data: RawPieceData) {
        // Doesn't actually have padding
        if new_data.maybe_padding_data.is_empty() {
            let mut piece_data = new_data.prefix_data.to_vec();
            piece_data.extend_from_slice(&new_data.suffix_data);

            self.add_piece_data_without_padding(piece_data);
            return;
        }

        assert!(
            !self.has_padding(),
            "add_piece_data_with_padding() can only be called once: {self:?}, {new_data:?}"
        );

        // Count the padding bytes
        let object_max_segment_padding_length =
            Self::count_padding_bytes(&new_data.maybe_padding_data);

        // Add the new data to the existing data
        self.prefix_data.append(&mut new_data.prefix_data);
        // Keep the remaining non-padding and potential padding bytes
        self.prefix_data.append(&mut new_data.maybe_padding_data);
        self.suffix_data = new_data.suffix_data;

        // There's only one data length, but now we have multiple padding lengths
        let data_length = self.shortest_object_length();
        // Avoid a range panic if there's actually no padding, by overwriting the existing length
        for ignored_padding_length in 0..=object_max_segment_padding_length {
            self.lengths.insert(ObjectLength {
                data_length,
                ignored_padding_length,
            });
        }
    }

    /// Add padding-less `piece_data` to the end of this partial object.
    pub fn add_piece_data_without_padding(&mut self, mut piece_data: Vec<u8>) {
        if self.has_padding() {
            // If there might be padding, or there is suffix data, new data must be added at the end
            // of the suffix data.
            self.suffix_data.append(&mut piece_data);
        } else {
            // For performance, add the data to the existing prefix data.
            self.prefix_data.append(&mut piece_data);
        }
    }

    /// Returns true if this object has padding, or might have padding.
    ///
    /// Objects can have no padding in three different ways:
    /// - they aren't at the end of a segment
    /// - they are at the end of a segment, but all potential padding bytes are non-zero
    /// - we've checked the non-zero ignored padding lengths, and they were all invalid
    ///
    /// Panics if the object has no valid lengths left.
    fn has_padding(&self) -> bool {
        !self.suffix_data.is_empty()
            || self.lengths.len() > 1
            || self.largest_ignored_padding_length() > 0
    }

    /// Returns the longest padding length the object could possibly have.
    /// Adding padding can change the object length, but this is always returns the longest
    /// possible amount of padding bytes.
    ///
    /// Panics if the object has no valid lengths left.
    fn largest_ignored_padding_length(&self) -> usize {
        self.lengths
            .iter()
            .map(|length| length.ignored_padding_length)
            .max()
            .expect("other methods return an error if lengths becomes empty; qed")
    }

    /// Check the hash against all possible objects with enough data.
    /// If a possible object's data doesn't match the mapping hash, its length is removed.
    ///
    /// Returns valid object data, `Ok(None)` if we need more data, or an error if all possible
    /// objects have invalid hashes.
    ///
    /// Panics if it is called after there are no possible lengths left.
    /// (The previous call returned an error, so the caller should have stopped checking.)
    pub fn try_reconstruct_object(
        &mut self,
        mapping: GlobalObject,
    ) -> Result<Option<Vec<u8>>, Error> {
        trace!(?mapping, ?self, "checking available objects");

        // Try to decode the shortest object(s), until we don't have enough data.
        loop {
            let outcome = Vec::<u8>::decode(&mut self.shortest_object_data());

            trace!(
                checked_length = ?self.lengths.first(),
                data = ?hex::encode(self.shortest_object_data().remaining_data()),
                outcome = ?outcome.as_ref().map(hex::encode),
                "checking object with length",
            );

            let Ok(data) = outcome else {
                // Tell the caller we need more data, because the remaining lengths are longer.
                return Ok(None);
            };

            let data_hash = blake3_hash(&data);

            if data_hash == mapping.hash {
                return Ok(Some(data));
            } else {
                // If we've run out of lengths to try, return a hash mismatch error.
                // Otherwise, move on to the next longest object or next largest ignored padding.
                self.mark_shortest_object_hash_invalid(data_hash, mapping, data)?;
            }
        }
    }

    /// Returns the maximum amount of data that still needs to be downloaded.
    pub fn max_remaining_download_length(&self) -> usize {
        // We add the ignored padding length, because if we ignore those padding bytes, we need to
        // download extra bytes in another piece.
        let longest_download = self
            .lengths
            .iter()
            .map(|length| length.data_length + length.ignored_padding_length)
            .max()
            .expect("other methods return an error if lengths becomes empty; qed");

        longest_download.saturating_sub(self.fetched_data_length())
    }

    /// Returns the shortest possible length for the object, based on potential segment padding.
    ///
    /// If the segment padding is outside the length prefix, the object length is known, and only
    /// the object data varies.
    ///
    /// Panics if the object has no valid lengths left.
    fn shortest_object_length(&self) -> usize {
        self.lengths
            .first()
            .expect("other methods return an error if lengths becomes empty; qed")
            .data_length
    }

    /// Returns the longest possible amount of data that has already been fetched for the object,
    /// based on potential segment padding.
    pub fn fetched_data_length(&self) -> usize {
        self.prefix_data.len() + self.suffix_data.len()
    }

    /// Returns the shortest available data for the object, based on potential segment padding.
    ///
    /// If the segment padding is outside the length prefix, the object length is known, and only
    /// the object data varies. These ties are broken using the smallest ignored padding length.
    ///
    /// Panics if the object has no valid lengths left.
    fn shortest_object_data(&self) -> ObjectDataInput {
        let length = self
            .lengths
            .first()
            .expect("other methods return an error if lengths becomes empty; qed");

        ObjectDataInput::new(self, *length)
    }

    /// Remove the shortest data, because it has an invalid hash.
    /// Call this method if the shortest data has an incorrect hash.
    ///
    /// The mapping and data are only used for error reporting.
    ///
    /// Returns an error if there are no object lengths left to try.
    fn mark_shortest_object_hash_invalid(
        &mut self,
        data_hash: Blake3Hash,
        mapping: GlobalObject,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        trace!(data = %hex::encode(&data), "Invalid object data");

        if self.lengths.len() > 1 {
            // We still have more lengths to try.
            let ignored_err = Error::InvalidDataHash {
                data_hash,
                data_length: self.shortest_object_length(),
                mapping,
                #[cfg(test)]
                data: hex::encode(&data),
            };
            debug!(
                ?ignored_err,
                "Invalid data hash, trying next padding length"
            );

            self.lengths.pop_first();
            Ok(())
        } else {
            // There are no lengths left, so we know all the possible data/padding combinations are invalid.
            Err(Error::InvalidDataHash {
                data_hash,
                data_length: self.shortest_object_length(),
                mapping,
                #[cfg(test)]
                data: hex::encode(&data),
            })
        }
    }
}

/// A wrapper struct which impls Input for a PartialObject's data.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectDataInput<'obj> {
    /// A sub-slice of the partial object's prefix data, with the exact amount of padding required.
    prefix_data: &'obj [u8],

    /// The partial object's suffix data.
    suffix_data: &'obj [u8],

    /// The number of bytes read from the input so far.
    read_bytes: usize,
}

impl Input for ObjectDataInput<'_> {
    fn remaining_len(&mut self) -> Result<Option<usize>, parity_scale_codec::Error> {
        Ok(Some(self.remaining_bytes()))
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), parity_scale_codec::Error> {
        let buf_len = buf.len();
        if buf_len > self.remaining_bytes() {
            return Err("Not enough data to fill buffer".into());
        }

        self.prefix_data
            .iter()
            .chain(self.suffix_data)
            .skip(self.read_bytes)
            .zip(buf)
            .for_each(|(input_byte, buf_byte)| {
                *buf_byte = *input_byte;
            });

        self.read_bytes += buf_len;

        Ok(())
    }
}

impl<'obj> ObjectDataInput<'obj> {
    /// Creates a new `ObjectDataInput` object from a `PartialObject` and an object length.
    fn new(partial_object: &'obj PartialObject, object_length: ObjectLength) -> Self {
        let (prefix_data, suffix_data) = padded_data(
            &partial_object.prefix_data,
            object_length.ignored_padding_length,
            &partial_object.suffix_data,
            object_length.data_length,
        );

        Self::new_from_parts(prefix_data, suffix_data)
    }

    /// Creates a new `ObjectDataInput` object from a slice pair.
    fn new_from_parts(prefix_data: &'obj [u8], suffix_data: &'obj [u8]) -> Self {
        Self {
            prefix_data,
            suffix_data,
            read_bytes: 0,
        }
    }

    /// Returns the total length of the data.
    fn len(&self) -> usize {
        self.prefix_data.len() + self.suffix_data.len()
    }

    /// Returns true if the data is empty.
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.prefix_data.is_empty() && self.suffix_data.is_empty()
    }

    /// Returns the total length of the data that has not been read.
    fn remaining_bytes(&self) -> usize {
        self.len().saturating_sub(self.read_bytes)
    }

    /// Reads `bytes` of unread data, and returns it as a vector.
    fn data(&mut self, bytes: usize) -> Result<Vec<u8>, parity_scale_codec::Error> {
        let mut data = vec![0; bytes];

        self.read(&mut data).map(|()| data)
    }

    /// Reads and returns all the unread data, as a vector.
    fn remaining_data(&mut self) -> Vec<u8> {
        self.data(self.remaining_bytes())
            .expect("vec has exact capacity needed; qed")
    }
}

/// Returns two subslices of padded data from `prefix_data` and `suffix_data`, ignoring
/// `ignored_padding_length` bytes at the end of the prefix data.
///
/// Limits the total length to `data_length` (or less, if the available data is shorter).
fn padded_data<'data>(
    prefix_data: &'data [u8],
    ignored_padding_length: usize,
    suffix_data: &'data [u8],
    data_length: usize,
) -> (&'data [u8], &'data [u8]) {
    let prefix_data = &prefix_data[..min(
        prefix_data.len().saturating_sub(ignored_padding_length),
        data_length,
    )];

    let remaining_length = data_length.saturating_sub(prefix_data.len());
    let suffix_data = &suffix_data[..min(suffix_data.len(), remaining_length)];

    (prefix_data, suffix_data)
}

#[cfg(test)]
mod test {
    use super::*;
    use parity_scale_codec::Encode;
    use subspace_archiving::archiver::SegmentItem;

    #[test]
    fn padding_byte_value_constant() {
        let padding_byte = SegmentItem::Padding.encode();
        assert_eq!(padding_byte, vec![PADDING_BYTE_VALUE]);
    }
}
