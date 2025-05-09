//! Tests for DSN object fetching.

use super::*;
use crate::object_fetcher::partial_object::PADDING_BYTE_VALUE;
use crate::piece_getter::get_pieces_individually;
use async_trait::async_trait;
use futures::lock::Mutex;
use futures::Stream;
use parity_scale_codec::{Compact, CompactLen, Encode};
use rand::{thread_rng, RngCore};
use std::collections::HashMap;
use std::fmt::Debug;
use std::iter;
use subspace_core_primitives::hashes::blake3_hash;
use subspace_core_primitives::segments::{
    ArchivedBlockProgress, ArchivedHistorySegment, LastArchivedBlock, SegmentCommitment,
    SegmentHeader,
};
use subspace_logging::init_logger;

/// A piece getter that panics if called - used to make sure that caches work
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct PanicPieceGetter;

#[async_trait]
impl PieceGetter for PanicPieceGetter {
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        unreachable!("the cache failed to answer the request for piece: {piece_index:?}")
    }

    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        unreachable!("the cache failed to answer the request for pieces: {piece_indices:?}")
    }
}

/// A piece getter that counts how often each piece is requested.
/// Doesn't actually return any pieces.
#[derive(Clone, Debug, Default)]
struct CountingPieceGetter(Arc<Mutex<HashMap<PieceIndex, usize>>>);

impl CountingPieceGetter {
    /// Returns the number of times each piece index has been requested.
    async fn piece_index_counts(&self) -> HashMap<PieceIndex, usize> {
        self.0.lock().await.clone()
    }
}

#[async_trait]
impl PieceGetter for CountingPieceGetter {
    async fn get_piece(&self, piece_index: PieceIndex) -> anyhow::Result<Option<Piece>> {
        *self.0.lock().await.entry(piece_index).or_default() += 1;

        Ok(None)
    }

    async fn get_pieces<'a>(
        &'a self,
        piece_indices: Vec<PieceIndex>,
    ) -> anyhow::Result<
        Box<dyn Stream<Item = (PieceIndex, anyhow::Result<Option<Piece>>)> + Send + Unpin + 'a>,
    > {
        // This could be implemented more efficiently, but it's only used in tests
        get_pieces_individually(|piece_index| self.get_piece(piece_index), piece_indices)
    }
}

/// Converts the supplied number to a `PieceIndex`.
fn idx<N>(piece_index: N) -> PieceIndex
where
    N: TryInto<u64> + Copy + Debug,
    <N as TryInto<u64>>::Error: Debug,
{
    PieceIndex::from(piece_index.try_into().expect("must fit in u64"))
}

/// Returns a piece filled with random data.
fn random_piece() -> Piece {
    let mut piece_data = vec![0u8; Piece::SIZE];
    thread_rng().fill_bytes(piece_data.as_mut_slice());
    Piece::try_from(piece_data).unwrap()
}

/// Returns a piece filled with `data`, repeated as many times as needed.
/// This function can be used instead of random_piece() to help diagnose test failures.
///
/// Only the safe bytes of the piece are filled, the other bytes are left zeroed.
///
/// Panics if `data` is empty.
#[allow(dead_code)]
fn fill_piece<I: IntoIterator<Item = u8>>(data: I) -> Piece
where
    <I as IntoIterator>::IntoIter: Clone,
{
    let fill_data = data.into_iter().cycle();

    let mut piece = Piece::default();

    extract_raw_data_mut(vec![&mut piece])
        .zip(fill_data)
        .for_each(|(raw_data_byte, fill_byte)| {
            *raw_data_byte = fill_byte;
        });

    piece
}

/// Returns `len` encoded as a `Compact<u32>`.
fn compact_encoded(object_len: usize) -> Vec<u8> {
    Compact(object_len as u32).encode()
}

/// Returns the raw data from the supplied pieces.
fn extract_raw_data(pieces: Vec<&Piece>) -> impl DoubleEndedIterator<Item = u8> + '_ {
    pieces
        .into_iter()
        .flat_map(|piece| piece.record().to_raw_record_chunks().flatten())
        .copied()
}

/// Returns mutable raw data from the supplied pieces.
fn extract_raw_data_mut(
    pieces: Vec<&mut Piece>,
) -> impl DoubleEndedIterator<Item = &'_ mut u8> + '_ {
    pieces
        .into_iter()
        .flat_map(|piece| piece.record_mut().to_mut_raw_record_chunks().flatten())
}

/// Sets the data at the end of the piece to the correct byte values for padding.
fn write_potential_padding(mut piece: &mut Piece, bytes_from_end: usize) {
    let raw_data = extract_raw_data_mut(vec![&mut piece]);
    raw_data
        .rev()
        .take(bytes_from_end)
        .for_each(|raw_data_byte| {
            *raw_data_byte = PADDING_BYTE_VALUE;
        });
}

/// Writes a segment header at the start of the piece, given the remaining object length.
/// Returns the remaining raw data from the piece, after the segment header that has been written.
fn write_segment_header(mut piece: &mut Piece, remaining_len: usize) -> Vec<u8> {
    let segment_prefix_len = {
        let mut raw_data = extract_raw_data_mut(vec![&mut piece]);

        // Segment::V0 and SegmentItem::ParentSegmentHeader(_) variants
        let segment_variants = [0_u8, 4_u8];
        // SegmentHeader
        let segment_header = SegmentHeader::V0 {
            segment_index: u64::MAX.into(),
            segment_commitment: SegmentCommitment::default(),
            prev_segment_header_hash: Blake3Hash::default(),
            last_archived_block: LastArchivedBlock {
                number: u32::MAX,
                archived_progress: ArchivedBlockProgress::Partial(u32::MAX),
            },
        }
        .encode();
        // SegmentItem::BlockContinuation variant
        let block_continuation_variant = [3_u8];
        // BlockContinuation length (which must be equal to or greater than the remaining object length)
        let block_continuation_len = compact_encoded(remaining_len);

        let segment_prefix_len = segment_variants.len()
            + segment_header.len()
            + block_continuation_variant.len()
            + block_continuation_len.len();
        let segment_prefix = segment_variants
            .into_iter()
            .chain(segment_header)
            .chain(block_continuation_variant)
            .chain(block_continuation_len);
        let mut replaced_bytes = Vec::new();

        // Replace raw data bytes with the segment prefix
        (&mut raw_data)
            .take(segment_prefix_len)
            .zip(segment_prefix)
            .for_each(|(raw_data_byte, segment_prefix_byte)| {
                replaced_bytes.push(*raw_data_byte);
                *raw_data_byte = segment_prefix_byte;
            });

        assert_eq!(replaced_bytes.len(), segment_prefix_len);

        // Now put those bytes back after the segment header (because they can contain part of the object length)
        raw_data
            .take(replaced_bytes.len())
            .zip(replaced_bytes)
            .for_each(|(raw_data_byte, replaced_byte)| {
                *raw_data_byte = replaced_byte;
            });

        segment_prefix_len
    };

    let raw_data = extract_raw_data(vec![&piece])
        .skip(segment_prefix_len)
        .collect::<Vec<u8>>();
    assert_eq!(raw_data.len(), RawRecord::SIZE - segment_prefix_len);

    raw_data
}

/// Encodes an object length at the supplied offset in the piece(s).
///
/// If skipping padding at `(prefix_bytes, padding_bytes)`, writes `prefix_bytes` of the length,
/// then skips `padding_bytes` of padding, then writes the rest of the length.
fn write_object_length(
    pieces: Vec<&mut Piece>,
    offset: usize,
    object_len: usize,
    skip_padding: Option<(usize, usize)>,
) {
    let object_len_encoded = compact_encoded(object_len);
    let object_len_encoded_len = object_len_encoded.len();

    let mut bytes_written = 0;

    if let Some((prefix_bytes, padding_bytes)) = skip_padding {
        let mut raw_data = extract_raw_data_mut(pieces);

        (&mut raw_data)
            .skip(offset)
            .take(prefix_bytes)
            .zip(object_len_encoded.iter().take(prefix_bytes))
            .for_each(|(raw_data_byte, len_byte)| {
                *raw_data_byte = *len_byte;
                bytes_written += 1;
            });

        assert_eq!(bytes_written, prefix_bytes);

        raw_data
            .skip(padding_bytes)
            .take(object_len_encoded_len - prefix_bytes)
            .zip(object_len_encoded.iter().skip(prefix_bytes))
            .for_each(|(raw_data_byte, len_byte)| {
                *raw_data_byte = *len_byte;
                bytes_written += 1;
            });

        assert_eq!(bytes_written, object_len_encoded_len);
    } else {
        let raw_data = extract_raw_data_mut(pieces);
        raw_data
            .skip(offset)
            .take(object_len_encoded_len)
            .zip(object_len_encoded)
            .for_each(|(raw_data_byte, len_byte)| {
                *raw_data_byte = len_byte;
                bytes_written += 1;
            });

        assert_eq!(bytes_written, object_len_encoded_len);
    }
}

/// Creates a mapping from piece(s), start piece index, offset, and object length.
/// Returns the mapping and object data.
///
/// If supplied:
/// - `skip_padding` is the amount of padding to skip, and
/// - `raw_data_after_segment_header` is the raw data from the piece at the start of the segment,
///   after the segment header has been written to it.
fn create_mapping(
    pieces: Vec<&Piece>,
    start_piece_index: usize,
    offset: usize,
    object_len: usize,
    mut skip_padding: Option<usize>,
    raw_data_after_segment_header: Option<Vec<u8>>,
) -> (GlobalObject, Vec<u8>) {
    // Simplify the code below by setting the default skip padding value.
    if raw_data_after_segment_header.is_some() && skip_padding.is_none() {
        skip_padding = Some(0);
    }
    if skip_padding.is_some() {
        assert!(
            raw_data_after_segment_header.is_some(),
            "can only skip padding if there is more data in the next segment"
        );
    }

    let object_len_encoded = compact_encoded(object_len);
    let pieces_len = pieces.len();
    let mut raw_data = extract_raw_data(pieces).collect::<Vec<u8>>();

    if let (Some(skip_padding), Some(raw_data_after_segment_header)) =
        (skip_padding, raw_data_after_segment_header)
    {
        // Find the next piece index with a segment header
        let segment_header_piece_index =
            start_piece_index.next_multiple_of(ArchivedHistorySegment::NUM_PIECES);
        // And the source piece before it can have padding
        let padding_piece_index = idx(segment_header_piece_index).prev_source_index();

        // Skip padding if needed
        if let Some(padding_piece_index) = padding_piece_index
            && skip_padding > 0
        {
            let original_len = raw_data.len();

            let byte_position_in_raw_data = byte_position_in_extract_raw_data(
                u64::from(padding_piece_index) as usize,
                start_piece_index,
                pieces_len,
                original_len,
            )
            .unwrap_or_else(|| {
                panic!(
                    "must have padding when skip_padding is set: \
                skip_padding: {skip_padding} bytes, \
                raw_data_after_segment_header: {} bytes, \
                padding_piece_index: {padding_piece_index}, \
                start_piece_index: {start_piece_index}, \
                pieces_len: {pieces_len}, \
                original_len: {original_len}",
                    raw_data_after_segment_header.len(),
                )
            });

            // Delete the padding bytes we want to skip
            let replaced_padding_data = raw_data
                .splice(
                    // The padding range we want to skip
                    byte_position_in_raw_data + RawRecord::SIZE - skip_padding
                        ..byte_position_in_raw_data + RawRecord::SIZE,
                    // Delete the padding bytes
                    iter::empty(),
                )
                .collect::<Vec<_>>();

            assert_eq!(raw_data.len(), original_len - skip_padding);
            assert_eq!(
                replaced_padding_data,
                vec![PADDING_BYTE_VALUE; skip_padding],
                "padding bytes must be zeroed: \
                skip_padding: {skip_padding} bytes, \
                raw_data_after_segment_header: {} bytes, \
                padding_piece_index: {padding_piece_index}, \
                start_piece_index: {start_piece_index}, \
                pieces_len: {pieces_len}, \
                original_len: {original_len}, \
                raw_data: {} ",
                raw_data_after_segment_header.len(),
                raw_data.len(),
            );
        }

        // If this is a segment header piece, the offset will have already skipped the segment
        // header. If it's any other piece, skip it now.
        if idx(start_piece_index).position() != 0 {
            let original_len = raw_data.len();

            if let Some(mut byte_position_in_raw_data) = byte_position_in_extract_raw_data(
                segment_header_piece_index,
                start_piece_index,
                pieces_len,
                original_len,
            ) {
                byte_position_in_raw_data -= skip_padding;

                // Replace the entire piece with just the raw data after the segment header
                let _replaced_piece_data = raw_data
                    .splice(
                        // The entire piece range, in bytes
                        byte_position_in_raw_data..byte_position_in_raw_data + RawRecord::SIZE,
                        // The remaining data from the piece, excluding the segment header
                        raw_data_after_segment_header.iter().copied(),
                    )
                    .collect::<Vec<_>>();

                assert_eq!(
                    raw_data.len(),
                    original_len - RawRecord::SIZE + raw_data_after_segment_header.len()
                );
            }
        }
    }

    let object_data = raw_data
        .into_iter()
        .skip(offset + object_len_encoded.len())
        .take(object_len)
        .collect::<Vec<u8>>();
    assert_eq!(object_data.len(), object_len);

    (
        GlobalObject {
            piece_index: idx(start_piece_index),
            offset: offset as u32,
            hash: blake3_hash(&object_data),
        },
        object_data,
    )
}

/// Returns the byte position of a piece in the raw data, after checking it is valid.
/// Returns `None` if the piece index is not in the supplied pieces.
fn byte_position_in_extract_raw_data(
    piece_index: usize,
    start_piece_index: usize,
    pieces_len: usize,
    raw_data_len: usize,
) -> Option<usize> {
    let piece_position_in_raw_data = (piece_index - start_piece_index) / 2;

    if piece_position_in_raw_data >= pieces_len {
        return None;
    }

    assert!(
        piece_position_in_raw_data < max_supported_object_length().div_ceil(RawRecord::SIZE),
        "object length not supported: {piece_position_in_raw_data} < {}",
        max_supported_object_length().div_ceil(RawRecord::SIZE)
    );

    let byte_position_in_raw_data = piece_position_in_raw_data * RawRecord::SIZE;
    assert!(
        byte_position_in_raw_data < raw_data_len,
        "byte position not in raw data: {byte_position_in_raw_data} < {raw_data_len}",
    );

    Some(byte_position_in_raw_data)
}

/// Creates an object fetcher from a piece and piece index.
fn create_object_fetcher(
    pieces: Vec<Piece>,
    start_piece_index: usize,
    first_piece_getter: Option<Box<dyn PieceGetter + Send + Sync>>,
    last_piece_getter: Option<Box<dyn PieceGetter + Send + Sync>>,
) -> ObjectFetcher<impl PieceGetter> {
    let piece_getter = pieces
        .into_iter()
        .enumerate()
        .map(|(i, piece)| (idx(start_piece_index + (i * 2)), piece))
        .collect::<Vec<(PieceIndex, Piece)>>();

    // Add the supplied first and last piece getters
    let piece_getter = first_piece_getter
        .with_fallback(piece_getter)
        .with_fallback(last_piece_getter);

    ObjectFetcher::new(Arc::new(piece_getter), max_supported_object_length())
}

#[test]
fn max_object_length_constant() {
    assert_eq!(
        Compact::<u32>::compact_len(&(max_supported_object_length() as u32)),
        MAX_ENCODED_LENGTH_SIZE,
    );
}

/// This test covers objects that are in a single piece with no segment padding.
#[tokio::test(flavor = "multi_thread")]
async fn get_single_piece_object_no_padding() {
    init_logger();

    // We need to cover 3 known good cases:

    // Set up the test case
    // - start of segment, offset already excludes segment header
    let offset = max_segment_header_encoded_size() + 1;
    let object_len = 100;
    let piece_index = 0;

    // Generate random piece data
    let mut piece = random_piece();

    // Set up the object, mapping, and object fetcher
    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    let object_fetcher = create_object_fetcher(vec![piece.clone()], piece_index, None, None);

    // Now get the object back
    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - middle of segment
    let offset = 0;
    let object_len = 1000;
    let piece_index = 60;

    let mut piece = random_piece();

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    let object_fetcher = create_object_fetcher(vec![piece.clone()], piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - end of segment, no padding
    let offset = 0;
    let object_len = 10_000;
    let piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece = random_piece();

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    let object_fetcher = create_object_fetcher(vec![piece.clone()], piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));
}

/// This test covers objects that are in multiple pieces with no segment padding.
#[tokio::test(flavor = "multi_thread")]
async fn get_multi_piece_object_no_padding() {
    init_logger();

    // We need to cover 3 known good cases:

    // Set up the test case
    // - start of segment, offset already excludes segment header
    let object_len = 100;
    let offset = RawRecord::SIZE - (object_len + compact_encoded(object_len).len()) / 2;
    let start_piece_index = 0;

    // Generate random piece data
    let mut piece1 = random_piece();
    let piece2 = random_piece();

    // Set up the object, mapping, and object fetcher
    write_object_length(vec![&mut piece1], offset, object_len, None);
    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        None,
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1.clone(), piece2.clone()],
        start_piece_index,
        None,
        None,
    );

    // Now get the object back
    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - middle of segment
    let object_len = 1000;
    let offset = RawRecord::SIZE - object_len / 2;
    let start_piece_index = 60;

    let mut piece1 = random_piece();
    let piece2 = random_piece();

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        None,
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1.clone(), piece2.clone()],
        start_piece_index,
        None,
        None,
    );

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - end of segment, no padding
    let object_len = 10_000;
    let offset = RawRecord::SIZE - object_len / 2;
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 4;

    let mut piece1 = random_piece();
    let piece2 = random_piece();

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        None,
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1.clone(), piece2.clone()],
        start_piece_index,
        None,
        None,
    );

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));
}

/// This test covers objects that are in the last piece of a segment, with potential segment
/// padding.
#[tokio::test(flavor = "multi_thread")]
async fn get_single_piece_object_potential_padding() {
    init_logger();

    // We need to cover 4 known good cases:

    // - end of segment, end of object goes into padding (but not into the next segment)
    // 3 sub-cases:
    // - - potential padding that has the wrong byte value for padding
    let object_len = 10;
    let offset = RawRecord::SIZE - object_len - compact_encoded(object_len).len();
    let piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece = random_piece();

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    let object_fetcher = create_object_fetcher(vec![piece.clone()], piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - potential padding that has the right byte value for padding, but is part of the object
    let object_len = 10;
    let offset = RawRecord::SIZE - object_len - compact_encoded(object_len).len();
    let piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    // Generate random piece data, but put potential padding at the end
    let mut piece = random_piece();
    write_potential_padding(&mut piece, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    let object_fetcher = create_object_fetcher(vec![piece.clone()], piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - potential padding that has the right byte value for padding, but only some is part of the object
    let object_len = 10;
    let unused_padding = 1;
    let offset = RawRecord::SIZE - object_len - compact_encoded(object_len).len() - unused_padding;
    let piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    // Generate random piece data, but put potential padding at the end
    let mut piece = random_piece();
    write_potential_padding(&mut piece, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    let object_fetcher = create_object_fetcher(vec![piece.clone()], piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - end of segment, start of object length is in potential padding (but object does not cross into the next segment)
    let object_len = 2;
    let offset = RawRecord::SIZE - object_len - compact_encoded(object_len).len();
    let piece_index = ArchivedHistorySegment::NUM_PIECES - 2;
    assert!(offset >= RawRecord::SIZE - MAX_SEGMENT_PADDING - 1);

    let mut piece = random_piece();
    write_potential_padding(&mut piece, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    let object_fetcher = create_object_fetcher(vec![piece.clone()], piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - end of segment, zero-length object in potential padding (but object does not cross into the next segment)
    let object_len = 0;
    let offset = RawRecord::SIZE - object_len - compact_encoded(object_len).len();
    let piece_index = ArchivedHistorySegment::NUM_PIECES - 2;
    assert!(offset >= RawRecord::SIZE - MAX_SEGMENT_PADDING - 1);

    let mut piece = random_piece();
    write_potential_padding(&mut piece, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    let object_fetcher = create_object_fetcher(vec![piece.clone()], piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));
}

/// This test covers objects that end in the last piece of a segment, with potential padding.
#[tokio::test(flavor = "multi_thread")]
async fn get_multi_piece_object_potential_padding() {
    init_logger();

    // We need to cover one known good case:

    // - end of segment, end of object goes into padding (but not into the next segment)
    // 3 sub-cases:
    // - - potential padding that has the wrong byte value for padding
    let object_len = 100 + RawRecord::SIZE;
    let offset = 2 * RawRecord::SIZE - object_len - compact_encoded(object_len).len();
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 4;

    let mut piece1 = random_piece();
    let piece2 = random_piece();

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        None,
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1.clone(), piece2.clone()],
        start_piece_index,
        None,
        None,
    );

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - potential padding that has the right byte value for padding, but is part of the object
    let object_len = 1000 + RawRecord::SIZE;
    let offset = 2 * RawRecord::SIZE - object_len - compact_encoded(object_len).len();
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 4;

    // Generate random piece data, but put potential padding at the end
    let mut piece1 = random_piece();
    let mut piece2 = random_piece();
    write_potential_padding(&mut piece2, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        None,
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1.clone(), piece2.clone()],
        start_piece_index,
        None,
        None,
    );

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - potential padding that has the right byte value for padding, but only some is part of the object
    let object_len = 10_000 + RawRecord::SIZE;
    let unused_padding = 1;
    let offset =
        2 * RawRecord::SIZE - object_len - compact_encoded(object_len).len() - unused_padding;
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 4;

    // Generate random piece data, but put potential padding at the end
    let mut piece1 = random_piece();
    let mut piece2 = random_piece();
    write_potential_padding(&mut piece2, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        None,
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1.clone(), piece2.clone()],
        start_piece_index,
        None,
        None,
    );

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));
}

/// This test covers objects that are split across multiple segments, including padding and segment
/// headers. They all have their lengths outside the padding.
#[tokio::test(flavor = "multi_thread")]
async fn get_multi_piece_object_length_outside_padding() {
    init_logger();

    // We need to cover 6 known good cases:

    // - end of segment, end of object goes into padding, and one piece into the next segment
    // 3 sub-cases:
    // - - potential padding that has the wrong byte value for padding
    let object_len = 1000;
    let offset = RawRecord::SIZE - object_len / 2 - compact_encoded(object_len).len();
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece1 = random_piece();
    let mut piece2 = random_piece();

    write_object_length(vec![&mut piece1], offset, object_len, None);
    // Also test we can handle block continuations that are longer than the object
    let after_segment_header = write_segment_header(&mut piece2, object_len / 2 + 100);

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        Some(after_segment_header),
    );
    let object_fetcher =
        create_object_fetcher(vec![piece1, piece2.clone()], start_piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - potential padding that has the right byte value for padding, but is part of the object
    let object_len = 100;
    let offset = RawRecord::SIZE - object_len / 2 - compact_encoded(object_len).len();
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece1 = random_piece();
    let mut piece2 = random_piece();
    write_potential_padding(&mut piece1, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let after_segment_header = write_segment_header(&mut piece2, object_len / 2);

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        Some(after_segment_header),
    );
    let object_fetcher =
        create_object_fetcher(vec![piece1, piece2.clone()], start_piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - actual padding that has the right byte value for padding, and isn't part of the object
    let object_len = 10;
    let skip_padding = 1;
    let offset = RawRecord::SIZE - object_len / 2 - compact_encoded(object_len).len();
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece1 = random_piece();
    let mut piece2 = random_piece();
    write_potential_padding(&mut piece1, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let after_segment_header = write_segment_header(&mut piece2, object_len / 2 + skip_padding);

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        Some(skip_padding),
        Some(after_segment_header),
    );
    let object_fetcher =
        create_object_fetcher(vec![piece1, piece2.clone()], start_piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - end of segment, end of object goes into padding, and multiple pieces from both segments
    // 3 sub-cases:
    // - - potential padding that has the wrong byte value for padding
    let object_len = 3 * RawRecord::SIZE;
    let offset = RawRecord::SIZE / 2 - compact_encoded(object_len).len();
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 4;

    let mut piece1 = random_piece();
    let piece2 = random_piece();
    let mut piece3 = random_piece();
    let piece4 = random_piece();

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let after_segment_header = write_segment_header(&mut piece3, object_len / 2);

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2, &piece3, &piece4],
        start_piece_index,
        offset,
        object_len,
        None,
        Some(after_segment_header),
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1, piece2, piece3, piece4.clone()],
        start_piece_index,
        None,
        None,
    );

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 6), piece4)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - potential padding that has the right byte value for padding, but is part of the object

    // Leave space for the block and object lengths, segment header data, and segment, header, and
    // block enum variants. Strictly we want compact_encoded(object_len) here, but it doesn't
    // change the encoded size in practice.
    let overhead =
        2 * compact_encoded(4 * RawRecord::SIZE).len() + max_segment_header_encoded_size() + 3;
    let object_len = 4 * RawRecord::SIZE - overhead;
    let offset = 0;
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 4;

    let mut piece1 = random_piece();
    let mut piece2 = random_piece();
    let mut piece3 = random_piece();
    let piece4 = random_piece();
    write_potential_padding(&mut piece2, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let after_segment_header = write_segment_header(&mut piece3, 2 * RawRecord::SIZE - overhead);

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2, &piece3, &piece4],
        start_piece_index,
        offset,
        object_len,
        None,
        Some(after_segment_header),
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1, piece2, piece3, piece4.clone()],
        start_piece_index,
        None,
        None,
    );

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 6), piece4)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - actual padding that has the right byte value for padding, and isn't part of the object

    // Leave space for the block and object lengths, segment header data, and segment, header, and
    // block enum variants. Strictly we want compact_encoded(object_len) here, but it doesn't
    // change the encoded size in practice.
    let skip_padding = MAX_SEGMENT_PADDING;
    let overhead = 2 * compact_encoded(6 * RawRecord::SIZE).len()
        + max_segment_header_encoded_size()
        + 3
        + skip_padding;
    let object_len = 6 * RawRecord::SIZE - overhead;
    let offset = 0;
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 6;

    let mut piece1 = random_piece();
    let piece2 = random_piece();
    let mut piece3 = random_piece();
    let mut piece4 = random_piece();
    let piece5 = random_piece();
    let piece6 = random_piece();
    write_potential_padding(&mut piece3, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let after_segment_header = write_segment_header(&mut piece4, 3 * RawRecord::SIZE - overhead);

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2, &piece3, &piece4, &piece5, &piece6],
        start_piece_index,
        offset,
        object_len,
        Some(skip_padding),
        Some(after_segment_header),
    );
    let object_fetcher = create_object_fetcher(
        vec![piece1, piece2, piece3, piece4, piece5, piece6.clone()],
        start_piece_index,
        None,
        None,
    );

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 10), piece6)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));
}

/// This test covers objects that are split across multiple segments, including padding and
/// segment headers. They all have their lengths overlapping the padding.
#[tokio::test(flavor = "multi_thread")]
async fn get_multi_piece_object_length_overlaps_padding() {
    init_logger();

    // We need to cover these known good cases:

    // - end of segment, end of object length overlaps start of padding, and one piece into the next segment
    // 3 sub-cases:
    // - - potential padding that has the wrong byte value for padding
    let in_first_segment = 1;
    let object_len = 64;
    let offset = RawRecord::SIZE - in_first_segment;
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece1 = random_piece();
    let mut piece2 = random_piece();
    write_potential_padding(&mut piece1, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece1, &mut piece2], offset, object_len, None);
    // The first byte of the length should be the last byte in the first piece.
    // The two-byte SCALE length encoding is `(len >> 8) << 2 | 0x01`.
    assert_eq!(extract_raw_data(vec![&piece1]).last(), Some(0x01));
    // The second byte of the length should be the first byte in the second piece (temporarily).
    // The two-byte SCALE length encoding is the raw byte value.
    assert_eq!(extract_raw_data(vec![&piece2]).next(), Some(0x01));

    let after_segment_header = write_segment_header(
        &mut piece2,
        object_len + compact_encoded(object_len).len() - in_first_segment,
    );
    // The second byte of the length should be the first byte after the segment header.
    assert_eq!(after_segment_header[0], 0x01);

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        Some(after_segment_header),
    );
    let object_fetcher =
        create_object_fetcher(vec![piece1, piece2.clone()], start_piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - potential padding that has the right byte value for padding, but is part of the length

    // The first SCALE-encoded number that ends in 0x00 is 16384 (except for zero).
    let object_len = 16384;
    let in_first_segment = compact_encoded(object_len).len();
    let offset = RawRecord::SIZE - in_first_segment;
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece1 = random_piece();
    let mut piece2 = random_piece();
    write_potential_padding(&mut piece1, MAX_SEGMENT_PADDING);

    write_object_length(vec![&mut piece1, &mut piece2], offset, object_len, None);
    // The second byte of the length should be the last byte in the first piece.
    // The two-byte SCALE length encoding is the raw byte value.
    assert_eq!(extract_raw_data(vec![&piece1]).last(), Some(0x00));

    let after_segment_header = write_segment_header(
        &mut piece2,
        object_len + compact_encoded(object_len).len() - in_first_segment,
    );

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        Some(after_segment_header),
    );
    let object_fetcher =
        create_object_fetcher(vec![piece1, piece2.clone()], start_piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - - actual padding that has the right byte value for padding, it could be part of the length, but isn't
    let object_len = 16384;
    let skip_padding = 1;
    let in_first_segment = compact_encoded(object_len).len() - skip_padding;
    let offset = RawRecord::SIZE - in_first_segment - skip_padding;
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece1 = random_piece();
    let mut piece2 = random_piece();
    write_potential_padding(&mut piece1, MAX_SEGMENT_PADDING);

    write_object_length(
        vec![&mut piece1, &mut piece2],
        offset,
        object_len,
        Some((in_first_segment, skip_padding)),
    );
    // The last byte in the first piece should be potential padding.
    assert_eq!(extract_raw_data(vec![&piece1]).last(), Some(0x00));
    // The last byte of the length should be the first byte in the second piece (temporarily).
    // The four-byte SCALE length encoding is the raw byte value.
    assert_eq!(extract_raw_data(vec![&piece2]).next(), Some(0x00));

    let after_segment_header = write_segment_header(
        &mut piece2,
        object_len + compact_encoded(object_len).len() - in_first_segment + skip_padding,
    );
    // The last byte of the length should be the first byte after the segment header.
    assert_eq!(extract_raw_data(vec![&piece2]).next(), Some(0x00));

    let (mapping, object_data) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        Some(skip_padding),
        Some(after_segment_header),
    );
    let object_fetcher =
        create_object_fetcher(vec![piece1, piece2.clone()], start_piece_index, None, None);

    let mut cache = None;
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(start_piece_index + 2), piece2)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));
}

/// Does the last piece cache work as expected?
#[tokio::test(flavor = "multi_thread")]
async fn last_piece_cache_works() {
    init_logger();

    // We need to cover 4 known good cases:
    // (empty caches are tested by the tests above)

    // - single mapping, cache already has the piece (middle of segment)
    let offset = 0;
    let object_len = 1000;
    let piece_index = 60;

    let mut piece = random_piece();

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    // Passing a PanicPieceGetter as the first piece getter makes sure the last piece cache is used before the ObjectFetcher's piece getters
    let object_fetcher = create_object_fetcher(
        vec![piece.clone()],
        piece_index,
        Some(Box::new(PanicPieceGetter)),
        Some(Box::new(PanicPieceGetter)),
    );

    let mut cache = Some((idx(piece_index), piece.clone()));
    let fetched_data = object_fetcher.fetch_object(mapping, &mut cache).await;
    assert_eq!(cache, Some((idx(piece_index), piece)));
    assert_eq!(fetched_data.map(hex::encode), Ok(hex::encode(object_data)));

    // - single mapping in a batch, internal cache not used (end of segment)
    let offset = 0;
    let object_len = 10_000;
    let piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece = random_piece();

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping, object_data) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);
    // Passing a PanicPieceGetter as the last piece getter makes sure the ObjectFetcher's piece getters are used
    let object_fetcher = create_object_fetcher(
        vec![piece],
        piece_index,
        None,
        Some(Box::new(PanicPieceGetter)),
    );

    let fetched_data = object_fetcher
        .fetch_objects(GlobalObjectMapping::from_object(mapping))
        .await
        .unwrap();
    assert_eq!(
        fetched_data
            .iter()
            .map(hex::encode)
            .collect::<Vec<String>>(),
        vec![hex::encode(object_data)],
    );

    // - multiple mappings in a batch, single piece requested once (end of segment)
    let offset = 0;
    let object_len = 10;
    let piece_index = ArchivedHistorySegment::NUM_PIECES - 2;

    let mut piece = random_piece();

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping1, object_data1) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);

    let offset = object_len + compact_encoded(object_len).len();
    let object_len = 20;

    write_object_length(vec![&mut piece], offset, object_len, None);
    let (mapping2, object_data2) =
        create_mapping(vec![&piece], piece_index, offset, object_len, None, None);

    // Passing a CountingPieceGetter as the first piece getter counts each request, except for
    // requests handled by ObjectFetcher::fetch_objects() internal last piece cache.
    let counter = CountingPieceGetter::default();
    let object_fetcher = create_object_fetcher(
        vec![piece],
        piece_index,
        Some(Box::new(counter.clone())),
        Some(Box::new(PanicPieceGetter)),
    );

    let fetched_data = object_fetcher
        .fetch_objects(GlobalObjectMapping::from_objects(vec![mapping1, mapping2]))
        .await
        .unwrap();
    assert_eq!(
        fetched_data
            .iter()
            .map(hex::encode)
            .collect::<Vec<String>>(),
        vec![hex::encode(object_data1), hex::encode(object_data2)],
    );
    assert_eq!(
        counter.piece_index_counts().await,
        [(idx(piece_index), 1)].into(),
    );

    // - multiple mappings in a batch, multiple pieces requested once each (middle of segment)
    let offset = 0;
    let object_len = 10;
    let start_piece_index = ArchivedHistorySegment::NUM_PIECES / 2;

    let mut piece1 = random_piece();
    let mut piece2 = random_piece();

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let (mapping1, object_data1) = create_mapping(
        vec![&piece1],
        start_piece_index,
        offset,
        object_len,
        None,
        None,
    );

    let object_len = 20;
    let offset = RawRecord::SIZE - object_len / 2;

    write_object_length(vec![&mut piece1], offset, object_len, None);
    let (mapping2, object_data2) = create_mapping(
        vec![&piece1, &piece2],
        start_piece_index,
        offset,
        object_len,
        None,
        None,
    );

    let object_len = 50;
    let offset = RawRecord::SIZE / 2;

    write_object_length(vec![&mut piece2], offset, object_len, None);
    let (mapping3, object_data3) = create_mapping(
        vec![&piece2],
        start_piece_index + 2,
        offset,
        object_len,
        None,
        None,
    );

    // Passing a CountingPieceGetter as the first piece getter counts each request, except for
    // requests handled by ObjectFetcher::fetch_objects() internal last piece cache.
    let counter = CountingPieceGetter::default();
    let object_fetcher = create_object_fetcher(
        vec![piece1, piece2],
        start_piece_index,
        Some(Box::new(counter.clone())),
        Some(Box::new(PanicPieceGetter)),
    );

    let fetched_data = object_fetcher
        .fetch_objects(GlobalObjectMapping::from_objects(vec![
            mapping1, mapping2, mapping3,
        ]))
        .await
        .unwrap();
    assert_eq!(
        fetched_data
            .iter()
            .map(hex::encode)
            .collect::<Vec<String>>(),
        vec![
            hex::encode(object_data1),
            hex::encode(object_data2),
            hex::encode(object_data3)
        ],
    );
    assert_eq!(
        counter.piece_index_counts().await,
        [(idx(start_piece_index), 1), (idx(start_piece_index + 2), 1)].into(),
    );
}
