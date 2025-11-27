//! Sector-related data structures
//!
//! Sectors and corresponding metadata created by functions in [`plotting`](crate::plotting) module
//! have a specific structure, represented by data structured in this module.
//!
//! It is typically not needed to construct these data structures explicitly outside of this crate,
//! instead they will be returned as a result of certain operations (like plotting).

use bitvec::prelude::*;
use parity_scale_codec::{Decode, Encode};
use rayon::prelude::*;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::{mem, slice};
use subspace_core_primitives::checksum::Blake3Checksummed;
use subspace_core_primitives::hashes::{Blake3Hash, blake3_hash};
use subspace_core_primitives::pieces::{PieceOffset, Record, RecordCommitment, RecordWitness};
use subspace_core_primitives::sectors::{SBucket, SectorIndex};
use subspace_core_primitives::segments::{HistorySize, SegmentIndex};
use thiserror::Error;
use tracing::debug;

/// Size of the part of the plot containing record chunks (s-buckets).
///
/// Total size of the plot can be computed with [`sector_size()`].
#[inline]
pub const fn sector_record_chunks_size(pieces_in_sector: u16) -> usize {
    pieces_in_sector as usize * Record::SIZE
}

/// Size of the part of the plot containing record metadata.
///
/// Total size of the plot can be computed with [`sector_size()`].
#[inline]
pub const fn sector_record_metadata_size(pieces_in_sector: u16) -> usize {
    pieces_in_sector as usize * RecordMetadata::encoded_size()
}

/// Exact sector plot size (sector contents map, record chunks, record metadata).
///
/// NOTE: Each sector also has corresponding fixed size metadata whose size can be obtained with
/// [`SectorMetadataChecksummed::encoded_size()`], size of the record chunks (s-buckets) with
/// [`sector_record_chunks_size()`] and size of record commitments and witnesses with
/// [`sector_record_metadata_size()`]. This function just combines those three together for
/// convenience.
#[inline]
pub const fn sector_size(pieces_in_sector: u16) -> usize {
    sector_record_chunks_size(pieces_in_sector)
        + sector_record_metadata_size(pieces_in_sector)
        + SectorContentsMap::encoded_size(pieces_in_sector)
        + Blake3Hash::SIZE
}

/// Metadata of the plotted sector
#[derive(Debug, Encode, Decode, Clone)]
pub struct SectorMetadata {
    /// Sector index
    pub sector_index: SectorIndex,
    /// Number of pieces stored in this sector
    pub pieces_in_sector: u16,
    /// S-bucket sizes in a sector
    pub s_bucket_sizes: Box<[u16; Record::NUM_S_BUCKETS]>,
    /// Size of the blockchain history at time of sector creation
    pub history_size: HistorySize,
}

impl SectorMetadata {
    /// Returns offsets of each s-bucket relatively to the beginning of the sector (in chunks)
    pub fn s_bucket_offsets(&self) -> Box<[u32; Record::NUM_S_BUCKETS]> {
        let s_bucket_offsets = self
            .s_bucket_sizes
            .iter()
            .map({
                let mut base_offset = 0;

                move |s_bucket_size| {
                    let offset = base_offset;
                    base_offset += u32::from(*s_bucket_size);
                    offset
                }
            })
            .collect::<Box<_>>();

        assert_eq!(s_bucket_offsets.len(), Record::NUM_S_BUCKETS);
        let mut s_bucket_offsets = ManuallyDrop::new(s_bucket_offsets);
        // SAFETY: Original memory is not dropped, number of elements checked above
        unsafe { Box::from_raw(s_bucket_offsets.as_mut_ptr() as *mut [u32; Record::NUM_S_BUCKETS]) }
    }
}

/// Same as [`SectorMetadata`], but with checksums verified during SCALE encoding/decoding
#[derive(Debug, Clone, Encode, Decode)]
pub struct SectorMetadataChecksummed(Blake3Checksummed<SectorMetadata>);

impl From<SectorMetadata> for SectorMetadataChecksummed {
    #[inline]
    fn from(value: SectorMetadata) -> Self {
        Self(Blake3Checksummed(value))
    }
}

impl Deref for SectorMetadataChecksummed {
    type Target = SectorMetadata;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0.0
    }
}

impl DerefMut for SectorMetadataChecksummed {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0.0
    }
}

impl SectorMetadataChecksummed {
    /// Size of encoded checksummed sector metadata.
    ///
    /// For sector plot size use [`sector_size()`].
    #[inline]
    pub fn encoded_size() -> usize {
        let default = SectorMetadataChecksummed::from(SectorMetadata {
            sector_index: 0,
            pieces_in_sector: 0,
            // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
            // SAFETY: Data structure filled with zeroes is a valid invariant
            s_bucket_sizes: unsafe { Box::new_zeroed().assume_init() },
            history_size: HistorySize::from(SegmentIndex::ZERO),
        });

        default.encoded_size()
    }
}

/// Commitment and witness corresponding to the same record
#[derive(Debug, Default, Clone, Encode, Decode)]
pub(crate) struct RecordMetadata {
    /// Record commitment
    pub(crate) commitment: RecordCommitment,
    /// Record witness
    pub(crate) witness: RecordWitness,
    /// Checksum (hash) of the whole piece
    pub(crate) piece_checksum: Blake3Hash,
}

impl RecordMetadata {
    pub(crate) const fn encoded_size() -> usize {
        RecordWitness::SIZE + RecordCommitment::SIZE + Blake3Hash::SIZE
    }
}

/// Raw sector before it is transformed and written to plot, used during plotting
#[derive(Debug, Clone)]
pub(crate) struct RawSector {
    /// List of records, likely downloaded from the network
    pub(crate) records: Vec<Record>,
    /// Metadata (commitment and witness) corresponding to the same record
    pub(crate) metadata: Vec<RecordMetadata>,
}

impl RawSector {
    /// Create new raw sector with internal vectors being allocated and filled with default values
    pub(crate) fn new(pieces_in_sector: u16) -> Self {
        Self {
            records: Record::new_zero_vec(usize::from(pieces_in_sector)),
            metadata: vec![RecordMetadata::default(); usize::from(pieces_in_sector)],
        }
    }
}

// Bit array containing space for bits equal to the number of s-buckets in a record
type SingleRecordBitArray = BitArray<[u8; Record::NUM_S_BUCKETS / u8::BITS as usize]>;

const SINGLE_RECORD_BIT_ARRAY_SIZE: usize = mem::size_of::<SingleRecordBitArray>();

// TODO: I really tried to avoid `count_ones()`, but wasn't able to with safe Rust due to lifetimes
/// Wrapper data structure that allows to iterate mutably over encoded chunks bitfields, while
/// maintaining up-to-date number of encoded chunks
///
/// ## Panics
/// Panics on drop if too many chunks are encoded
#[derive(Debug)]
pub struct EncodedChunksUsed<'a> {
    encoded_record_chunks_used: &'a mut SingleRecordBitArray,
    num_encoded_record_chunks: &'a mut SBucket,
    potentially_updated: bool,
}

impl Drop for EncodedChunksUsed<'_> {
    fn drop(&mut self) {
        if self.potentially_updated {
            let num_encoded_record_chunks = self.encoded_record_chunks_used.count_ones();
            assert!(num_encoded_record_chunks <= SBucket::MAX.into());
            *self.num_encoded_record_chunks = SBucket::try_from(num_encoded_record_chunks)
                .expect("Checked with explicit assert above; qed");
        }
    }
}

impl EncodedChunksUsed<'_> {
    /// Produces an iterator over encoded chunks bitfields.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = impl Deref<Target = bool> + '_> + '_ {
        self.encoded_record_chunks_used.iter()
    }

    /// Produces a mutable iterator over encoded chunks bitfields.
    pub fn iter_mut(
        &mut self,
    ) -> impl ExactSizeIterator<Item = impl DerefMut<Target = bool> + '_> + '_ {
        self.potentially_updated = true;
        self.encoded_record_chunks_used.iter_mut()
    }
}

/// Error happening when trying to create [`SectorContentsMap`] from bytes
#[derive(Debug, Error, Copy, Clone, Eq, PartialEq)]
pub enum SectorContentsMapFromBytesError {
    /// Invalid bytes length
    #[error("Invalid bytes length, expected {expected}, actual {actual}")]
    InvalidBytesLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },
    /// Invalid number of encoded record chunks
    #[error("Invalid number of encoded record chunks: {actual}")]
    InvalidEncodedRecordChunks {
        /// Actual number of encoded record chunks
        actual: usize,
        /// Max supported
        max: usize,
    },
    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

/// Error happening when trying to encode [`SectorContentsMap`] into bytes
#[derive(Debug, Error, Copy, Clone, Eq, PartialEq)]
pub enum SectorContentsMapEncodeIntoError {
    /// Invalid bytes length
    #[error("Invalid bytes length, expected {expected}, actual {actual}")]
    InvalidBytesLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },
}

/// Error happening when trying to create [`SectorContentsMap`] from bytes
#[derive(Debug, Error, Copy, Clone, Eq, PartialEq)]
pub enum SectorContentsMapIterationError {
    /// S-bucket provided is out of range
    #[error("S-bucket provided {provided} is out of range, max {max}")]
    SBucketOutOfRange {
        /// Provided s-bucket
        provided: usize,
        /// Max s-bucket
        max: usize,
    },
}

/// Map of sector contents.
///
/// Abstraction on top of bitfields that allow making sense of sector contents that contains both
/// encoded (meaning erasure coded and encoded with existing PoSpace quality) and unencoded chunks
/// (just erasure coded) used at the same time both in records (before writing to plot) and
/// s-buckets (written into the plot) format
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SectorContentsMap {
    /// Number of encoded chunks used in each record.
    ///
    /// This is technically redundant, but allows to drastically decrease amount of work in
    /// [`Self::iter_s_bucket_records()`] and other places, which become unusably slow otherwise.
    num_encoded_record_chunks: Vec<SBucket>,
    /// Bitfields for each record, each bit is `true` if encoded chunk at corresponding position was
    /// used
    encoded_record_chunks_used: Vec<SingleRecordBitArray>,
}

impl SectorContentsMap {
    /// Create new sector contents map initialized with zeroes to store data for `pieces_in_sector`
    /// records
    pub fn new(pieces_in_sector: u16) -> Self {
        Self {
            num_encoded_record_chunks: vec![SBucket::default(); usize::from(pieces_in_sector)],
            encoded_record_chunks_used: vec![
                SingleRecordBitArray::default();
                usize::from(pieces_in_sector)
            ],
        }
    }

    /// Reconstruct sector contents map from bytes.
    ///
    /// Returns error if length of the vector doesn't match [`Self::encoded_size()`] for
    /// `pieces_in_sector`.
    pub fn from_bytes(
        bytes: &[u8],
        pieces_in_sector: u16,
    ) -> Result<Self, SectorContentsMapFromBytesError> {
        if bytes.len() != Self::encoded_size(pieces_in_sector) {
            return Err(SectorContentsMapFromBytesError::InvalidBytesLength {
                expected: Self::encoded_size(pieces_in_sector),
                actual: bytes.len(),
            });
        }

        let (single_records_bit_arrays, expected_checksum) =
            bytes.split_at(bytes.len() - Blake3Hash::SIZE);
        // Verify checksum
        let actual_checksum = blake3_hash(single_records_bit_arrays);
        if *actual_checksum != *expected_checksum {
            debug!(
                actual_checksum = %hex::encode(actual_checksum),
                expected_checksum = %hex::encode(expected_checksum),
                "Hash doesn't match, corrupted bytes"
            );

            return Err(SectorContentsMapFromBytesError::ChecksumMismatch);
        }

        let mut encoded_record_chunks_used =
            vec![SingleRecordBitArray::default(); pieces_in_sector.into()];

        let num_encoded_record_chunks = encoded_record_chunks_used
            .iter_mut()
            .zip(
                single_records_bit_arrays
                    .as_chunks::<{ SINGLE_RECORD_BIT_ARRAY_SIZE }>()
                    .0,
            )
            .map(|(encoded_record_chunks_used, bytes)| {
                encoded_record_chunks_used
                    .as_raw_mut_slice()
                    .copy_from_slice(bytes);
                let num_encoded_record_chunks = encoded_record_chunks_used.count_ones();
                if num_encoded_record_chunks > Record::NUM_CHUNKS {
                    return Err(
                        SectorContentsMapFromBytesError::InvalidEncodedRecordChunks {
                            actual: num_encoded_record_chunks,
                            max: Record::NUM_CHUNKS,
                        },
                    );
                }
                Ok(SBucket::try_from(num_encoded_record_chunks).expect("Verified above; qed"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            num_encoded_record_chunks,
            encoded_record_chunks_used,
        })
    }

    /// Size of sector contents map when encoded and stored in the plot for specified number of
    /// pieces in sector
    pub const fn encoded_size(pieces_in_sector: u16) -> usize {
        SINGLE_RECORD_BIT_ARRAY_SIZE * pieces_in_sector as usize + Blake3Hash::SIZE
    }

    /// Encode internal contents into `output`
    pub fn encode_into(&self, output: &mut [u8]) -> Result<(), SectorContentsMapEncodeIntoError> {
        if output.len() != Self::encoded_size(self.encoded_record_chunks_used.len() as u16) {
            return Err(SectorContentsMapEncodeIntoError::InvalidBytesLength {
                expected: Self::encoded_size(self.encoded_record_chunks_used.len() as u16),
                actual: output.len(),
            });
        }

        let slice = self.encoded_record_chunks_used.as_slice();
        // SAFETY: `BitArray` is a transparent data structure containing array of bytes
        let slice = unsafe {
            slice::from_raw_parts(
                slice.as_ptr() as *const u8,
                slice.len() * SINGLE_RECORD_BIT_ARRAY_SIZE,
            )
        };

        // Write data and checksum
        output[..slice.len()].copy_from_slice(slice);
        output[slice.len()..].copy_from_slice(blake3_hash(slice).as_ref());

        Ok(())
    }

    /// Number of encoded chunks in each record
    pub fn num_encoded_record_chunks(&self) -> &[SBucket] {
        &self.num_encoded_record_chunks
    }

    /// Iterate over individual record bitfields
    pub fn iter_record_bitfields(&self) -> &[SingleRecordBitArray] {
        &self.encoded_record_chunks_used
    }

    /// Iterate mutably over individual record bitfields
    pub fn iter_record_bitfields_mut(
        &mut self,
    ) -> impl ExactSizeIterator<Item = EncodedChunksUsed<'_>> + '_ {
        self.encoded_record_chunks_used
            .iter_mut()
            .zip(&mut self.num_encoded_record_chunks)
            .map(
                |(encoded_record_chunks_used, num_encoded_record_chunks)| EncodedChunksUsed {
                    encoded_record_chunks_used,
                    num_encoded_record_chunks,
                    potentially_updated: false,
                },
            )
    }

    /// Returns sizes of each s-bucket
    pub fn s_bucket_sizes(&self) -> Box<[u16; Record::NUM_S_BUCKETS]> {
        // Rayon doesn't support iteration over custom types yet
        let s_bucket_sizes = (u16::from(SBucket::ZERO)..=u16::from(SBucket::MAX))
            .into_par_iter()
            .map(SBucket::from)
            .map(|s_bucket| {
                self.iter_s_bucket_records(s_bucket)
                    .expect("S-bucket guaranteed to be in range; qed")
                    .count() as u16
            })
            .collect::<Box<_>>();

        assert_eq!(s_bucket_sizes.len(), Record::NUM_S_BUCKETS);
        let mut s_bucket_sizes = ManuallyDrop::new(s_bucket_sizes);
        // SAFETY: Original memory is not dropped, number of elements checked above
        unsafe { Box::from_raw(s_bucket_sizes.as_mut_ptr() as *mut [u16; Record::NUM_S_BUCKETS]) }
    }

    /// Creates an iterator of `(s_bucket, encoded_chunk_used, chunk_location)`, where `s_bucket` is
    /// position of the chunk in the erasure coded record, `encoded_chunk_used` indicates whether it
    /// was encoded and `chunk_location` is the offset of the chunk in the plot (across all
    /// s-buckets).
    pub fn iter_record_chunk_to_plot(
        &self,
        piece_offset: PieceOffset,
    ) -> impl Iterator<Item = (SBucket, bool, usize)> + '_ {
        // Iterate over all s-buckets
        (SBucket::ZERO..=SBucket::MAX)
            // In each s-bucket map all records used
            .flat_map(|s_bucket| {
                self.iter_s_bucket_records(s_bucket)
                    .expect("S-bucket guaranteed to be in range; qed")
                    .map(move |(current_piece_offset, encoded_chunk_used)| {
                        (s_bucket, current_piece_offset, encoded_chunk_used)
                    })
            })
            // We've got contents of all s-buckets in a flat iterator, enumerating them so it is
            // possible to find in the plot later if desired
            .enumerate()
            // Everything about the piece offset we care about
            .filter_map(
                move |(chunk_location, (s_bucket, current_piece_offset, encoded_chunk_used))| {
                    // In case record for `piece_offset` is found, return necessary information
                    (current_piece_offset == piece_offset).then_some((
                        s_bucket,
                        encoded_chunk_used,
                        chunk_location,
                    ))
                },
            )
            // Tiny optimization in case we have found chunks for all records already
            .take(Record::NUM_CHUNKS)
    }

    /// Creates an iterator of `Option<(chunk_offset, encoded_chunk_used)>`, where each entry
    /// corresponds s-bucket/position of the chunk in the erasure coded record, `encoded_chunk_used`
    /// indicates whether it was encoded and `chunk_offset` is the offset of the chunk in the
    /// corresponding s-bucket.
    ///
    /// Similar to `Self::iter_record_chunk_to_plot()`, but runs in parallel, returns entries for
    /// all s-buckets and offsets are within corresponding s-buckets rather than the whole plot.
    pub fn par_iter_record_chunk_to_plot(
        &self,
        piece_offset: PieceOffset,
    ) -> impl IndexedParallelIterator<Item = Option<(usize, bool)>> + '_ {
        let piece_offset = usize::from(piece_offset);
        (u16::from(SBucket::ZERO)..=u16::from(SBucket::MAX))
            .into_par_iter()
            .map(SBucket::from)
            // In each s-bucket map all records used
            .map(move |s_bucket| {
                let encoded_chunk_used = record_has_s_bucket_chunk(
                    s_bucket.into(),
                    &self.encoded_record_chunks_used[piece_offset],
                    usize::from(self.num_encoded_record_chunks[piece_offset]),
                )?;

                // How many other record chunks we have in s-bucket before piece offset we care
                // about
                let chunk_offset = self
                    .encoded_record_chunks_used
                    .iter()
                    .zip(&self.num_encoded_record_chunks)
                    .take(piece_offset)
                    .filter(move |(record_bitfields, num_encoded_record_chunks)| {
                        record_has_s_bucket_chunk(
                            s_bucket.into(),
                            record_bitfields,
                            usize::from(**num_encoded_record_chunks),
                        )
                        .is_some()
                    })
                    .count();

                Some((chunk_offset, encoded_chunk_used))
            })
    }

    /// Creates an iterator of `(piece_offset, encoded_chunk_used)`, where `piece_offset`
    /// corresponds to the record to which chunk belongs and `encoded_chunk_used` indicates whether
    /// it was encoded.
    ///
    /// Returns error if `s_bucket` is outside of [`Record::NUM_S_BUCKETS`] range.
    pub fn iter_s_bucket_records(
        &self,
        s_bucket: SBucket,
    ) -> Result<impl Iterator<Item = (PieceOffset, bool)> + '_, SectorContentsMapIterationError>
    {
        let s_bucket = usize::from(s_bucket);

        if s_bucket >= Record::NUM_S_BUCKETS {
            return Err(SectorContentsMapIterationError::SBucketOutOfRange {
                provided: s_bucket,
                max: Record::NUM_S_BUCKETS,
            });
        }

        Ok((PieceOffset::ZERO..)
            .zip(
                self.encoded_record_chunks_used
                    .iter()
                    .zip(&self.num_encoded_record_chunks),
            )
            .filter_map(
                move |(piece_offset, (record_bitfields, num_encoded_record_chunks))| {
                    let encoded_chunk_used = record_has_s_bucket_chunk(
                        s_bucket,
                        record_bitfields,
                        usize::from(*num_encoded_record_chunks),
                    )?;

                    Some((piece_offset, encoded_chunk_used))
                },
            ))
    }

    /// Iterate over chunks of s-bucket indicating if encoded chunk is used at corresponding
    /// position
    ///
    /// ## Panics
    /// Panics if `s_bucket` is outside of [`Record::NUM_S_BUCKETS`] range.
    pub fn iter_s_bucket_encoded_record_chunks_used(
        &self,
        s_bucket: SBucket,
    ) -> Result<impl Iterator<Item = bool> + '_, SectorContentsMapIterationError> {
        let s_bucket = usize::from(s_bucket);

        if s_bucket >= Record::NUM_S_BUCKETS {
            return Err(SectorContentsMapIterationError::SBucketOutOfRange {
                provided: s_bucket,
                max: Record::NUM_S_BUCKETS,
            });
        }

        Ok(self
            .encoded_record_chunks_used
            .iter()
            .map(move |record_bitfields| record_bitfields[s_bucket]))
    }
}

/// Checks if record has corresponding s-bucket chunk, returns `Some(true)` if yes and chunk is
/// encoded, `Some(false)` if yes and chunk is not encoded, `None` if chunk at corresponding
/// s-bucket is not found.
fn record_has_s_bucket_chunk(
    s_bucket: usize,
    record_bitfields: &SingleRecordBitArray,
    num_encoded_record_chunks: usize,
) -> Option<bool> {
    if record_bitfields[s_bucket] {
        // Bit is explicitly set to `true`, easy case
        Some(true)
    } else if num_encoded_record_chunks == Record::NUM_CHUNKS {
        None
    } else {
        // Count how many encoded chunks we have before current offset
        let encoded_before = record_bitfields[..s_bucket].count_ones();
        let unencoded_before = s_bucket - encoded_before;
        // And how many unencoded we have total and how many before current offset
        // (we know that total number of used chunks is always `Record::NUM_CHUNKS`)
        let unencoded_total = Record::NUM_CHUNKS.saturating_sub(num_encoded_record_chunks);

        if unencoded_before < unencoded_total {
            // Have not seen all unencoded chunks before current offset yet, hence
            // current offset qualifies
            Some(false)
        } else {
            None
        }
    }
}
