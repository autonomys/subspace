use bitvec::prelude::*;
use parity_scale_codec::{Decode, Encode};
use rayon::prelude::*;
use std::num::NonZeroU64;
use std::ops::{Deref, DerefMut};
use std::{mem, slice};
use subspace_core_primitives::{
    HistorySize, PieceOffset, Record, RecordCommitment, RecordWitness, SBucket, SectorIndex,
    SegmentIndex,
};
use thiserror::Error;

/// Size of the part of the plot containing record chunks (s-buckets).
///
/// Total size of the plot can be computed with [`sector_size()`].
pub const fn sector_record_chunks_size(pieces_in_sector: u16) -> usize {
    usize::from(pieces_in_sector) * Record::SIZE
}

/// Size of the part of the plot containing commitments and witnesses for records.
///
/// Total size of the plot can be computed with [`sector_size()`].
pub const fn sector_commitments_witnesses_size(pieces_in_sector: u16) -> usize {
    usize::from(pieces_in_sector) * (RecordWitness::SIZE + RecordCommitment::SIZE)
}

/// Exact sector plot size (sector contents map, record chunks, record commitments and witnesses).
///
/// NOTE: Each sector also has corresponding fixed size metadata whose size can be obtained with
/// [`SectorMetadata::encoded_size()`], size of the record chunks (s-buckets) with
/// [`sector_record_chunks_size()`] and size of record commitments and witnesses with
/// [`sector_commitments_witnesses_size()`]. This function just combines those three together for
/// convenience.
pub const fn sector_size(pieces_in_sector: u16) -> usize {
    sector_record_chunks_size(pieces_in_sector)
        + sector_commitments_witnesses_size(pieces_in_sector)
        + SectorContentsMap::encoded_size(pieces_in_sector)
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
    /// Sector expiration, defined as sector of the archived history of the blockchain
    pub expires_at: SegmentIndex,
}

impl SectorMetadata {
    /// Returns offsets of each s-bucket relatively to the beginning of the sector (in chunks)
    pub fn s_bucket_offsets(&self) -> Box<[u32; Record::NUM_S_BUCKETS]> {
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        let mut s_bucket_offsets =
            unsafe { Box::<[u32; Record::NUM_S_BUCKETS]>::new_zeroed().assume_init() };

        self.s_bucket_sizes
            .iter()
            .zip(s_bucket_offsets.iter_mut())
            .for_each({
                let mut base_offset = 0;

                move |(s_bucket_size, s_bucket_offset)| {
                    *s_bucket_offset = base_offset;
                    base_offset += u32::from(*s_bucket_size);
                }
            });

        s_bucket_offsets
    }

    /// Size of encoded sector metadata.
    ///
    /// For sector plot size use [`sector_size()`].
    #[inline]
    pub fn encoded_size() -> usize {
        let default = SectorMetadata {
            sector_index: 0,
            pieces_in_sector: 0,
            // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
            // SAFETY: Data structure filled with zeroes is a valid invariant
            s_bucket_sizes: unsafe { Box::new_zeroed().assume_init() },
            history_size: HistorySize::from(NonZeroU64::new(1).expect("1 is not 0; qed")),
            expires_at: SegmentIndex::default(),
        };

        default.encoded_size()
    }
}

/// Commitment and witness corresponding to the same record
#[derive(Debug, Clone, Encode, Decode)]
pub struct RecordMetadata {
    /// Record commitment
    pub commitment: RecordCommitment,
    /// Record witness
    pub witness: RecordWitness,
}

/// Raw sector before it is transformed and written to plot, used during plotting
#[derive(Debug, Clone)]
pub struct RawSector {
    /// List of records, likely downloaded from the network
    pub records: Vec<Record>,
    /// Metadata (commitment and witness) corresponding to the same record
    pub metadata: Vec<RecordMetadata>,
}

impl RawSector {
    /// Create new raw sector with internal vectors being allocated (but not filled) to be able to
    /// store data for specified number of pieces in sector
    pub fn new(pieces_in_sector: u16) -> Self {
        Self {
            records: Vec::with_capacity(usize::from(pieces_in_sector)),
            metadata: Vec::with_capacity(usize::from(pieces_in_sector)),
        }
    }
}

// Bit array containing space for bits equal to the number of s-buckets in a record
type SingleRecordBitArray = BitArray<[u8; Record::NUM_S_BUCKETS / u8::BITS as usize]>;
const SINGLE_RECORD_BIT_ARRAY_SIZE: usize = mem::size_of::<SingleRecordBitArray>();

// TODO: I really tried to avoid `count_ones()`, but wasn't able to with safe Rust due to lifetimes
/// Wrapper data structure that allows to iterate mutably over encoded chunks bitfields, while
/// maintaining up to date number of encoded chunks
///
/// ## Panics
/// Panics on drop if too many chunks are encoded
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

/// Abstraction on top of bitfields that allow making sense of sector contents that contains both
/// encoded (meaning erasure coded and encoded with existing PoSpace quality) and unencoded chunks
/// (just erasure coded) used at the same time both in records (before writing to plot) and
/// s-buckets (written into the plot) format
#[derive(Debug, Clone)]
pub struct SectorContentsMap {
    /// Number of encoded chunks used in each record.
    ///
    /// This is technically redundant, but allows to drastically decrease amount of work in
    /// [`Self::iter_s_bucket_records()`] and other places, which become unusably slow otherwise.
    num_encoded_record_chunks: Vec<SBucket>,
    /// Bitfields for each record, each bit is `true` if encoded chunk at corresponding position was
    /// used
    // TODO: Vector of bit arrays since number of s-buckets is known and fixed
    encoded_record_chunks_used: Vec<SingleRecordBitArray>,
}

impl AsRef<[u8]> for SectorContentsMap {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        let slice = self.encoded_record_chunks_used.as_slice();
        // SAFETY: `BitArray` is a transparent data structure containing array of bytes
        unsafe {
            slice::from_raw_parts(
                slice.as_ptr() as *const u8,
                slice.len() * SINGLE_RECORD_BIT_ARRAY_SIZE,
            )
        }
    }
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

        let mut encoded_record_chunks_used =
            vec![SingleRecordBitArray::default(); pieces_in_sector.into()];

        let num_encoded_record_chunks = encoded_record_chunks_used
            .iter_mut()
            .zip(bytes.array_chunks::<{ SINGLE_RECORD_BIT_ARRAY_SIZE }>())
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
                Ok(SBucket::try_from(num_encoded_record_chunks).expect("Verified above ; qed"))
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
        SINGLE_RECORD_BIT_ARRAY_SIZE * usize::from(pieces_in_sector)
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
        // TODO: Should have been just `::new()`, but https://github.com/rust-lang/rust/issues/53827
        // SAFETY: Data structure filled with zeroes is a valid invariant
        let mut s_bucket_sizes =
            unsafe { Box::<[u16; Record::NUM_S_BUCKETS]>::new_zeroed().assume_init() };
        // Rayon doesn't support iteration over custom types yet
        (u16::from(SBucket::ZERO)..=u16::from(SBucket::MAX))
            .into_par_iter()
            .map(SBucket::from)
            .zip(s_bucket_sizes.par_iter_mut())
            .for_each(|(s_bucket, s_bucket_size)| {
                *s_bucket_size = self
                    .iter_s_bucket_records(s_bucket)
                    .expect("S-bucket guaranteed to be in range; qed")
                    .count() as u16;
            });

        s_bucket_sizes
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
        (u16::from(SBucket::ZERO)..=u16::from(SBucket::MAX))
            .into_par_iter()
            .map(SBucket::from)
            // In each s-bucket map all records used
            .map(move |s_bucket| {
                // Searching for an entry corresponding to `piece_offset` in this s-bucket
                self.iter_s_bucket_records(s_bucket)
                    .expect("S-bucket guaranteed to be in range; qed")
                    .enumerate()
                    .find_map(
                        move |(chunk_offset, (current_piece_offset, encoded_chunk_used))| {
                            (current_piece_offset == piece_offset)
                                .then_some((chunk_offset, encoded_chunk_used))
                        },
                    )
            })
    }

    /// Creates an iterator of `(piece_offset, encoded_chunk_used)`, where `piece_offset`
    /// corresponds to the record to which chunk belongs and `encoded_chunk_used` indicates whether
    /// it was encoded.
    ///
    /// ## Panics
    /// Panics if `s_bucket` is outside of [`Record::NUM_S_BUCKETS`] range.
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
                    let num_encoded_record_chunks = usize::from(*num_encoded_record_chunks);
                    if record_bitfields[s_bucket] {
                        // Bit is explicitly set to `true`, easy case
                        Some((piece_offset, true))
                    } else if num_encoded_record_chunks == Record::NUM_CHUNKS {
                        None
                    } else {
                        // Count how many encoded chunks we before current offset
                        let encoded_before = record_bitfields[..s_bucket].count_ones();
                        let unencoded_before = s_bucket - encoded_before;
                        // And how many unencoded we have total and how many before current offset
                        // (we know that total number of used chunks is always `Record::NUM_CHUNKS`)
                        let unencoded_total =
                            Record::NUM_CHUNKS.saturating_sub(num_encoded_record_chunks);

                        if unencoded_before < unencoded_total {
                            // Have not seen all unencoded chunks before current offset yet, hence
                            // current offset qualifies
                            Some((piece_offset, false))
                        } else {
                            None
                        }
                    }
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
