use crate::sector::{
    sector_record_chunks_size, sector_size, SectorContentsMap, SectorContentsMapFromBytesError,
    SectorMetadata,
};
use rayon::prelude::*;
use std::mem::ManuallyDrop;
use std::simd::Simd;
use subspace_core_primitives::crypto::Scalar;
use subspace_core_primitives::{
    Piece, PieceOffset, Record, RecordCommitment, RecordWitness, SBucket, SectorId,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_proof_of_space::{Quality, Table};
use thiserror::Error;

/// Errors that happen during reading
#[derive(Debug, Error)]
pub enum ReadingError {
    /// Wrong sector size
    #[error("Wrong sector size: expected {expected}, actual {actual}")]
    WrongSectorSize {
        /// Expected size in bytes
        expected: usize,
        /// Actual size in bytes
        actual: usize,
    },
    /// Failed to read chunk.
    ///
    /// This is an implementation bug, most likely due to mismatch between sector contents map and
    /// other farming parameters.
    #[error("Failed to read chunk at location {chunk_location}")]
    FailedToReadChunk {
        /// Chunk location
        chunk_location: usize,
    },
    /// Invalid chunk, possible disk corruption
    #[error(
        "Invalid chunk at location {chunk_location} s-bucket {s_bucket} encoded \
        {encoded_chunk_used}, possible disk corruption: {error}"
    )]
    InvalidChunk {
        /// S-bucket
        s_bucket: SBucket,
        /// Indicates whether chunk was encoded
        encoded_chunk_used: bool,
        /// Chunk location
        chunk_location: usize,
        /// Lower-level error
        error: String,
    },
    /// Failed to erasure-decode record
    #[error("Failed to erasure-decode record at offset {piece_offset}: {error}")]
    FailedToErasureDecodeRecord {
        /// Piece offset
        piece_offset: PieceOffset,
        /// Lower-level error
        error: String,
    },
    /// Wrong record size after decoding
    #[error("Wrong record size after decoding: expected {expected}, actual {actual}")]
    WrongRecordSizeAfterDecoding {
        /// Expected size in bytes
        expected: usize,
        /// Actual size in bytes
        actual: usize,
    },
    /// Failed to decode sector contents map
    #[error("Failed to decode sector contents map: {0}")]
    FailedToDecodeSectorContentsMap(#[from] SectorContentsMapFromBytesError),
}

/// Record contained in the plot
#[derive(Debug, Clone)]
pub struct PlotRecord {
    /// Record scalars
    pub scalars: Box<[Scalar; Record::NUM_CHUNKS]>,
    /// Record commitment
    pub commitment: RecordCommitment,
    /// Record witness
    pub witness: RecordWitness,
}

/// Read sector record chunks, only plotted s-buckets are returned (in decoded form)
pub fn read_sector_record_chunks<PosTable>(
    piece_offset: PieceOffset,
    pieces_in_sector: u16,
    s_bucket_offsets: &[u32; Record::NUM_S_BUCKETS],
    sector_contents_map: &SectorContentsMap,
    pos_table: &PosTable,
    sector: &[u8],
) -> Result<Box<[Option<Scalar>; Record::NUM_S_BUCKETS]>, ReadingError>
where
    PosTable: Table,
{
    if sector.len() != sector_size(pieces_in_sector) {
        return Err(ReadingError::WrongSectorSize {
            expected: sector_size(pieces_in_sector),
            actual: sector.len(),
        });
    }

    let mut record_chunks = vec![None; Record::NUM_S_BUCKETS];

    record_chunks
        .par_iter_mut()
        .zip(sector_contents_map.par_iter_record_chunk_to_plot(piece_offset))
        .zip(
            (u16::from(SBucket::ZERO)..=u16::from(SBucket::MAX))
                .into_par_iter()
                .map(SBucket::from)
                .zip(s_bucket_offsets.par_iter()),
        )
        .try_for_each(
            |((maybe_record_chunk, maybe_chunk_details), (s_bucket, &s_bucket_offset))| {
                let (chunk_offset, encoded_chunk_used) = match maybe_chunk_details {
                    Some(chunk_details) => chunk_details,
                    None => {
                        return Ok(());
                    }
                };

                let chunk_location = chunk_offset + s_bucket_offset as usize;

                let mut record_chunk = sector[SectorContentsMap::encoded_size(pieces_in_sector)..]
                    .array_chunks::<{ Scalar::FULL_BYTES }>()
                    .nth(chunk_location)
                    .copied()
                    .ok_or(ReadingError::FailedToReadChunk { chunk_location })?;

                // Decode chunk if necessary
                if encoded_chunk_used {
                    let quality = pos_table
                        .find_quality(s_bucket.into())
                        .expect("encoded_chunk_used implies quality exists for this chunk; qed");

                    // NOTE: Quality is already hashed in the `subspace-chiapos` library
                    record_chunk =
                        Simd::to_array(Simd::from(record_chunk) ^ Simd::from(*quality.to_bytes()));
                }

                maybe_record_chunk.replace(Scalar::try_from(record_chunk).map_err(|error| {
                    ReadingError::InvalidChunk {
                        s_bucket,
                        encoded_chunk_used,
                        chunk_location,
                        error,
                    }
                })?);

                Ok::<_, ReadingError>(())
            },
        )?;

    let mut record_chunks = ManuallyDrop::new(record_chunks);

    // SAFETY: Original memory is not dropped, layout is exactly what we need here
    let record_chunks = unsafe {
        Box::from_raw(record_chunks.as_mut_ptr() as *mut [Option<Scalar>; Record::NUM_S_BUCKETS])
    };

    Ok(record_chunks)
}

/// Given sector record chunks recover extended record chunks (both source and parity)
pub fn recover_extended_record_chunks(
    sector_record_chunks: &[Option<Scalar>; Record::NUM_S_BUCKETS],
    piece_offset: PieceOffset,
    erasure_coding: &ErasureCoding,
) -> Result<Box<[Scalar; Record::NUM_S_BUCKETS]>, ReadingError> {
    // Restore source record scalars
    let record_chunks = erasure_coding
        .recover(sector_record_chunks)
        .map_err(|error| ReadingError::FailedToErasureDecodeRecord {
            piece_offset,
            error,
        })?;

    // Required for safety invariant below
    if record_chunks.len() != Record::NUM_S_BUCKETS {
        return Err(ReadingError::WrongRecordSizeAfterDecoding {
            expected: Record::NUM_S_BUCKETS,
            actual: record_chunks.len(),
        });
    }

    let mut record_chunks = ManuallyDrop::new(record_chunks);

    // SAFETY: Original memory is not dropped, size of the data checked above
    let record_chunks = unsafe {
        Box::from_raw(record_chunks.as_mut_ptr() as *mut [Scalar; Record::NUM_S_BUCKETS])
    };

    Ok(record_chunks)
}

/// Given sector record chunks recover source record chunks in form of an iterator.
pub fn recover_source_record_chunks(
    sector_record_chunks: &[Option<Scalar>; Record::NUM_S_BUCKETS],
    piece_offset: PieceOffset,
    erasure_coding: &ErasureCoding,
) -> Result<impl ExactSizeIterator<Item = Scalar>, ReadingError> {
    // Restore source record scalars
    let record_chunks = erasure_coding
        .recover_source(sector_record_chunks)
        .map_err(|error| ReadingError::FailedToErasureDecodeRecord {
            piece_offset,
            error,
        })?;

    // Required for safety invariant below
    if record_chunks.len() != Record::NUM_CHUNKS {
        return Err(ReadingError::WrongRecordSizeAfterDecoding {
            expected: Record::NUM_CHUNKS,
            actual: record_chunks.len(),
        });
    }

    Ok(record_chunks)
}

/// Read metadata (commitment and witness) for record
pub fn read_record_metadata(
    piece_offset: PieceOffset,
    pieces_in_sector: u16,
    sector: &[u8],
) -> Result<(RecordCommitment, RecordWitness), ReadingError> {
    if sector.len() != sector_size(pieces_in_sector) {
        return Err(ReadingError::WrongSectorSize {
            expected: sector_size(pieces_in_sector),
            actual: sector.len(),
        });
    }

    let sector_metadata_start = SectorContentsMap::encoded_size(pieces_in_sector)
        + sector_record_chunks_size(pieces_in_sector);
    let commitment_witness_size = RecordCommitment::SIZE + RecordWitness::SIZE;
    let (record_commitment, record_witness) = sector[sector_metadata_start..]
        // Move to the beginning of the commitment and witness we care about
        [commitment_witness_size * usize::from(piece_offset)..]
        // Take commitment and witness we care about
        [..commitment_witness_size]
        // Separate commitment from witness
        .split_at(RecordCommitment::SIZE);

    let record_commitment = RecordCommitment::try_from(record_commitment)
        .expect("Correctly sliced above from correctly sized plot; qed");
    let record_witness = RecordWitness::try_from(record_witness)
        .expect("Correctly sliced above from correctly sized plot; qed");

    Ok((record_commitment, record_witness))
}

/// Read piece from sector
pub fn read_piece<PosTable>(
    piece_offset: PieceOffset,
    sector_id: &SectorId,
    sector_metadata: &SectorMetadata,
    sector: &[u8],
    erasure_coding: &ErasureCoding,
) -> Result<Piece, ReadingError>
where
    PosTable: Table,
{
    let pieces_in_sector = sector_metadata.pieces_in_sector;

    if sector.len() != sector_size(pieces_in_sector) {
        return Err(ReadingError::WrongSectorSize {
            expected: sector_size(pieces_in_sector),
            actual: sector.len(),
        });
    }

    let sector_contents_map = {
        SectorContentsMap::from_bytes(
            &sector[..SectorContentsMap::encoded_size(pieces_in_sector)],
            pieces_in_sector,
        )?
    };

    // Restore source record scalars
    let record_chunks = recover_source_record_chunks(
        &*read_sector_record_chunks(
            piece_offset,
            pieces_in_sector,
            &sector_metadata.s_bucket_offsets(),
            &sector_contents_map,
            &PosTable::generate(
                &sector_id.derive_evaluation_seed(piece_offset, sector_metadata.history_size),
            ),
            sector,
        )?,
        piece_offset,
        erasure_coding,
    )?;

    let (commitment, witness) = read_record_metadata(piece_offset, pieces_in_sector, sector)?;

    let mut piece = Piece::default();

    piece
        .record_mut()
        .iter_mut()
        .zip(record_chunks)
        .for_each(|(output, input)| {
            *output = input.to_bytes();
        });

    *piece.commitment_mut() = commitment;
    *piece.witness_mut() = witness;

    Ok(piece)
}
