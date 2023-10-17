use crate::sector::{
    sector_record_chunks_size, RecordMetadata, SectorContentsMap, SectorContentsMapFromBytesError,
    SectorMetadataChecksummed,
};
use crate::{ReadAt, ReadAtAsync, ReadAtSync};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use parity_scale_codec::Decode;
use rayon::prelude::*;
use std::io;
use std::mem::ManuallyDrop;
use std::simd::Simd;
use subspace_core_primitives::crypto::{blake3_hash, Scalar};
use subspace_core_primitives::{
    Piece, PieceOffset, Record, RecordCommitment, RecordWitness, SBucket, SectorId,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_proof_of_space::{Quality, Table, TableGenerator};
use thiserror::Error;
use tracing::debug;

/// Errors that happen during reading
#[derive(Debug, Error)]
pub enum ReadingError {
    /// Failed to read chunk.
    ///
    /// This is an implementation bug, most likely due to mismatch between sector contents map and
    /// other farming parameters.
    #[error("Failed to read chunk at location {chunk_location}")]
    FailedToReadChunk {
        /// Chunk location
        chunk_location: usize,
        /// Low-level error
        error: io::Error,
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
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
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

/// Read sector record chunks, only plotted s-buckets are returned (in decoded form).
///
/// NOTE: This is an async function, but it also does CPU-intensive operation internally, while it
/// is not very long, make sure it is okay to do so in your context.
pub async fn read_sector_record_chunks<PosTable, S, A>(
    piece_offset: PieceOffset,
    pieces_in_sector: u16,
    s_bucket_offsets: &[u32; Record::NUM_S_BUCKETS],
    sector_contents_map: &SectorContentsMap,
    pos_table: &PosTable,
    sector: &ReadAt<S, A>,
) -> Result<Box<[Option<Scalar>; Record::NUM_S_BUCKETS]>, ReadingError>
where
    PosTable: Table,
    S: ReadAtSync,
    A: ReadAtAsync,
{
    let mut record_chunks = vec![None; Record::NUM_S_BUCKETS];

    let read_chunks_inputs = record_chunks
        .par_iter_mut()
        .zip(sector_contents_map.par_iter_record_chunk_to_plot(piece_offset))
        .zip(
            (u16::from(SBucket::ZERO)..=u16::from(SBucket::MAX))
                .into_par_iter()
                .map(SBucket::from)
                .zip(s_bucket_offsets.par_iter()),
        )
        .map(
            |((maybe_record_chunk, maybe_chunk_details), (s_bucket, &s_bucket_offset))| {
                let (chunk_offset, encoded_chunk_used) = maybe_chunk_details?;

                let chunk_location = chunk_offset + s_bucket_offset as usize;

                Some((
                    maybe_record_chunk,
                    chunk_location,
                    encoded_chunk_used,
                    s_bucket,
                ))
            },
        )
        .collect::<Vec<_>>();

    match sector {
        ReadAt::Sync(sector) => {
            read_chunks_inputs.into_par_iter().flatten().try_for_each(
                |(maybe_record_chunk, chunk_location, encoded_chunk_used, s_bucket)| {
                    let mut record_chunk = [0; Scalar::FULL_BYTES];
                    sector
                        .read_at(
                            &mut record_chunk,
                            SectorContentsMap::encoded_size(pieces_in_sector)
                                + chunk_location * Scalar::FULL_BYTES,
                        )
                        .map_err(|error| ReadingError::FailedToReadChunk {
                            chunk_location,
                            error,
                        })?;

                    // Decode chunk if necessary
                    if encoded_chunk_used {
                        let quality = pos_table.find_quality(s_bucket.into()).expect(
                            "encoded_chunk_used implies quality exists for this chunk; qed",
                        );

                        record_chunk = Simd::to_array(
                            Simd::from(record_chunk) ^ Simd::from(quality.create_proof().hash()),
                        );
                    }

                    maybe_record_chunk.replace(Scalar::try_from(record_chunk).map_err(
                        |error| ReadingError::InvalidChunk {
                            s_bucket,
                            encoded_chunk_used,
                            chunk_location,
                            error,
                        },
                    )?);

                    Ok::<_, ReadingError>(())
                },
            )?;
        }
        ReadAt::Async(sector) => {
            let processing_chunks = read_chunks_inputs
                .into_iter()
                .flatten()
                .map(
                    |(maybe_record_chunk, chunk_location, encoded_chunk_used, s_bucket)| async move {
                        let mut record_chunk = [0; Scalar::FULL_BYTES];
                        record_chunk.copy_from_slice(
                            &sector
                                .read_at(
                                    vec![0; Scalar::FULL_BYTES],
                                    SectorContentsMap::encoded_size(pieces_in_sector)
                                        + chunk_location * Scalar::FULL_BYTES,
                                )
                                .await
                                .map_err(|error| ReadingError::FailedToReadChunk {
                                    chunk_location,
                                    error,
                                })?
                        );


                        // Decode chunk if necessary
                        if encoded_chunk_used {
                            let quality = pos_table.find_quality(s_bucket.into()).expect(
                                "encoded_chunk_used implies quality exists for this chunk; qed",
                            );

                            record_chunk = Simd::to_array(
                                Simd::from(record_chunk) ^ Simd::from(quality.create_proof().hash()),
                            );
                        }

                        maybe_record_chunk.replace(Scalar::try_from(record_chunk).map_err(
                            |error| ReadingError::InvalidChunk {
                                s_bucket,
                                encoded_chunk_used,
                                chunk_location,
                                error,
                            },
                        )?);

                        Ok::<_, ReadingError>(())
                    },
                )
                .collect::<FuturesUnordered<_>>()
                .filter_map(|result| async move {
                    match result {
                        Ok(()) => None,
                        Err(error) => Some(error),
                    }
                });

            std::pin::pin!(processing_chunks)
                .next()
                .await
                .map_or(Ok(()), Err)?;
        }
    }

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
pub(crate) async fn read_record_metadata<S, A>(
    piece_offset: PieceOffset,
    pieces_in_sector: u16,
    sector: &ReadAt<S, A>,
) -> Result<RecordMetadata, ReadingError>
where
    S: ReadAtSync,
    A: ReadAtAsync,
{
    let sector_metadata_start = SectorContentsMap::encoded_size(pieces_in_sector)
        + sector_record_chunks_size(pieces_in_sector);
    // Move to the beginning of the commitment and witness we care about
    let record_metadata_offset =
        sector_metadata_start + RecordMetadata::encoded_size() * usize::from(piece_offset);

    let mut record_metadata_bytes = vec![0; RecordMetadata::encoded_size()];
    match sector {
        ReadAt::Sync(sector) => {
            sector.read_at(&mut record_metadata_bytes, record_metadata_offset)?;
        }
        ReadAt::Async(sector) => {
            record_metadata_bytes = sector
                .read_at(record_metadata_bytes, record_metadata_offset)
                .await?;
        }
    }
    let record_metadata = RecordMetadata::decode(&mut record_metadata_bytes.as_ref())
        .expect("Length is correct, contents doesn't have specific structure to it; qed");

    Ok(record_metadata)
}

/// Read piece from sector.
///
/// NOTE: Even though this function is async, proof of time table generation is expensive and should
/// be done in a dedicated thread where blocking is allowed.
pub async fn read_piece<PosTable, S, A>(
    piece_offset: PieceOffset,
    sector_id: &SectorId,
    sector_metadata: &SectorMetadataChecksummed,
    sector: &ReadAt<S, A>,
    erasure_coding: &ErasureCoding,
    table_generator: &mut PosTable::Generator,
) -> Result<Piece, ReadingError>
where
    PosTable: Table,
    S: ReadAtSync,
    A: ReadAtAsync,
{
    let pieces_in_sector = sector_metadata.pieces_in_sector;

    let sector_contents_map = {
        let mut sector_contents_map_bytes =
            vec![0; SectorContentsMap::encoded_size(pieces_in_sector)];
        match sector {
            ReadAt::Sync(sector) => {
                sector.read_at(&mut sector_contents_map_bytes, 0)?;
            }
            ReadAt::Async(sector) => {
                sector_contents_map_bytes = sector.read_at(sector_contents_map_bytes, 0).await?;
            }
        }

        SectorContentsMap::from_bytes(&sector_contents_map_bytes, pieces_in_sector)?
    };

    let sector_record_chunks = read_sector_record_chunks(
        piece_offset,
        pieces_in_sector,
        &sector_metadata.s_bucket_offsets(),
        &sector_contents_map,
        &table_generator.generate(
            &sector_id.derive_evaluation_seed(piece_offset, sector_metadata.history_size),
        ),
        sector,
    )
    .await?;
    // Restore source record scalars
    let record_chunks =
        recover_source_record_chunks(&sector_record_chunks, piece_offset, erasure_coding)?;

    let record_metadata = read_record_metadata(piece_offset, pieces_in_sector, sector).await?;

    let mut piece = Piece::default();

    piece
        .record_mut()
        .iter_mut()
        .zip(record_chunks)
        .for_each(|(output, input)| {
            *output = input.to_bytes();
        });

    *piece.commitment_mut() = record_metadata.commitment;
    *piece.witness_mut() = record_metadata.witness;

    // Verify checksum
    let actual_checksum = blake3_hash(piece.as_ref());
    if actual_checksum != record_metadata.piece_checksum {
        debug!(
            ?sector_id,
            %piece_offset,
            actual_checksum = %hex::encode(actual_checksum),
            expected_checksum = %hex::encode(record_metadata.piece_checksum),
            "Hash doesn't match, plotted piece is corrupted"
        );

        return Err(ReadingError::ChecksumMismatch);
    }

    Ok(piece)
}
