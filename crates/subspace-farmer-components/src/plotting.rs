//! Plotting utilities
//!
//! This module contains functions and data structures that can be used for plotting purposes
//! (primarily with CPU).
//!
//! Plotted sectors can be written to plot and later [`read`](crate::reading) and/or
//! [`audited`](crate::auditing)/[`proven`](crate::proving) using other modules of this crate.

use crate::sector::{
    sector_record_chunks_size, sector_size, EncodedChunksUsed, RawSector, RecordMetadata,
    SectorContentsMap, SectorMetadata, SectorMetadataChecksummed,
};
use crate::segment_reconstruction::recover_missing_piece;
use crate::{FarmerProtocolInfo, PieceGetter};
use async_lock::{Mutex as AsyncMutex, Semaphore};
use backoff::future::retry;
use backoff::{Error as BackoffError, ExponentialBackoff};
use futures::stream::FuturesUnordered;
use futures::{select, StreamExt};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use rayon::prelude::*;
use std::collections::HashMap;
use std::simd::Simd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::hashes::{blake3_hash, blake3_hash_parallel, Blake3Hash};
use subspace_core_primitives::pieces::{Piece, PieceIndex, PieceOffset, Record};
use subspace_core_primitives::pos::PosSeed;
use subspace_core_primitives::sectors::{SBucket, SectorId, SectorIndex};
use subspace_core_primitives::segments::HistorySize;
use subspace_core_primitives::{PublicKey, ScalarBytes};
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::{Kzg, Scalar};
use subspace_proof_of_space::{Table, TableGenerator};
use thiserror::Error;
use tracing::{debug, trace, warn};

const RECONSTRUCTION_CONCURRENCY_LIMIT: usize = 1;

fn default_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        initial_interval: Duration::from_secs(15),
        max_interval: Duration::from_secs(10 * 60),
        // Try until we get a valid piece
        max_elapsed_time: None,
        ..ExponentialBackoff::default()
    }
}

/// Information about sector that was plotted
#[derive(Debug, Clone, Encode, Decode)]
pub struct PlottedSector {
    /// Sector ID
    pub sector_id: SectorId,
    /// Sector index
    pub sector_index: SectorIndex,
    /// Sector metadata
    pub sector_metadata: SectorMetadataChecksummed,
    /// Indexes of pieces that were plotted
    pub piece_indexes: Vec<PieceIndex>,
}

/// Plotting status
#[derive(Debug, Error)]
pub enum PlottingError {
    /// Records encoder error
    #[error("Records encoder error: {error}")]
    RecordsEncoderError {
        /// Lower-level error
        error: anyhow::Error,
    },
    /// Bad sector output size
    #[error("Bad sector output size: provided {provided}, expected {expected}")]
    BadSectorOutputSize {
        /// Actual size
        provided: usize,
        /// Expected size
        expected: usize,
    },
    /// Can't recover missing piece
    #[error("Can't recover missing piece {piece_index}: {error}")]
    PieceRecoveryFailed {
        /// Piece index
        piece_index: PieceIndex,
        /// Lower-level error
        error: anyhow::Error,
    },
    /// Failed to retrieve piece
    #[error("Failed to retrieve pieces: {error}")]
    FailedToRetrievePieces {
        /// Lower-level error
        error: anyhow::Error,
    },
    /// Abort early
    #[error("Abort early")]
    AbortEarly,
}

/// Options for plotting a sector.
///
/// Sector output and sector metadata output should be either empty (in which case they'll be
/// resized to correct size automatically) or correctly sized from the beginning or else error will
/// be returned.
#[derive(Debug)]
pub struct PlotSectorOptions<'a, RE, PG> {
    /// Public key corresponding to sector
    pub public_key: &'a PublicKey,
    /// Sector index
    pub sector_index: SectorIndex,
    /// Getter for pieces of archival history
    pub piece_getter: &'a PG,
    /// Farmer protocol info
    pub farmer_protocol_info: FarmerProtocolInfo,
    /// KZG instance
    pub kzg: &'a Kzg,
    /// Erasure coding instance
    pub erasure_coding: &'a ErasureCoding,
    /// How many pieces should sector contain
    pub pieces_in_sector: u16,
    /// Where plotted sector should be written, vector must either be empty (in which case it'll be
    /// resized to correct size automatically) or correctly sized from the beginning
    pub sector_output: &'a mut Vec<u8>,
    /// Semaphore for part of the plotting when farmer downloads new sector, allows to limit memory
    /// usage of the plotting process, permit will be held until the end of the plotting process
    pub downloading_semaphore: Option<Arc<Semaphore>>,
    /// Semaphore for part of the plotting when farmer encodes downloaded sector, should typically
    /// allow one permit at a time for efficient CPU utilization
    pub encoding_semaphore: Option<&'a Semaphore>,
    /// Proof of space table generators
    pub records_encoder: &'a mut RE,
    /// Whether encoding should be aborted early
    pub abort_early: &'a AtomicBool,
}

/// Plot a single sector.
///
/// This is a convenient wrapper around [`download_sector`] and [`encode_sector`] functions.
///
/// NOTE: Even though this function is async, it has blocking code inside and must be running in a
/// separate thread in order to prevent blocking an executor.
pub async fn plot_sector<RE, PG>(
    options: PlotSectorOptions<'_, RE, PG>,
) -> Result<PlottedSector, PlottingError>
where
    RE: RecordsEncoder,
    PG: PieceGetter + Send + Sync,
{
    let PlotSectorOptions {
        public_key,
        sector_index,
        piece_getter,
        farmer_protocol_info,
        kzg,
        erasure_coding,
        pieces_in_sector,
        sector_output,
        downloading_semaphore,
        encoding_semaphore,
        records_encoder,
        abort_early,
    } = options;

    let _downloading_permit = match downloading_semaphore {
        Some(downloading_semaphore) => Some(downloading_semaphore.acquire_arc().await),
        None => None,
    };

    let download_sector_fut = download_sector(DownloadSectorOptions {
        public_key,
        sector_index,
        piece_getter,
        farmer_protocol_info,
        kzg,
        erasure_coding,
        pieces_in_sector,
    });

    let _encoding_permit = match encoding_semaphore {
        Some(encoding_semaphore) => Some(encoding_semaphore.acquire().await),
        None => None,
    };

    let encoded_sector = encode_sector(
        download_sector_fut.await?,
        EncodeSectorOptions::<RE> {
            sector_index,
            records_encoder,
            abort_early,
        },
    )?;

    if abort_early.load(Ordering::Acquire) {
        return Err(PlottingError::AbortEarly);
    }

    write_sector(&encoded_sector, sector_output)?;

    Ok(encoded_sector.plotted_sector)
}

/// Opaque sector downloading result and ready for writing
#[derive(Debug)]
pub struct DownloadedSector {
    sector_id: SectorId,
    piece_indices: Vec<PieceIndex>,
    raw_sector: RawSector,
    history_size: HistorySize,
}

/// Options for sector downloading
#[derive(Debug)]
pub struct DownloadSectorOptions<'a, PG> {
    /// Public key corresponding to sector
    pub public_key: &'a PublicKey,
    /// Sector index
    pub sector_index: SectorIndex,
    /// Getter for pieces of archival history
    pub piece_getter: &'a PG,
    /// Farmer protocol info
    pub farmer_protocol_info: FarmerProtocolInfo,
    /// KZG instance
    pub kzg: &'a Kzg,
    /// Erasure coding instance
    pub erasure_coding: &'a ErasureCoding,
    /// How many pieces should sector contain
    pub pieces_in_sector: u16,
}

/// Download sector for plotting.
///
/// This will identify necessary pieces and download them using provided piece getter, after which
/// they can be encoded using [`encode_sector`] and written to the plot.
pub async fn download_sector<PG>(
    options: DownloadSectorOptions<'_, PG>,
) -> Result<DownloadedSector, PlottingError>
where
    PG: PieceGetter + Send + Sync,
{
    let DownloadSectorOptions {
        public_key,
        sector_index,
        piece_getter,
        farmer_protocol_info,
        kzg,
        erasure_coding,
        pieces_in_sector,
    } = options;

    let sector_id = SectorId::new(
        public_key.hash(),
        sector_index,
        farmer_protocol_info.history_size,
    );

    let piece_indices = (PieceOffset::ZERO..)
        .take(pieces_in_sector.into())
        .map(|piece_offset| {
            sector_id.derive_piece_index(
                piece_offset,
                farmer_protocol_info.history_size,
                farmer_protocol_info.max_pieces_in_sector,
                farmer_protocol_info.recent_segments,
                farmer_protocol_info.recent_history_fraction,
            )
        })
        .collect::<Vec<_>>();

    let raw_sector = {
        let mut raw_sector = RawSector::new(pieces_in_sector);
        let mut pieces_to_download =
            HashMap::<PieceIndex, Vec<_>>::with_capacity(usize::from(pieces_in_sector));
        for (piece_index, (record, metadata)) in piece_indices
            .iter()
            .copied()
            .zip(raw_sector.records.iter_mut().zip(&mut raw_sector.metadata))
        {
            pieces_to_download
                .entry(piece_index)
                .or_default()
                .push((record, metadata));
        }
        // This map will be mutated, removing piece indices we have already processed
        let pieces_to_download = AsyncMutex::new(pieces_to_download);

        retry(default_backoff(), || async {
            let mut pieces_to_download = pieces_to_download.lock().await;

            if let Err(error) =
                download_sector_internal(&mut pieces_to_download, piece_getter, kzg, erasure_coding)
                    .await
            {
                warn!(
                    %sector_index,
                    %error,
                    %pieces_in_sector,
                    remaining_pieces = %pieces_to_download.len(),
                    "Sector downloading attempt failed, will retry later"
                );

                return Err(BackoffError::transient(error));
            }

            debug!(%sector_index, "Sector downloaded successfully");

            Ok(())
        })
        .await?;

        raw_sector
    };

    Ok(DownloadedSector {
        sector_id,
        piece_indices,
        raw_sector,
        history_size: farmer_protocol_info.history_size,
    })
}

/// Records encoder for plotting purposes
pub trait RecordsEncoder {
    /// Encode provided sector records
    fn encode_records(
        &mut self,
        sector_id: &SectorId,
        records: &mut [Record],
        abort_early: &AtomicBool,
    ) -> anyhow::Result<SectorContentsMap>;
}

/// CPU implementation of [`RecordsEncoder`]
#[derive(Debug)]
pub struct CpuRecordsEncoder<'a, PosTable>
where
    PosTable: Table,
{
    table_generators: &'a mut [PosTable::Generator],
    erasure_coding: &'a ErasureCoding,
    global_mutex: &'a AsyncMutex<()>,
}

impl<PosTable> RecordsEncoder for CpuRecordsEncoder<'_, PosTable>
where
    PosTable: Table,
{
    fn encode_records(
        &mut self,
        sector_id: &SectorId,
        records: &mut [Record],
        abort_early: &AtomicBool,
    ) -> anyhow::Result<SectorContentsMap> {
        if self.erasure_coding.max_shards() < Record::NUM_S_BUCKETS {
            return Err(anyhow::anyhow!(
                "Invalid erasure coding instance: {} shards needed, {} supported",
                Record::NUM_S_BUCKETS,
                self.erasure_coding.max_shards()
            ));
        }

        if self.table_generators.is_empty() {
            return Err(anyhow::anyhow!("No table generators"));
        }

        let pieces_in_sector = records
            .len()
            .try_into()
            .map_err(|error| anyhow::anyhow!("Failed to convert pieces in sector: {error}"))?;
        let mut sector_contents_map = SectorContentsMap::new(pieces_in_sector);

        {
            let table_generators = &mut *self.table_generators;
            let global_mutex = self.global_mutex;
            let erasure_coding = self.erasure_coding;

            let iter = Mutex::new(
                (PieceOffset::ZERO..)
                    .zip(records.iter_mut())
                    .zip(sector_contents_map.iter_record_bitfields_mut()),
            );

            rayon::scope(|scope| {
                for table_generator in table_generators {
                    scope.spawn(|_scope| {
                        let mut chunks_scratch = Vec::with_capacity(Record::NUM_S_BUCKETS);

                        loop {
                            // Take mutex briefly to make sure encoding is allowed right now
                            global_mutex.lock_blocking();

                            // This instead of `while` above because otherwise mutex will be held
                            // for the duration of the loop and will limit concurrency to 1 record
                            let Some(((piece_offset, record), encoded_chunks_used)) =
                                iter.lock().next()
                            else {
                                return;
                            };
                            let pos_seed = sector_id.derive_evaluation_seed(piece_offset);

                            record_encoding::<PosTable>(
                                &pos_seed,
                                record,
                                encoded_chunks_used,
                                table_generator,
                                erasure_coding,
                                &mut chunks_scratch,
                            );

                            if abort_early.load(Ordering::Relaxed) {
                                return;
                            }
                        }
                    });
                }
            });
        }

        Ok(sector_contents_map)
    }
}

impl<'a, PosTable> CpuRecordsEncoder<'a, PosTable>
where
    PosTable: Table,
{
    /// Create new instance
    pub fn new(
        table_generators: &'a mut [PosTable::Generator],
        erasure_coding: &'a ErasureCoding,
        global_mutex: &'a AsyncMutex<()>,
    ) -> Self {
        Self {
            table_generators,
            erasure_coding,
            global_mutex,
        }
    }
}

/// Options for encoding a sector.
///
/// Sector output and sector metadata output should be either empty (in which case they'll be
/// resized to correct size automatically) or correctly sized from the beginning or else error will
/// be returned.
#[derive(Debug)]
pub struct EncodeSectorOptions<'a, RE>
where
    RE: RecordsEncoder,
{
    /// Sector index
    pub sector_index: SectorIndex,
    /// Records encoding instance
    pub records_encoder: &'a mut RE,
    /// Whether encoding should be aborted early
    pub abort_early: &'a AtomicBool,
}

/// Mostly opaque sector encoding result ready for writing
#[derive(Debug)]
pub struct EncodedSector {
    /// Information about sector that was plotted
    pub plotted_sector: PlottedSector,
    raw_sector: RawSector,
    sector_contents_map: SectorContentsMap,
}

/// Encode downloaded sector.
///
/// This function encodes downloaded sector records and returns sector encoding result that can be
/// written using [`write_sector`].
pub fn encode_sector<RE>(
    downloaded_sector: DownloadedSector,
    encoding_options: EncodeSectorOptions<'_, RE>,
) -> Result<EncodedSector, PlottingError>
where
    RE: RecordsEncoder,
{
    let DownloadedSector {
        sector_id,
        piece_indices,
        mut raw_sector,
        history_size,
    } = downloaded_sector;
    let EncodeSectorOptions {
        sector_index,
        records_encoder,
        abort_early,
    } = encoding_options;

    let pieces_in_sector = raw_sector.records.len().try_into().expect(
        "Raw sector can only be created in this crate and it is always done correctly; qed",
    );

    let sector_contents_map = records_encoder
        .encode_records(&sector_id, &mut raw_sector.records, abort_early)
        .map_err(|error| PlottingError::RecordsEncoderError { error })?;

    let sector_metadata = SectorMetadataChecksummed::from(SectorMetadata {
        sector_index,
        pieces_in_sector,
        s_bucket_sizes: sector_contents_map.s_bucket_sizes(),
        history_size,
    });

    Ok(EncodedSector {
        plotted_sector: PlottedSector {
            sector_id,
            sector_index,
            sector_metadata,
            piece_indexes: piece_indices,
        },
        raw_sector,
        sector_contents_map,
    })
}

/// Write encoded sector into sector output
pub fn write_sector(
    encoded_sector: &EncodedSector,
    sector_output: &mut Vec<u8>,
) -> Result<(), PlottingError> {
    let EncodedSector {
        plotted_sector: _,
        raw_sector,
        sector_contents_map,
    } = encoded_sector;

    let pieces_in_sector = raw_sector.records.len().try_into().expect(
        "Raw sector can only be created in this crate and it is always done correctly; qed",
    );

    let sector_size = sector_size(pieces_in_sector);

    if !sector_output.is_empty() && sector_output.len() != sector_size {
        return Err(PlottingError::BadSectorOutputSize {
            provided: sector_output.len(),
            expected: sector_size,
        });
    }

    sector_output.resize(sector_size, 0);

    // Write sector to disk in form of following regions:
    // * sector contents map
    // * record chunks as s-buckets
    // * record metadata
    // * checksum
    {
        let (sector_contents_map_region, remaining_bytes) =
            sector_output.split_at_mut(SectorContentsMap::encoded_size(pieces_in_sector));
        // Slice remaining memory into belonging to s-buckets and metadata
        let (s_buckets_region, metadata_region) =
            remaining_bytes.split_at_mut(sector_record_chunks_size(pieces_in_sector));

        // Write sector contents map so we can decode it later
        sector_contents_map
            .encode_into(sector_contents_map_region)
            .expect("Chunked into correct size above; qed");

        let num_encoded_record_chunks = sector_contents_map.num_encoded_record_chunks();
        let mut next_encoded_record_chunks_offset = vec![0_usize; pieces_in_sector.into()];
        let mut next_unencoded_record_chunks_offset = vec![0_usize; pieces_in_sector.into()];
        // Write record chunks, one s-bucket at a time
        for ((piece_offset, encoded_chunk_used), output) in (SBucket::ZERO..=SBucket::MAX)
            .flat_map(|s_bucket| {
                sector_contents_map
                    .iter_s_bucket_records(s_bucket)
                    .expect("S-bucket guaranteed to be in range; qed")
            })
            .zip(s_buckets_region.array_chunks_mut::<{ ScalarBytes::FULL_BYTES }>())
        {
            let num_encoded_record_chunks =
                usize::from(num_encoded_record_chunks[usize::from(piece_offset)]);
            let next_encoded_record_chunks_offset =
                &mut next_encoded_record_chunks_offset[usize::from(piece_offset)];
            let next_unencoded_record_chunks_offset =
                &mut next_unencoded_record_chunks_offset[usize::from(piece_offset)];

            // We know that s-buckets in `raw_sector.records` are stored in order (encoded first,
            // then unencoded), hence we don't need to calculate the position, we can just store a
            // few cursors and know the position that way
            let chunk_position;
            if encoded_chunk_used {
                chunk_position = *next_encoded_record_chunks_offset;
                *next_encoded_record_chunks_offset += 1;
            } else {
                chunk_position = num_encoded_record_chunks + *next_unencoded_record_chunks_offset;
                *next_unencoded_record_chunks_offset += 1;
            }
            output.copy_from_slice(&raw_sector.records[usize::from(piece_offset)][chunk_position]);
        }

        let metadata_chunks =
            metadata_region.array_chunks_mut::<{ RecordMetadata::encoded_size() }>();
        for (record_metadata, output) in raw_sector.metadata.iter().zip(metadata_chunks) {
            record_metadata.encode_to(&mut output.as_mut_slice());
        }

        // It would be more efficient to not re-read the whole sector again, but it makes above code
        // significantly more convoluted and most likely not worth it
        let (sector_contents, sector_checksum) =
            sector_output.split_at_mut(sector_size - Blake3Hash::SIZE);
        sector_checksum.copy_from_slice(blake3_hash_parallel(sector_contents).as_ref());
    }

    Ok(())
}

fn record_encoding<PosTable>(
    pos_seed: &PosSeed,
    record: &mut Record,
    mut encoded_chunks_used: EncodedChunksUsed<'_>,
    table_generator: &mut PosTable::Generator,
    erasure_coding: &ErasureCoding,
    chunks_scratch: &mut Vec<[u8; ScalarBytes::FULL_BYTES]>,
) where
    PosTable: Table,
{
    // Derive PoSpace table
    let pos_table = table_generator.generate_parallel(pos_seed);

    // Erasure code source record chunks
    let parity_record_chunks = erasure_coding
        .extend(
            &record
                .iter()
                .map(|scalar_bytes| {
                    Scalar::try_from(scalar_bytes).expect(
                        "Piece getter must returns valid pieces of history that contain \
                        proper scalar bytes; qed",
                    )
                })
                .collect::<Vec<_>>(),
        )
        .expect("Instance was verified to be able to work with this many values earlier; qed")
        .into_iter()
        .map(<[u8; ScalarBytes::FULL_BYTES]>::from)
        .collect::<Vec<_>>();
    let source_record_chunks = record.to_vec();

    chunks_scratch.clear();
    // For every erasure coded chunk check if there is proof present, if so then encode
    // with PoSpace proof bytes and set corresponding `encoded_chunks_used` bit to `true`
    (u16::from(SBucket::ZERO)..=u16::from(SBucket::MAX))
        .into_par_iter()
        .map(SBucket::from)
        .zip(
            source_record_chunks
                .par_iter()
                .interleave(&parity_record_chunks),
        )
        .map(|(s_bucket, record_chunk)| {
            if let Some(proof) = pos_table.find_proof(s_bucket.into()) {
                (Simd::from(*record_chunk) ^ Simd::from(*proof.hash())).to_array()
            } else {
                // Dummy value indicating no proof
                [0; ScalarBytes::FULL_BYTES]
            }
        })
        .collect_into_vec(chunks_scratch);
    let num_successfully_encoded_chunks = chunks_scratch
        .drain(..)
        .zip(encoded_chunks_used.iter_mut())
        .filter_map(|(maybe_encoded_chunk, mut encoded_chunk_used)| {
            // No proof, see above
            if maybe_encoded_chunk == [0; ScalarBytes::FULL_BYTES] {
                None
            } else {
                *encoded_chunk_used = true;

                Some(maybe_encoded_chunk)
            }
        })
        // Make sure above filter function (and corresponding `encoded_chunk_used` update)
        // happen at most as many times as there is number of chunks in the record,
        // otherwise `n+1` iterations could happen and update extra `encoded_chunk_used`
        // unnecessarily causing issues down the line
        .take(record.len())
        .zip(record.iter_mut())
        // Write encoded chunk back so we can reuse original allocation
        .map(|(input_chunk, output_chunk)| {
            *output_chunk = input_chunk;
        })
        .count();

    // In some cases there is not enough PoSpace proofs available, in which case we add
    // remaining number of unencoded erasure coded record chunks to the end
    source_record_chunks
        .iter()
        .zip(&parity_record_chunks)
        .flat_map(|(a, b)| [a, b])
        .zip(encoded_chunks_used.iter())
        // Skip chunks that were used previously
        .filter_map(|(record_chunk, encoded_chunk_used)| {
            if *encoded_chunk_used {
                None
            } else {
                Some(record_chunk)
            }
        })
        // First `num_successfully_encoded_chunks` chunks are encoded
        .zip(record.iter_mut().skip(num_successfully_encoded_chunks))
        // Write necessary number of unencoded chunks at the end
        .for_each(|(input_chunk, output_chunk)| {
            *output_chunk = *input_chunk;
        });
}

async fn download_sector_internal<PG>(
    pieces_to_download: &mut HashMap<PieceIndex, Vec<(&mut Record, &mut RecordMetadata)>>,
    piece_getter: &PG,
    kzg: &Kzg,
    erasure_coding: &ErasureCoding,
) -> Result<(), PlottingError>
where
    PG: PieceGetter + Send + Sync,
{
    // TODO: Make configurable, likely allowing user to specify RAM usage expectations and inferring
    //  concurrency from there
    let recovery_semaphore = &Semaphore::new(RECONSTRUCTION_CONCURRENCY_LIMIT);

    // Allocate to decouple lifetime from `pieces_to_download` that will be modified below
    let piece_indices = pieces_to_download.keys().copied().collect::<Vec<_>>();
    let mut downloaded_pieces = piece_getter
        .get_pieces(piece_indices)
        .await
        .map_err(|error| PlottingError::FailedToRetrievePieces { error })?
        .fuse();
    let mut reconstructed_pieces = FuturesUnordered::new();

    let mut final_result = Ok(());

    loop {
        let (piece_index, result) = select! {
            (piece_index, result) = downloaded_pieces.select_next_some() => {
                match result {
                    Ok(Some(piece)) => (piece_index, Ok(piece)),
                    Ok(None) => {
                        trace!(%piece_index, "Piece was not found, trying reconstruction");

                        reconstructed_pieces.push(reconstruct_piece(
                            piece_index,
                            recovery_semaphore,
                            piece_getter,
                            kzg,
                            erasure_coding,
                        ));
                        continue;
                    }
                    Err(error) => {
                        trace!(
                            %error,
                            %piece_index,
                            "Failed to download piece, trying reconstruction"
                        );

                        reconstructed_pieces.push(reconstruct_piece(
                            piece_index,
                            recovery_semaphore,
                            piece_getter,
                            kzg,
                            erasure_coding,
                        ));
                        continue;
                    }
                }
            },
            (piece_index, result) = reconstructed_pieces.select_next_some() => {
                (piece_index, result)
            },
            complete => {
                break;
            }
        };

        match result {
            Ok(piece) => {
                process_piece(piece_index, piece, pieces_to_download);
            }
            Err(error) => {
                trace!(%error, %piece_index, "Failed to download piece");

                if final_result.is_ok() {
                    final_result = Err(error);
                }
            }
        }
    }

    if final_result.is_ok() && !pieces_to_download.is_empty() {
        return Err(PlottingError::FailedToRetrievePieces {
            error: anyhow::anyhow!(
                "Successful result, but not all pieces were downloaded, this is likely a piece \
                getter implementation bug"
            ),
        });
    }

    final_result
}

async fn reconstruct_piece<PG>(
    piece_index: PieceIndex,
    recovery_semaphore: &Semaphore,
    piece_getter: &PG,
    kzg: &Kzg,
    erasure_coding: &ErasureCoding,
) -> (PieceIndex, Result<Piece, PlottingError>)
where
    PG: PieceGetter + Send + Sync,
{
    let _permit = recovery_semaphore.acquire().await;
    let recovered_piece_fut = recover_missing_piece(
        piece_getter,
        kzg.clone(),
        erasure_coding.clone(),
        piece_index,
    );

    (
        piece_index,
        recovered_piece_fut
            .await
            .map_err(|error| PlottingError::PieceRecoveryFailed {
                piece_index,
                error: error.into(),
            }),
    )
}

fn process_piece(
    piece_index: PieceIndex,
    piece: Piece,
    pieces_to_download: &mut HashMap<PieceIndex, Vec<(&mut Record, &mut RecordMetadata)>>,
) {
    for (record, metadata) in pieces_to_download.remove(&piece_index).unwrap_or_default() {
        // Fancy way to insert value in order to avoid going through stack (if naive
        // de-referencing is used) and potentially causing stack overflow as the
        // result
        record
            .as_flattened_mut()
            .copy_from_slice(piece.record().as_flattened());
        *metadata = RecordMetadata {
            commitment: *piece.commitment(),
            witness: *piece.witness(),
            piece_checksum: blake3_hash(piece.as_ref()),
        };
    }
}
