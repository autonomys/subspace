use crate::sector::{
    sector_record_chunks_size, sector_size, RawSector, RecordMetadata, SectorContentsMap,
    SectorMetadata, SectorMetadataChecksummed,
};
use crate::segment_reconstruction::recover_missing_piece;
use crate::FarmerProtocolInfo;
use async_lock::Mutex;
use async_trait::async_trait;
use backoff::future::retry;
use backoff::{Error as BackoffError, ExponentialBackoff};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use parity_scale_codec::Encode;
use std::error::Error;
use std::mem;
use std::simd::Simd;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::crypto::{blake3_hash, blake3_hash_parallel, Scalar};
use subspace_core_primitives::{
    ArchivedHistorySegment, Blake3Hash, Piece, PieceIndex, PieceOffset, PublicKey, Record, SBucket,
    SectorId, SectorIndex,
};
use subspace_erasure_coding::ErasureCoding;
use subspace_proof_of_space::{Quality, Table, TableGenerator};
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::yield_now;
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

/// Defines retry policy on error during piece acquiring.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub enum PieceGetterRetryPolicy {
    /// Retry N times (including zero)
    Limited(u16),
    /// No restrictions on retries
    Unlimited,
}

impl Default for PieceGetterRetryPolicy {
    #[inline]
    fn default() -> Self {
        Self::Limited(0)
    }
}

/// Duplicate trait for the subspace_networking::PieceReceiver. The goal of this trait is
/// simplifying dependency graph.
#[async_trait]
pub trait PieceGetter {
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>>;
}

#[async_trait]
impl<T> PieceGetter for Arc<T>
where
    T: PieceGetter + Send + Sync,
{
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        self.as_ref().get_piece(piece_index, retry_policy).await
    }
}

#[async_trait]
impl PieceGetter for ArchivedHistorySegment {
    async fn get_piece(
        &self,
        piece_index: PieceIndex,
        _retry_policy: PieceGetterRetryPolicy,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>> {
        Ok(self
            .get(usize::try_from(u64::from(piece_index))?)
            .map(Piece::from))
    }
}

/// Information about sector that was plotted
#[derive(Debug, Clone)]
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
    /// Invalid erasure coding instance
    #[error("Invalid erasure coding instance")]
    InvalidErasureCodingInstance,
    /// Bad sector output size
    #[error("Bad sector output size: provided {provided}, expected {expected}")]
    BadSectorOutputSize {
        /// Actual size
        provided: usize,
        /// Expected size
        expected: usize,
    },
    /// Bad sector metadata output size
    #[error("Bad sector metadata output size: provided {provided}, expected {expected}")]
    BadSectorMetadataOutputSize {
        /// Actual size
        provided: usize,
        /// Expected size
        expected: usize,
    },
    /// Piece not found, can't create sector, this should never happen
    #[error("Piece {piece_index} not found, can't create sector, this should never happen")]
    PieceNotFound {
        /// Piece index
        piece_index: PieceIndex,
    },
    /// Can't recover missing piece
    #[error("Can't recover missing piece")]
    PieceRecoveryFailed {
        /// Piece index
        piece_index: PieceIndex,
    },
    /// Failed to retrieve piece
    #[error("Failed to retrieve piece {piece_index}: {error}")]
    FailedToRetrievePiece {
        /// Piece index
        piece_index: PieceIndex,
        /// Lower-level error
        error: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

/// Options for plotting a sector.
///
/// Sector output and sector metadata output should be either empty (in which case they'll be
/// resized to correct size automatically) or correctly sized from the beginning or else error will
/// be returned.
pub struct PlotSectorOptions<'a, PosTable, PG>
where
    PosTable: Table,
{
    /// Public key corresponding to sector
    pub public_key: &'a PublicKey,
    /// Sector index
    pub sector_index: SectorIndex,
    /// Getter for pieces of archival history
    pub piece_getter: &'a PG,
    /// Retry policy for piece getter
    pub piece_getter_retry_policy: PieceGetterRetryPolicy,
    /// Farmer protocol info
    pub farmer_protocol_info: &'a FarmerProtocolInfo,
    /// KZG instance
    pub kzg: &'a Kzg,
    /// Erasure coding instance
    pub erasure_coding: &'a ErasureCoding,
    /// How many pieces should sector contain
    pub pieces_in_sector: u16,
    /// Where plotted sector should be written, vector must either be empty (in which case it'll be
    /// resized to correct size automatically) or correctly sized from the beginning
    pub sector_output: &'a mut Vec<u8>,
    /// Where plotted sector metadata should be written, vector must either be empty (in which case
    /// it'll be resized to correct size automatically) or correctly sized from the beginning
    pub sector_metadata_output: &'a mut Vec<u8>,
    /// Semaphore for part of the plotting when farmer downloads new sector, allows to limit memory
    /// usage of the plotting process, permit will be held until the end of the plotting process
    pub downloading_semaphore: Option<&'a Semaphore>,
    /// Semaphore for part of the plotting when farmer encodes downloaded sector, should typically
    /// allow one permit at a time for efficient CPU utilization
    pub encoding_semaphore: Option<&'a Semaphore>,
    /// Proof of space table generator
    pub table_generator: &'a mut PosTable::Generator,
}

/// Plot a single sector.
///
/// NOTE: Even though this function is async, it has blocking code inside and must be running in a
/// separate thread in order to prevent blocking an executor.
pub async fn plot_sector<PosTable, PG>(
    options: PlotSectorOptions<'_, PosTable, PG>,
) -> Result<PlottedSector, PlottingError>
where
    PosTable: Table,
    PG: PieceGetter,
{
    let PlotSectorOptions {
        public_key,
        sector_index,
        piece_getter,
        piece_getter_retry_policy,
        farmer_protocol_info,
        kzg,
        erasure_coding,
        pieces_in_sector,
        sector_output,
        sector_metadata_output,
        downloading_semaphore,
        encoding_semaphore,
        table_generator,
    } = options;

    if erasure_coding.max_shards() < Record::NUM_S_BUCKETS {
        return Err(PlottingError::InvalidErasureCodingInstance);
    }

    let sector_size = sector_size(pieces_in_sector);

    if !sector_output.is_empty() && sector_output.len() != sector_size {
        return Err(PlottingError::BadSectorOutputSize {
            provided: sector_output.len(),
            expected: sector_size,
        });
    }

    if !sector_metadata_output.is_empty()
        && sector_metadata_output.len() != SectorMetadataChecksummed::encoded_size()
    {
        return Err(PlottingError::BadSectorMetadataOutputSize {
            provided: sector_metadata_output.len(),
            expected: SectorMetadataChecksummed::encoded_size(),
        });
    }

    let _downloading_permit = match downloading_semaphore {
        Some(downloading_semaphore) => Some(downloading_semaphore.acquire().await),
        None => None,
    };

    let sector_id = SectorId::new(public_key.hash(), sector_index);

    let piece_indexes: Vec<PieceIndex> = (PieceOffset::ZERO..)
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
        .collect();

    // TODO: Downloading and encoding below can happen in parallel, but a bit tricky to implement
    //  due to sync/async pairing

    let raw_sector = Mutex::new(RawSector::new(pieces_in_sector));

    {
        // This list will be mutated, replacing pieces we have already processed with `None`
        let incremental_piece_indices =
            Mutex::new(piece_indexes.iter().copied().map(Some).collect::<Vec<_>>());

        retry(default_backoff(), || async {
            let mut raw_sector = raw_sector.lock().await;
            let mut incremental_piece_indices = incremental_piece_indices.lock().await;

            if let Err(error) = download_sector(
                &mut raw_sector,
                piece_getter,
                piece_getter_retry_policy,
                kzg,
                &mut incremental_piece_indices,
            )
            .await
            {
                let retrieved_pieces = incremental_piece_indices
                    .iter()
                    .filter(|maybe_piece_index| maybe_piece_index.is_none())
                    .count();
                warn!(
                    %sector_index,
                    %error,
                    %pieces_in_sector,
                    %retrieved_pieces,
                    "Sector plotting attempt failed, will retry later"
                );

                return Err(BackoffError::transient(error));
            }

            debug!(%sector_index, "Sector downloaded successfully");

            Ok(())
        })
        .await?;
    }

    let mut raw_sector = raw_sector.into_inner();

    let _encoding_permit = match encoding_semaphore {
        Some(encoding_semaphore) => Some(encoding_semaphore.acquire().await),
        None => None,
    };

    let mut sector_contents_map = SectorContentsMap::new(pieces_in_sector);

    for ((piece_offset, record), mut encoded_chunks_used) in (PieceOffset::ZERO..)
        .zip(raw_sector.records.iter_mut())
        .zip(sector_contents_map.iter_record_bitfields_mut())
    {
        // Derive PoSpace table (use parallel mode because multiple tables concurrently will use
        // too much RAM)
        let pos_table = table_generator.generate_parallel(
            &sector_id.derive_evaluation_seed(piece_offset, farmer_protocol_info.history_size),
        );

        let source_record_chunks = record
            .iter()
            .map(|scalar_bytes| {
                Scalar::try_from(scalar_bytes).expect(
                    "Piece getter must returns valid pieces of history that contain proper \
                    scalar bytes; qed",
                )
            })
            .collect::<Vec<_>>();
        // Erasure code source record chunks
        let parity_record_chunks = erasure_coding
            .extend(&source_record_chunks)
            .expect("Instance was verified to be able to work with this many values earlier; qed");

        // For every erasure coded chunk check if there is quality present, if so then encode
        // with PoSpace quality bytes and set corresponding `quality_present` bit to `true`
        let num_successfully_encoded_chunks = (SBucket::ZERO..=SBucket::MAX)
            .zip(
                source_record_chunks
                    .iter()
                    .zip(&parity_record_chunks)
                    .flat_map(|(a, b)| [a, b]),
            )
            .zip(encoded_chunks_used.iter_mut())
            .filter_map(|((s_bucket, record_chunk), mut encoded_chunk_used)| {
                let quality = pos_table.find_quality(s_bucket.into())?;

                *encoded_chunk_used = true;

                Some(
                    Simd::from(record_chunk.to_bytes()) ^ Simd::from(quality.create_proof().hash()),
                )
            })
            // Make sure above filter function (and corresponding `encoded_chunk_used` update)
            // happen at most as many times as there is number of chunks in the record,
            // otherwise `n+1` iterations could happen and update extra `encoded_chunk_used`
            // unnecessarily causing issues down the line
            .take(record.iter().count())
            .zip(record.iter_mut())
            // Write encoded chunk back so we can reuse original allocation
            .map(|(input_chunk, output_chunk)| {
                *output_chunk = input_chunk.to_array();
            })
            .count();

        // In some cases there is not enough PoSpace qualities available, in which case we add
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
                *output_chunk = input_chunk.to_bytes();
            });

        // Give a chance to interrupt plotting if necessary in between pieces
        yield_now().await
    }

    sector_output.resize(sector_size, 0);
    sector_metadata_output.resize(SectorMetadataChecksummed::encoded_size(), 0);

    // Write sector to disk in form of following regions:
    // * sector contents map
    // * record chunks as s-buckets
    // * record metadata
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
            .zip(s_buckets_region.array_chunks_mut::<{ Scalar::FULL_BYTES }>())
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
        for (record_metadata, output) in raw_sector.metadata.into_iter().zip(metadata_chunks) {
            record_metadata.encode_to(&mut output.as_mut_slice());
        }

        // It would be more efficient to not re-read the whole sector again, but it makes above code
        // significantly more convoluted and most likely not worth it
        let (sector_contents, sector_checksum) =
            sector_output.split_at_mut(sector_size - mem::size_of::<Blake3Hash>());
        sector_checksum.copy_from_slice(&blake3_hash_parallel(sector_contents));
    }

    let sector_metadata = SectorMetadataChecksummed::from(SectorMetadata {
        sector_index,
        pieces_in_sector,
        s_bucket_sizes: sector_contents_map.s_bucket_sizes(),
        history_size: farmer_protocol_info.history_size,
    });

    sector_metadata_output.copy_from_slice(&sector_metadata.encode());

    Ok(PlottedSector {
        sector_id,
        sector_index,
        sector_metadata,
        piece_indexes,
    })
}

async fn download_sector<PG: PieceGetter>(
    raw_sector: &mut RawSector,
    piece_getter: &PG,
    piece_getter_retry_policy: PieceGetterRetryPolicy,
    kzg: &Kzg,
    piece_indexes: &mut [Option<PieceIndex>],
) -> Result<(), PlottingError> {
    // TODO: Make configurable, likely allowing user to specify RAM usage expectations and inferring
    //  concurrency from there
    let recovery_semaphore = Semaphore::new(RECONSTRUCTION_CONCURRENCY_LIMIT);

    let mut pieces_receiving_futures = piece_indexes
        .iter_mut()
        .zip(raw_sector.records.iter_mut().zip(&mut raw_sector.metadata))
        .map(|(maybe_piece_index, (record, metadata))| async {
            // We skip pieces that we have already processed previously
            let Some(piece_index) = *maybe_piece_index else {
                return Ok(());
            };

            let mut piece_result = piece_getter
                .get_piece(piece_index, piece_getter_retry_policy)
                .await;

            let succeeded = piece_result
                .as_ref()
                .map(|piece| piece.is_some())
                .unwrap_or_default();

            // All retries failed
            if !succeeded {
                let _permit = match recovery_semaphore.acquire().await {
                    Ok(permit) => permit,
                    Err(error) => {
                        let error = format!("Recovery semaphore was closed: {error}").into();
                        return Err(PlottingError::FailedToRetrievePiece { piece_index, error });
                    }
                };
                let recovered_piece =
                    recover_missing_piece(piece_getter, kzg.clone(), piece_index).await;

                piece_result = recovered_piece.map(Some).map_err(Into::into);
            }

            let piece = piece_result
                .map_err(|error| PlottingError::FailedToRetrievePiece { piece_index, error })?
                .ok_or(PlottingError::PieceNotFound { piece_index })?;

            // Fancy way to insert value in order to avoid going through stack (if naive de-referencing
            // is used) and potentially causing stack overflow as the result
            record
                .flatten_mut()
                .copy_from_slice(piece.record().flatten());
            *metadata = RecordMetadata {
                commitment: *piece.commitment(),
                witness: *piece.witness(),
                piece_checksum: blake3_hash(piece.as_ref()),
            };

            // We have processed this piece index, clear it
            maybe_piece_index.take();

            Ok(())
        })
        .collect::<FuturesUnordered<_>>();

    let mut final_result = Ok(());

    while let Some(result) = pieces_receiving_futures.next().await {
        if let Err(error) = result {
            trace!(%error, "Failed to download piece");

            if final_result.is_ok() {
                final_result = Err(error);
            }
        }
    }

    final_result
}
