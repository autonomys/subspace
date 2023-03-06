use crate::piece_caching::PieceMemoryCache;
use crate::segment_reconstruction::recover_missing_piece;
use crate::{FarmerProtocolInfo, SectorMetadata};
use async_trait::async_trait;
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use parity_scale_codec::Encode;
use std::error::Error;
use std::io;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::{Commitment, Kzg};
use subspace_core_primitives::sector_codec::{SectorCodec, SectorCodecError};
use subspace_core_primitives::{
    Piece, PieceIndex, PieceIndexHash, PublicKey, Scalar, SectorId, SectorIndex, PIECE_SIZE,
    PLOT_SECTOR_SIZE,
};
use thiserror::Error;
use tracing::info;

/// Defines retry policy on error during piece acquiring.
#[derive(PartialEq, Eq, Clone, Debug, Copy)]
pub enum PieceGetterRetryPolicy {
    /// Exit on the first error
    NoRetry,

    /// Try N times
    Limited(u16),

    /// No restrictions on retries
    Eternal,
}

impl Default for PieceGetterRetryPolicy {
    fn default() -> Self {
        Self::NoRetry
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

/// Information about sector that was plotted
#[derive(Debug, Clone)]
pub struct PlottedSector {
    /// Sector ID
    pub sector_id: SectorId,
    /// Sector index
    pub sector_index: SectorIndex,
    /// Sector metadata
    pub sector_metadata: SectorMetadata,
    /// Indexes of pieces that were plotted
    pub piece_indexes: Vec<PieceIndex>,
}

/// Plotting status
#[derive(Debug, Error)]
pub enum PlottingError {
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
    /// Failed to encode sector
    #[error("Failed to encode sector: {0}")]
    FailedToEncodeSector(#[from] SectorCodecError),
    /// Failed to commit
    #[error("Failed to commit: {0}")]
    FailedToCommit(#[from] kzg::Error),
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Plot a single sector, where `sector` and `sector_metadata` must be positioned correctly (seek to
/// desired offset before calling this function if necessary)
///
/// NOTE: Even though this function is async, it has blocking code inside and must be running in a
/// separate thread in order to prevent blocking an executor.
#[allow(clippy::too_many_arguments)]
pub async fn plot_sector<PG, S, SM>(
    public_key: &PublicKey,
    sector_index: u64,
    piece_getter: &PG,
    piece_getter_retry_policy: PieceGetterRetryPolicy,
    farmer_protocol_info: &FarmerProtocolInfo,
    kzg: &Kzg,
    sector_codec: &SectorCodec,
    mut sector_output: S,
    mut sector_metadata_output: SM,
    piece_memory_cache: PieceMemoryCache,
) -> Result<PlottedSector, PlottingError>
where
    PG: PieceGetter,
    S: io::Write,
    SM: io::Write,
{
    let sector_id = SectorId::new(public_key, sector_index);
    // TODO: Consider adding number of pieces in a sector to protocol info
    //  explicitly and, ideally, we need to remove 2x replication
    //  expectation from other places too
    let current_segment_index = farmer_protocol_info.total_pieces.get()
        / u64::from(farmer_protocol_info.recorded_history_segment_size)
        / u64::from(farmer_protocol_info.record_size.get())
        * 2;
    let expires_at = current_segment_index + farmer_protocol_info.sector_expiration;

    let piece_indexes: Vec<PieceIndex> = (0u64..)
        .take(PLOT_SECTOR_SIZE as usize / (PIECE_SIZE / Scalar::SAFE_BYTES * Scalar::FULL_BYTES))
        .map(|piece_offset| {
            sector_id.derive_piece_index(
                piece_offset as PieceIndex,
                farmer_protocol_info.total_pieces,
            )
        })
        .collect();

    let mut in_memory_sector_scalars =
        Vec::with_capacity(PLOT_SECTOR_SIZE as usize / Scalar::FULL_BYTES);

    plot_pieces_in_batches_non_blocking(
        &mut in_memory_sector_scalars,
        sector_index,
        piece_getter,
        piece_getter_retry_policy,
        kzg,
        &piece_indexes,
        piece_memory_cache,
    )
    .await?;

    sector_codec
        .encode(&mut in_memory_sector_scalars)
        .map_err(PlottingError::FailedToEncodeSector)?;

    let mut in_memory_sector = vec![0u8; PLOT_SECTOR_SIZE as usize];

    in_memory_sector
        .chunks_exact_mut(Scalar::FULL_BYTES)
        .zip(in_memory_sector_scalars)
        .for_each(|(output, input)| {
            input.write_to_bytes(
                <&mut [u8; Scalar::FULL_BYTES]>::try_from(output)
                    .expect("Chunked into scalar full bytes above; qed"),
            );
        });

    sector_output
        .write_all(&in_memory_sector)
        .map_err(PlottingError::Io)?;

    let commitments = in_memory_sector
        .chunks_exact(PIECE_SIZE)
        .map(|piece| {
            // TODO: This is a workaround to the fact that `kzg.poly()` expects `data` to be a slice
            //  32-byte chunks that have up to 254 bits of data in them and in sector encoding we're
            //  dealing with 31-byte chunks instead. This workaround will not be necessary once we
            //  change `kzg.poly()` API to use 31-byte chunks as well.
            let mut expanded_piece = Vec::with_capacity(PIECE_SIZE / Scalar::SAFE_BYTES * 32);
            piece.chunks_exact(Scalar::SAFE_BYTES).for_each(|chunk| {
                expanded_piece.extend(chunk);
                expanded_piece.extend([0]);
            });
            let polynomial = kzg.poly(&expanded_piece)?;
            kzg.commit(&polynomial).map_err(Into::into)
        })
        .collect::<Result<Vec<Commitment>, PlottingError>>()?;

    let sector_metadata = SectorMetadata {
        total_pieces: farmer_protocol_info.total_pieces,
        expires_at,
        commitments,
    };

    sector_metadata_output.write_all(&sector_metadata.encode())?;

    Ok(PlottedSector {
        sector_id,
        sector_index,
        sector_metadata,
        piece_indexes,
    })
}

async fn plot_pieces_in_batches_non_blocking<PG: PieceGetter>(
    in_memory_sector_scalars: &mut Vec<Scalar>,
    sector_index: u64,
    piece_getter: &PG,
    piece_getter_retry_policy: PieceGetterRetryPolicy,
    kzg: &Kzg,
    piece_indexes: &[PieceIndex],
    piece_memory_cache: PieceMemoryCache,
) -> Result<(), PlottingError> {
    let mut pieces_receiving_futures = piece_indexes
        .iter()
        .map(|piece_index| async {
            let piece_result = piece_getter
                .get_piece(*piece_index, piece_getter_retry_policy)
                .await;

            let failed = piece_result
                .as_ref()
                .map(|piece| piece.is_none())
                .unwrap_or(true);

            // all retries failed
            if failed {
                let recovered_piece = recover_missing_piece(piece_getter, kzg, *piece_index).await;

                return (*piece_index, recovered_piece.map(Some).map_err(Into::into));
            }

            (*piece_index, piece_result)
        })
        .collect::<FuturesOrdered<_>>();

    while let Some((piece_index, piece_result)) = pieces_receiving_futures.next().await {
        let piece = piece_result
            .map_err(|error| PlottingError::FailedToRetrievePiece { piece_index, error })?
            .ok_or(PlottingError::PieceNotFound { piece_index })?;

        in_memory_sector_scalars.extend(piece.chunks_exact(Scalar::SAFE_BYTES).map(|bytes| {
            Scalar::from(
                <&[u8; Scalar::SAFE_BYTES]>::try_from(bytes)
                    .expect("Chunked into scalar safe bytes above; qed"),
            )
        }));

        piece_memory_cache.add_piece(PieceIndexHash::from_index(piece_index), piece);
    }

    info!(%sector_index, "Plotting was successful.");

    Ok(())
}
