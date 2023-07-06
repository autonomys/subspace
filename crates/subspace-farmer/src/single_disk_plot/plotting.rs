use crate::single_disk_plot::{Handlers, PlotMetadataHeader, RESERVED_PLOT_METADATA};
use crate::{node_client, NodeClient};
use memmap2::{MmapMut, MmapOptions};
use parity_scale_codec::Encode;
use parking_lot::RwLock;
use std::fs::File;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::{io, mem};
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PieceOffset, PublicKey, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting;
use subspace_farmer_components::plotting::{
    plot_sector, PieceGetter, PieceGetterRetryPolicy, PlottedSector,
};
use subspace_farmer_components::sector::SectorMetadata;
use subspace_proof_of_space::Table;
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};

/// Get piece retry attempts number.
const PIECE_GETTER_RETRY_NUMBER: NonZeroU16 = NonZeroU16::new(3).expect("Not zero; qed");

/// Errors that happen during plotting
#[derive(Debug, Error)]
pub enum PlottingError {
    /// Failed to retrieve farmer info
    #[error("Failed to retrieve farmer info: {error}")]
    FailedToGetFarmerInfo {
        /// Lower-level error
        error: node_client::Error,
    },
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Low-level plotting error
    #[error("Low-level plotting error: {0}")]
    LowLevel(#[from] plotting::PlottingError),
}

/// Starts plotting process.
///
/// NOTE: Returned future is async, but does blocking operations and should be running in dedicated
/// thread.
#[allow(clippy::too_many_arguments)]
pub(super) async fn plotting<NC, PG, PosTable>(
    public_key: PublicKey,
    node_client: NC,
    pieces_in_sector: u16,
    sector_size: usize,
    sector_metadata_size: usize,
    target_sector_count: SectorIndex,
    mut metadata_header: PlotMetadataHeader,
    mut metadata_header_mmap: MmapMut,
    plot_file: Arc<File>,
    metadata_file: File,
    sectors_metadata: Arc<RwLock<Vec<SectorMetadata>>>,
    piece_getter: PG,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    handlers: Arc<Handlers>,
    modifying_sector_index: Arc<RwLock<Option<SectorIndex>>>,
    concurrent_plotting_semaphore: Arc<Semaphore>,
) -> Result<(), PlottingError>
where
    NC: NodeClient,
    PG: PieceGetter + Send + 'static,
    PosTable: Table,
{
    // Some sectors may already be plotted, skip them
    let sectors_indices_left_to_plot = metadata_header.sector_count..target_sector_count;

    // TODO: Concurrency
    for sector_index in sectors_indices_left_to_plot {
        trace!(%sector_index, "Preparing to plot sector");

        let mut sector = unsafe {
            MmapOptions::new()
                .offset((sector_index as usize * sector_size) as u64)
                .len(sector_size)
                .map_mut(&*plot_file)?
        };
        let mut sector_metadata = unsafe {
            MmapOptions::new()
                .offset(
                    RESERVED_PLOT_METADATA
                        + (u64::from(sector_index) * sector_metadata_size as u64),
                )
                .len(sector_metadata_size)
                .map_mut(&metadata_file)?
        };
        let plotting_permit = match concurrent_plotting_semaphore.clone().acquire_owned().await {
            Ok(plotting_permit) => plotting_permit,
            Err(error) => {
                warn!(
                    %sector_index,
                    %error,
                    "Semaphore was closed, interrupting plotting"
                );
                return Ok(());
            }
        };

        debug!(%sector_index, "Plotting sector");

        let farmer_app_info = node_client
            .farmer_app_info()
            .await
            .map_err(|error| PlottingError::FailedToGetFarmerInfo { error })?;

        let plot_sector_fut = plot_sector::<_, PosTable>(
            &public_key,
            sector_index,
            &piece_getter,
            PieceGetterRetryPolicy::Limited(PIECE_GETTER_RETRY_NUMBER.get()),
            &farmer_app_info.protocol_info,
            &kzg,
            &erasure_coding,
            pieces_in_sector,
            &mut sector,
            &mut sector_metadata,
        );

        // Inform others that this sector is being modified
        modifying_sector_index.write().replace(sector_index);

        let plotted_sector = plot_sector_fut.await?;
        sector.flush()?;
        sector_metadata.flush()?;

        metadata_header.sector_count += 1;
        metadata_header_mmap.copy_from_slice(metadata_header.encode().as_slice());
        let maybe_old_sector_metadata = {
            let mut sectors_metadata = sectors_metadata.write();
            // If exists then we're replotting, otherwise we create sector for the first time
            if let Some(existing_sector_metadata) = sectors_metadata.get_mut(sector_index as usize)
            {
                let mut sector_metadata_tmp = plotted_sector.sector_metadata.clone();
                mem::swap(existing_sector_metadata, &mut sector_metadata_tmp);
                Some(sector_metadata_tmp)
            } else {
                sectors_metadata.push(plotted_sector.sector_metadata.clone());
                None
            }
        };

        let old_plotted_sector = maybe_old_sector_metadata.map(|old_sector_metadata| {
            let old_history_size = old_sector_metadata.history_size;

            PlottedSector {
                sector_id: plotted_sector.sector_id,
                sector_index: plotted_sector.sector_index,
                sector_metadata: old_sector_metadata,
                piece_indexes: {
                    let mut piece_indexes = Vec::with_capacity(usize::from(pieces_in_sector));
                    (PieceOffset::ZERO..)
                        .take(usize::from(pieces_in_sector))
                        .map(|piece_offset| {
                            plotted_sector.sector_id.derive_piece_index(
                                piece_offset,
                                old_history_size,
                                farmer_app_info.protocol_info.max_pieces_in_sector,
                                farmer_app_info.protocol_info.recent_segments,
                                farmer_app_info.protocol_info.recent_history_fraction,
                            )
                        })
                        .collect_into(&mut piece_indexes);
                    piece_indexes
                },
            }
        });

        // Inform others that this sector is no longer being modified
        modifying_sector_index.write().take();

        info!(%sector_index, "Sector plotted successfully");

        handlers.sector_plotted.call_simple(&(
            plotted_sector,
            old_plotted_sector,
            Arc::new(plotting_permit),
        ));
    }

    Ok(())
}
