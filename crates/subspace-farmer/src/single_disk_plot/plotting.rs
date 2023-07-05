use crate::single_disk_plot::{Handlers, PlotMetadataHeader, RESERVED_PLOT_METADATA};
use crate::{node_client, NodeClient};
use memmap2::{MmapMut, MmapOptions};
use parity_scale_codec::Encode;
use parking_lot::RwLock;
use std::fs::File;
use std::io;
use std::num::NonZeroU16;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{PublicKey, SectorIndex};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::plotting;
use subspace_farmer_components::plotting::{plot_sector, PieceGetter, PieceGetterRetryPolicy};
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
                .offset(RESERVED_PLOT_METADATA + (sector_index * sector_metadata_size as u64))
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
        sectors_metadata
            .write()
            .push(plotted_sector.sector_metadata.clone());

        // Inform others that this sector is no longer being modified
        modifying_sector_index.write().take();

        info!(%sector_index, "Sector plotted successfully");

        handlers
            .sector_plotted
            .call_simple(&(plotted_sector, Arc::new(plotting_permit)));
    }

    Ok(())
}
