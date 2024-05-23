pub mod cpu;

use async_trait::async_trait;
use futures::{Sink, Stream};
use std::error::Error;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{PublicKey, SectorIndex};
use subspace_farmer_components::plotting::PlottedSector;
use subspace_farmer_components::FarmerProtocolInfo;

/// Sector plotting progress
pub enum SectorPlottingProgress {
    /// Downloading sector pieces
    Downloading,
    /// Downloaded sector pieces
    Downloaded(Duration),
    /// Encoding sector pieces
    Encoding,
    /// Encoded sector pieces
    Encoded(Duration),
    /// Finished plotting
    Finished {
        /// Information about plotted sector
        plotted_sector: PlottedSector,
        /// How much time it took to plot a sector
        time: Duration,
        /// Stream of all plotted sector bytes
        sector: Pin<Box<dyn Stream<Item = Result<Vec<u8>, String>> + Send + Sync>>,
    },
    /// Plotting failed
    Error {
        /// Error message
        error: String,
    },
}

impl fmt::Debug for SectorPlottingProgress {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SectorPlottingProgress::Downloading => fmt::Formatter::write_str(f, "Downloading"),
            SectorPlottingProgress::Downloaded(time) => {
                f.debug_tuple_field1_finish("Downloaded", &time)
            }
            SectorPlottingProgress::Encoding => fmt::Formatter::write_str(f, "Encoding"),
            SectorPlottingProgress::Encoded(time) => f.debug_tuple_field1_finish("Encoded", &time),
            SectorPlottingProgress::Finished {
                plotted_sector,
                time,
                sector: _,
            } => f.debug_struct_field3_finish(
                "Finished",
                "plotted_sector",
                plotted_sector,
                "time",
                time,
                "sector",
                &"<stream>",
            ),
            SectorPlottingProgress::Error { error } => {
                f.debug_struct_field1_finish("Error", "error", &error)
            }
        }
    }
}

/// Abstract plotter implementation
#[async_trait]
pub trait Plotter {
    /// Whether plotter has free capacity to encode more sectors
    async fn has_free_capacity(&self) -> Result<bool, String>;

    /// Plot one sector, sending sector plotting events via provided stream.
    ///
    /// Future returns once plotting is successfully scheduled (for backpressure purposes).
    async fn plot_sector<PS>(
        &self,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        replotting: bool,
        progress_sender: PS,
    ) where
        PS: Sink<SectorPlottingProgress> + Unpin + Send + 'static,
        PS::Error: Error;

    /// Try to plot one sector, sending sector plotting events via provided stream.
    ///
    /// Returns `true` if plotting started successfully and `false` if there is no capacity to start
    /// plotting immediately.
    async fn try_plot_sector<PS>(
        &self,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        replotting: bool,
        progress_sender: PS,
    ) -> bool
    where
        PS: Sink<SectorPlottingProgress> + Unpin + Send + 'static,
        PS::Error: Error;
}

#[async_trait]
impl<P> Plotter for Arc<P>
where
    P: Plotter + Send + Sync,
{
    #[inline]
    async fn has_free_capacity(&self) -> Result<bool, String> {
        self.as_ref().has_free_capacity().await
    }

    #[inline]
    async fn plot_sector<PS>(
        &self,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        replotting: bool,
        progress_sender: PS,
    ) where
        PS: Sink<SectorPlottingProgress> + Unpin + Send + 'static,
        PS::Error: Error,
    {
        self.as_ref()
            .plot_sector(
                public_key,
                sector_index,
                farmer_protocol_info,
                pieces_in_sector,
                replotting,
                progress_sender,
            )
            .await
    }

    #[inline]
    async fn try_plot_sector<PS>(
        &self,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        replotting: bool,
        progress_sender: PS,
    ) -> bool
    where
        PS: Sink<SectorPlottingProgress> + Unpin + Send + 'static,
        PS::Error: Error,
    {
        self.as_ref()
            .try_plot_sector(
                public_key,
                sector_index,
                farmer_protocol_info,
                pieces_in_sector,
                replotting,
                progress_sender,
            )
            .await
    }
}
