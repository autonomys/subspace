pub mod cpu;

use async_trait::async_trait;
use futures::Sink;
use parity_scale_codec::{Decode, Encode};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{PublicKey, SectorIndex};
use subspace_farmer_components::plotting::PlottedSector;
use subspace_farmer_components::FarmerProtocolInfo;

// TODO: It is a bit awkward that this mimics `SectorPlottingDetails` with slight differences, maybe
//  `SectorPlottingDetails` should be a bit generic and support customization of
//  `Starting`/`Finished` contents
/// Sector plotting progress
#[derive(Debug, Clone, Encode, Decode)]
#[allow(clippy::large_enum_variant)]
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
        /// All plotted sector bytes
        sector: Vec<u8>,
        /// All plotted sector metadata bytes
        sector_metadata: Vec<u8>,
    },
    /// Plotting failed
    Error {
        /// Error message
        error: String,
    },
}

/// Abstract plotter implementation
#[async_trait]
pub trait Plotter {
    /// Plot one sector, returns a stream of sector plotting events.
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
}

#[async_trait]
impl<P> Plotter for Arc<P>
where
    P: Plotter + Send + Sync,
{
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
}
