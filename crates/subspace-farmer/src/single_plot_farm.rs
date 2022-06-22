use crate::commitments::Commitments;
use crate::dsn;
use crate::dsn::{PieceIndexHashNumber, SyncOptions};
use crate::farming::Farming;
use crate::plot::Plot;
use crate::plotting::plot_pieces;
use std::future::Future;
use subspace_networking::{Node, PiecesToPlot};
use subspace_solving::SubspaceCodec;

// TODO: Make fields private
pub struct SinglePlotFarm {
    pub(crate) codec: SubspaceCodec,
    pub plot: Plot,
    pub commitments: Commitments,
    pub(crate) farming: Option<Farming>,
    pub(crate) node: Node,
}

impl SinglePlotFarm {
    pub(crate) fn dsn_sync(
        &self,
        max_plot_size: u64,
        total_pieces: u64,
    ) -> impl Future<Output = anyhow::Result<()>> {
        let plot = self.plot.clone();
        let commitments = self.commitments.clone();
        let codec = self.codec.clone();
        let node = self.node.clone();

        let options = SyncOptions {
            range_size: PieceIndexHashNumber::MAX / 1024,
            public_key: plot.public_key(),
            max_plot_size,
            total_pieces,
        };
        let mut plot_pieces = plot_pieces(codec, &plot, commitments);

        dsn::sync(node, options, move |pieces, piece_indexes| {
            if !plot_pieces(PiecesToPlot {
                pieces,
                piece_indexes,
            }) {
                return Err(anyhow::anyhow!("Failed to plot pieces in archiving"));
            }
            Ok(())
        })
    }
}
