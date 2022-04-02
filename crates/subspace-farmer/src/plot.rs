mod single_plot;
#[cfg(test)]
mod single_plot_tests;

pub(crate) use single_plot::PieceOffset;
pub use single_plot::{Plot, PlotError};
