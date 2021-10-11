pub(crate) mod commitments;
pub mod erase_plot;
pub mod farm;
pub(crate) mod object_mappings;
pub(crate) mod plot;
pub(crate) mod utils;

pub(crate) use subspace_core_primitives::PIECE_SIZE;

pub(crate) type Tag = [u8; 8];
pub(crate) type Salt = [u8; 8];

pub(crate) const BATCH_SIZE: u64 = (16 * 1024 * 1024 / PIECE_SIZE) as u64;
