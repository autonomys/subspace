use subspace_core_primitives::PIECE_SIZE;

pub(crate) const BATCH_SIZE: u64 = (16 * 1024 * 1024 / PIECE_SIZE) as u64;
