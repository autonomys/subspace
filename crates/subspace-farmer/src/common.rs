use subspace_core_primitives::PIECE_SIZE;

pub(crate) type Tag = [u8; 8];
pub(crate) type Salt = [u8; 8];
pub(crate) const BATCH_SIZE: u64 = (16 * 1024 * 1024 / PIECE_SIZE) as u64;
