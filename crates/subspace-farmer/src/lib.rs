//! subspace-farmer implementation overview
//!
//! The application typically runs two processes in parallel: plotting and farming.
//!
//! During plotting we create a binary plot file, which contains subspace-encoded pieces one
//! after another as well as RocksDB key-value database with tags, where key is tag (first 8 bytes
//! of `hmac(encoding, salt)`) and value is an offset of corresponding encoded piece in the plot (we
//! can do this because all pieces have the same size). So for every 4096 bytes we also store a
//! record with 8-bytes tag and 8-bytes index (+some overhead of RocksDB itself).
//!
//! During farming we receive a global challenge and need to find a solution, given target and
//! solution range. In order to find solution we derive local challenge as our target and do range
//! query in RocksDB. For that we interpret target as 64-bit unsigned integer, and find all of the
//! keys in tags database that are `target ± solution range` (while also handing overflow/underlow)
//! converted back to bytes.
#![feature(try_blocks)]
#![feature(hash_drain_filter)]

mod commitments;
mod erase_plot;
mod farm;
mod object_mappings;
mod plot;
mod utils;

use subspace_core_primitives::PIECE_SIZE;

pub use erase_plot::erase_plot;
pub use farm::farm_caller;

type Tag = [u8; 8];
type Salt = [u8; 8];

const BATCH_SIZE: u64 = (16 * 1024 * 1024 / PIECE_SIZE) as u64;
// TODO: Move to codec
// const CUDA_BATCH_SIZE: u64 = (32 * 1024) as u64;
