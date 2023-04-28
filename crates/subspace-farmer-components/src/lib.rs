#![feature(
    array_chunks,
    const_num_from_num,
    const_option,
    const_trait_impl,
    int_roundings,
    iter_collect_into,
    new_uninit,
    portable_simd,
    slice_flatten,
    try_blocks
)]

//! Components of the reference implementation of Subspace Farmer for Subspace Network Blockchain.
//!
//! These components are used to implement farmer itself, but can also be used independently if necessary.

pub mod auditing;
pub mod file_ext;
pub mod piece_caching;
pub mod plotting;
pub mod proving;
pub mod reading;
pub mod sector;
mod segment_reconstruction;

use serde::{Deserialize, Serialize};
use static_assertions::const_assert;
use subspace_core_primitives::{HistorySize, SegmentIndex};

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// Information about the protocol necessary for farmer operation
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FarmerProtocolInfo {
    /// Size of the blockchain history
    pub history_size: HistorySize,
    /// How many pieces one sector is supposed to contain (max)
    pub max_pieces_in_sector: u16,
    /// Number of segments after which sector expires
    pub sector_expiration: SegmentIndex,
}
