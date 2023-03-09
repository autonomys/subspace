#![feature(const_option)]

//! Components of the reference implementation of Subspace Farmer for Subspace Network Blockchain.
//!
//! These components are used to implement farmer itself, but can also be used independently if necessary.

pub mod farming;
pub mod file_ext;
pub mod piece_caching;
pub mod plotting;
pub mod segment_reconstruction;

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;
use std::num::{NonZeroU32, NonZeroU64};
use subspace_core_primitives::crypto::kzg::Commitment;
use subspace_core_primitives::{SegmentIndex, PIECE_SIZE, PLOT_SECTOR_SIZE};

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// Information about the protocol necessary for farmer operation
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FarmerProtocolInfo {
    /// The size of data in one piece (in bytes).
    pub record_size: NonZeroU32,
    /// Recorded history is encoded and plotted in segments of this size (in bytes).
    pub recorded_history_segment_size: u32,
    /// Total number of pieces stored on the network
    pub total_pieces: NonZeroU64,
    /// Number of segments after which sector expires
    pub sector_expiration: SegmentIndex,
}

/// Metadata of the plotted sector
#[derive(Debug, Encode, Decode, Clone)]
pub struct SectorMetadata {
    /// Total number of pieces in archived history of the blockchain as of sector creation
    pub total_pieces: NonZeroU64,
    /// Sector expiration, defined as sector of the archived history of the blockchain
    pub expires_at: SegmentIndex,
    /// Commitments to encoded pieces within sector
    pub commitments: Vec<Commitment>,
}

impl SectorMetadata {
    /// Size of encoded sector metadata
    pub fn encoded_size() -> usize {
        let default = SectorMetadata {
            total_pieces: NonZeroU64::new(1).expect("1 is not 0; qed"),
            expires_at: 0,
            commitments: vec![Commitment::default(); PLOT_SECTOR_SIZE as usize / PIECE_SIZE],
        };

        default.encoded_size()
    }
}
