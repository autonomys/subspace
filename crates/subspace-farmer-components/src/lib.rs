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
use std::num::NonZeroU64;
use subspace_core_primitives::crypto::kzg::Commitment;
use subspace_core_primitives::{HistorySize, Piece, SegmentIndex, PLOT_SECTOR_SIZE};

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// Information about the protocol necessary for farmer operation
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FarmerProtocolInfo {
    /// Size of the blockchain history
    pub history_size: HistorySize,
    /// Number of segments after which sector expires
    pub sector_expiration: SegmentIndex,
}

/// Metadata of the plotted sector
#[derive(Debug, Encode, Decode, Clone)]
pub struct SectorMetadata {
    /// Size of the blockchain history at time of sector creation
    pub history_size: HistorySize,
    /// Sector expiration, defined as sector of the archived history of the blockchain
    pub expires_at: SegmentIndex,
    /// Commitments to encoded pieces within sector
    pub commitments: Vec<Commitment>,
}

impl SectorMetadata {
    /// Size of encoded sector metadata
    pub fn encoded_size() -> usize {
        let default = SectorMetadata {
            history_size: HistorySize::from(NonZeroU64::new(1).expect("1 is not 0; qed")),
            expires_at: SegmentIndex::default(),
            commitments: vec![Commitment::default(); PLOT_SECTOR_SIZE as usize / Piece::SIZE],
        };

        default.encoded_size()
    }
}
