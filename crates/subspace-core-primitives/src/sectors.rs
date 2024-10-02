//! Sectors-related data structures.

#[cfg(test)]
mod tests;

use crate::crypto::{blake3_hash_list, blake3_hash_with_key};
use crate::pieces::{PieceIndex, PieceOffset, Record};
use crate::segments::{HistorySize, SegmentCommitment};
use crate::{Blake3Hash, PosSeed, U256};
#[cfg(feature = "serde")]
use ::serde::{Deserialize, Serialize};
use core::hash::Hash;
use core::iter::Step;
use core::num::{NonZeroU64, TryFromIntError};
use core::simd::Simd;
use derive_more::{
    Add, AddAssign, AsRef, Deref, Display, Div, DivAssign, From, Into, Mul, MulAssign, Sub,
    SubAssign,
};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use static_assertions::const_assert_eq;

/// Sector index in consensus
pub type SectorIndex = u16;

/// Challenge used for a particular sector for particular slot
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deref)]
pub struct SectorSlotChallenge(Blake3Hash);

impl SectorSlotChallenge {
    /// Index of s-bucket within sector to be audited
    #[inline]
    pub fn s_bucket_audit_index(&self) -> SBucket {
        // As long as number of s-buckets is 2^16, we can pick first two bytes instead of actually
        // calculating `U256::from_le_bytes(self.0) % Record::NUM_S_BUCKETS)`
        const_assert_eq!(Record::NUM_S_BUCKETS, 1 << u16::BITS as usize);
        SBucket::from(u16::from_le_bytes([self.0[0], self.0[1]]))
    }
}

/// Data structure representing sector ID in farmer's plot
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SectorId(#[cfg_attr(feature = "serde", serde(with = "hex"))] Blake3Hash);

impl AsRef<[u8]> for SectorId {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SectorId {
    /// Create new sector ID by deriving it from public key and sector index
    pub fn new(public_key_hash: Blake3Hash, sector_index: SectorIndex) -> Self {
        Self(blake3_hash_with_key(
            &public_key_hash,
            &sector_index.to_le_bytes(),
        ))
    }

    /// Derive piece index that should be stored in sector at `piece_offset` for specified size of
    /// blockchain history
    pub fn derive_piece_index(
        &self,
        piece_offset: PieceOffset,
        history_size: HistorySize,
        max_pieces_in_sector: u16,
        recent_segments: HistorySize,
        recent_history_fraction: (HistorySize, HistorySize),
    ) -> PieceIndex {
        let recent_segments_in_pieces = recent_segments.in_pieces().get();
        // Recent history must be at most `recent_history_fraction` of all history to use separate
        // policy for recent pieces
        let min_history_size_in_pieces = recent_segments_in_pieces
            * recent_history_fraction.1.in_pieces().get()
            / recent_history_fraction.0.in_pieces().get();
        let input_hash = {
            let piece_offset_bytes = piece_offset.to_bytes();
            let mut key = [0; 32];
            key[..piece_offset_bytes.len()].copy_from_slice(&piece_offset_bytes);
            U256::from_le_bytes(*blake3_hash_with_key(&key, self.as_ref()))
        };
        let history_size_in_pieces = history_size.in_pieces().get();
        let num_interleaved_pieces = 1.max(
            u64::from(max_pieces_in_sector) * recent_history_fraction.0.in_pieces().get()
                / recent_history_fraction.1.in_pieces().get()
                * 2,
        );

        let piece_index = if history_size_in_pieces > min_history_size_in_pieces
            && u64::from(piece_offset) < num_interleaved_pieces
            && u16::from(piece_offset) % 2 == 1
        {
            // For odd piece offsets at the beginning of the sector pick pieces at random from
            // recent history only
            input_hash % U256::from(recent_segments_in_pieces)
                + U256::from(history_size_in_pieces - recent_segments_in_pieces)
        } else {
            input_hash % U256::from(history_size_in_pieces)
        };

        PieceIndex::from(u64::try_from(piece_index).expect(
            "Remainder of division by PieceIndex is guaranteed to fit into PieceIndex; qed",
        ))
    }

    /// Derive sector slot challenge for this sector from provided global challenge
    pub fn derive_sector_slot_challenge(
        &self,
        global_challenge: &Blake3Hash,
    ) -> SectorSlotChallenge {
        let sector_slot_challenge = Simd::from(*self.0) ^ Simd::from(**global_challenge);
        SectorSlotChallenge(sector_slot_challenge.to_array().into())
    }

    /// Derive evaluation seed
    pub fn derive_evaluation_seed(
        &self,
        piece_offset: PieceOffset,
        history_size: HistorySize,
    ) -> PosSeed {
        let evaluation_seed = blake3_hash_list(&[
            self.as_ref(),
            &piece_offset.to_bytes(),
            &history_size.get().to_le_bytes(),
        ]);

        PosSeed::from(*evaluation_seed)
    }

    /// Derive history size when sector created at `history_size` expires.
    ///
    /// Returns `None` on overflow.
    pub fn derive_expiration_history_size(
        &self,
        history_size: HistorySize,
        sector_expiration_check_segment_commitment: &SegmentCommitment,
        min_sector_lifetime: HistorySize,
    ) -> Option<HistorySize> {
        let sector_expiration_check_history_size =
            history_size.sector_expiration_check(min_sector_lifetime)?;

        let input_hash = U256::from_le_bytes(*blake3_hash_list(&[
            self.as_ref(),
            sector_expiration_check_segment_commitment.as_ref(),
        ]));

        let last_possible_expiration =
            min_sector_lifetime.checked_add(history_size.get().checked_mul(4u64)?)?;
        let expires_in = input_hash
            % U256::from(
                last_possible_expiration
                    .get()
                    .checked_sub(sector_expiration_check_history_size.get())?,
            );
        let expires_in = u64::try_from(expires_in).expect("Number modulo u64 fits into u64; qed");

        let expiration_history_size = sector_expiration_check_history_size.get() + expires_in;
        let expiration_history_size = NonZeroU64::try_from(expiration_history_size).expect(
            "History size is not zero, so result is not zero even if expires immediately; qed",
        );
        Some(HistorySize::from(expiration_history_size))
    }
}

/// S-bucket used in consensus
#[derive(
    Debug,
    Display,
    Default,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Encode,
    Decode,
    Add,
    AddAssign,
    Sub,
    SubAssign,
    Mul,
    MulAssign,
    Div,
    DivAssign,
    TypeInfo,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(transparent)]
pub struct SBucket(u16);

impl Step for SBucket {
    #[inline]
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u16::steps_between(&start.0, &end.0)
    }

    #[inline]
    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u16::forward_checked(start.0, count).map(Self)
    }

    #[inline]
    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u16::backward_checked(start.0, count).map(Self)
    }
}

impl TryFrom<usize> for SBucket {
    type Error = TryFromIntError;

    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(u16::try_from(value)?))
    }
}

impl From<u16> for SBucket {
    #[inline]
    fn from(original: u16) -> Self {
        Self(original)
    }
}

impl From<SBucket> for u16 {
    #[inline]
    fn from(original: SBucket) -> Self {
        original.0
    }
}

impl From<SBucket> for u32 {
    #[inline]
    fn from(original: SBucket) -> Self {
        u32::from(original.0)
    }
}

impl From<SBucket> for usize {
    #[inline]
    fn from(original: SBucket) -> Self {
        usize::from(original.0)
    }
}

impl SBucket {
    /// S-bucket 0.
    pub const ZERO: SBucket = SBucket(0);
    /// Max s-bucket index
    pub const MAX: SBucket = SBucket((Record::NUM_S_BUCKETS - 1) as u16);
}
