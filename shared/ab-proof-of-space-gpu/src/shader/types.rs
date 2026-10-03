use crate::shader::constants::{MAX_BUCKET_SIZE, NUM_BUCKETS, PARAM_BC, PARAM_EXT, PARAM_M};
use crate::shader::u32n::U32N;
use core::fmt;
use core::iter::Step;
use derive_more::{From, Into};

/// Stores data in lower bits
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, From, Into)]
#[repr(C)]
pub(super) struct X(u32);

impl Step for X {
    #[inline(always)]
    fn steps_between(start: &Self, end: &Self) -> (usize, Option<usize>) {
        u32::steps_between(&start.0, &end.0)
    }

    #[inline(always)]
    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u32::forward_checked(start.0, count).map(Self)
    }

    #[inline(always)]
    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u32::backward_checked(start.0, count).map(Self)
    }
}

impl X {
    #[cfg(test)]
    pub(super) const ZERO: Self = Self(0);
}

/// Stores data in lower bits
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, From, Into)]
#[repr(C)]
pub struct Y(u32);

impl From<Y> for U32N<4> {
    #[inline(always)]
    fn from(value: Y) -> Self {
        Self::from(value.0)
    }
}

impl Y {
    /// Get the first `K` bits
    #[inline(always)]
    pub(in super::super) const fn first_k_bits(self) -> u32 {
        self.0 >> PARAM_EXT
    }

    pub(super) fn into_bucket_index_and_r(self) -> (u32, R) {
        let bucket_index = self.0 / u32::from(PARAM_BC);
        let r = self.0 % u32::from(PARAM_BC);
        // SAFETY: `r` is within `0..PARAM_BC` range
        let r = unsafe { R::new(r) };
        (bucket_index, r)
    }
}

// TODO: The struct in this form currently doesn't compile:
//  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
// #[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, From, Into)]
// #[repr(C)]
// pub struct Position(u32);
//
// impl From<Position> for usize {
//     #[inline(always)]
//     fn from(value: Position) -> Self {
//         value.0 as Self
//     }
// }
//
// impl Position {
//     /// Position that can't exist
//     pub(super) const SENTINEL: Self =
//        Self(u32::MAX >> (u32::BITS - (NUM_BUCKETS * MAX_BUCKET_SIZE).bit_width()));
// }

pub type Position = u32;

// TODO: Remove once normal `Position` struct can be used
pub(super) trait PositionExt: Sized {
    /// Position that can't exist
    const SENTINEL: Self;

    // TODO: This is just `Position::from()` usually
    fn from_u32(value: u32) -> Self;
}

impl PositionExt for Position {
    const SENTINEL: Self = u32::MAX >> (u32::BITS - (NUM_BUCKETS * MAX_BUCKET_SIZE).bit_width());

    #[inline(always)]
    fn from_u32(value: u32) -> Self {
        value
    }
}

/// Stores data in lower bits
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct Metadata(U32N<3>);

impl Default for Metadata {
    #[inline(always)]
    fn default() -> Self {
        Self(U32N::ZERO)
    }
}

impl From<Metadata> for U32N<3> {
    #[inline(always)]
    fn from(value: Metadata) -> Self {
        value.0
    }
}

impl From<Metadata> for U32N<4> {
    #[inline(always)]
    fn from(value: Metadata) -> Self {
        value.0.cast()
    }
}

impl From<U32N<3>> for Metadata {
    #[inline(always)]
    fn from(value: U32N<3>) -> Self {
        Self(value)
    }
}

impl From<Position> for Metadata {
    #[inline(always)]
    fn from(value: Position) -> Self {
        Self(U32N::from(value))
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[repr(C)]
pub struct R(u32);

impl R {
    /// R that can't exist
    pub(super) const SENTINEL: Self = Self(u32::MAX);
    /// Number of bits used to fully represent `R`
    pub(super) const BITS: u32 = (PARAM_BC - 1).bit_width();

    /// Create new `R` from provided value.
    ///
    /// # Safety
    /// `r` value must be within `0..PARAM_BC` range.
    #[inline(always)]
    pub(super) unsafe fn new(r: u32) -> Self {
        Self(r)
    }

    /// Get the inner stored value
    #[inline(always)]
    pub(super) fn get(self) -> u32 {
        self.0
    }
}

/// A tuple of [`Position`] and [`Y`] with guaranteed memory layout
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[repr(C)]
pub struct PositionR {
    /// Position
    pub position: Position,
    /// R
    pub r: R,
}

impl PositionR {
    /// PositionR that can't exist
    pub(super) const SENTINEL: Self = Self {
        position: Position::SENTINEL,
        r: R::SENTINEL,
    };
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct Match(u32);

impl fmt::Debug for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (bucket_offset, r_target, positions_offset) = self.split();
        f.debug_struct("Match")
            .field("bucket_offset", &bucket_offset)
            .field("r_target", &r_target)
            .field("positions_offset", &positions_offset)
            .finish()
    }
}

impl Match {
    /// Match that can't exist
    pub(super) const SENTINEL: Self = Self(u32::MAX);

    /// NOTE: `m` is only present here to ensure correct sorting order, it is not used for anything
    /// else.
    ///
    /// # Safety
    /// `bucket_offset` value must be within `0..MAX_BUCKET_SIZE` range, `m` must be within
    /// `0..PARAM_M` range and `r_target` must be within `0..PARAM_BC` range
    #[inline(always)]
    pub(super) unsafe fn new(bucket_offset: u32, m: u32, r_target: u32) -> Self {
        #[expect(clippy::int_plus_one, reason = "Better explains the underlying logic")]
        const {
            assert!(
                (MAX_BUCKET_SIZE - 1).bit_width() + (PARAM_M - 1).bit_width() + R::BITS + 1
                    <= u32::BITS
            );
        }

        // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
        //  shouldn't be necessary otherwise
        Self(
            (bucket_offset << const { (PARAM_M - 1).bit_width() + R::BITS + 1 })
                | (m << const { R::BITS + 1 })
                | (r_target << 1),
        )
    }

    /// Initially, `Match` assumes the first position is used. This allows changing it to the
    /// second.
    ///
    /// # Safety
    /// Must only be called once on any `Match` instance.
    #[inline(always)]
    pub(super) fn second_second_position(mut self) -> Self {
        self.0 += 1;
        self
    }

    /// Returns `(bucket_offset, r_target, positions_offset)`
    #[inline(always)]
    pub(super) fn split(self) -> (u32, u32, u32) {
        // TODO: `const {}` is a workaround for https://github.com/Rust-GPU/rust-gpu/issues/322 and
        //  shouldn't be necessary otherwise
        (
            self.0 >> const { (PARAM_M - 1).bit_width() + R::BITS + 1 },
            (self.0 >> 1) & const { u32::MAX >> (u32::BITS - R::BITS) },
            self.0 & 1,
        )
    }

    /// Extracts a key that can be used for sorting matches
    #[inline(always)]
    pub(super) fn cmp_key(self) -> u32 {
        self.0
    }
}
