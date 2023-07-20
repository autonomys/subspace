use crate::chiapos::constants::PARAM_EXT;
use core::iter::Step;
use core::ops::Range;
use derive_more::{Add, AddAssign, From, Into};

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, From, Into, Add, AddAssign)]
#[repr(transparent)]
pub(crate) struct X(u32);

impl Step for X {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u32::steps_between(&start.0, &end.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u32::forward_checked(start.0, count).map(Self)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u32::backward_checked(start.0, count).map(Self)
    }
}

impl From<X> for u64 {
    fn from(value: X) -> Self {
        Self::from(value.0)
    }
}

impl From<X> for u128 {
    fn from(value: X) -> Self {
        Self::from(value.0)
    }
}

impl From<X> for usize {
    fn from(value: X) -> Self {
        value.0 as Self
    }
}

impl X {
    /// All possible values of `x` for given `K`
    pub(crate) const fn all<const K: u8>() -> Range<Self> {
        Self(0)..Self(1 << K)
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, From, Into)]
#[repr(transparent)]
pub(crate) struct Y(u32);

impl From<Y> for u128 {
    fn from(value: Y) -> Self {
        Self::from(value.0)
    }
}

impl From<Y> for usize {
    fn from(value: Y) -> Self {
        value.0 as Self
    }
}

impl Y {
    pub(crate) const fn first_k_bits<const K: u8>(self) -> u32 {
        self.0 >> PARAM_EXT as usize
    }
}

#[derive(
    Debug, Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, From, Into, Add, AddAssign,
)]
#[repr(transparent)]
pub(crate) struct Position(u32);

impl Step for Position {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        u32::steps_between(&start.0, &end.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        u32::forward_checked(start.0, count).map(Self)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        u32::backward_checked(start.0, count).map(Self)
    }
}

impl From<Position> for usize {
    fn from(value: Position) -> Self {
        value.0 as Self
    }
}

impl Position {
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self(1);
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, From, Into)]
#[repr(transparent)]
pub(crate) struct Metadata<const TABLE_NUMBER: u8>(u128);

impl<const TABLE_NUMBER: u8> From<X> for Metadata<TABLE_NUMBER> {
    fn from(value: X) -> Self {
        Self(u128::from(value.0))
    }
}
