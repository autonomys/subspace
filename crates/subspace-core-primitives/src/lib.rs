// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Core primitives for Subspace Network.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(rust_2018_idioms, missing_docs)]
#![cfg_attr(feature = "std", warn(missing_debug_implementations))]
#![feature(
    array_chunks,
    const_trait_impl,
    const_try,
    new_zeroed_alloc,
    portable_simd,
    step_trait
)]

pub mod checksum;
pub mod hashes;
pub mod objects;
pub mod pieces;
pub mod pos;
pub mod pot;
pub mod sectors;
pub mod segments;
pub mod solutions;
#[cfg(test)]
mod tests;

use crate::hashes::{blake3_hash, blake3_hash_list, Blake3Hash};
use core::fmt;
use derive_more::{Add, AsMut, AsRef, Deref, DerefMut, Display, Div, From, Into, Mul, Rem, Sub};
use num_traits::{WrappingAdd, WrappingSub};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;

// Refuse to compile on lower than 32-bit platforms
const_assert!(core::mem::size_of::<usize>() >= core::mem::size_of::<u32>());

/// Signing context used for creating reward signatures by farmers.
pub const REWARD_SIGNING_CONTEXT: &[u8] = b"subspace_reward";

/// Byte length of a randomness type.
pub const RANDOMNESS_LENGTH: usize = 32;

/// Type of randomness.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    From,
    Into,
    Deref,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Randomness(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; RANDOMNESS_LENGTH]);

impl AsRef<[u8]> for Randomness {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Randomness {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Randomness {
    /// Derive global slot challenge from global randomness.
    // TODO: Separate type for global challenge
    pub fn derive_global_challenge(&self, slot: SlotNumber) -> Blake3Hash {
        blake3_hash_list(&[&self.0, &slot.to_le_bytes()])
    }
}

/// Block number in Subspace network.
pub type BlockNumber = u32;

/// Block hash in Subspace network.
pub type BlockHash = [u8; 32];

/// Slot number in Subspace network.
pub type SlotNumber = u64;

/// BlockWeight type for fork choice rules.
///
/// The closer solution's tag is to the target, the heavier it is.
pub type BlockWeight = u128;

/// A Ristretto Schnorr public key as bytes produced by `schnorrkel` crate.
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Encode,
    Decode,
    TypeInfo,
    Deref,
    From,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey(#[cfg_attr(feature = "serde", serde(with = "hex"))] [u8; Self::SIZE]);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<PublicKey> for [u8; PublicKey::SIZE] {
    #[inline]
    fn from(value: PublicKey) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PublicKey {
    /// Public key size in bytes
    pub const SIZE: usize = 32;

    /// Public key hash.
    pub fn hash(&self) -> Blake3Hash {
        blake3_hash(&self.0)
    }
}

/// Single BLS12-381 scalar with big-endian representation, not guaranteed to be valid
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    From,
    Into,
    AsRef,
    AsMut,
    Deref,
    DerefMut,
    Encode,
    Decode,
    TypeInfo,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct ScalarBytes([u8; ScalarBytes::FULL_BYTES]);

impl ScalarBytes {
    /// How many full bytes can be stored in BLS12-381 scalar (for instance before encoding). It is
    /// actually 254 bits, but bits are mut harder to work with and likely not worth it.
    ///
    /// NOTE: After encoding more bytes can be used, so don't rely on this as the max number of
    /// bytes stored within at all times!
    pub const SAFE_BYTES: usize = 31;
    /// How many bytes Scalar contains physically, use [`Self::SAFE_BYTES`] for the amount of data
    /// that you can put into it safely (for instance before encoding).
    pub const FULL_BYTES: usize = 32;
}

#[allow(clippy::assign_op_pattern, clippy::ptr_offset_with_cast)]
mod private_u256 {
    //! This module is needed to scope clippy allows
    use parity_scale_codec::{Decode, Encode};
    use scale_info::TypeInfo;

    uint::construct_uint! {
        #[derive(Encode, Decode, TypeInfo)]
        pub struct U256(4);
    }
}

/// 256-bit unsigned integer
#[derive(
    Debug,
    Display,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Encode,
    Decode,
    TypeInfo,
)]
pub struct U256(private_u256::U256);

impl U256 {
    /// Zero (additive identity) of this type.
    #[inline]
    pub const fn zero() -> Self {
        Self(private_u256::U256::zero())
    }

    /// One (multiplicative identity) of this type.
    #[inline]
    pub fn one() -> Self {
        Self(private_u256::U256::one())
    }

    /// Create from big endian bytes
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(private_u256::U256::from_big_endian(&bytes))
    }

    /// Convert to big endian bytes
    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_big_endian()
    }

    /// Create from little endian bytes
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(private_u256::U256::from_little_endian(&bytes))
    }

    /// Convert to little endian bytes
    pub fn to_le_bytes(self) -> [u8; 32] {
        self.0.to_little_endian()
    }

    /// Adds two numbers, checking for overflow. If overflow happens, `None` is returned.
    pub fn checked_add(&self, v: &Self) -> Option<Self> {
        self.0.checked_add(v.0).map(Self)
    }

    /// Subtracts two numbers, checking for underflow. If underflow happens, `None` is returned.
    pub fn checked_sub(&self, v: &Self) -> Option<Self> {
        self.0.checked_sub(v.0).map(Self)
    }

    /// Multiplies two numbers, checking for underflow or overflow. If underflow or overflow
    /// happens, `None` is returned.
    pub fn checked_mul(&self, v: &Self) -> Option<Self> {
        self.0.checked_mul(v.0).map(Self)
    }

    /// Divides two numbers, checking for underflow, overflow and division by zero. If any of that
    /// happens, `None` is returned.
    pub fn checked_div(&self, v: &Self) -> Option<Self> {
        self.0.checked_div(v.0).map(Self)
    }

    /// Saturating addition. Computes `self + other`, saturating at the relevant high or low
    /// boundary of the type.
    pub fn saturating_add(&self, v: &Self) -> Self {
        Self(self.0.saturating_add(v.0))
    }

    /// Saturating subtraction. Computes `self - other`, saturating at the relevant high or low
    /// boundary of the type.
    pub fn saturating_sub(&self, v: &Self) -> Self {
        Self(self.0.saturating_sub(v.0))
    }

    /// Saturating multiplication. Computes `self * other`, saturating at the relevant high or low
    /// boundary of the type.
    pub fn saturating_mul(&self, v: &Self) -> Self {
        Self(self.0.saturating_mul(v.0))
    }

    /// The middle of the piece distance field.
    /// The analogue of `0b1000_0000` for `u8`.
    pub const MIDDLE: Self = {
        // TODO: This assumes that numbers are stored little endian,
        //  should be replaced with just `Self::MAX / 2`, but it is not `const fn` in Rust yet.
        Self(private_u256::U256([
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX / 2,
        ]))
    };

    /// Maximum value.
    pub const MAX: Self = Self(private_u256::U256::MAX);
}

// Necessary for division derive
impl From<U256> for private_u256::U256 {
    #[inline]
    fn from(number: U256) -> Self {
        number.0
    }
}

impl WrappingAdd for U256 {
    #[inline]
    fn wrapping_add(&self, other: &Self) -> Self {
        Self(self.0.overflowing_add(other.0).0)
    }
}

impl WrappingSub for U256 {
    #[inline]
    fn wrapping_sub(&self, other: &Self) -> Self {
        Self(self.0.overflowing_sub(other.0).0)
    }
}

impl From<u8> for U256 {
    #[inline]
    fn from(number: u8) -> Self {
        Self(number.into())
    }
}

impl From<u16> for U256 {
    #[inline]
    fn from(number: u16) -> Self {
        Self(number.into())
    }
}

impl From<u32> for U256 {
    #[inline]
    fn from(number: u32) -> Self {
        Self(number.into())
    }
}

impl From<u64> for U256 {
    #[inline]
    fn from(number: u64) -> Self {
        Self(number.into())
    }
}

impl From<u128> for U256 {
    #[inline]
    fn from(number: u128) -> Self {
        Self(number.into())
    }
}

impl TryFrom<U256> for u8 {
    type Error = &'static str;

    #[inline]
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl TryFrom<U256> for u16 {
    type Error = &'static str;

    #[inline]
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl TryFrom<U256> for u32 {
    type Error = &'static str;

    #[inline]
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl TryFrom<U256> for u64 {
    type Error = &'static str;

    #[inline]
    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl Default for U256 {
    fn default() -> Self {
        Self::zero()
    }
}
