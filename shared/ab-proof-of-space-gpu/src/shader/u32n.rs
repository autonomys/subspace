#[cfg(test)]
mod tests;

use core::cmp::{Eq, PartialEq};
use core::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Shl, ShlAssign,
    Shr, ShrAssign, Sub, SubAssign,
};

#[cfg(test)]
const U32_WORDS_TO_BYTES<const N: usize>: usize = N * 4;

/// Generalized unsigned integer as an array of u32 words, least significant word first
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct U32N<const N: usize>([u32; N]);

impl<const N: usize> U32N<N> {
    pub const ZERO: Self = Self([0; N]);
    pub const BITS: u32 = u32::BITS * N as u32;
    pub const WORD_BITS: u32 = u32::BITS;

    #[cfg(test)]
    #[inline(always)]
    pub(super) fn to_be_bytes(self) -> [u8; U32_WORDS_TO_BYTES::<N>] {
        let mut bytes = [0u8; _];
        let mut idx = 0;
        for &word in self.0.iter().rev() {
            let b = word.to_be_bytes();
            bytes[idx..idx + 4].copy_from_slice(&b);
            idx += 4;
        }
        bytes
    }

    #[cfg(test)]
    #[inline(always)]
    pub(super) fn from_be_bytes(bytes: [u8; U32_WORDS_TO_BYTES::<N>]) -> Self {
        let mut words = [0u32; _];
        let mut idx = 0;
        for i in (0..N).rev() {
            let b = [bytes[idx], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]];
            words[i] = u32::from_be_bytes(b);
            idx += 4;
        }
        Self(words)
    }

    #[inline(always)]
    pub(super) fn as_u32(&self) -> u32 {
        self.0[0]
    }

    pub(super) fn cast<const O: usize>(self) -> U32N<O> {
        let mut output = [0u32; O];
        if N.min(O) > 0 {
            output[0] = self.0[0];
        }
        if N.min(O) > 1 {
            output[1] = self.0[1];
        }
        if N.min(O) > 2 {
            output[2] = self.0[2];
        }
        if N.min(O) > 3 {
            output[3] = self.0[3];
        }
        if N.min(O) > 4 {
            unimplemented!();
        }
        U32N(output)
    }
}

impl U32N<2> {
    #[inline(always)]
    pub(super) fn from_low_high(low: u32, high: u32) -> Self {
        Self([low, high])
    }
}

impl From<u32> for U32N<2> {
    #[inline(always)]
    fn from(n: u32) -> Self {
        Self([n, 0])
    }
}

impl Add for U32N<2> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut result = [0u32; 2];
        let mut carry = false;
        (result[0], carry) = self.0[0].carrying_add(rhs.0[0], carry);
        (result[1], _) = self.0[1].carrying_add(rhs.0[1], carry);
        Self(result)
    }
}

impl AddAssign for U32N<2> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for U32N<2> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        let mut result = [0u32; 2];
        let mut borrow = false;
        (result[0], borrow) = self.0[0].borrowing_sub(rhs.0[0], borrow);
        (result[1], _) = self.0[1].borrowing_sub(rhs.0[1], borrow);
        Self(result)
    }
}

impl SubAssign for U32N<2> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl BitAnd for U32N<2> {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self {
        Self([self.0[0] & rhs.0[0], self.0[1] & rhs.0[1]])
    }
}

impl BitAndAssign for U32N<2> {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitXor for U32N<2> {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        Self([self.0[0] ^ rhs.0[0], self.0[1] ^ rhs.0[1]])
    }
}

impl BitXorAssign for U32N<2> {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitOr for U32N<2> {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self {
        Self([self.0[0] | rhs.0[0], self.0[1] | rhs.0[1]])
    }
}

impl BitOrAssign for U32N<2> {
    #[inline(always)]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl Shl<u32> for U32N<2> {
    type Output = Self;

    #[inline(always)]
    fn shl(mut self, rhs: u32) -> Self {
        if rhs == 0 {
            return self;
        }

        let bit_shift = rhs % u32::BITS;
        match rhs / u32::BITS {
            0 => {
                self.0[1] =
                    (self.0[1] << bit_shift) | (self.0[0].unbounded_shr(u32::BITS - bit_shift));
                self.0[0] <<= bit_shift;
            }
            1 => {
                self.0[1] = self.0[0] << bit_shift;
                self.0[0] = 0;
            }
            _ => unreachable!(),
        }

        self
    }
}

impl ShlAssign<u32> for U32N<2> {
    #[inline(always)]
    fn shl_assign(&mut self, rhs: u32) {
        *self = *self << rhs;
    }
}

impl Shr<u32> for U32N<2> {
    type Output = Self;

    #[inline(always)]
    fn shr(mut self, rhs: u32) -> Self {
        if rhs == 0 {
            return self;
        }

        let bit_shift = rhs % u32::BITS;
        match rhs / u32::BITS {
            0 => {
                self.0[0] =
                    (self.0[0] >> bit_shift) | (self.0[1].unbounded_shl(u32::BITS - bit_shift));
                self.0[1] >>= bit_shift;
            }
            1 => {
                self.0[0] = self.0[1] >> bit_shift;
                self.0[1] = 0;
            }
            _ => unreachable!(),
        }

        self
    }
}

impl ShrAssign<u32> for U32N<2> {
    #[inline(always)]
    fn shr_assign(&mut self, rhs: u32) {
        *self = *self >> rhs;
    }
}

impl From<u32> for U32N<3> {
    #[inline(always)]
    fn from(n: u32) -> Self {
        Self([n, 0, 0])
    }
}

impl Add for U32N<3> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut result = [0u32; 3];
        let mut carry = false;
        (result[0], carry) = self.0[0].carrying_add(rhs.0[0], carry);
        (result[1], carry) = self.0[1].carrying_add(rhs.0[1], carry);
        (result[2], _) = self.0[2].carrying_add(rhs.0[2], carry);
        Self(result)
    }
}

impl AddAssign for U32N<3> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for U32N<3> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        let mut result = [0u32; 3];
        let mut borrow = false;
        (result[0], borrow) = self.0[0].borrowing_sub(rhs.0[0], borrow);
        (result[1], borrow) = self.0[1].borrowing_sub(rhs.0[1], borrow);
        (result[2], _) = self.0[2].borrowing_sub(rhs.0[2], borrow);
        Self(result)
    }
}

impl SubAssign for U32N<3> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl BitAnd for U32N<3> {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self {
        Self([
            self.0[0] & rhs.0[0],
            self.0[1] & rhs.0[1],
            self.0[2] & rhs.0[2],
        ])
    }
}

impl BitAndAssign for U32N<3> {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitXor for U32N<3> {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        Self([
            self.0[0] ^ rhs.0[0],
            self.0[1] ^ rhs.0[1],
            self.0[2] ^ rhs.0[2],
        ])
    }
}

impl BitXorAssign for U32N<3> {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitOr for U32N<3> {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self {
        Self([
            self.0[0] | rhs.0[0],
            self.0[1] | rhs.0[1],
            self.0[2] | rhs.0[2],
        ])
    }
}

impl BitOrAssign for U32N<3> {
    #[inline(always)]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl Shl<u32> for U32N<3> {
    type Output = Self;

    #[inline(always)]
    fn shl(mut self, rhs: u32) -> Self {
        if rhs == 0 {
            return self;
        }

        let bit_shift = rhs % u32::BITS;
        match rhs / u32::BITS {
            0 => {
                self.0[2] =
                    (self.0[2] << bit_shift) | (self.0[1].unbounded_shr(u32::BITS - bit_shift));
                self.0[1] =
                    (self.0[1] << bit_shift) | (self.0[0].unbounded_shr(u32::BITS - bit_shift));
                self.0[0] <<= bit_shift;
            }
            1 => {
                self.0[2] =
                    (self.0[1] << bit_shift) | (self.0[0].unbounded_shr(u32::BITS - bit_shift));
                self.0[1] = self.0[0] << bit_shift;
                self.0[0] = 0;
            }
            2 => {
                self.0[2] = self.0[0] << bit_shift;
                self.0[1] = 0;
                self.0[0] = 0;
            }
            _ => unreachable!(),
        }

        self
    }
}

impl ShlAssign<u32> for U32N<3> {
    #[inline(always)]
    fn shl_assign(&mut self, rhs: u32) {
        *self = *self << rhs;
    }
}

impl Shr<u32> for U32N<3> {
    type Output = Self;

    #[inline(always)]
    fn shr(mut self, rhs: u32) -> Self {
        if rhs == 0 {
            return self;
        }

        let bit_shift = rhs % u32::BITS;
        match rhs / u32::BITS {
            0 => {
                self.0[0] =
                    (self.0[0] >> bit_shift) | (self.0[1].unbounded_shl(u32::BITS - bit_shift));
                self.0[1] =
                    (self.0[1] >> bit_shift) | (self.0[2].unbounded_shl(u32::BITS - bit_shift));
                self.0[2] >>= bit_shift;
            }
            1 => {
                self.0[0] =
                    (self.0[1] >> bit_shift) | (self.0[2].unbounded_shl(u32::BITS - bit_shift));
                self.0[1] = self.0[2] >> bit_shift;
                self.0[2] = 0;
            }
            2 => {
                self.0[0] = self.0[2] >> bit_shift;
                self.0[1] = 0;
                self.0[2] = 0;
            }
            _ => unreachable!(),
        }

        self
    }
}

impl ShrAssign<u32> for U32N<3> {
    #[inline(always)]
    fn shr_assign(&mut self, rhs: u32) {
        *self = *self >> rhs;
    }
}

impl U32N<4> {
    #[inline(always)]
    pub(super) fn as_be_bytes_to_le_u32_words(&self) -> [u32; 4] {
        [
            self.0[3].swap_bytes(),
            self.0[2].swap_bytes(),
            self.0[1].swap_bytes(),
            self.0[0].swap_bytes(),
        ]
    }

    #[inline(always)]
    pub(super) fn from_le_u32_words_as_be_bytes(words: &[u32; 4]) -> Self {
        Self([
            words[3].swap_bytes(),
            words[2].swap_bytes(),
            words[1].swap_bytes(),
            words[0].swap_bytes(),
        ])
    }
}

impl From<u32> for U32N<4> {
    #[inline(always)]
    fn from(n: u32) -> Self {
        Self([n, 0, 0, 0])
    }
}

impl Add for U32N<4> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut result = [0u32; 4];
        let mut carry = false;
        (result[0], carry) = self.0[0].carrying_add(rhs.0[0], carry);
        (result[1], carry) = self.0[1].carrying_add(rhs.0[1], carry);
        (result[2], carry) = self.0[2].carrying_add(rhs.0[2], carry);
        (result[3], _) = self.0[3].carrying_add(rhs.0[3], carry);
        Self(result)
    }
}

impl AddAssign for U32N<4> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for U32N<4> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        let mut result = [0u32; 4];
        let mut borrow = false;
        (result[0], borrow) = self.0[0].borrowing_sub(rhs.0[0], borrow);
        (result[1], borrow) = self.0[1].borrowing_sub(rhs.0[1], borrow);
        (result[2], borrow) = self.0[2].borrowing_sub(rhs.0[2], borrow);
        (result[3], _) = self.0[3].borrowing_sub(rhs.0[3], borrow);
        Self(result)
    }
}

impl SubAssign for U32N<4> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl BitAnd for U32N<4> {
    type Output = Self;

    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self {
        Self([
            self.0[0] & rhs.0[0],
            self.0[1] & rhs.0[1],
            self.0[2] & rhs.0[2],
            self.0[3] & rhs.0[3],
        ])
    }
}

impl BitAndAssign for U32N<4> {
    #[inline(always)]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitXor for U32N<4> {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        Self([
            self.0[0] ^ rhs.0[0],
            self.0[1] ^ rhs.0[1],
            self.0[2] ^ rhs.0[2],
            self.0[3] ^ rhs.0[3],
        ])
    }
}

impl BitXorAssign for U32N<4> {
    #[inline(always)]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl BitOr for U32N<4> {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self {
        Self([
            self.0[0] | rhs.0[0],
            self.0[1] | rhs.0[1],
            self.0[2] | rhs.0[2],
            self.0[3] | rhs.0[3],
        ])
    }
}

impl BitOrAssign for U32N<4> {
    #[inline(always)]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl Shl<u32> for U32N<4> {
    type Output = Self;

    #[inline(always)]
    fn shl(mut self, rhs: u32) -> Self {
        if rhs == 0 {
            return self;
        }

        let bit_shift = rhs % u32::BITS;
        match rhs / u32::BITS {
            0 => {
                self.0[3] =
                    (self.0[3] << bit_shift) | (self.0[2].unbounded_shr(u32::BITS - bit_shift));
                self.0[2] =
                    (self.0[2] << bit_shift) | (self.0[1].unbounded_shr(u32::BITS - bit_shift));
                self.0[1] =
                    (self.0[1] << bit_shift) | (self.0[0].unbounded_shr(u32::BITS - bit_shift));
                self.0[0] <<= bit_shift;
            }
            1 => {
                self.0[3] =
                    (self.0[2] << bit_shift) | (self.0[1].unbounded_shr(u32::BITS - bit_shift));
                self.0[2] =
                    (self.0[1] << bit_shift) | (self.0[0].unbounded_shr(u32::BITS - bit_shift));
                self.0[1] = self.0[0] << bit_shift;
                self.0[0] = 0;
            }
            2 => {
                self.0[3] =
                    (self.0[1] << bit_shift) | (self.0[0].unbounded_shr(u32::BITS - bit_shift));
                self.0[2] = self.0[0] << bit_shift;
                self.0[1] = 0;
                self.0[0] = 0;
            }
            3 => {
                self.0[3] = self.0[0] << bit_shift;
                self.0[2] = 0;
                self.0[1] = 0;
                self.0[0] = 0;
            }
            _ => unreachable!(),
        }

        self
    }
}

impl ShlAssign<u32> for U32N<4> {
    #[inline(always)]
    fn shl_assign(&mut self, rhs: u32) {
        *self = *self << rhs;
    }
}

impl Shr<u32> for U32N<4> {
    type Output = Self;

    #[inline(always)]
    fn shr(mut self, rhs: u32) -> Self {
        if rhs == 0 {
            return self;
        }

        let bit_shift = rhs % u32::BITS;
        match rhs / u32::BITS {
            0 => {
                self.0[0] =
                    (self.0[0] >> bit_shift) | (self.0[1].unbounded_shl(u32::BITS - bit_shift));
                self.0[1] =
                    (self.0[1] >> bit_shift) | (self.0[2].unbounded_shl(u32::BITS - bit_shift));
                self.0[2] =
                    (self.0[2] >> bit_shift) | (self.0[3].unbounded_shl(u32::BITS - bit_shift));
                self.0[3] >>= bit_shift;
            }
            1 => {
                self.0[0] =
                    (self.0[1] >> bit_shift) | (self.0[2].unbounded_shl(u32::BITS - bit_shift));
                self.0[1] =
                    (self.0[2] >> bit_shift) | (self.0[3].unbounded_shl(u32::BITS - bit_shift));
                self.0[2] = self.0[3] >> bit_shift;
                self.0[3] = 0;
            }
            2 => {
                self.0[0] =
                    (self.0[2] >> bit_shift) | (self.0[3].unbounded_shl(u32::BITS - bit_shift));
                self.0[1] = self.0[3] >> bit_shift;
                self.0[2] = 0;
                self.0[3] = 0;
            }
            3 => {
                self.0[0] = self.0[3] >> bit_shift;
                self.0[1] = 0;
                self.0[2] = 0;
                self.0[3] = 0;
            }
            _ => unreachable!(),
        }

        self
    }
}

impl ShrAssign<u32> for U32N<4> {
    #[inline(always)]
    fn shr_assign(&mut self, rhs: u32) {
        *self = *self >> rhs;
    }
}
