use crate::chiapos::constants::{PARAM_B, PARAM_C, PARAM_M};
use crate::chiapos::table::types::R;
use core::array;
use core::ops::{Add, Sub};
use core::simd::prelude::*;
use core::simd::{Mask, Simd, SimdElement};

/// Number of left targets calculated at a time
#[cfg(feature = "alloc")]
const SIMD_FACTOR: usize = 16;

/// Calculates left targets of the left bucket with a given parity.
///
/// Two `y`s match when `r` of the right entry is one of the [`PARAM_M`] targets calculated here
/// from `r` of the left entry.
#[derive(Debug)]
pub(super) struct LeftTargets {
    /// [`Self::SQUARES`] of the parity this instance was created for
    squares: &'static [u16; const { usize::from(PARAM_M) }],
}

impl LeftTargets {
    /// `(2 * m + parity)^2 % PARAM_C` for each `m` of each parity.
    ///
    /// This is the only part of a target that doesn't depend on `r`, the rest is a handful of
    /// cheap SIMD instructions, which is why targets are calculated on the fly instead of being
    /// read from a large precomputed table (the GPU implementation calculates them too).
    const SQUARES: [[u16; const { usize::from(PARAM_M) }]; 2] =
        [Self::squares(0), Self::squares(1)];

    /// A single row of [`Self::SQUARES`].
    ///
    /// `array::from_fn()` would have been nicer, but it needs a `const` closure to be usable here.
    const fn squares(parity: u16) -> [u16; const { usize::from(PARAM_M) }] {
        let mut squares = [0; _];

        let mut m = 0;
        while m < PARAM_M {
            let value = 2 * m + parity;
            squares[usize::from(m)] = (value * value) % PARAM_C;
            m += 1;
        }

        squares
    }

    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub(super) fn new(odd_parity: bool) -> Self {
        Self {
            squares: &Self::SQUARES[usize::from(odd_parity)],
        }
    }

    /// `a + b` modulo `modulus`.
    ///
    /// Both `a` and `b` must be below `modulus`, which puts the sum below `modulus * 2` and turns
    /// the modulo into a single conditional subtraction.
    ///
    /// Writing `%` instead is not an option. LLVM derives the necessary bound for scalars only:
    /// the range of a splat is whatever the scalar's range was, but `LazyValueInfo` has no rule
    /// for `shufflevector`, and `InstCombine` canonicalizes a masked splat into exactly that
    /// shape, so no way of writing this expression reaches the conditional subtraction.
    /// `std::hint::assert_unchecked()` doesn't help either. What is emitted instead is the generic
    /// reciprocal multiply, which for `u16x16` is 7 instructions with two multiplications against
    /// 4 here on x86-64, and 16 with six against 7 on aarch64.
    // TODO: Use `%` once LLVM looks through splats when computing ranges:
    //  https://github.com/llvm/llvm-project/issues/223468
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn add_mod<T, const N: usize>(a: Simd<T, N>, b: Simd<T, N>, modulus: Simd<T, N>) -> Simd<T, N>
    where
        T: SimdElement + Default,
        Simd<T, N>: Add<Output = Simd<T, N>>
            + Sub<Output = Simd<T, N>>
            + SimdPartialOrd<Mask = Mask<T::Mask, N>>,
    {
        let sum = a + b;

        sum - modulus.simd_le(sum).select(modulus, Simd::default())
    }

    /// Calculate all [`PARAM_M`] targets of `r` at once
    #[cfg(feature = "alloc")]
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub(super) fn calculate(&self, r: R) -> [R; const { usize::from(PARAM_M) }] {
        let r = u16::from(r);
        let c = Simd::splat(r / PARAM_C);
        let d = Simd::splat(r % PARAM_C);
        let param_b = Simd::splat(PARAM_B);
        let param_c = Simd::splat(PARAM_C);

        let mut targets = [0u16; _];

        for (index, (targets, squares)) in targets
            .as_chunks_mut::<SIMD_FACTOR>()
            .0
            .iter_mut()
            .zip(self.squares.as_chunks::<SIMD_FACTOR>().0)
            .enumerate()
        {
            let ms = Simd::splat((index * SIMD_FACTOR) as u16)
                + Simd::from_array(array::from_fn(|offset| offset as u16));

            let target_c = Self::add_mod(c, ms, param_b);
            let target_d = Self::add_mod(d, Simd::from_array(*squares), param_c);

            *targets = (target_c * param_c + target_d).to_array();
        }

        R::array_from_repr(targets)
    }

    /// Calculate all [`PARAM_M`] targets of `r` at once and check whether `r_target` is one of
    /// them.
    ///
    /// This is what [`Self::calculate()`] is for verification, where targets are only compared to
    /// a single `r` and never stored.
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub(super) fn contains(&self, r: R, r_target: R) -> bool {
        let r = u16::from(r);
        let c = Simd::splat(r / PARAM_C);
        let d = Simd::splat(r % PARAM_C);
        let param_b = Simd::splat(PARAM_B);
        let param_c = Simd::splat(PARAM_C);

        let ms = Simd::from_array(array::from_fn(|m| m as u16));

        let target_c = Self::add_mod(c, ms, param_b);
        let target_d = Self::add_mod(d, Simd::from_array(*self.squares), param_c);

        (target_c * param_c + target_d)
            .simd_eq(Simd::splat(u16::from(r_target)))
            .any()
    }
}
