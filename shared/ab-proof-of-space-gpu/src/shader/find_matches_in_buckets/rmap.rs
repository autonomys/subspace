#[cfg(all(test, not(target_arch = "spirv")))]
mod tests;

use crate::shader::constants::PARAM_BC;
#[cfg(target_arch = "spirv")]
use crate::shader::polyfills::ArrayIndexingPolyfill;
use crate::shader::types::R;
use spirv_std::arch::atomic_or;
use spirv_std::memory::{Scope, Semantics};

const PRESENCE_FLAGS_WORDS: usize = (PARAM_BC as usize * 2).div_ceil(u32::BITS as usize);

#[derive(Debug, Copy, Clone)]
pub(super) struct Rmap {
    /// Store two bits per target, indicating whether matching elements are present (two at most)
    presence_flags: [u32; PRESENCE_FLAGS_WORDS],
}

impl Rmap {
    #[cfg(test)]
    #[inline(always)]
    fn new() -> Self {
        Self {
            presence_flags: [0; _],
        }
    }

    /// Returns `0`, `1` or `2` depending on whether `r` was present and whether there were
    /// duplicates.
    ///
    /// `0` means not present, `1` means exactly one value. `2` means two or more values, but
    /// doesn't track how many exactly.
    pub(super) fn num_r_items(&self, r_target: R) -> u32 {
        let bit_position = r_target.get() * 2;
        let word_offset = (bit_position / u32::BITS) as usize;
        let bit_offset = bit_position % u32::BITS;
        // SAFETY: `bit_position` is within bounds of presence flags
        let word = *unsafe { self.presence_flags.get_unchecked(word_offset) };

        ((word >> bit_offset) & 0b11).count_ones()
    }

    pub(super) fn add_with_data_parallel(&mut self, r: R) {
        let bit_position = r.get() * 2;
        let word_offset = (bit_position / u32::BITS) as usize;
        let bit_offset = bit_position % u32::BITS;
        // SAFETY: `bit_position` is within bounds of presence flags
        let word = unsafe { self.presence_flags.get_unchecked_mut(word_offset) };
        let mask = 1 << bit_offset;

        if cfg!(target_arch = "spirv") {
            // SAFETY: TODO: Probably should not be unsafe to begin with:
            //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
            let prev_word_value = unsafe {
                atomic_or::<_, { Scope::Workgroup as u32 }, { Semantics::NONE.bits() }>(word, mask)
            };

            if prev_word_value & mask != 0 {
                // Bit was already set, so this is not the first such `r` value, set a flag
                // indicating there was a duplicate
                // SAFETY: TODO: Probably should not be unsafe to begin with:
                //  https://github.com/Rust-GPU/rust-gpu/pull/394#issuecomment-3316594485
                unsafe {
                    atomic_or::<_, { Scope::Workgroup as u32 }, { Semantics::NONE.bits() }>(
                        word,
                        mask << 1u8,
                    );
                }
            }
        } else if *word & mask != 0 {
            // Bit was already set, so this is not the first such `r` value, set a flag
            // indicating there was a duplicate
            *word |= mask << 1u8;
        } else {
            *word |= mask;
        }
    }
}
