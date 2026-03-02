//! Small GPU-friendly software implementation of ChaCha8

#![no_std]

#[cfg(test)]
mod tests;

/// A single ChaCha8 block
pub type ChaCha8Block = [u32; 16];

/// Convert block to bytes
#[inline(always)]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn block_to_bytes(block: &ChaCha8Block) -> [u8; 64] {
    // SAFETY: Same size and no alignment requirements
    unsafe { block.as_ptr().cast::<[u8; 64]>().read() }
}

/// Create an instance from internal representation
#[inline(always)]
#[cfg_attr(feature = "no-panic", no_panic::no_panic)]
pub fn bytes_to_block(bytes: &[u8; 64]) -> ChaCha8Block {
    // SAFETY: Same size, all bit patterns are valid
    unsafe { bytes.as_ptr().cast::<ChaCha8Block>().read_unaligned() }
}

/// State of ChaCha8 cipher
#[derive(Debug, Copy, Clone)]
pub struct ChaCha8State {
    data: ChaCha8Block,
}

impl ChaCha8State {
    const ROUNDS: usize = 8;

    /// Initialize ChaCha8 state
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn init(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut data = [0u32; 16];
        data[0] = 0x61707865;
        data[1] = 0x3320646e;
        data[2] = 0x79622d32;
        data[3] = 0x6b206574;

        for (i, &chunk) in key.as_chunks::<4>().0.iter().enumerate() {
            data[4 + i] = u32::from_le_bytes(chunk);
        }

        // `data[12]` and `data[13]` is counter specific to each block, thus not set here

        for (i, &chunk) in nonce.as_chunks::<4>().0.iter().enumerate() {
            data[13 + i] = u32::from_le_bytes(chunk);
        }

        Self { data }
    }

    /// Convert to internal representation
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn to_repr(self) -> ChaCha8Block {
        self.data
    }

    /// Create an instance from internal representation
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn from_repr(data: ChaCha8Block) -> Self {
        Self { data }
    }

    /// Compute block for specified counter.
    ///
    /// Counter is only 32-bit because that is all that is needed for target use case.
    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    pub fn compute_block(mut self, counter: u32) -> ChaCha8Block {
        self.data[12] = counter;
        // Not setting `data[13]` due to counter being limited to `u32`

        let initial = self.data;

        for _ in 0..Self::ROUNDS / 2 {
            self.quarter_round(0, 4, 8, 12);
            self.quarter_round(1, 5, 9, 13);
            self.quarter_round(2, 6, 10, 14);
            self.quarter_round(3, 7, 11, 15);

            self.quarter_round(0, 5, 10, 15);
            self.quarter_round(1, 6, 11, 12);
            self.quarter_round(2, 7, 8, 13);
            self.quarter_round(3, 4, 9, 14);
        }

        // TODO: More idiomatic version currently doesn't compile:
        //  https://github.com/Rust-GPU/rust-gpu/issues/241#issuecomment-3005693043
        #[allow(clippy::needless_range_loop)]
        // for (d, initial) in self.data.iter_mut().zip(initial) {
        //     *d = d.wrapping_add(initial);
        // }
        for i in 0..16 {
            self.data[i] = self.data[i].wrapping_add(initial[i]);
        }

        self.data
    }

    #[inline(always)]
    #[cfg_attr(feature = "no-panic", no_panic::no_panic)]
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        self.data[a] = self.data[a].wrapping_add(self.data[b]);
        self.data[d] ^= self.data[a];
        self.data[d] = self.data[d].rotate_left(16);

        self.data[c] = self.data[c].wrapping_add(self.data[d]);
        self.data[b] ^= self.data[c];
        self.data[b] = self.data[b].rotate_left(12);

        self.data[a] = self.data[a].wrapping_add(self.data[b]);
        self.data[d] ^= self.data[a];
        self.data[d] = self.data[d].rotate_left(8);

        self.data[c] = self.data[c].wrapping_add(self.data[d]);
        self.data[b] ^= self.data[c];
        self.data[b] = self.data[b].rotate_left(7);
    }
}
