//! Virtual-to-physical mapping table implementation.

#[cfg(test)]
mod tests;

use crate::chiapos::constants::PARAM_BC;
use crate::chiapos::table::REDUCED_BUCKET_SIZE;
use crate::chiapos::table::types::{Position, R};

pub(super) struct Rmap {
    /// `0` is a sentinel value indicating no virtual pointer is stored yet.
    ///
    /// Physical pointer must be increased by `1` to get a virtual pointer before storing. Virtual
    /// pointer must be decreased by `1` before reading to get a physical pointer.
    virtual_pointers: [u16; PARAM_BC as usize],
    /// `(start_index_in_positions, count)` per distinct r-value.
    entries: [(u16, u8); REDUCED_BUCKET_SIZE],
    /// Flat storage for all positions. Positions for the same r-value are consecutive here because
    /// `add()` is called in Y-sorted bucket iteration order. Within a single bucket, same `r`
    /// means same `Y` (since `r = y - base` and Y values span exactly one `PARAM_BC` interval),
    /// so Y-sorted iteration ensures same-`r` additions are consecutive.
    positions: [Position; REDUCED_BUCKET_SIZE],
    next_entry: u16,
    next_position: u16,
}

impl Rmap {
    #[inline(always)]
    pub(super) fn new() -> Self {
        Self {
            virtual_pointers: [0; _],
            entries: [(0, 0); _],
            positions: [Position::SENTINEL; _],
            next_entry: 0,
            next_position: 0,
        }
    }

    /// # Safety
    /// - `r` must be in the range `0..PARAM_BC`
    /// - There must be at most [`REDUCED_BUCKET_SIZE`] items inserted
    /// - Additions for the same `r` value must be consecutive (no interleaving with different `r`
    ///   values between them). This is naturally satisfied when iterating a Y-sorted bucket since
    ///   same `r` implies same `Y` within a bucket.
    #[inline(always)]
    pub(super) unsafe fn add(&mut self, r: R, position: Position) {
        // SAFETY: Guaranteed by function contract
        let virtual_pointer = unsafe { self.virtual_pointers.get_unchecked_mut(usize::from(r)) };

        if let Some(physical_pointer) = virtual_pointer.checked_sub(1) {
            // Existing r-value: increment count, append position
            // SAFETY: Internal pointers are always valid
            let entry = unsafe { self.entries.get_unchecked_mut(physical_pointer as usize) };
            debug_assert!(
                entry.1 < u8::MAX,
                "Rmap entry count overflow for r={}",
                u16::from(r)
            );
            entry.1 += 1;
        } else {
            // New r-value: allocate entry
            let physical_pointer = self.next_entry;
            self.next_entry += 1;
            *virtual_pointer = physical_pointer + 1;

            // SAFETY: It is guaranteed by the function contract that the number of distinct
            // r-values will never exceed `REDUCED_BUCKET_SIZE`
            let entry = unsafe { self.entries.get_unchecked_mut(physical_pointer as usize) };
            *entry = (self.next_position, 1);
        }

        // Store position in flat array
        // SAFETY: Total positions never exceed REDUCED_BUCKET_SIZE
        unsafe {
            *self
                .positions
                .get_unchecked_mut(self.next_position as usize) = position;
        }
        self.next_position += 1;
    }

    /// Returns all positions for the given r-value as a slice.
    /// Returns an empty slice if no entry exists.
    ///
    /// # Safety
    /// `r` must be in the range `0..PARAM_BC`
    #[inline(always)]
    pub(super) unsafe fn get(&self, r: R) -> &[Position] {
        // SAFETY: Guaranteed by function contract
        let virtual_pointer = *unsafe { self.virtual_pointers.get_unchecked(usize::from(r)) };

        if let Some(physical_pointer) = virtual_pointer.checked_sub(1) {
            // SAFETY: Internal pointers are always valid
            let &(start_index, count) =
                unsafe { self.entries.get_unchecked(physical_pointer as usize) };
            // SAFETY: start_index..start_index+count is always within bounds
            unsafe {
                self.positions
                    .get_unchecked(start_index as usize..start_index as usize + count as usize)
            }
        } else {
            &[]
        }
    }
}
