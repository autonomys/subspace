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
    positions: [[Position; 2]; REDUCED_BUCKET_SIZE],
    next_physical_pointer: u16,
}

impl Rmap {
    #[inline(always)]
    pub(super) fn new() -> Self {
        Self {
            virtual_pointers: [0; _],
            positions: [[Position::ZERO; 2]; _],
            next_physical_pointer: 0,
        }
    }

    /// # Safety
    /// `r` must be in the range `0..PARAM_BC`, there must be at most [`REDUCED_BUCKET_SIZE`] items
    /// inserted
    #[inline(always)]
    unsafe fn insertion_item(&mut self, r: R) -> &mut [Position; 2] {
        // SAFETY: Guaranteed by function contract
        let virtual_pointer = unsafe { self.virtual_pointers.get_unchecked_mut(usize::from(r)) };

        if let Some(physical_pointer) = virtual_pointer.checked_sub(1) {
            // SAFETY: Internal pointers are always valid
            return unsafe { self.positions.get_unchecked_mut(physical_pointer as usize) };
        }

        let physical_pointer = self.next_physical_pointer;
        self.next_physical_pointer += 1;
        *virtual_pointer = physical_pointer + 1;

        // SAFETY: It is guaranteed by the function contract that the number of added elements will
        // never exceed `REDUCED_BUCKETS_SIZE`, hence allocated pointers will always be within
        // bounds
        unsafe { self.positions.get_unchecked_mut(physical_pointer as usize) }
    }

    /// Note that `position == Position::ZERO` is effectively ignored here, supporting it cost too
    /// much in terms of performance and not required for correctness.
    ///
    /// # Safety
    /// `r` must be in the range `0..PARAM_BC`, there must be at most [`REDUCED_BUCKET_SIZE`] items
    /// inserted
    #[inline(always)]
    pub(super) unsafe fn add(&mut self, r: R, position: Position) {
        // SAFETY: Guaranteed by function contract
        let rmap_item = unsafe { self.insertion_item(r) };

        // The same `r` can appear in the table multiple times, one duplicate is supported here
        if rmap_item[0] == Position::ZERO {
            rmap_item[0] = position;
        } else if rmap_item[1] == Position::ZERO {
            rmap_item[1] = position;
        }
    }

    /// # Safety
    /// `r` must be in the range `0..PARAM_BC`
    #[inline(always)]
    pub(super) unsafe fn get(&self, r: R) -> [Position; 2] {
        // SAFETY: Guaranteed by function contract
        let virtual_pointer = *unsafe { self.virtual_pointers.get_unchecked(usize::from(r)) };

        if let Some(physical_pointer) = virtual_pointer.checked_sub(1) {
            // SAFETY: Internal pointers are always valid
            *unsafe { self.positions.get_unchecked(physical_pointer as usize) }
        } else {
            [Position::ZERO; 2]
        }
    }
}
