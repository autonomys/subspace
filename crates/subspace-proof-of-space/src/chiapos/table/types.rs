use crate::chiapos::table::{
    metadata_size_bits, metadata_size_bytes, x_size_bytes, y_size_bits, y_size_bytes,
};
use crate::chiapos::utils::EvaluatableUsize;
use bitvec::prelude::*;
use core::ops::Deref;
use core::{fmt, mem};
use std::cmp::Ordering;

/// Copy `size` bits from `source` starting at `source_offset` into `destination` at
/// `destination_offset`
///
/// ## Panics
/// Panics if `source_offset > 7` or `destination_offset > 7`.
/// Panics if `source_offset + size > source * u8::BITS` or
/// `destination_offset + size > destination * u8::BITS`.
// TODO: Should benefit from SIMD instructions
// Inlining helps compiler remove most of the logic in this function
#[inline(always)]
#[track_caller]
fn copy_bits(
    source: &[u8],
    source_offset: usize,
    destination: &mut [u8],
    destination_offset: usize,
    size: usize,
) {
    const BYTE_SIZE: usize = u8::BITS as usize;

    // TODO: Make it skip bytes automatically
    assert!(source_offset <= 7, "source_offset {source_offset} > 7");
    assert!(destination_offset <= 7, "source_offset {source_offset} > 7");
    // Source length in bytes
    let source_len = source.len();
    // Destination length in bytes
    let destination_len = destination.len();
    assert!(
        source_offset + size <= source_len * BYTE_SIZE,
        "source_offset {source_offset} + size {size} > source.len() {source_len} * BYTE_SIZE {BYTE_SIZE}",
    );
    assert!(
        destination_offset + size <= destination_len * BYTE_SIZE,
        "destination_offset {destination_offset} + size {size} > destination.len() {destination_len} * BYTE_SIZE {BYTE_SIZE}",
    );

    // This number of bits in the last destination byte will be composed from source bits
    let last_byte_bits_from_source = {
        let last_byte_bits_from_source = (destination_offset + size) % BYTE_SIZE;
        if last_byte_bits_from_source == 0 {
            BYTE_SIZE
        } else {
            last_byte_bits_from_source
        }
    };

    // Copy and shift bits left or right to match desired `OUT_OFFSET`
    match destination_offset.cmp(&source_offset) {
        // Strategy in case we shift bits left
        //
        // We start with the first byte that we compose into the final form form its original bits
        // that do not need to be updated and bits from the source that need to be moved into it.
        //
        // Observation here is that source is potentially one byte longer than destination, so by
        // processing the first byte separately we can continue iterating over source bytes with
        // offset by 1 byte to the right with previous byte in destination allows us to move forward
        // without touching previous bytes in the process.
        //
        // If length of source and destination bytes is not the same we skip very last iteration in
        // general way. This is because last destination byte might have bits that need to be
        // preserved and we don't want to read destination unnecessarily here, so we do another pass
        // afterwards with destination bit preserved.
        //
        // If length of source and destination are the same, we iterate all the way to the end (but
        // we still skip one destination byte due to iterating over source and destination bytes
        // with offset to each other). After iteration the only thing left is just to take
        // accumulator and apply to the last destination byte (again, the only byte we actually need
        // to read).
        Ordering::Less => {
            // Offset between source and destination
            let offset = source_offset - destination_offset;
            // Preserve first bits from destination that must not be changed in accumulator
            let mut left_acc = if destination_offset == 0 {
                // Byte will be fully overridden by the source
                0
            } else {
                destination[0] & (u8::MAX << (BYTE_SIZE - destination_offset))
            };
            // Add bits from the first source byte to the accumulator
            left_acc |= (source[0] << offset) & (u8::MAX >> destination_offset);

            // Compose destination bytes, skip the first source byte since we have already processed
            // it above.
            //
            // Note that on every step source byte is to the right of the destination, skip last
            // pair such that we can preserve trailing bits of the destination unchanged
            // (this is an optimization, it allows us to not read `destination` in this loop at all)
            for (source, destination) in source[1..]
                .iter()
                .zip(destination.iter_mut())
                .rev()
                .skip(if source_len != destination_len { 1 } else { 0 })
                .rev()
            {
                // Take bits that were be moved out of the byte boundary and add the left side from
                // accumulator
                *destination = left_acc | (*source >> (BYTE_SIZE - offset));
                // Store left side of the source bits in the accumulator that will be applied to the
                // next byte
                left_acc = *source << offset;
            }

            // Clear bits in accumulator that must not be copied into destination
            let left_acc = left_acc & (u8::MAX << (BYTE_SIZE - last_byte_bits_from_source));

            if source_len != destination_len {
                if let Some((source, destination)) =
                    source[1..].iter().zip(destination.iter_mut()).last()
                {
                    let preserved_bits = if last_byte_bits_from_source == BYTE_SIZE {
                        // Byte will be fully overridden by the source
                        0
                    } else {
                        *destination & (u8::MAX >> last_byte_bits_from_source)
                    };
                    // Take bits that were be moved out of the byte boundary
                    let source_bits = (*source >> (BYTE_SIZE - offset))
                        & (u8::MAX << (BYTE_SIZE - last_byte_bits_from_source));
                    // Combine last accumulator bits (left most bits) with source bits and preserved
                    // bits in destination
                    *destination = left_acc | source_bits | preserved_bits;
                }
            } else {
                // Shift source bits to the right and remove trailing bits that we'll get from
                // destination, this is the middle part of the last destination byte
                let source_bits = (source[source_len - 1] >> (BYTE_SIZE - offset))
                    & (u8::MAX << (BYTE_SIZE - last_byte_bits_from_source));
                // Bits preserved in destination
                let preserved_bits = if last_byte_bits_from_source == BYTE_SIZE {
                    // Byte will be fully overridden by the source
                    0
                } else {
                    destination[destination_len - 1] & (u8::MAX >> last_byte_bits_from_source)
                };
                // Combine last accumulator bits (left most bits) with source bits and preserved
                // bits in destination
                destination[destination_len - 1] = left_acc | source_bits | preserved_bits;
            }
        }
        // Strategy here is much simpler: copy first and last bytes while accounting for bits that
        // should be preserved in destination, otherwise do bulk copy
        Ordering::Equal => {
            if destination_offset > 0 {
                // Clear bits of the first byte that will be overridden by bits from source
                destination[0] &= u8::MAX << ((BYTE_SIZE - destination_offset) % BYTE_SIZE);
                // Add bits to the first byte from source
                destination[0] |= source[0] & (u8::MAX >> destination_offset);
            } else {
                destination[0] = source[0];
            }

            // Copy some bytes in bulk
            if destination_len > 2 {
                // Copy everything except first and last bytes
                destination[1..destination_len - 1]
                    .copy_from_slice(&source[1..destination_len - 1]);
            }

            if last_byte_bits_from_source == BYTE_SIZE {
                destination[destination_len - 1] = source[destination_len - 1];
            } else {
                // Clear bits of the last byte that will be overridden by bits from source
                destination[destination_len - 1] &= u8::MAX >> last_byte_bits_from_source;
                // Add bits to the last byte from source
                destination[destination_len - 1] |= source[destination_len - 1]
                    & (u8::MAX << (BYTE_SIZE - last_byte_bits_from_source));
            }
        }
        // Strategy in case we shift bits right
        //
        // We start with the first byte that we compose into the final form form its original bits
        // that do not need to be updated and bits from the source that need to be moved into it.
        //
        // Here destination is potentially one byte longer than source and we still need to preserve
        // last destination bits that should not have been modified.
        //
        // If length of source and destination bytes is the same, we skip very last iteration. That
        // is because it might have bits that need to be preserved and we don't want to read
        // destination unnecessarily here, so we do another pass afterwards with destination bit
        // preserved.
        //
        // If length of source and destination are not the same, we iterate all the way to the end.
        // After iteration the only thing left is just to take accumulator and apply to the last
        // destination byte (again, the only byte we actually need to read).
        Ordering::Greater => {
            // Offset between source and destination
            let offset = destination_offset - source_offset;
            {
                // Bits preserved in destination
                let preserved_bits = destination[0] & (u8::MAX << (BYTE_SIZE - destination_offset));
                // Source bits that will be stored in the first byte
                let source_bits = (source[0] >> offset) & (u8::MAX >> destination_offset);
                // Combine preserved bits and source bits into the first destination byte
                destination[0] = preserved_bits | source_bits;
            }
            // Store bits from first source byte that didn't fit into first destination byte into
            // the accumulator
            let mut left_acc = (source[0] & (u8::MAX >> source_offset)) << (BYTE_SIZE - offset);

            // Compose destination bytes, skip the first pair since we have already processed
            // them above.
            //
            // Note that we skip last pair in case source and destination are the same, such that we
            // can preserve trailing bits of the destination unchanged (this is an optimization, it
            // allows us to not read `destination` in this loop at all)
            for (source, destination) in source
                .iter()
                .zip(destination.iter_mut())
                .skip(1)
                .rev()
                .skip(if source_len == destination_len { 1 } else { 0 })
                .rev()
            {
                // Shift source bits to the right and add the left side from accumulator
                *destination = left_acc | (*source >> offset);
                // Take bits that were moved out of the boundary into accumulator that will be
                // applied to the next byte
                left_acc = *source << (BYTE_SIZE - offset);
            }

            // Clear bits in accumulator that must not be copied into destination
            let left_acc = left_acc & (u8::MAX << (BYTE_SIZE - last_byte_bits_from_source));

            if source_len == destination_len {
                // In case we skipped last pair above, process it here
                if let Some((source, destination)) =
                    source.iter().zip(destination.iter_mut()).skip(1).last()
                {
                    let preserved_bits = if last_byte_bits_from_source == BYTE_SIZE {
                        // Byte will be fully overridden by the source
                        0
                    } else {
                        *destination & (u8::MAX >> last_byte_bits_from_source)
                    };
                    // Shift source bits to the right and clear bits that correspond to preserved
                    // bits
                    let source_bits =
                        (*source >> offset) & (u8::MAX << (BYTE_SIZE - last_byte_bits_from_source));
                    // Combine last accumulator bits (left most bits) with source bits and preserved
                    // bits in destination
                    *destination = left_acc | source_bits | preserved_bits;
                }
            } else {
                // Bits preserved in destination
                let preserved_bits =
                    destination[destination_len - 1] & (u8::MAX >> last_byte_bits_from_source);
                // Combine last accumulator bits (left most bits) with preserved bits in destination
                destination[destination_len - 1] = left_acc | preserved_bits;
            }
        }
    }
}

/// Container with data source and information about contents
pub(in super::super) struct CopyBitsSourceData<'a> {
    pub(in super::super) bytes: &'a [u8],
    /// Where do bits of useful data start
    pub(in super::super) bit_offset: usize,
    /// Size in bits
    pub(in super::super) bit_size: usize,
}

pub(in super::super) trait CopyBitsSource {
    fn data(&self) -> CopyBitsSourceData<'_>;
}

pub(in super::super) trait CopyBitsDestination {
    /// Where do bits of useful data start
    const DATA_OFFSET: usize;

    /// Underlying data container
    fn data_mut(&mut self) -> &mut [u8];

    /// Size in bits
    fn bits(&self) -> usize;

    /// Copy `size` bits from [`Source`] bits starting at `source_offset` and write at
    /// `destination_offset` into this data structure. Contents of bits after `DESTINATION_OFFSET`
    /// is not defined.
    ///
    /// ## Panics
    /// Panics if `SOURCE_OFFSET + SIZE` is more bits than [`Source`] has or
    /// `DESTINATION_OFFSET + SIZE` is more bits than [`Self::bits()`], higher level code must ensure
    /// this never happens, method is not exposed outside of this crate and crate boundaries are
    /// supposed to protect this invariant. Exposing error handling from here will be too noisy and
    /// seemed not worth it.
    // Inlining helps compiler remove most of the logic in this function
    #[inline(always)]
    fn copy_bits_from<Source, SourceOffset, Size, DestinationOffset>(
        &mut self,
        source: &Source,
        source_offset: SourceOffset,
        size: Size,
        destination_offset: DestinationOffset,
    ) where
        Source: CopyBitsSource + ?Sized,
        usize: From<SourceOffset>,
        usize: From<Size>,
        usize: From<DestinationOffset>,
    {
        let source_offset = usize::from(source_offset);
        let size = usize::from(size);
        let destination_offset = usize::from(destination_offset);
        let source_data = source.data();

        assert!(source_offset + size <= source_data.bit_size);
        assert!(destination_offset + size <= self.bits());

        // Which byte to start reading bytes at, taking into account where actual data bits start
        // and desired offset
        let read_byte_offset = (source_data.bit_offset + source_offset) / u8::BITS as usize;
        // Which bit in read bytes is the first one we care about
        let read_bit_offset = (source_data.bit_offset + source_offset) % u8::BITS as usize;
        // How many bytes to read from source, while taking into account the fact desired source
        // offset
        let bytes_to_read = (read_bit_offset + size).div_ceil(u8::BITS as usize);
        // Source bytes at which we have `SIZE` bits of data starting at `read_bit_offset` bit
        let source_bytes = &source_data.bytes[read_byte_offset..][..bytes_to_read];

        // Which byte to start writing bytes at, taking into account where actual data bits start
        // and desired offset
        let write_byte_offset = (Self::DATA_OFFSET + destination_offset) / u8::BITS as usize;
        // Which bit in destination is the first bit at which source should actually be written,
        // bits before that must be preserved
        let write_bit_offset = (Self::DATA_OFFSET + destination_offset) % u8::BITS as usize;
        // How many bytes to write into destination, while taking into account the fact desired
        // destination offset
        let bytes_to_write = (write_bit_offset + size).div_ceil(u8::BITS as usize);
        // Destination bytes at which we have `SIZE` bits to write starting at `write_bit_offset`
        let destination_bytes = &mut self.data_mut()[write_byte_offset..][..bytes_to_write];

        // Defensive checks in debug builds before we have robust test for bit copying
        #[cfg(debug_assertions)]
        let first_destination_bits =
            destination_bytes.view_bits::<Msb0>()[..write_bit_offset].to_bitvec();
        #[cfg(debug_assertions)]
        let last_destination_bits =
            destination_bytes.view_bits::<Msb0>()[write_bit_offset + size..].to_bitvec();
        copy_bits(
            source_bytes,
            read_bit_offset,
            destination_bytes,
            write_bit_offset,
            size,
        );
        #[cfg(debug_assertions)]
        assert_eq!(
            first_destination_bits,
            destination_bytes.view_bits::<Msb0>()[..write_bit_offset].to_bitvec(),
            "Implementation bug in subspace-proof-of-space bit copy, please report to Nazar \
            immediately with reproduction steps"
        );
        #[cfg(debug_assertions)]
        assert_eq!(
            destination_bytes.view_bits::<Msb0>()[write_bit_offset..][..size].to_bitvec(),
            source_bytes.view_bits::<Msb0>()[read_bit_offset..][..size].to_bitvec(),
            "Implementation bug in subspace-proof-of-space bit copy, please report to Nazar \
            immediately with reproduction steps"
        );
        #[cfg(debug_assertions)]
        assert_eq!(
            last_destination_bits,
            destination_bytes.view_bits::<Msb0>()[write_bit_offset + size..].to_bitvec(),
            "Implementation bug in subspace-proof-of-space bit copy, please report to Nazar \
            immediately with reproduction steps"
        );
    }
}

impl<T> CopyBitsSource for T
where
    T: AsRef<[u8]> + ?Sized,
{
    fn data(&self) -> CopyBitsSourceData<'_> {
        CopyBitsSourceData {
            bytes: self.as_ref(),
            bit_offset: 0,
            bit_size: self.as_ref().len() * u8::BITS as usize,
        }
    }
}

impl<T> CopyBitsDestination for T
where
    T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
{
    const DATA_OFFSET: usize = 0;

    fn data_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }

    fn bits(&self) -> usize {
        self.as_ref().len() * u8::BITS as usize
    }
}

/// Wrapper data structure around bits of `x` values, stores data in the last bits of internal array
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[repr(transparent)]
pub(in super::super) struct X<const K: u8>([u8; x_size_bytes(K)])
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized;

impl<const K: u8> Default for X<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    fn default() -> Self {
        Self([0; x_size_bytes(K)])
    }
}

impl<const K: u8> fmt::Debug for X<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("X")
            .field(&&self.0.view_bits::<Msb0>()[Self::BYTES * u8::BITS as usize - Self::BITS..])
            .finish()
    }
}

impl<const K: u8> From<usize> for X<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    /// Will silently drop data if [`K`] is too small to store useful data in [`usize`], higher
    /// level code must ensure this never happens, method is not exposed outside of this crate and
    /// crate boundaries are supposed to protect this invariant. Exposing error handling from here
    /// will be too noisy and seemed not worth it.
    fn from(value: usize) -> Self {
        let mut output = [0; x_size_bytes(K)];
        // Copy last bytes
        output.copy_from_slice(&value.to_be_bytes()[mem::size_of::<usize>() - Self::BYTES..]);
        Self(output)
    }
}

impl<const K: u8> From<&X<K>> for usize
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    /// Panics if conversion to [`usize`] fails, higher level code must ensure this never happens,
    /// method is not exposed outside of this crate and crate boundaries are supposed to protect
    /// this invariant. Exposing error handling from here will be too noisy and seemed not worth it.
    fn from(value: &X<K>) -> Self {
        let mut output = 0_usize.to_be_bytes();
        output[mem::size_of::<usize>() - x_size_bytes(K)..].copy_from_slice(&value.0);
        usize::from_be_bytes(output)
    }
}

impl<const K: u8> CopyBitsSource for X<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    fn data(&self) -> CopyBitsSourceData<'_> {
        CopyBitsSourceData {
            bytes: &self.0,
            bit_offset: Self::DATA_OFFSET,
            bit_size: Self::BITS,
        }
    }
}

impl<const K: u8> CopyBitsDestination for X<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    const DATA_OFFSET: usize = Self::DATA_OFFSET;

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn bits(&self) -> usize {
        Self::BITS
    }
}

impl<const K: u8> X<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    /// Size in bytes
    const BYTES: usize = x_size_bytes(K);
    /// Size in bits
    const BITS: usize = K as usize;
    /// Where do bits of useful data start
    const DATA_OFFSET: usize = Self::BYTES * u8::BITS as usize - Self::BITS;
}

/// Wrapper data structure around bits of `y` values, stores data in the last bits of internal
/// array
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[repr(transparent)]
pub(in super::super) struct Y<const K: u8>([u8; y_size_bytes(K)])
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized;

impl<const K: u8> Default for Y<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    fn default() -> Self {
        Self([0; y_size_bytes(K)])
    }
}

impl<const K: u8> fmt::Debug for Y<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Y").field(&self.deref()).finish()
    }
}

// TODO: Implement bit matching and remove this
impl<const K: u8> Deref for Y<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    type Target = BitSlice<u8, Msb0>;

    fn deref(&self) -> &Self::Target {
        &self.0.view_bits::<Msb0>()[Self::DATA_OFFSET..]
    }
}

impl<const K: u8> CopyBitsSource for Y<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    fn data(&self) -> CopyBitsSourceData<'_> {
        CopyBitsSourceData {
            bytes: &self.0,
            bit_offset: Self::DATA_OFFSET,
            bit_size: Self::BITS,
        }
    }
}

impl<const K: u8> CopyBitsDestination for Y<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    const DATA_OFFSET: usize = Self::DATA_OFFSET;

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn bits(&self) -> usize {
        Self::BITS
    }
}

#[cfg(test)]
impl<const K: u8> From<usize> for Y<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    /// Will silently drop data if [`K`] is too small to store useful data in [`usize`], higher
    /// level code must ensure this never happens, method is not exposed outside of this crate and
    /// crate boundaries are supposed to protect this invariant. Exposing error handling from here
    /// will be too noisy and seemed not worth it.
    fn from(value: usize) -> Self {
        let mut output = Self::default();
        // Copy last bytes from big-endian `value` into `Y`
        output
            .0
            .copy_from_slice(&value.to_be_bytes()[mem::size_of::<usize>() - Self::BYTES..]);
        output
    }
}

impl<const K: u8> From<&Y<K>> for usize
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    /// Panics if conversion to [`usize`] fails, higher level code must ensure this never happens,
    /// method is not exposed outside of this crate and crate boundaries are supposed to protect
    /// this invariant. Exposing error handling from here will be too noisy and seemed not worth it.
    fn from(value: &Y<K>) -> Self {
        let mut output = 0_usize.to_be_bytes();
        output[mem::size_of::<usize>() - y_size_bytes(K)..].copy_from_slice(&value.0);
        usize::from_be_bytes(output)
    }
}

impl<const K: u8> Y<K>
where
    EvaluatableUsize<{ y_size_bytes(K) }>: Sized,
{
    /// Size in bytes
    const BYTES: usize = y_size_bytes(K);
    /// Size in bits
    const BITS: usize = y_size_bits(K);
    /// Where do bits of useful data start
    const DATA_OFFSET: usize = Self::BYTES * u8::BITS as usize - Self::BITS;
}

/// Wrapper data structure around bits of `metadata` values, stores data in the last bits of
/// internal array
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[repr(transparent)]
pub(in super::super) struct Metadata<const K: u8, const TABLE_NUMBER: u8>(
    [u8; metadata_size_bytes(K, TABLE_NUMBER)],
)
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized;

impl<const K: u8, const TABLE_NUMBER: u8> Default for Metadata<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    fn default() -> Self {
        Self([0; metadata_size_bytes(K, TABLE_NUMBER)])
    }
}

impl<const K: u8, const TABLE_NUMBER: u8> fmt::Debug for Metadata<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Metadata")
            .field(&&self.0.view_bits::<Msb0>()[Self::DATA_OFFSET..])
            .finish()
    }
}

impl<const K: u8, const TABLE_NUMBER: u8> CopyBitsSource for Metadata<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    fn data(&self) -> CopyBitsSourceData<'_> {
        CopyBitsSourceData {
            bytes: &self.0,
            bit_offset: Self::DATA_OFFSET,
            bit_size: Self::BITS,
        }
    }
}

impl<const K: u8, const TABLE_NUMBER: u8> CopyBitsDestination for Metadata<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    const DATA_OFFSET: usize = Self::DATA_OFFSET;

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn bits(&self) -> usize {
        Self::BITS
    }
}

#[cfg(test)]
impl<const K: u8, const TABLE_NUMBER: u8> From<usize> for Metadata<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    /// Will silently drop data if [`K`] is too small to store useful data in [`usize`], higher
    /// level code must ensure this never happens, method is not exposed outside of this crate and
    /// crate boundaries are supposed to protect this invariant. Exposing error handling from here
    /// will be too noisy and seemed not worth it.
    fn from(value: usize) -> Self {
        let mut output = Self::default();
        // Copy last bytes from big-endian `value` into `Metadata`
        output
            .0
            .copy_from_slice(&value.to_be_bytes()[mem::size_of::<usize>() - Self::BYTES..]);
        output
    }
}

impl<const K: u8, const TABLE_NUMBER: u8> Metadata<K, TABLE_NUMBER>
where
    EvaluatableUsize<{ metadata_size_bytes(K, TABLE_NUMBER) }>: Sized,
{
    /// Size in bytes
    const BYTES: usize = metadata_size_bytes(K, TABLE_NUMBER);
    /// Size in bits
    const BITS: usize = metadata_size_bits(K, TABLE_NUMBER);
    /// Where do bits of useful data start
    const DATA_OFFSET: usize = Self::BYTES * u8::BITS as usize - Self::BITS;
}

/// Wrapper data structure around bits of `position` values, stores data in the last bits of internal
/// array. Has the same size as [`X`], but different internal layout.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[repr(transparent)]
pub(in super::super) struct Position<const K: u8>([u8; x_size_bytes(K)])
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized;

impl<const K: u8> fmt::Debug for Position<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Position")
            .field(&usize::from(*self))
            .finish()
    }
}

impl<const K: u8> From<usize> for Position<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    /// Will silently drop data if [`K`] is too small to store useful data in [`usize`], higher
    /// level code must ensure this never happens, method is not exposed outside of this crate and
    /// crate boundaries are supposed to protect this invariant. Exposing error handling from here
    /// will be too noisy and seemed not worth it.
    fn from(value: usize) -> Self {
        let mut output = [0; x_size_bytes(K)];
        // Copy last bytes
        output.copy_from_slice(&value.to_be_bytes()[mem::size_of::<usize>() - Self::BYTES..]);
        Self(output)
    }
}

impl<const K: u8> From<Position<K>> for usize
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    /// Panics if conversion to [`usize`] fails, higher level code must ensure this never happens,
    /// method is not exposed outside of this crate and crate boundaries are supposed to protect
    /// this invariant. Exposing error handling from here will be too noisy and seemed not worth it.
    fn from(value: Position<K>) -> Self {
        let mut output = 0_usize.to_be_bytes();
        output[mem::size_of::<usize>() - Position::<K>::BYTES..].copy_from_slice(&value.0);
        usize::from_be_bytes(output)
    }
}

impl<const K: u8> Position<K>
where
    EvaluatableUsize<{ x_size_bytes(K) }>: Sized,
{
    /// Size in bytes
    const BYTES: usize = x_size_bytes(K);
}
