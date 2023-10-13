#![feature(
    array_chunks,
    const_option,
    const_trait_impl,
    int_roundings,
    iter_collect_into,
    new_uninit,
    portable_simd,
    slice_flatten,
    try_blocks
)]

//! Components of the reference implementation of Subspace Farmer for Subspace Network Blockchain.
//!
//! These components are used to implement farmer itself, but can also be used independently if necessary.

pub mod auditing;
pub mod file_ext;
pub mod plotting;
pub mod proving;
pub mod reading;
pub mod sector;
mod segment_reconstruction;

use crate::file_ext::FileExt;
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;
use std::fs::File;
use std::io;
use subspace_core_primitives::HistorySize;

/// Trait for reading data at specific offset
pub trait ReadAt: Send + Sync {
    /// Get implementation of [`ReadAt`] that add specified offset to all attempted reads
    fn offset(&self, offset: usize) -> ReadAtOffset<&Self>
    where
        Self: Sized,
    {
        ReadAtOffset {
            inner: self,
            offset,
        }
    }

    /// Fill the buffer by reading bytes at a specific offset
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()>;
}

impl ReadAt for [u8] {
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()> {
        if buf.len() + offset > self.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Buffer length with offset exceeds own length",
            ));
        }

        buf.copy_from_slice(&self[offset..][..buf.len()]);

        Ok(())
    }
}

impl ReadAt for &[u8] {
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()> {
        if buf.len() + offset > self.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Buffer length with offset exceeds own length",
            ));
        }

        buf.copy_from_slice(&self[offset..][..buf.len()]);

        Ok(())
    }
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()> {
        self.as_slice().read_at(buf, offset)
    }
}

impl ReadAt for &Vec<u8> {
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()> {
        self.as_slice().read_at(buf, offset)
    }
}

impl ReadAt for File {
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()> {
        self.read_exact_at(buf, offset as u64)
    }
}

impl ReadAt for &File {
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()> {
        self.read_exact_at(buf, offset as u64)
    }
}

/// Reader with fixed offset added to all attempted reads
#[derive(Debug, Copy, Clone)]
pub struct ReadAtOffset<T> {
    inner: T,
    offset: usize,
}

impl<T> ReadAt for ReadAtOffset<T>
where
    T: ReadAt,
{
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()> {
        self.inner.read_at(buf, offset + self.offset)
    }
}

impl<T> ReadAt for &ReadAtOffset<T>
where
    T: ReadAt,
{
    fn read_at(&self, buf: &mut [u8], offset: usize) -> io::Result<()> {
        self.inner.read_at(buf, offset + self.offset)
    }
}

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// Information about the protocol necessary for farmer operation
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FarmerProtocolInfo {
    /// Size of the blockchain history
    pub history_size: HistorySize,
    /// How many pieces one sector is supposed to contain (max)
    pub max_pieces_in_sector: u16,
    /// Number of latest archived segments that are considered "recent history".
    pub recent_segments: HistorySize,
    /// Fraction of pieces from the "recent history" (`recent_segments`) in each sector.
    pub recent_history_fraction: (HistorySize, HistorySize),
    /// Minimum lifetime of a plotted sector, measured in archived segment
    pub min_sector_lifetime: HistorySize,
}
