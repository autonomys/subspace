//! Components of the reference implementation of Subspace Farmer for Subspace Network Blockchain.
//!
//! These components are used to implement farmer itself, but can also be used independently if necessary.

#![feature(
    const_trait_impl,
    exact_size_is_empty,
    int_roundings,
    iter_collect_into,
    never_type,
    portable_simd,
    try_blocks
)]
#![warn(rust_2018_idioms, missing_debug_implementations, missing_docs)]

pub mod auditing;
pub mod file_ext;
pub mod plotting;
pub mod proving;
pub mod reading;
pub mod sector;
mod segment_reconstruction;

use crate::file_ext::FileExt;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;
use std::fs::File;
use std::future::Future;
use std::io;
use subspace_core_primitives::segments::HistorySize;

/// Enum to encapsulate the selection between [`ReadAtSync`] and [`ReadAtAsync]` variants
#[derive(Debug, Copy, Clone)]
pub enum ReadAt<S, A>
where
    S: ReadAtSync,
    A: ReadAtAsync,
{
    /// Sync variant
    Sync(S),
    /// Async variant
    Async(A),
}

impl<S> ReadAt<S, !>
where
    S: ReadAtSync,
{
    /// Instantiate [`ReadAt`] from some [`ReadAtSync`] implementation
    pub fn from_sync(value: S) -> Self {
        Self::Sync(value)
    }
}

impl<A> ReadAt<!, A>
where
    A: ReadAtAsync,
{
    /// Instantiate [`ReadAt`] from some [`ReadAtAsync`] implementation
    pub fn from_async(value: A) -> Self {
        Self::Async(value)
    }
}

/// Sync version of [`ReadAt`], it is both [`Send`] and [`Sync`] and is supposed to be used with a
/// thread pool
pub trait ReadAtSync: Send + Sync {
    /// Get implementation of [`ReadAtSync`] that add specified offset to all attempted reads
    fn offset(&self, offset: u64) -> ReadAtOffset<'_, Self>
    where
        Self: Sized,
    {
        ReadAtOffset {
            inner: self,
            offset,
        }
    }

    /// Fill the buffer by reading bytes at a specific offset
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
}

impl ReadAtSync for ! {
    fn read_at(&self, _buf: &mut [u8], _offset: u64) -> io::Result<()> {
        unreachable!("Is never called")
    }
}

/// Container or asynchronously reading bytes using in [`ReadAtAsync`]
#[repr(transparent)]
#[derive(Debug)]
pub struct AsyncReadBytes<B>(B)
where
    B: AsMut<[u8]> + Unpin + 'static;

impl From<Vec<u8>> for AsyncReadBytes<Vec<u8>> {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Box<[u8]>> for AsyncReadBytes<Box<[u8]>> {
    fn from(value: Box<[u8]>) -> Self {
        Self(value)
    }
}

impl<B> AsMut<[u8]> for AsyncReadBytes<B>
where
    B: AsMut<[u8]> + Unpin + 'static,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<B> AsyncReadBytes<B>
where
    B: AsMut<[u8]> + Unpin + 'static,
{
    /// Extract inner value
    pub fn into_inner(self) -> B {
        self.0
    }
}

/// Async version of [`ReadAt`], it is neither [`Send`] nor [`Sync`] and is supposed to be used with
/// concurrent async combinators
pub trait ReadAtAsync {
    /// Get implementation of [`ReadAtAsync`] that add specified offset to all attempted reads
    fn offset(&self, offset: u64) -> ReadAtOffset<'_, Self>
    where
        Self: Sized,
    {
        ReadAtOffset {
            inner: self,
            offset,
        }
    }

    /// Fill the buffer by reading bytes at a specific offset and return the buffer back
    fn read_at<B>(&self, buf: B, offset: u64) -> impl Future<Output = io::Result<B>>
    where
        AsyncReadBytes<B>: From<B>,
        B: AsMut<[u8]> + Unpin + 'static;
}

impl ReadAtAsync for ! {
    async fn read_at<B>(&self, _buf: B, _offset: u64) -> io::Result<B>
    where
        AsyncReadBytes<B>: From<B>,
        B: AsMut<[u8]> + Unpin + 'static,
    {
        unreachable!("Is never called")
    }
}

impl ReadAtSync for [u8] {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        if buf.len() as u64 + offset > self.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Buffer length with offset exceeds own length",
            ));
        }

        buf.copy_from_slice(&self[offset as usize..][..buf.len()]);

        Ok(())
    }
}

impl ReadAtSync for &[u8] {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        if buf.len() as u64 + offset > self.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Buffer length with offset exceeds own length",
            ));
        }

        buf.copy_from_slice(&self[offset as usize..][..buf.len()]);

        Ok(())
    }
}

impl ReadAtSync for Vec<u8> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.as_slice().read_at(buf, offset)
    }
}

impl ReadAtSync for &Vec<u8> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.as_slice().read_at(buf, offset)
    }
}

impl ReadAtSync for File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.read_exact_at(buf, offset)
    }
}

impl ReadAtSync for &File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.read_exact_at(buf, offset)
    }
}

/// Reader with fixed offset added to all attempted reads
#[derive(Debug, Copy, Clone)]
pub struct ReadAtOffset<'a, T> {
    inner: &'a T,
    offset: u64,
}

impl<T> ReadAtSync for ReadAtOffset<'_, T>
where
    T: ReadAtSync,
{
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.inner.read_at(buf, offset + self.offset)
    }
}

impl<T> ReadAtSync for &ReadAtOffset<'_, T>
where
    T: ReadAtSync,
{
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.inner.read_at(buf, offset + self.offset)
    }
}

impl<T> ReadAtAsync for ReadAtOffset<'_, T>
where
    T: ReadAtAsync,
{
    async fn read_at<B>(&self, buf: B, offset: u64) -> io::Result<B>
    where
        AsyncReadBytes<B>: From<B>,
        B: AsMut<[u8]> + Unpin + 'static,
    {
        self.inner.read_at(buf, offset + self.offset).await
    }
}

impl<T> ReadAtAsync for &ReadAtOffset<'_, T>
where
    T: ReadAtAsync,
{
    async fn read_at<B>(&self, buf: B, offset: u64) -> io::Result<B>
    where
        AsyncReadBytes<B>: From<B>,
        B: AsMut<[u8]> + Unpin + 'static,
    {
        self.inner.read_at(buf, offset + self.offset).await
    }
}

// Refuse to compile on non-64-bit platforms, offsets may fail on those when converting from u64 to
// usize depending on chain parameters
const_assert!(std::mem::size_of::<usize>() >= std::mem::size_of::<u64>());

/// Information about the protocol necessary for farmer operation
#[derive(Debug, Copy, Clone, Encode, Decode, Serialize, Deserialize)]
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
