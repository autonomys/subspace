//! Wrapper data structure for direct/unbuffered I/O

use parking_lot::Mutex;
use static_assertions::const_assert_eq;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::{io, mem};
use subspace_farmer_components::ReadAtSync;
use subspace_farmer_components::file_ext::{FileExt, OpenOptionsExt};

/// 4096 is as a relatively safe size due to sector size on SSDs commonly being 512 or 4096 bytes
pub const DISK_SECTOR_SIZE: usize = 4096;
/// Restrict how much data to read from disk in a single call to avoid very large memory usage
const MAX_READ_SIZE: usize = 1024 * 1024;

const_assert_eq!(MAX_READ_SIZE % DISK_SECTOR_SIZE, 0);

#[derive(Debug, Copy, Clone)]
#[repr(C, align(4096))]
struct AlignedSectorSize([u8; DISK_SECTOR_SIZE]);

const_assert_eq!(align_of::<AlignedSectorSize>(), DISK_SECTOR_SIZE);

impl Default for AlignedSectorSize {
    fn default() -> Self {
        Self([0; DISK_SECTOR_SIZE])
    }
}

impl AlignedSectorSize {
    fn slice_mut_to_repr(slice: &mut [Self]) -> &mut [[u8; DISK_SECTOR_SIZE]] {
        // SAFETY: `AlignedSectorSize` is `#[repr(C)]` and its alignment is larger than inner value
        unsafe { mem::transmute(slice) }
    }
}

/// Wrapper data structure for direct/unbuffered I/O
#[derive(Debug)]
pub struct DirectIoFile {
    file: File,
    /// Scratch buffer of aligned memory for reads and writes
    scratch_buffer: Mutex<Vec<AlignedSectorSize>>,
}

impl ReadAtSync for DirectIoFile {
    #[inline]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.read_exact_at(buf, offset)
    }
}

impl ReadAtSync for &DirectIoFile {
    #[inline]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (*self).read_at(buf, offset)
    }
}

impl FileExt for DirectIoFile {
    fn size(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn preallocate(&self, len: u64) -> io::Result<()> {
        self.file.preallocate(len)
    }

    fn advise_random_access(&self) -> io::Result<()> {
        // Ignore, already set
        Ok(())
    }

    fn advise_sequential_access(&self) -> io::Result<()> {
        // Ignore, not supported
        Ok(())
    }

    fn disable_cache(&self) -> io::Result<()> {
        // Ignore, not supported
        Ok(())
    }

    fn read_exact_at(&self, buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut scratch_buffer = self.scratch_buffer.lock();

        // First read up to `MAX_READ_SIZE - padding`
        let padding = (offset % DISK_SECTOR_SIZE as u64) as usize;
        let first_unaligned_chunk_size = (MAX_READ_SIZE - padding).min(buf.len());
        let (unaligned_start, buf) = buf.split_at_mut(first_unaligned_chunk_size);
        {
            let bytes_to_read = unaligned_start.len();
            unaligned_start.copy_from_slice(self.read_exact_at_internal(
                &mut scratch_buffer,
                bytes_to_read,
                offset,
            )?);
            offset += unaligned_start.len() as u64;
        }

        if buf.is_empty() {
            return Ok(());
        }

        // Process the rest of the chunks, up to `MAX_READ_SIZE` at a time
        for buf in buf.chunks_mut(MAX_READ_SIZE) {
            let bytes_to_read = buf.len();
            buf.copy_from_slice(self.read_exact_at_internal(
                &mut scratch_buffer,
                bytes_to_read,
                offset,
            )?);
            offset += buf.len() as u64;
        }

        Ok(())
    }

    fn write_all_at(&self, buf: &[u8], mut offset: u64) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut scratch_buffer = self.scratch_buffer.lock();

        // First write up to `MAX_READ_SIZE - padding`
        let padding = (offset % DISK_SECTOR_SIZE as u64) as usize;
        let first_unaligned_chunk_size = (MAX_READ_SIZE - padding).min(buf.len());
        let (unaligned_start, buf) = buf.split_at(first_unaligned_chunk_size);
        {
            self.write_all_at_internal(&mut scratch_buffer, unaligned_start, offset)?;
            offset += unaligned_start.len() as u64;
        }

        if buf.is_empty() {
            return Ok(());
        }

        // Process the rest of the chunks, up to `MAX_READ_SIZE` at a time
        for buf in buf.chunks(MAX_READ_SIZE) {
            self.write_all_at_internal(&mut scratch_buffer, buf, offset)?;
            offset += buf.len() as u64;
        }

        Ok(())
    }
}

impl DirectIoFile {
    /// Open file at specified path for direct/unbuffered I/O for reads (if file doesn't exist, it
    /// will be created).
    ///
    /// This is especially important on Windows to prevent huge memory usage.
    pub fn open<P>(path: P) -> io::Result<Self>
    where
        P: AsRef<Path>,
    {
        let mut open_options = OpenOptions::new();
        open_options.use_direct_io();
        let file = open_options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        file.disable_cache()?;

        Ok(Self {
            file,
            // In many cases we'll want to read this much at once, so pre-allocate it right away
            scratch_buffer: Mutex::new(vec![
                AlignedSectorSize::default();
                MAX_READ_SIZE / DISK_SECTOR_SIZE
            ]),
        })
    }

    /// Truncates or extends the underlying file, updating the size of this file to become `size`.
    pub fn set_len(&self, size: u64) -> io::Result<()> {
        self.file.set_len(size)
    }

    fn read_exact_at_internal<'a>(
        &self,
        scratch_buffer: &'a mut Vec<AlignedSectorSize>,
        bytes_to_read: usize,
        offset: u64,
    ) -> io::Result<&'a [u8]> {
        let aligned_offset = offset / DISK_SECTOR_SIZE as u64 * DISK_SECTOR_SIZE as u64;
        let padding = (offset - aligned_offset) as usize;

        // Make scratch buffer of a size that is necessary to read aligned memory, accounting
        // for extra bytes at the beginning and the end that will be thrown away
        let desired_buffer_size = (padding + bytes_to_read).div_ceil(DISK_SECTOR_SIZE);
        if scratch_buffer.len() < desired_buffer_size {
            scratch_buffer.resize_with(desired_buffer_size, AlignedSectorSize::default);
        }
        let scratch_buffer = AlignedSectorSize::slice_mut_to_repr(scratch_buffer)
            [..desired_buffer_size]
            .as_flattened_mut();

        self.file.read_exact_at(scratch_buffer, aligned_offset)?;

        Ok(&scratch_buffer[padding..][..bytes_to_read])
    }

    /// Panics on writes over `MAX_READ_SIZE` (including padding on both ends)
    fn write_all_at_internal(
        &self,
        scratch_buffer: &mut Vec<AlignedSectorSize>,
        bytes_to_write: &[u8],
        offset: u64,
    ) -> io::Result<()> {
        // This is guaranteed by constructor
        assert!(
            AlignedSectorSize::slice_mut_to_repr(scratch_buffer)
                .as_flattened()
                .len()
                <= MAX_READ_SIZE
        );

        let aligned_offset = offset / DISK_SECTOR_SIZE as u64 * DISK_SECTOR_SIZE as u64;
        let padding = (offset - aligned_offset) as usize;

        // Calculate the size of the read including padding on both ends
        let bytes_to_read =
            (padding + bytes_to_write.len()).div_ceil(DISK_SECTOR_SIZE) * DISK_SECTOR_SIZE;

        if padding == 0 && bytes_to_read == bytes_to_write.len() {
            let scratch_buffer =
                AlignedSectorSize::slice_mut_to_repr(scratch_buffer).as_flattened_mut();
            let scratch_buffer = &mut scratch_buffer[..bytes_to_read];
            scratch_buffer.copy_from_slice(bytes_to_write);
            self.file.write_all_at(scratch_buffer, offset)?;
        } else {
            // Read whole pages where `bytes_to_write` will be written
            self.read_exact_at_internal(scratch_buffer, bytes_to_read, aligned_offset)?;
            let scratch_buffer =
                AlignedSectorSize::slice_mut_to_repr(scratch_buffer).as_flattened_mut();
            let scratch_buffer = &mut scratch_buffer[..bytes_to_read];
            // Update contents of existing pages and write into the file
            scratch_buffer[padding..][..bytes_to_write.len()].copy_from_slice(bytes_to_write);
            self.file.write_all_at(scratch_buffer, aligned_offset)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::single_disk_farm::direct_io_file::{DirectIoFile, MAX_READ_SIZE};
    use rand::prelude::*;
    use std::fs;
    use subspace_farmer_components::file_ext::FileExt;
    use tempfile::tempdir;

    #[test]
    fn basic() {
        let tempdir = tempdir().unwrap();
        let file_path = tempdir.as_ref().join("file.bin");
        let mut data = vec![0u8; MAX_READ_SIZE * 5];
        thread_rng().fill(data.as_mut_slice());
        fs::write(&file_path, &data).unwrap();

        let file = DirectIoFile::open(&file_path).unwrap();

        let mut buffer = Vec::new();
        for (offset, size) in [
            (0_usize, 512_usize),
            (0_usize, 4096_usize),
            (0, 500),
            (0, 4000),
            (5, 50),
            (12, 500),
            (96, 4000),
            (4000, 96),
            (10000, 5),
            (0, MAX_READ_SIZE),
            (0, MAX_READ_SIZE * 2),
            (5, MAX_READ_SIZE - 5),
            (5, MAX_READ_SIZE * 2 - 5),
            (5, MAX_READ_SIZE),
            (5, MAX_READ_SIZE * 2),
            (MAX_READ_SIZE, MAX_READ_SIZE),
            (MAX_READ_SIZE, MAX_READ_SIZE * 2),
            (MAX_READ_SIZE + 5, MAX_READ_SIZE - 5),
            (MAX_READ_SIZE + 5, MAX_READ_SIZE * 2 - 5),
            (MAX_READ_SIZE + 5, MAX_READ_SIZE),
            (MAX_READ_SIZE + 5, MAX_READ_SIZE * 2),
        ] {
            let data = &mut data[offset..][..size];
            buffer.resize(size, 0);
            // Read contents
            file.read_exact_at(buffer.as_mut_slice(), offset as u64)
                .unwrap_or_else(|error| panic!("Offset {offset}, size {size}: {error}"));

            // Ensure it is correct
            assert_eq!(data, buffer.as_slice(), "Offset {offset}, size {size}");

            // Update data with random contents and write
            thread_rng().fill(data);
            file.write_all_at(data, offset as u64)
                .unwrap_or_else(|error| panic!("Offset {offset}, size {size}: {error}"));

            // Read contents again
            file.read_exact_at(buffer.as_mut_slice(), offset as u64)
                .unwrap_or_else(|error| panic!("Offset {offset}, size {size}: {error}"));

            // Ensure it is correct too
            assert_eq!(data, buffer.as_slice(), "Offset {offset}, size {size}");
        }
    }
}
