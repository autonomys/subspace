use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use subspace_farmer_components::file_ext::{FileExt, OpenOptionsExt};
use subspace_farmer_components::ReadAtSync;

/// 4096 is as a relatively safe size due to sector size on SSDs commonly being 512 or 4096 bytes
pub const DISK_SECTOR_SIZE: usize = 4096;
/// Restrict how much data to read from disk in a single call to avoid very large memory usage
const MAX_READ_SIZE: usize = 1024 * 1024;

/// Wrapper data structure for unbuffered I/O on Windows.
#[derive(Debug)]
pub struct UnbufferedIoFileWindows {
    read_file: File,
    write_file: File,
    physical_sector_size: usize,
    /// Scratch buffer of aligned memory for reads and writes
    scratch_buffer: Mutex<Vec<[u8; DISK_SECTOR_SIZE]>>,
}

impl ReadAtSync for UnbufferedIoFileWindows {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.read_exact_at(buf, offset)
    }
}

impl ReadAtSync for &UnbufferedIoFileWindows {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (*self).read_at(buf, offset)
    }
}

impl FileExt for UnbufferedIoFileWindows {
    fn size(&mut self) -> io::Result<u64> {
        self.write_file.seek(SeekFrom::End(0))
    }

    fn preallocate(&mut self, len: u64) -> io::Result<()> {
        self.write_file.preallocate(len)
    }

    fn advise_random_access(&self) -> io::Result<()> {
        // Ignore, already set
        Ok(())
    }

    fn advise_sequential_access(&self) -> io::Result<()> {
        // Ignore, not supported
        Ok(())
    }

    fn read_exact_at(&self, buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }

        let mut scratch_buffer = self.scratch_buffer.lock();

        // First read up to `MAX_READ_SIZE - padding`
        let padding = (offset % self.physical_sector_size as u64) as usize;
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

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        self.write_file.write_all_at(buf, offset)
    }
}

impl UnbufferedIoFileWindows {
    /// Open file at specified path for random unbuffered access on Windows for reads to prevent
    /// huge memory usage (if file doesn't exist, it will be created).
    ///
    /// This abstraction is useless on other platforms and will just result in extra memory copies
    pub fn open(path: &Path) -> io::Result<Self> {
        // Open file without unbuffered I/O for easier handling of writes
        let write_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .advise_random_access()
            .open(path)?;

        let mut open_options = OpenOptions::new();
        #[cfg(windows)]
        open_options.advise_unbuffered();
        let read_file = open_options.read(true).open(path)?;

        // Physical sector size on many SSDs is smaller than 4096 and should improve performance
        let physical_sector_size = if read_file.read_at(&mut [0; 512], 512).is_ok() {
            512
        } else {
            DISK_SECTOR_SIZE
        };

        Ok(Self {
            read_file,
            write_file,
            physical_sector_size,
            scratch_buffer: Mutex::default(),
        })
    }

    /// Truncates or extends the underlying file, updating the size of this file to become `size`.
    pub fn set_len(&self, size: u64) -> io::Result<()> {
        self.write_file.set_len(size)
    }

    fn read_exact_at_internal<'a>(
        &self,
        scratch_buffer: &'a mut Vec<[u8; DISK_SECTOR_SIZE]>,
        bytes_to_read: usize,
        offset: u64,
    ) -> io::Result<&'a [u8]> {
        // Make scratch buffer of a size that is necessary to read aligned memory, accounting
        // for extra bytes at the beginning and the end that will be thrown away
        let offset_in_buffer = (offset % DISK_SECTOR_SIZE as u64) as usize;
        let desired_buffer_size = (bytes_to_read + offset_in_buffer).div_ceil(DISK_SECTOR_SIZE);
        if scratch_buffer.len() < desired_buffer_size {
            scratch_buffer.resize(desired_buffer_size, [0; DISK_SECTOR_SIZE]);
        }

        // While buffer above is allocated with granularity of `MAX_DISK_SECTOR_SIZE`, reads are
        // done with granularity of physical sector size
        let offset_in_buffer = (offset % self.physical_sector_size as u64) as usize;
        self.read_file.read_exact_at(
            &mut scratch_buffer.flatten_mut()[..(bytes_to_read + offset_in_buffer)
                .div_ceil(self.physical_sector_size)
                * self.physical_sector_size],
            offset / self.physical_sector_size as u64 * self.physical_sector_size as u64,
        )?;

        Ok(&scratch_buffer.flatten()[offset_in_buffer..][..bytes_to_read])
    }
}

#[cfg(test)]
mod tests {
    use crate::single_disk_farm::unbuffered_io_file_windows::{
        UnbufferedIoFileWindows, MAX_READ_SIZE,
    };
    use rand::prelude::*;
    use std::fs;
    use subspace_farmer_components::ReadAtSync;
    use tempfile::tempdir;

    #[test]
    fn basic() {
        let tempdir = tempdir().unwrap();
        let file_path = tempdir.as_ref().join("file.bin");
        let mut data = vec![0u8; MAX_READ_SIZE * 3];
        thread_rng().fill(data.as_mut_slice());
        fs::write(&file_path, &data).unwrap();

        let mut file = UnbufferedIoFileWindows::open(&file_path).unwrap();

        for override_physical_sector_size in [None, Some(4096)] {
            if let Some(physical_sector_size) = override_physical_sector_size {
                file.physical_sector_size = physical_sector_size;
            }

            let mut buffer = Vec::new();
            for (offset, size) in [
                (0_usize, 4096_usize),
                (0, 4000),
                (5, 50),
                (5, 4091),
                (4091, 5),
                (10000, 5),
                (5, MAX_READ_SIZE * 2),
            ] {
                buffer.resize(size, 0);
                file.read_at(buffer.as_mut_slice(), offset as u64)
                    .unwrap_or_else(|error| {
                        panic!(
                            "Offset {offset}, size {size}, override physical sector size \
                            {override_physical_sector_size:?}: {error}"
                        )
                    });

                assert_eq!(
                    &data[offset..][..size],
                    buffer.as_slice(),
                    "Offset {offset}, size {size}, override physical sector size \
                    {override_physical_sector_size:?}"
                );
            }
        }
    }
}
