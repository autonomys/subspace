use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::{io, mem};
#[cfg(windows)]
use subspace_farmer_components::file_ext::OpenOptionsExt;
use subspace_farmer_components::ReadAtSync;

/// 4096 is as a relatively safe size due to sector size on SSDs commonly being 512 or 4096 bytes
pub const DISK_SECTOR_SIZE: usize = 4096;
/// Restrict how much data to read from disk in a single call to avoid very large memory usage
const MAX_READ_SIZE: usize = 1024 * 1024;

/// Wrapper data structure for unbuffered I/O on Windows.
// TODO: Implement `FileExt` and use for all reads on Windows
pub struct UnbufferedIoFileWindows {
    file: File,
    /// Scratch buffer of aligned memory for reads and writes
    buffer: Mutex<Vec<[u8; DISK_SECTOR_SIZE]>>,
}

impl ReadAtSync for UnbufferedIoFileWindows {
    fn read_at(&self, buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        let mut buffer = self.buffer.lock();

        // Read from disk in at most 1M chunks to avoid too high memory usage, account for offset
        // that would cause extra bytes to be read from disk
        for buf in buf.chunks_mut(MAX_READ_SIZE - (offset % mem::size_of::<u8>() as u64) as usize) {
            // Make scratch buffer of a size that is necessary to read aligned memory, accounting
            // for extra bytes at the beginning and the end that will be thrown away
            let bytes_to_read = buf.len();
            let offset_in_buffer = (offset % DISK_SECTOR_SIZE as u64) as usize;
            let desired_buffer_size = (bytes_to_read + offset_in_buffer).div_ceil(DISK_SECTOR_SIZE);
            if buffer.len() < desired_buffer_size {
                buffer.resize(desired_buffer_size, [0; DISK_SECTOR_SIZE]);
            }

            self.file.read_at(
                buffer[..desired_buffer_size].flatten_mut(),
                offset / DISK_SECTOR_SIZE as u64 * DISK_SECTOR_SIZE as u64,
            )?;

            buf.copy_from_slice(&buffer.flatten()[offset_in_buffer..][..bytes_to_read]);

            offset += buf.len() as u64;
        }

        Ok(())
    }
}

impl ReadAtSync for &UnbufferedIoFileWindows {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (*self).read_at(buf, offset)
    }
}

impl UnbufferedIoFileWindows {
    /// Open file at specified path for random unbuffered access on Windows.
    ///
    /// This abstraction is useless on other platforms and will just result in extra memory copies
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut open_options = OpenOptions::new();
        #[cfg(windows)]
        open_options.advise_unbuffered();
        let file = open_options.read(true).open(path)?;

        Ok(Self {
            file,
            buffer: Mutex::default(),
        })
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

        let file = UnbufferedIoFileWindows::open(&file_path).unwrap();

        let mut buffer = Vec::new();
        for (offset, size) in [
            (0_usize, 4096_usize),
            (0, 4000),
            (5, 50),
            (5, 4091),
            (5, MAX_READ_SIZE * 2),
        ] {
            buffer.resize(size, 0);
            file.read_at(buffer.as_mut_slice(), offset as u64)
                .unwrap_or_else(|error| panic!("Offset {offset}, size {size}: {error}"));
            assert_eq!(
                &data[offset..][..size],
                buffer.as_slice(),
                "Offset {offset}, size {size}"
            );
        }
    }
}
