//! File extension trait

use std::fs::File;
use std::io::Result;

/// Extension convenience trait that allows pre-allocating files, suggesting random access pattern
/// and doing cross-platform exact reads/writes
pub trait FileExt {
    /// Make sure file has specified number of bytes allocated for it
    fn preallocate(&self, len: u64) -> Result<()>;

    /// Advise OS/file system that file will use random access and read-ahead behavior is
    /// undesirable
    fn advise_random_access(&self) -> Result<()>;

    /// Read exact number of bytes at a specific offset
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()>;

    /// Write all provided bytes at a specific offset
    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()>;
}

impl FileExt for File {
    fn preallocate(&self, len: u64) -> Result<()> {
        fs2::FileExt::allocate(self, len)
    }

    #[cfg(target_os = "linux")]
    fn advise_random_access(&self) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        let err = unsafe { libc::posix_fadvise(self.as_raw_fd(), 0, 0, libc::POSIX_FADV_RANDOM) };
        if err != 0 {
            Err(std::io::Error::from_raw_os_error(err))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    fn advise_random_access(&self) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::fcntl(self.as_raw_fd(), libc::F_RDAHEAD, 0) } != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn advise_random_access(&self) -> Result<()> {
        // Not supported
        Ok(())
    }

    #[cfg(unix)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }

    #[cfg(unix)]
    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()> {
        std::os::unix::fs::FileExt::write_all_at(self, buf, offset)
    }

    #[cfg(windows)]
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> Result<()> {
        while !buf.is_empty() {
            match std::os::windows::fs::FileExt::seek_read(self, buf, offset) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    // Try again
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        if !buf.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn write_all_at(&self, mut buf: &[u8], mut offset: u64) -> Result<()> {
        while !buf.is_empty() {
            match std::os::windows::fs::FileExt::seek_write(self, buf, offset) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                }
                Ok(n) => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    // Try again
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}
