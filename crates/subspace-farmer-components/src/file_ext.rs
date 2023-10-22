//! File extension trait

use std::fs::{File, OpenOptions};
use std::io::Result;

/// Extension convenience trait that allows setting some file opening options in cross-platform way
pub trait OpenOptionsExt {
    /// Advise OS/file system that file will use random access and read-ahead behavior is
    /// undesirable, only has impact on Windows, for other operating systems see [`FileExt`]
    fn advise_random_access(&mut self) -> &mut Self;

    /// Advise OS/file system that file will use sequential access and read-ahead behavior is
    /// desirable, only has impact on Windows, for other operating systems see [`FileExt`]
    fn advise_sequential_access(&mut self) -> &mut Self;
}

impl OpenOptionsExt for OpenOptions {
    #[cfg(target_os = "linux")]
    fn advise_random_access(&mut self) -> &mut Self {
        // Not supported
        self
    }

    #[cfg(target_os = "macos")]
    fn advise_random_access(&mut self) -> &mut Self {
        // Not supported
        self
    }

    #[cfg(windows)]
    fn advise_random_access(&mut self) -> &mut Self {
        use std::os::windows::fs::OpenOptionsExt;
        self.custom_flags(winapi::um::winbase::FILE_FLAG_RANDOM_ACCESS)
    }

    #[cfg(target_os = "linux")]
    fn advise_sequential_access(&mut self) -> &mut Self {
        // Not supported
        self
    }

    #[cfg(target_os = "macos")]
    fn advise_sequential_access(&mut self) -> &mut Self {
        // Not supported
        self
    }

    #[cfg(windows)]
    fn advise_sequential_access(&mut self) -> &mut Self {
        use std::os::windows::fs::OpenOptionsExt;
        self.custom_flags(winapi::um::winbase::FILE_FLAG_SEQUENTIAL_SCAN)
    }
}

/// Extension convenience trait that allows pre-allocating files, suggesting random access pattern
/// and doing cross-platform exact reads/writes
pub trait FileExt {
    /// Make sure file has specified number of bytes allocated for it
    fn preallocate(&self, len: u64) -> Result<()>;

    /// Advise OS/file system that file will use random access and read-ahead behavior is
    /// undesirable, on Windows this can only be set when file is opened, see [`OpenOptionsExt`]
    fn advise_random_access(&self) -> Result<()>;

    /// Advise OS/file system that file will use sequential access and read-ahead behavior is
    /// desirable, on Windows this can only be set when file is opened, see [`OpenOptionsExt`]
    fn advise_sequential_access(&self) -> Result<()>;

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

    #[cfg(windows)]
    fn advise_random_access(&self) -> Result<()> {
        // Not supported
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn advise_sequential_access(&self) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        let err =
            unsafe { libc::posix_fadvise(self.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
        if err != 0 {
            Err(std::io::Error::from_raw_os_error(err))
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    fn advise_sequential_access(&self) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::fcntl(self.as_raw_fd(), libc::F_RDAHEAD, 1) } != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn advise_sequential_access(&self) -> Result<()> {
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
