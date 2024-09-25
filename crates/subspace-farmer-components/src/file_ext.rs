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

    /// Use Direct I/O on Linux and disable buffering on Windows.
    ///
    /// NOTE: There are major alignment requirements described here:
    /// https://learn.microsoft.com/en-us/windows/win32/fileio/file-buffering#alignment-and-file-access-requirements
    /// https://man7.org/linux/man-pages/man2/open.2.html
    fn use_direct_io(&mut self) -> &mut Self;
}

impl OpenOptionsExt for OpenOptions {
    #[cfg(not(windows))]
    fn advise_random_access(&mut self) -> &mut Self {
        // Not supported
        self
    }

    #[cfg(windows)]
    fn advise_random_access(&mut self) -> &mut Self {
        use std::os::windows::fs::OpenOptionsExt;
        // `FILE_FLAG_WRITE_THROUGH` below is a bit of a hack, especially in `advise_random_access`,
        // but it helps with memory usage and feels like should be default. Since `.custom_flags()`
        // overrides previous value, we need to set bitwise OR of two flags rather that two flags
        // separately.
        self.custom_flags(
            winapi::um::winbase::FILE_FLAG_RANDOM_ACCESS
                | winapi::um::winbase::FILE_FLAG_WRITE_THROUGH,
        )
    }

    #[cfg(not(windows))]
    fn advise_sequential_access(&mut self) -> &mut Self {
        // Not supported
        self
    }

    #[cfg(windows)]
    fn advise_sequential_access(&mut self) -> &mut Self {
        use std::os::windows::fs::OpenOptionsExt;
        self.custom_flags(winapi::um::winbase::FILE_FLAG_SEQUENTIAL_SCAN)
    }

    #[cfg(windows)]
    fn use_direct_io(&mut self) -> &mut Self {
        use std::os::windows::fs::OpenOptionsExt;
        self.custom_flags(
            winapi::um::winbase::FILE_FLAG_WRITE_THROUGH
                | winapi::um::winbase::FILE_FLAG_NO_BUFFERING,
        )
    }

    #[cfg(target_os = "linux")]
    fn use_direct_io(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(libc::O_DIRECT)
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    fn use_direct_io(&mut self) -> &mut Self {
        // Not supported
        self
    }
}

/// Extension convenience trait that allows pre-allocating files, suggesting random access pattern
/// and doing cross-platform exact reads/writes
pub trait FileExt {
    /// Get file size
    fn size(&self) -> Result<u64>;

    /// Make sure file has specified number of bytes allocated for it
    fn preallocate(&self, len: u64) -> Result<()>;

    /// Advise OS/file system that file will use random access and read-ahead behavior is
    /// undesirable, on Windows this can only be set when file is opened, see [`OpenOptionsExt`]
    fn advise_random_access(&self) -> Result<()>;

    /// Advise OS/file system that file will use sequential access and read-ahead behavior is
    /// desirable, on Windows this can only be set when file is opened, see [`OpenOptionsExt`]
    fn advise_sequential_access(&self) -> Result<()>;

    /// Disable cache on macOS
    fn disable_cache(&self) -> Result<()>;

    /// Read exact number of bytes at a specific offset
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()>;

    /// Write all provided bytes at a specific offset
    fn write_all_at(&self, buf: &[u8], offset: u64) -> Result<()>;
}

impl FileExt for File {
    fn size(&self) -> Result<u64> {
        Ok(self.metadata()?.len())
    }

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

    #[cfg(not(target_os = "macos"))]
    fn disable_cache(&self) -> Result<()> {
        // Not supported
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn disable_cache(&self) -> Result<()> {
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::fcntl(self.as_raw_fd(), libc::F_NOCACHE, 1) } != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
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
