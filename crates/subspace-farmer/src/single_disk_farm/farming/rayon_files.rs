use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use subspace_farmer_components::file_ext::{FileExt, OpenOptionsExt};
use subspace_farmer_components::ReadAtSync;

/// Wrapper data structure for multiple files to be used with [`rayon`] thread pool, where the same
/// file is opened multiple times, once for each thread.
pub struct RayonFiles {
    files: Vec<File>,
}

impl ReadAtSync for RayonFiles {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let thread_index = rayon::current_thread_index().unwrap_or_default();
        let file = self.files.get(thread_index).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "No files entry for this rayon thread")
        })?;

        file.read_at(buf, offset)
    }
}

impl ReadAtSync for &RayonFiles {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (*self).read_at(buf, offset)
    }
}

impl RayonFiles {
    /// Open file at specified as many times as there is number of threads in current [`rayon`]
    /// thread pool.
    pub fn open(path: &Path) -> io::Result<Self> {
        let files = (0..rayon::current_num_threads())
            .map(|_| {
                let file = OpenOptions::new()
                    .read(true)
                    .advise_random_access()
                    .open(path)?;
                file.advise_random_access()?;

                Ok::<_, io::Error>(file)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { files })
    }
}
