use std::time::Duration;
use tracing::{info, warn};

/// Returns the current process RSS (Resident Set Size) in MiB, or `None` if unavailable.
pub(crate) fn process_rss_mib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // /proc/self/statm fields: size resident shared text lib data dt (all in pages)
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return None;
        }
        Some(resident_pages * page_size as u64 / 1024 / 1024)
    }

    #[cfg(target_os = "macos")]
    {
        // getrusage returns ru_maxrss in bytes on macOS
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        if ret == 0 {
            Some(usage.ru_maxrss as u64 / 1024 / 1024)
        } else {
            None
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::mem;

        #[repr(C)]
        #[allow(non_snake_case)]
        struct ProcessMemoryCounters {
            cb: u32,
            PageFaultCount: u32,
            PeakWorkingSetSize: usize,
            WorkingSetSize: usize,
            QuotaPeakPagedPoolUsage: usize,
            QuotaPagedPoolUsage: usize,
            QuotaPeakNonPagedPoolUsage: usize,
            QuotaNonPagedPoolUsage: usize,
            PagefileUsage: usize,
            PeakPagefileUsage: usize,
        }

        extern "system" {
            fn K32GetProcessMemoryInfo(
                process: *mut std::ffi::c_void,
                pmc: *mut ProcessMemoryCounters,
                cb: u32,
            ) -> i32;
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
        }

        unsafe {
            let mut pmc: ProcessMemoryCounters = mem::zeroed();
            pmc.cb = mem::size_of::<ProcessMemoryCounters>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
                Some(pmc.WorkingSetSize as u64 / 1024 / 1024)
            } else {
                None
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Returns the total system memory in MiB, or `None` if unavailable.
pub(crate) fn total_system_memory_mib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb: u64 = rest.trim().strip_suffix("kB")?.trim().parse().ok()?;
                return Some(kb / 1024);
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let total = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if total <= 0 || page_size <= 0 {
            return None;
        }
        Some(total as u64 * page_size as u64 / 1024 / 1024)
    }

    #[cfg(target_os = "windows")]
    {
        use std::mem;

        #[repr(C)]
        #[allow(non_snake_case)]
        struct MemoryStatusEx {
            dwLength: u32,
            dwMemoryLoad: u32,
            ullTotalPhys: u64,
            ullAvailPhys: u64,
            ullTotalPageFile: u64,
            ullAvailPageFile: u64,
            ullTotalVirtual: u64,
            ullAvailVirtual: u64,
            ullAvailExtendedVirtual: u64,
        }

        extern "system" {
            fn GlobalMemoryStatusEx(lpBuffer: *mut MemoryStatusEx) -> i32;
        }

        unsafe {
            let mut status: MemoryStatusEx = mem::zeroed();
            status.dwLength = mem::size_of::<MemoryStatusEx>() as u32;
            if GlobalMemoryStatusEx(&mut status) != 0 {
                Some(status.ullTotalPhys / 1024 / 1024)
            } else {
                None
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Spawns a background task that logs process RSS every `interval`.
pub(crate) fn spawn_rss_monitor(interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match process_rss_mib() {
                Some(rss) => {
                    info!(rss_mib = rss, "Process memory usage");
                }
                None => {
                    warn!("Unable to read process memory usage");
                    break;
                }
            }
        }
    });
}
