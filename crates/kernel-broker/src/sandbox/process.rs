//! The child's process setup: close-on-exec descriptors, the resource caps
//! and the process-count headroom.

use super::limits::{MAX_COMMAND_MEMORY_BYTES, MAX_OPEN_FILES};

/// Mark every open descriptor >= 3 close-on-exec, except `keep_fd` (the
/// read-only per-call marker).
///
/// `closefrom(3)` is deliberately not used: it would also close the
/// error-reporting pipe Rust's process spawner holds across `exec`, breaking
/// exec-failure reporting. `PROC_PIDLISTFDS` lists exactly the fds this
/// process has; if that fails, sweep a bounded range instead.
#[cfg(unix)]
pub(super) fn mark_inherited_fds_close_on_exec(keep_fd: i32) {
    #[cfg(target_os = "macos")]
    {
        const PROC_PIDLISTFDS: libc::c_int = 1;
        let mut buf = [0u8; 4096 * 8];
        let n = unsafe {
            libc::proc_pidinfo(
                std::process::id() as libc::c_int,
                PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr().cast(),
                buf.len() as libc::c_int,
            )
        };
        if n > 0 {
            for entry in buf[..n as usize].as_chunks::<8>().0 {
                let fd = i32::from_ne_bytes([entry[0], entry[1], entry[2], entry[3]]);
                if fd < 3 {
                    continue;
                }
                if fd == keep_fd {
                    // The marker is created with `O_CLOEXEC` like every Rust
                    // file; clear it so the marker survives exec.
                    set_close_on_exec(fd, false);
                } else {
                    set_close_on_exec(fd, true);
                }
            }
            return;
        }
    }
    // Fallback (non-macOS or a failed proc_pidinfo): sweep the inherited
    // soft limit, capped so a huge limit cannot stall the spawn.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let max = unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            limit.rlim_cur.min(65_536) as i32
        } else {
            1024
        }
    };
    for fd in 3..max {
        set_close_on_exec(fd, fd != keep_fd);
    }
}

#[cfg(unix)]
fn set_close_on_exec(fd: i32, close: bool) {
    let flags = if close { libc::FD_CLOEXEC } else { 0 };
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, flags);
    }
}

/// Best-effort resource caps for the command (and everything it forks).
///
/// `RLIMIT_NPROC` is a per-user total on macOS, so when `max_processes` is
/// non-zero it is set to the current user process count plus that headroom:
/// the command can still spawn its normal toolset, but cannot fork-bomb the
/// whole user session. `0` leaves it unset (the shell tool's own process
/// watchdog covers that path).
#[cfg(unix)]
pub(super) fn set_child_limits(cpu_seconds: u64, max_file_bytes: u64, max_processes: u64) {
    let limit = |value: u64| libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CPU, &limit(cpu_seconds));
        libc::setrlimit(libc::RLIMIT_FSIZE, &limit(max_file_bytes));
        libc::setrlimit(libc::RLIMIT_NOFILE, &limit(MAX_OPEN_FILES));
        if max_processes > 0 {
            let nproc = user_process_count().saturating_add(max_processes);
            if nproc > 0 {
                libc::setrlimit(libc::RLIMIT_NPROC, &limit(nproc));
            }
        }
        // Best effort: Linux enforces the address-space cap, macOS rejects it
        // (EINVAL) and may accept DATA.
        libc::setrlimit(libc::RLIMIT_AS, &limit(MAX_COMMAND_MEMORY_BYTES));
        libc::setrlimit(libc::RLIMIT_DATA, &limit(MAX_COMMAND_MEMORY_BYTES));
    }
}

/// Number of live processes owned by this user (RLIMIT_NPROC headroom).
#[cfg(target_os = "macos")]
fn user_process_count() -> u64 {
    const PROC_ALL_PIDS: u32 = 1;
    let mut capacity = 1024usize;
    for _ in 0..4 {
        let mut buf = vec![0i32; capacity];
        let n = unsafe {
            libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                buf.as_mut_ptr().cast(),
                (buf.len() * std::mem::size_of::<i32>()) as i32,
            )
        };
        if n <= 0 {
            return 0;
        }
        let count = n as usize / std::mem::size_of::<i32>();
        if count < capacity {
            buf.truncate(count);
            let euid = unsafe { libc::geteuid() };
            return buf
                .into_iter()
                .filter(|pid| {
                    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
                    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
                    let n = unsafe {
                        libc::proc_pidinfo(
                            *pid,
                            libc::PROC_PIDTBSDINFO,
                            0,
                            info.as_mut_ptr().cast(),
                            size,
                        )
                    };
                    n == size && unsafe { info.assume_init() }.pbi_uid == euid
                })
                .count() as u64;
        }
        capacity = capacity.saturating_mul(2);
    }
    0
}

#[cfg(target_os = "linux")]
fn user_process_count() -> u64 {
    use std::os::unix::fs::MetadataExt;
    let euid = unsafe { libc::geteuid() };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.chars().all(|ch| ch.is_ascii_digit()))
        })
        .filter(|entry| {
            std::fs::metadata(entry.path())
                .map(|metadata| metadata.uid() == euid)
                .unwrap_or(false)
        })
        .count() as u64
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn user_process_count() -> u64 {
    0
}
