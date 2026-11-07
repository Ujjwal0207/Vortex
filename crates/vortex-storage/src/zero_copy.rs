use vortex_core::error::{Result, VortexError};
#[cfg(unix)]
use std::os::unix::io::RawFd;

pub struct ZeroCopySplicer;

impl ZeroCopySplicer {
    /// Transfers `len` bytes from `file` starting at `offset` directly to `out_fd`
    /// via direct kernel page-cache splicing (`sendfile(2)`), bypassing userspace heap memory buffers.
    #[cfg(unix)]
    pub fn splice_file_to_fd(
        file: &std::fs::File,
        out_fd: RawFd,
        offset: u64,
        len: u64,
    ) -> Result<u64> {
        use std::os::unix::io::AsRawFd;
        sendfile_all(file.as_raw_fd(), out_fd, offset, len)
    }

    #[cfg(not(unix))]
    pub fn splice_file_to_fd(
        _file: &std::fs::File,
        _out_fd: i32,
        _offset: u64,
        _len: u64,
    ) -> Result<u64> {
        Err(VortexError::Io("zero-copy sendfile is only supported on Unix targets".into()))
    }
}

#[cfg(target_os = "macos")]
fn sendfile_all(in_fd: RawFd, out_fd: RawFd, offset: u64, len: u64) -> Result<u64> {
    let mut written: u64 = 0;
    while written < len {
        let chunk_offset = (offset + written) as libc::off_t;
        let mut chunk_len = (len - written) as libc::off_t;
        let ret = unsafe {
            libc::sendfile(
                in_fd,
                out_fd,
                chunk_offset,
                &mut chunk_len,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                written += chunk_len as u64;
                continue;
            }
            if err.raw_os_error() == Some(libc::EAGAIN) {
                written += chunk_len as u64;
                if chunk_len == 0 {
                    std::thread::yield_now();
                }
                continue;
            }
            return Err(VortexError::Io(format!("macOS sendfile failed: {err}")));
        }
        written += chunk_len as u64;
        if chunk_len == 0 {
            break;
        }
    }
    Ok(written)
}

#[cfg(target_os = "linux")]
fn sendfile_all(in_fd: RawFd, out_fd: RawFd, offset: u64, len: u64) -> Result<u64> {
    let mut written: u64 = 0;
    let mut curr_offset = offset as libc::off_t;
    while written < len {
        let count = (len - written) as usize;
        let res = unsafe {
            libc::sendfile(
                out_fd,
                in_fd,
                &mut curr_offset,
                count,
            )
        };
        if res < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if err.raw_os_error() == Some(libc::EAGAIN) {
                std::thread::yield_now();
                continue;
            }
            return Err(VortexError::Io(format!("Linux sendfile failed: {err}")));
        }
        if res == 0 {
            break;
        }
        written += res as u64;
    }
    Ok(written)
}
