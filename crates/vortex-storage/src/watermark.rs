use std::path::Path;
use vortex_core::{error::Result, VortexError};

pub const WATERMARK_SOFT_WARN_PERCENT: u8 = 85;
pub const WATERMARK_INGRESS_SHED_PERCENT: u8 = 92;
pub const WATERMARK_FREEZE_PERCENT: u8 = 97;

/// Returns the current filesystem disk usage percentage (0..100) for the volume hosting `path`.
pub fn get_disk_usage_percent(path: &Path) -> Result<u8> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;
        use std::os::unix::ffi::OsStrExt;

        let path_to_probe = if path.exists() {
            path.to_path_buf()
        } else if let Some(parent) = path.parent() {
            parent.to_path_buf()
        } else {
            Path::new(".").to_path_buf()
        };

        let c_path = CString::new(path_to_probe.as_os_str().as_bytes())
            .map_err(|e| VortexError::Io(format!("Invalid path for statvfs: {}", e)))?;

        let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
        let res = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
        if res != 0 {
            return Err(VortexError::Io(format!(
                "statvfs failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let stat = unsafe { stat.assume_init() };
        if stat.f_blocks == 0 {
            return Ok(0);
        }

        let total_blocks = stat.f_blocks as f64;
        let free_blocks = stat.f_bavail as f64;
        let used_blocks = total_blocks - free_blocks;
        let usage = ((used_blocks / total_blocks) * 100.0).clamp(0.0, 100.0) as u8;
        Ok(usage)
    }

    #[cfg(not(unix))]
    {
        Ok(0)
    }
}

/// Validates that filesystem disk usage has not exceeded the proactive ingress shedding threshold (92%).
/// Throws `VortexError::DiskQuasiFull` if usage is >= 92%, protecting active segments from corrupt torn writes.
pub fn check_ingress_watermark(path: &Path) -> Result<u8> {
    let usage = get_disk_usage_percent(path)?;
    if usage >= WATERMARK_INGRESS_SHED_PERCENT {
        return Err(VortexError::DiskQuasiFull {
            usage_percent: usage,
            threshold: WATERMARK_INGRESS_SHED_PERCENT,
        });
    }
    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_usage_probe() {
        let usage = get_disk_usage_percent(Path::new(".")).unwrap();
        assert!(usage <= 100);
    }
}
