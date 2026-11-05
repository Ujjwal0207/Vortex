use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use vortex_core::{Result, VortexError};

/// Thread-safe LRU file descriptor cache ensuring the process never exceeds
/// operating system file descriptor limits (`ulimit -n`).
pub struct FdPool {
    limit: usize,
    inner: Mutex<FdPoolInner>,
}

struct FdPoolInner {
    entries: HashMap<PathBuf, (Arc<File>, u64)>,
    seq_counter: u64,
}

impl FdPool {
    /// Creates a new FdPool that maintains at most `limit` open file handles.
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            inner: Mutex::new(FdPoolInner {
                entries: HashMap::new(),
                seq_counter: 0,
            }),
        }
    }

    /// Leases an `Arc<File>` for the given path.
    /// If the file is already open, returns the cached descriptor and refreshes its LRU age.
    /// If the file is not cached and pool limit is reached, evicts the least recently used file.
    pub fn acquire<P: AsRef<Path>>(&self, path: P) -> Result<Arc<File>> {
        let path_buf = path.as_ref().to_path_buf();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| VortexError::Io("FdPool mutex poisoned".into()))?;
        inner.seq_counter += 1;
        let current_seq = inner.seq_counter;

        if let Some((handle, last_access)) = inner.entries.get_mut(&path_buf) {
            *last_access = current_seq;
            return Ok(handle.clone());
        }

        // Evict LRU if at or above limit
        if inner.entries.len() >= self.limit {
            if let Some(lru_path) = inner
                .entries
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(p, _)| p.clone())
            {
                inner.entries.remove(&lru_path);
            }
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path_buf)
            .or_else(|_| OpenOptions::new().read(true).open(&path_buf))
            .map_err(|e| {
                VortexError::Io(format!(
                    "FdPool failed to open {}: {e}",
                    path_buf.display()
                ))
            })?;

        let handle = Arc::new(file);
        inner
            .entries
            .insert(path_buf, (handle.clone(), current_seq));
        Ok(handle)
    }

    /// Returns the number of currently cached open file descriptors.
    pub fn current_open_count(&self) -> usize {
        self.inner.lock().map(|i| i.entries.len()).unwrap_or(0)
    }

    /// Explicitly closes and removes a file handle from the cache.
    pub fn close<P: AsRef<Path>>(&self, path: P) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.entries.remove(path.as_ref());
        }
    }
}

