//! Unit-aligned decrypted reads with a small LRU cache.
//!
//! libbluray (inside HandBrake) reads streams in 6144-byte aligned units,
//! while the NFS client asks in ~128 KiB chunks that do not line up with unit
//! boundaries. This module turns an arbitrary `(offset, len)` request into
//! whole-unit reads from the encrypted source file, decrypts each unit once
//! through libmmbd, and keeps recently decrypted units around so overlapping
//! and repeated requests (HandBrake's title scan re-reads a lot) are cheap.

use std::collections::HashMap;
use std::fs::File;
use std::num::NonZeroUsize;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use lru::LruCache;
use tracing::{debug, warn};

use crate::disc::{Node, NodeId, NodeKind};
use crate::mmbd::{self, Mmbd, UNIT_SIZE};
use crate::rawudf::RawUdf;

type UnitKey = (u32, u64);
type UnitBuf = Arc<[u8; UNIT_SIZE]>;

/// Counters exposed by `bdmount status`/logs.
#[derive(Default)]
pub struct Stats {
    pub units_decrypted: AtomicU64,
    pub units_cached: AtomicU64,
    pub bytes_served: AtomicU64,
    pub decrypt_errors: AtomicU64,
}

/// Units read from the disc per cache miss when the caller is streaming
/// sequentially. Optical drives are fast for large sequential reads and
/// terrible for many small ones, so we read well ahead of the NFS client's
/// ~124 KiB requests and let the unit cache absorb the rest.
const SEQUENTIAL_WINDOW_UNITS: u64 = (crate::rawudf::PREFETCH_WINDOW as u64) / UNIT_SIZE as u64;
/// Units read per cache miss for random access (HandBrake's title scan pokes
/// at the start of every clip; do not drag 4 MiB off the disc for each).
const RANDOM_WINDOW_UNITS: u64 = (384 * 1024) / UNIT_SIZE as u64;
/// A request starting within this distance of where the previous one on the
/// same file ended counts as sequential (NFS readahead reorders slightly).
const SEQUENTIAL_SLACK: u64 = 8 * 1024 * 1024;

pub struct DecryptEngine {
    /// `None` after [`DecryptEngine::shutdown`]. Also serves as the lock
    /// that serializes disc I/O: one optical drive, one reader.
    mmbd: Mutex<Option<Mmbd>>,
    cache: Mutex<LruCache<UnitKey, UnitBuf>>,
    /// Byte offset where the previous read on each file ended.
    last_end: Mutex<HashMap<NodeId, u64>>,
    shutting_down: AtomicBool,
    /// When set, encrypted/passthrough bytes come from raw UDF, not `/Volumes`.
    udf: Option<Arc<Mutex<RawUdf>>>,
    pub stats: Stats,
}

// Note: we deliberately do NOT keep the encrypted source files open between
// reads. An open descriptor on the optical volume makes macOS refuse to
// unmount it when the user presses Eject ("one or more programs may be using
// it"), and a process blocked on such a volume mid-eject can wedge the whole
// optical stack. Opening the file per window read costs microseconds.

impl DecryptEngine {
    /// Wrap an already-open libmmbd context. `cache_bytes` bounds the LRU.
    pub fn new(mmbd: Mmbd, cache_bytes: usize) -> DecryptEngine {
        let units = (cache_bytes / UNIT_SIZE).max(64);
        DecryptEngine {
            mmbd: Mutex::new(Some(mmbd)),
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(units).unwrap())),
            last_end: Mutex::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
            udf: None,
            stats: Stats::default(),
        }
    }

    pub fn new_with_udf(mmbd: Mmbd, cache_bytes: usize, udf: Arc<Mutex<RawUdf>>) -> DecryptEngine {
        let mut e = Self::new(mmbd, cache_bytes);
        e.udf = Some(udf);
        e
    }

    fn read_source(&self, node: &Node, offset: u64, count: usize) -> Result<Vec<u8>> {
        if let Some(u) = &self.udf {
            let rel = node.path.to_string_lossy();
            return u.lock().unwrap().read_at(&rel, offset, count);
        }
        read_plain(&node.path, offset, count)
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// Close the disc and terminate the background `makemkvcon` now, rather
    /// than whenever the last `Arc` happens to drop. Subsequent reads of
    /// encrypted files fail. Blocks until any in-flight disc read finishes.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        if let Some(mut m) = self.mmbd.lock().unwrap().take() {
            m.close();
            drop(m);
            debug!("libmmbd context destroyed");
        }
    }

    /// Read `count` decrypted bytes at `offset` from an encrypted stream node.
    /// Short reads happen only at end of file.
    pub fn read(&self, node: &Node, offset: u64, count: usize) -> Result<Vec<u8>> {
        if self.is_shutting_down() {
            anyhow::bail!("decryption engine has been shut down");
        }
        let NodeKind::Encrypted { name_flags } = node.kind else {
            return self.read_source(node, offset, count);
        };
        if offset >= node.size || count == 0 {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(count as u64).min(node.size);
        let unit_size = UNIT_SIZE as u64;
        let first_unit = offset / unit_size;
        let last_unit = (end - 1) / unit_size;
        let file_units = node.size.div_ceil(unit_size);

        // Fast path: everything already decrypted.
        let mut out = Vec::with_capacity((end - offset) as usize);
        {
            let mut cache = self.cache.lock().unwrap();
            let mut all_hit = true;
            for unit in first_unit..=last_unit {
                match cache.get(&(name_flags, unit)) {
                    Some(buf) => append_slice(&mut out, &buf[..], unit, offset, end),
                    None => {
                        all_hit = false;
                        break;
                    }
                }
            }
            if all_hit {
                self.stats.units_cached.fetch_add(last_unit - first_unit + 1, Ordering::Relaxed);
                self.stats.bytes_served.fetch_add(out.len() as u64, Ordering::Relaxed);
                self.note_read(node.id, end);
                return Ok(out);
            }
            out.clear();
        }

        // Slow path. Hold the engine lock for the whole miss so concurrent
        // NFS requests do not each drag their own window off the disc.
        let mut guard = self.mmbd.lock().unwrap();
        if self.is_shutting_down() {
            anyhow::bail!("decryption engine has been shut down");
        }
        let Some(mm) = guard.as_mut() else {
            anyhow::bail!("decryption engine has been shut down");
        };
        let sequential = {
            let last = self.last_end.lock().unwrap().get(&node.id).copied();
            matches!(last, Some(prev) if offset.abs_diff(prev) <= SEQUENTIAL_SLACK)
        };
        let window_units = if sequential { SEQUENTIAL_WINDOW_UNITS } else { RANDOM_WINDOW_UNITS };
        // Opened per miss and closed on return; see the note on the struct.
        let mut unit = first_unit;
        while unit <= last_unit {
            let cached = self.cache.lock().unwrap().get(&(name_flags, unit)).cloned();
            if let Some(buf) = cached {
                self.stats.units_cached.fetch_add(1, Ordering::Relaxed);
                append_slice(&mut out, &buf[..], unit, offset, end);
                unit += 1;
                continue;
            }
            // Read a whole window from here, even past what was asked for.
            let run_end = (unit + window_units).min(file_units).max(unit + 1);
            let run_len = ((run_end - unit) * unit_size) as usize;
            let mut raw = self.read_source(node, unit * unit_size, run_len)?;
            let got = raw.len();
            self.kick_prefetch(node, unit * unit_size + got as u64);

            for (i, chunk) in raw.chunks_mut(UNIT_SIZE).enumerate() {
                let this_unit = unit + i as u64;
                let file_offset = this_unit * unit_size;
                if chunk.len() == UNIT_SIZE {
                    if chunk[4] == 0x47 {
                        match mm.decrypt_unit(name_flags, file_offset, chunk) {
                            Ok(()) => {
                                self.stats.units_decrypted.fetch_add(1, Ordering::Relaxed);
                                if !mmbd::unit_looks_like_clear_ts(chunk) {
                                    self.stats.decrypt_errors.fetch_add(1, Ordering::Relaxed);
                                    warn!(
                                        "unit {} of {} did not decrypt to clean TS packets",
                                        this_unit,
                                        node.path.display()
                                    );
                                }
                            }
                            Err(e) => {
                                self.stats.decrypt_errors.fetch_add(1, Ordering::Relaxed);
                                warn!("{e}");
                                anyhow::bail!("decryption failed for {} unit {this_unit}", node.path.display());
                            }
                        }
                    } else {
                        // Not a TS aligned unit (padding, damaged sector); serve as-is.
                        debug!("unit {} of {} has no sync byte, passing through", this_unit, node.path.display());
                    }
                    let mut arr = [0u8; UNIT_SIZE];
                    arr.copy_from_slice(chunk);
                    self.cache.lock().unwrap().put((name_flags, this_unit), Arc::new(arr));
                }
                append_slice(&mut out, chunk, this_unit, offset, end);
            }
            if got < run_len {
                break; // hit EOF
            }
            unit = run_end;
        }
        drop(guard);
        self.stats.bytes_served.fetch_add(out.len() as u64, Ordering::Relaxed);
        self.note_read(node.id, end);
        Ok(out)
    }

    fn note_read(&self, id: NodeId, end: u64) {
        self.last_end.lock().unwrap().insert(id, end);
    }

    fn kick_prefetch(&self, node: &Node, offset: u64) {
        let Some(udf) = self.udf.clone() else {
            return;
        };
        if offset >= node.size {
            return;
        }
        let rel = node.path.to_string_lossy().into_owned();
        let n = crate::rawudf::PREFETCH_WINDOW.min((node.size - offset) as usize);
        let _ = std::thread::Builder::new().name("bdmount-prefetch".into()).spawn(move || {
            let _ = udf.lock().unwrap().prefetch(&rel, offset, n);
        });
    }

    /// `(units_decrypted, cache_hits, bytes_served, decrypt_errors)`.
    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.units_decrypted.load(Ordering::Relaxed),
            self.stats.units_cached.load(Ordering::Relaxed),
            self.stats.bytes_served.load(Ordering::Relaxed),
            self.stats.decrypt_errors.load(Ordering::Relaxed),
        )
    }
}

/// Copy the part of `unit_buf` (unit number `unit`) that falls inside the
/// requested `[req_start, req_end)` window onto `out`.
fn append_slice(out: &mut Vec<u8>, unit_buf: &[u8], unit: u64, req_start: u64, req_end: u64) {
    let unit_start = unit * UNIT_SIZE as u64;
    let unit_end = unit_start + unit_buf.len() as u64;
    let s = req_start.max(unit_start);
    let e = req_end.min(unit_end);
    if s < e {
        out.extend_from_slice(&unit_buf[(s - unit_start) as usize..(e - unit_start) as usize]);
    }
}

/// `pread` until the buffer is full or EOF; returns bytes read.
fn read_exact_at(file: &File, buf: &mut [u8], mut offset: u64) -> Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match file.read_at(&mut buf[done..], offset) {
            Ok(0) => break,
            Ok(n) => {
                done += n;
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(done)
}

/// Read a passthrough file region.
pub fn read_plain(path: &Path, offset: u64, count: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut buf = vec![0u8; count];
    let got = read_exact_at(&file, &mut buf, offset)?;
    buf.truncate(got);
    Ok(buf)
}
