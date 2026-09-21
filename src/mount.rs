//! Orchestrates one decrypted disc: libmmbd session, tree scan, NFS server
//! on `127.0.0.1`, and the `mount_nfs` / `umount` calls around it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::decrypt::DecryptEngine;
use crate::disc::{self, DiscTree};
use crate::idle::{self, Snapshot, State};
use crate::mmbd::Mmbd;
use crate::rawudf::RawUdf;
use crate::vfs::BdFs;

/// Default cache for decrypted units.
pub const DEFAULT_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// `~/BluRay Decrypted`, or `$BDMOUNT_BASE` if set.
pub fn default_base_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("BDMOUNT_BASE") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join("BluRay Decrypted")
}

#[derive(Debug, Clone)]
pub struct MountOptions {
    pub base_dir: PathBuf,
    pub cache_bytes: usize,
    /// Explicit mountpoint; otherwise `<base_dir>/<label>`.
    pub mountpoint: Option<PathBuf>,
}

impl Default for MountOptions {
    fn default() -> Self {
        MountOptions {
            base_dir: default_base_dir(),
            cache_bytes: DEFAULT_CACHE_BYTES,
            mountpoint: None,
        }
    }
}

/// A live decrypted mount. Dropping it does **not** unmount; call
/// [`MountedDisc::unmount`].
///
/// The state lives behind an `Arc` so that the DiskArbitration eject hook
/// (see [`crate::da`]) can tear the view down synchronously from its own
/// thread when the user presses Eject on the disc.
#[derive(Clone)]
pub struct MountedDisc(Arc<Inner>);

pub struct Inner {
    pub source: PathBuf,
    pub label: String,
    pub mountpoint: PathBuf,
    pub port: u16,
    pub engine: Arc<DecryptEngine>,
    /// `/dev/rdiskN` recorded at mount time so release never calls `diskutil`.
    pub raw_device: Option<String>,
    server: JoinHandle<()>,
    /// True while our NFS view is mounted and we are responsible for unmounting it.
    mounted: AtomicBool,
    /// Set once teardown ran (from any thread).
    torn_down: AtomicBool,
}

/// All live mounts, keyed by canonical source volume and by mountpoint, for
/// the eject hook. Populated by [`MountedDisc::mount`], drained on teardown.
static REGISTRY: Mutex<Vec<MountedDisc>> = Mutex::new(Vec::new());

/// Sources we released (eject hook or unmount). The watcher must not open
/// these again until the volume has left the mount table *and* this settle
/// window has elapsed. Remounting while macOS is still ejecting is what
/// wedged Finder: libmmbd issued SCSI to a drive mid-eject.
const HOLD_OFF: Duration = Duration::from_secs(15);
static RELEASED: Mutex<Option<HashMap<PathBuf, Instant>>> = Mutex::new(None);

fn released_map() -> std::sync::MutexGuard<'static, Option<HashMap<PathBuf, Instant>>> {
    RELEASED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record that we gave up a source. Safe to call from any thread.
pub fn mark_source_released(source: &Path) {
    released_map()
        .get_or_insert_with(HashMap::new)
        .insert(source.to_path_buf(), Instant::now());
}

/// Drop hold-offs whose volume is gone and whose settle window has elapsed.
pub fn sweep_hold_off() {
    let mut guard = released_map();
    let Some(map) = guard.as_mut() else { return };
    map.retain(|path, since| is_volume_mounted(path) || since.elapsed() < HOLD_OFF);
}

/// Source paths we must not stat or remount (mid-eject or still settling).
pub fn held_off_sources() -> Vec<PathBuf> {
    sweep_hold_off();
    released_map()
        .as_ref()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn registry() -> std::sync::MutexGuard<'static, Vec<MountedDisc>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Find the live mount whose source volume or mountpoint is `path`.
pub fn find_by_path(path: &Path) -> Option<MountedDisc> {
    registry()
        .iter()
        .find(|m| m.0.source == path || m.0.mountpoint == path)
        .cloned()
}

/// Kill `makemkvcon guiserver` helpers whose parent has died (re-parented
/// to launchd, PID 1). libmmbd hosts are always their parent while alive, so
/// such processes are leftovers from a crashed/killed host and would
/// otherwise sit around forever holding memory. Returns how many were killed.
pub fn reap_orphaned_helpers() -> usize {
    let Ok(out) = Command::new("/bin/ps").args(["-axo", "pid=,ppid=,command="]).output() else {
        return 0;
    };
    let mut killed = 0;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (it.next(), it.next()) else { continue };
        let cmd: Vec<&str> = it.collect();
        if ppid != "1" || cmd.len() < 2 || !cmd[0].ends_with("/makemkvcon") || cmd[1] != "guiserver" {
            continue;
        }
        if let Ok(pid) = pid.parse::<i32>() {
            // They ignore SIGTERM once their pipe is gone, so use SIGKILL.
            if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                warn!("killed orphaned makemkvcon helper (pid {pid}) left behind by an earlier crash");
                killed += 1;
            }
        }
    }
    killed
}

/// Open the disc in libmmbd, trying the volume path first and the raw
/// whole-disk device second.
pub fn open_disc(source: &Path) -> Result<Mmbd> {
    reap_orphaned_helpers();
    let mut mmbd = Mmbd::new()?;
    let path_str = source.to_string_lossy().into_owned();
    match mmbd.open(&path_str) {
        Ok(()) => return Ok(mmbd),
        Err(e) => warn!("{e}; retrying with the raw device"),
    }
    let dev = disc::raw_device_for_volume(source)
        .ok_or_else(|| anyhow!("could not resolve the device backing {}", source.display()))?;
    mmbd.open(&dev)
        .with_context(|| format!("MakeMKV could not open {} via {dev}", source.display()))?;
    Ok(mmbd)
}

impl MountedDisc {
    pub async fn mount(source: &Path, opts: &MountOptions) -> Result<MountedDisc> {
        let started = Instant::now();
        let source = if source.starts_with("/dev/") {
            source.to_path_buf()
        } else {
            source.canonicalize().with_context(|| format!("cannot access {}", source.display()))?
        };

        let raw_device = if source.starts_with("/dev/r") {
            Some(source.to_string_lossy().into_owned())
        } else if source.starts_with("/dev/") {
            Some(format!("/dev/r{}", source.file_name().unwrap().to_string_lossy().trim_start_matches('r')))
        } else {
            disc::raw_device_for_volume(&source)
        };

        let src = source.clone();
        let cache = opts.cache_bytes;
        let (tree, engine) = tokio::task::spawn_blocking(move || -> Result<_> {
            if src.starts_with("/dev/") {
                let udf = Arc::new(Mutex::new(RawUdf::open(&src)?));
                let tree = DiscTree::scan_udf(&udf)?;
                info!(
                    "{}: {} files, {} encrypted streams (raw UDF, no /Volumes)",
                    tree.label, tree.file_count, tree.encrypted_count
                );
                let mmbd = open_disc(&src)?;
                info!(
                    "MakeMKV opened {} in {:.1}s: MKB v{}, bus encryption: {}, disc id {}",
                    src.display(),
                    started.elapsed().as_secs_f32(),
                    mmbd.mkb_version(),
                    if mmbd.bus_encrypted() { "yes" } else { "no" },
                    mmbd.disc_id().map(hex).unwrap_or_default()
                );
                let engine = Arc::new(DecryptEngine::new_with_udf(mmbd, cache, udf));
                Ok((tree, engine))
            } else {
                let vol = disc::inspect_volume(&src)
                    .ok_or_else(|| anyhow!("{} is not a Blu-ray volume (no BDMV/index.bdmv)", src.display()))?;
                let tree = DiscTree::scan(&src)?;
                info!(
                    "{}: {} files, {} encrypted streams",
                    tree.label, tree.file_count, tree.encrypted_count
                );
                let mmbd = if vol.protected || tree.encrypted_count > 0 {
                    Some(open_disc(&src)?)
                } else {
                    None
                };
                let engine = match mmbd {
                    Some(m) => Arc::new(DecryptEngine::new(m, cache)),
                    None => Arc::new(DecryptEngine::new(Mmbd::new()?, cache)),
                };
                Ok((tree, engine))
            }
        })
        .await??;
        let tree = Arc::new(tree);

        let fs = BdFs::new(tree.clone(), engine.clone());
        let listener = NFSTcpListener::bind("127.0.0.1:0", fs)
            .await
            .context("binding NFS listener on 127.0.0.1")?;
        let port = listener.get_listen_port();
        let server = tokio::spawn(async move {
            if let Err(e) = listener.handle_forever().await {
                warn!("NFS server stopped: {e}");
            }
        });

        let mountpoint = opts
            .mountpoint
            .clone()
            .unwrap_or_else(|| opts.base_dir.join(sanitize(&tree.label)));
        prepare_mountpoint(&mountpoint)?;

        let md = MountedDisc(Arc::new(Inner {
            source: source.clone(),
            label: tree.label.clone(),
            mountpoint: mountpoint.clone(),
            port,
            engine,
            raw_device,
            server,
            mounted: AtomicBool::new(false),
            torn_down: AtomicBool::new(false),
        }));

        if let Err(e) = run_mount_nfs(port, &mountpoint) {
            md.0.server.abort();
            md.0.engine.shutdown();
            let _ = std::fs::remove_dir(&mountpoint);
            return Err(e);
        }
        md.0.mounted.store(true, Ordering::SeqCst);
        registry().push(md.clone());
        let mut snap = idle::observe(
            Some(&source),
            Some(&mountpoint),
            md.0.raw_device.as_deref(),
            State::Serving,
        );
        snap.mount_pid = Some(std::process::id());
        idle::write_snapshot(&snap);
        info!(
            "mounted {} -> {} (nfs://127.0.0.1:{port}) in {:.1}s",
            source.display(),
            mountpoint.display(),
            started.elapsed().as_secs_f32()
        );
        Ok(md)
    }

    pub fn source(&self) -> &Path {
        &self.0.source
    }
    pub fn label(&self) -> &str {
        &self.0.label
    }
    pub fn mountpoint(&self) -> &Path {
        &self.0.mountpoint
    }
    pub fn port(&self) -> u16 {
        self.0.port
    }
    pub fn raw_device(&self) -> Option<&str> {
        self.0.raw_device.as_deref()
    }

    /// Unmount, stop the server and release the disc in MakeMKV.
    pub async fn unmount(self) -> Result<()> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.teardown(true)).await?
    }

    /// Synchronous teardown, safe to call from any thread and idempotent.
    ///
    /// With `unmount_view == false` the NFS view is left in the mount table
    /// for someone else (DiskArbitration) to unmount; we only stop serving it.
    pub fn teardown(&self, unmount_view: bool) -> Result<()> {
        let inner = &self.0;
        mark_source_released(&inner.source);
        if inner.torn_down.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let others_remain = {
            let mut reg = registry();
            reg.retain(|m| !Arc::ptr_eq(&m.0, inner));
            !reg.is_empty()
        };
        if !others_remain {
            let mut releasing = idle::observe(
                Some(&inner.source),
                Some(&inner.mountpoint),
                inner.raw_device.as_deref(),
                State::Releasing,
            );
            releasing.mount_pid = Some(std::process::id());
            idle::write_snapshot(&releasing);
        }

        let r = if inner.mounted.swap(false, Ordering::SeqCst) && unmount_view {
            unmount_path(&inner.mountpoint)
        } else {
            Ok(())
        };
        inner.server.abort();
        inner.engine.shutdown(); // closes the disc; that disc's makemkvcon child should exit
        if !others_remain {
            idle::release_our_helpers();
        }
        if unmount_view {
            let _ = std::fs::remove_dir(&inner.mountpoint);
        }
        let leftovers =
            idle::wait_until_idle_for(&inner.source, inner.raw_device.as_deref(), Some(&inner.mountpoint));
        let s = inner.engine.stats();
        info!(
            "released {}: {} units decrypted, {} cache hits, {} MiB served, {} errors",
            inner.mountpoint.display(),
            s.0,
            s.1,
            s.2 / (1024 * 1024),
            s.3
        );
        if others_remain {
            return r;
        }
        let done = if idle::is_safe_to_eject(&leftovers, &inner.source) {
            State::SafeToEject
        } else {
            State::Stuck
        };
        let mut snap = Snapshot {
            state: done,
            safe_to_eject: done == State::SafeToEject,
            label: Some(inner.label.clone()),
            source: Some(inner.source.display().to_string()),
            mountpoint: Some(inner.mountpoint.display().to_string()),
            holders: leftovers,
            claimed_bsd: crate::da::all_claimed_bsd_names(),
            mount_pid: Some(std::process::id()),
            drives: Vec::new(),
        };
        idle::attach_drives(&mut snap, &[]);
        idle::write_snapshot(&snap);
        r
    }

    /// False once the view was torn down (e.g. by the eject hook).
    pub fn is_active(&self) -> bool {
        !self.0.torn_down.load(Ordering::SeqCst)
    }

    /// True while the source volume is still in the mount table. Consults
    /// only the kernel mount table; never touches the disc.
    pub fn source_present(&self) -> bool {
        if self.0.source.starts_with("/dev/") {
            std::fs::metadata(&self.0.source).is_ok()
        } else {
            is_volume_mounted(&self.0.source)
        }
    }
}

fn hex(id: [u8; 20]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Make a label safe to use as a directory name.
fn sanitize(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| if c == '/' || c == ':' || c == '\0' { '_' } else { c })
        .collect();
    let s = s.trim();
    if s.is_empty() { "BluRay".to_string() } else { s.to_string() }
}

fn prepare_mountpoint(mp: &Path) -> Result<()> {
    if is_mounted(mp) {
        // Our mountpoints are dedicated directories, so anything mounted
        // there is a leftover from a bdmount that died without unmounting.
        warn!("{} still has a stale mount from a previous run; unmounting it", mp.display());
        unmount_path(mp).with_context(|| {
            format!(
                "{} already has something mounted on it and it could not be unmounted; \
                 run `bdmount unmount \"{}\"` and retry",
                mp.display(),
                mp.display()
            )
        })?;
    }
    std::fs::create_dir_all(mp).with_context(|| format!("creating mountpoint {}", mp.display()))?;
    if std::fs::read_dir(mp)?.next().is_some() {
        bail!("mountpoint {} is not empty", mp.display());
    }
    Ok(())
}

fn run_mount_nfs(port: u16, mountpoint: &Path) -> Result<()> {
    let opts = format!(
        // hard: a HandBrake title scan seeks all over the disc; a single
        // optical read can take many seconds. `soft` is what produced the
        // Finder "Server connection interrupted" dialog.
        "ro,nolocks,vers=3,tcp,hard,intr,rsize=131072,readahead=16,actimeo=3600,timeo=600,port={port},mountport={port}"
    );
    debug!("mount_nfs -o {opts} 127.0.0.1:/ {}", mountpoint.display());
    let out = Command::new("/sbin/mount_nfs")
        .arg("-o")
        .arg(&opts)
        .arg("127.0.0.1:/")
        .arg(mountpoint)
        .output()
        .context("running /sbin/mount_nfs")?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let hint = if stderr.contains("Operation not permitted") || stderr.contains("Permission denied") {
        "\nhint: macOS refused an unprivileged NFS mount here. Make sure the mountpoint is a directory you own, \
         or run bdmount with sudo."
    } else {
        ""
    };
    bail!("mount_nfs failed ({}): {stderr}{hint}", out.status)
}

/// Normal unmount of an OS volume (Finder UDF). Never `-f` / `unmount force`.
/// Those are what wedged `IOBDMediaBSDClient` after a hot HandBrake scan.
pub fn unmount_os_volume_polite(mp: &Path) -> Result<()> {
    if !is_volume_mounted(mp) {
        return Ok(());
    }
    let timeout = Duration::from_secs(12);
    for (bin, args) in [("/sbin/umount", vec![] as Vec<&str>), ("/usr/sbin/diskutil", vec!["unmount"])] {
        match run_unmount_timeout(bin, &args, mp, timeout) {
            Some(true) => {
                info!("released OS mount {}", mp.display());
                return Ok(());
            }
            Some(false) => {}
            None => warn!("{bin} timed out on {}", mp.display()),
        }
    }
    if !is_volume_mounted(mp) {
        return Ok(());
    }
    bail!(
        "could not unmount {} without force. Quit apps using the disc, or eject in Disk Utility / reboot. \
         We will not `umount -f` a live UDF volume.",
        mp.display()
    )
}

fn run_unmount_timeout(bin: &str, args: &[&str], mp: &Path, timeout: Duration) -> Option<bool> {
    let mut child = Command::new(bin).args(args).arg(mp).spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.success()),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
}

/// Unmount a path, escalating from `umount` to `umount -f` to `diskutil unmount force`.
/// NFS leftovers only — never call this on a live OS UDF `/Volumes` disc.
pub fn unmount_path(mp: &Path) -> Result<()> {
    if !is_mounted(mp) {
        debug!("{} is not mounted", mp.display());
        return Ok(());
    }
    let attempts: [(&str, Vec<&str>); 3] = [
        ("/sbin/umount", vec![]),
        ("/sbin/umount", vec!["-f"]),
        ("/usr/sbin/diskutil", vec!["unmount", "force"]),
    ];
    let mut last_err = String::new();
    for (bin, args) in attempts {
        let out = Command::new(bin).args(&args).arg(mp).output()?;
        if out.status.success() {
            info!("unmounted {}", mp.display());
            return Ok(());
        }
        last_err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        warn!("{bin} {} {} failed: {last_err}", args.join(" "), mp.display());
    }
    bail!("could not unmount {}: {last_err}", mp.display())
}

/// One entry of the kernel mount table.
#[derive(Debug, Clone)]
pub struct MountEntry {
    pub mount_point: PathBuf,
    pub from: String,
    pub fs_type: String,
}

/// Snapshot of the mount table via `getfsstat(2)` with `MNT_NOWAIT`.
///
/// This never performs I/O on the mounted volumes, which matters for optical
/// discs: a `stat()` on a volume that is half-way through an eject can block
/// the caller in an uninterruptible kernel wait.
pub fn mount_table() -> Vec<MountEntry> {
    fn cstr(buf: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }
    unsafe {
        let n = libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT);
        if n <= 0 {
            return vec![];
        }
        let mut buf: Vec<libc::statfs> = Vec::with_capacity(n as usize + 8);
        let bytes = (buf.capacity() * std::mem::size_of::<libc::statfs>()) as libc::c_int;
        let n = libc::getfsstat(buf.as_mut_ptr(), bytes, libc::MNT_NOWAIT);
        if n <= 0 {
            return vec![];
        }
        buf.set_len(n as usize);
        buf.iter()
            .map(|s| MountEntry {
                mount_point: PathBuf::from(cstr(&s.f_mntonname)),
                from: cstr(&s.f_mntfromname),
                fs_type: cstr(&s.f_fstypename),
            })
            .collect()
    }
}

/// Mountpoints of our own NFS views (`127.0.0.1:/` over nfs).
pub fn active_mounts() -> Vec<PathBuf> {
    mount_table()
        .into_iter()
        .filter(|m| m.fs_type == "nfs" && (m.from == "127.0.0.1:/" || m.from == "localhost:/"))
        .map(|m| m.mount_point)
        .collect()
}

pub fn is_mounted(mp: &Path) -> bool {
    let target = mp.canonicalize().unwrap_or_else(|_| mp.to_path_buf());
    active_mounts().iter().any(|m| *m == target || m == mp)
}

/// Whether some filesystem is mounted exactly at `path` (no disc I/O).
pub fn is_volume_mounted(path: &Path) -> bool {
    mount_table().iter().any(|m| m.mount_point == path)
}
