//! Who is holding a disc, and whether it is actually idle enough to eject.
//!
//! `safe_to_eject` is true only when no `makemkvcon` is running and nothing
//! has the UDF volume or the raw optical device open. Spotlight / HandBrake /
//! Finder are reported as holders too so a UI can say why we are waiting.
//!
//! `lsof` is invoked with `-b` (non-blocking) and a short timeout so this
//! never `stat`s a wedged optical volume — that is how Finder froze.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// How long we wait after teardown for helpers and fds to drain.
pub const IDLE_WAIT: Duration = Duration::from_secs(20);
const LSOF_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Idle,
    Opening,
    Serving,
    Releasing,
    SafeToEject,
    Stuck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub state: State,
    pub safe_to_eject: bool,
    pub label: Option<String>,
    pub source: Option<String>,
    pub mountpoint: Option<String>,
    pub holders: Vec<Holder>,
    /// Whole-disk / slice BSD names whose UDF mount we refused.
    #[serde(default)]
    pub claimed_bsd: Vec<String>,
    /// PID of the `bdmount mount` process, if we wrote this snapshot.
    #[serde(default)]
    pub mount_pid: Option<u32>,
    /// Every optical drive (empty, DVD passthrough, or serving).
    #[serde(default)]
    pub drives: Vec<DriveStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriveStatus {
    pub id: String,
    pub device: String,
    pub bus: String,
    pub media_class: String,
    pub media: bool,
    pub bd_capable: bool,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub mountpoint: Option<String>,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub safe_to_eject: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EjectRequest {
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub all: bool,
}

pub fn eject_request_path() -> PathBuf {
    status_path().with_file_name("eject-request.json")
}

pub fn write_eject_request(req: &EjectRequest) {
    let path = eject_request_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(text) = serde_json::to_string(req) {
        let _ = std::fs::write(path, text);
    }
}

pub fn take_eject_request() -> Option<EjectRequest> {
    let path = eject_request_path();
    let text = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    serde_json::from_str(&text).ok()
}

pub fn status_path() -> PathBuf {
    if let Some(p) = std::env::var_os("BDMOUNT_STATUS") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join("Library/Application Support/bdmount/status.json")
}

pub fn write_snapshot(snap: &Snapshot) {
    let path = status_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let Ok(text) = serde_json::to_string_pretty(snap) else { return };
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

pub fn read_snapshot() -> Option<Snapshot> {
    let text = std::fs::read_to_string(status_path()).ok()?;
    serde_json::from_str(&text).ok()
}

/// Paths that, if open, mean the optical stack is still busy.
pub fn optical_paths(source: &Path, raw_device: Option<&str>) -> Vec<PathBuf> {
    let mut paths = vec![source.to_path_buf()];
    if let Some(raw) = raw_device {
        paths.push(PathBuf::from(raw));
        if let Some(block) = raw.strip_prefix("/dev/r") {
            paths.push(PathBuf::from(format!("/dev/{block}")));
        } else if let Some(block) = raw.strip_prefix("/dev/") {
            if !block.starts_with('r') {
                paths.push(PathBuf::from(format!("/dev/r{block}")));
            }
        }
    }
    paths
}

#[derive(Debug, Clone)]
pub struct HelperProc {
    pub pid: u32,
    pub ppid: u32,
    pub cmd: String,
}

impl HelperProc {
    /// Child of this `bdmount`, or re-parented to launchd after we crashed.
    /// Never a helper still owned by MakeMKV.app.
    pub fn is_ours(&self) -> bool {
        let us = std::process::id();
        self.ppid == us || (self.ppid == 1 && self.cmd.contains("guiserver"))
    }

    pub fn as_holder(&self) -> Holder {
        Holder {
            pid: self.pid,
            name: "makemkvcon".into(),
            path: self.cmd.clone(),
        }
    }
}

pub fn list_makemkvcon() -> Vec<HelperProc> {
    let Ok(out) = Command::new("/bin/ps").args(["-axo", "pid=,ppid=,command="]).output() else {
        return Vec::new();
    };
    let mut v = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (it.next(), it.next()) else { continue };
        let cmd: Vec<&str> = it.collect();
        if cmd.is_empty() || !cmd[0].contains("makemkvcon") {
            continue;
        }
        let (Ok(pid), Ok(ppid)) = (pid.parse(), ppid.parse()) else { continue };
        v.push(HelperProc {
            pid,
            ppid,
            cmd: cmd.join(" "),
        });
    }
    v
}

/// `makemkvcon` processes (ours, orphans, and MakeMKV.app).
pub fn makemkvcon_helpers() -> Vec<Holder> {
    list_makemkvcon().into_iter().map(|h| h.as_holder()).collect()
}

/// After libmmbd is destroyed, wait for *our* helper to exit. Only then
/// SIGKILL leftovers that are still our children or orphans. Never touch a
/// helper whose parent is MakeMKV.app — that is what crashed the GUI and
/// left SCSI in-flight so the next unmount hung on "Please wait".
pub fn release_our_helpers() -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let ours: Vec<HelperProc> = list_makemkvcon().into_iter().filter(HelperProc::is_ours).collect();
        if ours.is_empty() {
            return 0;
        }
        if Instant::now() >= deadline {
            let mut n = 0;
            for h in ours {
                if unsafe { libc::kill(h.pid as i32, libc::SIGKILL) } == 0 {
                    warn!("killed our leftover makemkvcon pid {} (ppid {})", h.pid, h.ppid);
                    n += 1;
                }
            }
            return n;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Processes with an open handle on any of `paths`. Uses `lsof -b` and a timeout.
pub fn holders_on(paths: &[PathBuf]) -> Vec<Holder> {
    let existing: Vec<&Path> = paths.iter().map(|p| p.as_path()).filter(|p| path_exists_fast(p)).collect();
    if existing.is_empty() {
        return Vec::new();
    }
    let mut cmd = Command::new("/usr/sbin/lsof");
    cmd.args(["-nP", "-b", "-F", "pcn0"]).args(&existing).stdin(Stdio::null()).stderr(Stdio::null());
    let output = match run_with_timeout(cmd, LSOF_TIMEOUT) {
        Some(o) => o,
        None => {
            debug!("lsof timed out or failed (treating as no extra holders)");
            return Vec::new();
        }
    };
    parse_lsof_f(&String::from_utf8_lossy(&output.stdout))
}

fn path_exists_fast(path: &Path) -> bool {
    // `path.exists()` can block on a wedged UDF volume. Use the mount table
    // for /Volumes and metadata only for device nodes (local, non-blocking).
    if path.starts_with("/dev/") {
        return std::fs::metadata(path).is_ok();
    }
    if path.starts_with("/Volumes") {
        return crate::mount::is_volume_mounted(path);
    }
    true
}

/// After we have closed libmmbd, wait until helpers and optical fds are gone.
/// Returns the leftover holders (empty ⇒ safe to eject).
///
/// Only watches this disc’s device (and optional folder). Other live mounts
/// stay out of the wait so one tray can eject while another is still serving.
pub fn wait_until_idle(source: &Path, raw_device: Option<&str>) -> Vec<Holder> {
    wait_until_idle_for(source, raw_device, None)
}

pub fn wait_until_idle_for(source: &Path, raw_device: Option<&str>, mountpoint: Option<&Path>) -> Vec<Holder> {
    let mut optical = optical_paths(source, raw_device);
    if let Some(mp) = mountpoint {
        let p = mp.to_path_buf();
        if !optical.contains(&p) {
            optical.push(p);
        }
    }
    let deadline = Instant::now() + IDLE_WAIT;
    loop {
        crate::mount::reap_orphaned_helpers();
        let holders = holders_on(&optical);
        // Only fds on *this* disc keep us waiting. A sibling Blu-ray's
        // makemkvcon is still "ours" and must not block this tray.
        // `holders` already includes every makemkvcon; those use the
        // command line as `path`, so they do not match `/dev/` here.
        let src = source.to_string_lossy();
        let our_busy = holders.iter().any(|h| {
            h.path.starts_with("/dev/") || h.path.starts_with(src.as_ref())
        });
        if !our_busy {
            return holders;
        }
        if Instant::now() >= deadline {
            warn!("drive still busy after {}s: {holders:?}", IDLE_WAIT.as_secs());
            return holders;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub fn is_safe_to_eject(holders: &[Holder], source: &Path) -> bool {
    !holders.iter().any(|h| holder_blocks_eject(h, source))
}

/// Holders that mean we must not touch a live OS UDF volume (HandBrake scan,
/// MakeMKV, players). Finder / Spotlight are not this — a polite `umount` is OK.
pub fn is_hard_os_udf_holder(h: &Holder) -> bool {
    let n = h.name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "makemkvcon" | "handbrake" | "handbrakecli" | "vlc" | "iina" | "mpv" | "infuse"
    ) || h.path.contains("makemkvcon")
        || h.path.starts_with("/dev/disk")
        || h.path.starts_with("/dev/rdisk")
}

fn holder_blocks_eject(h: &Holder, source: &Path) -> bool {
    let p = &h.path;
    h.name == "makemkvcon"
        || h.name.eq_ignore_ascii_case("HandBrake")
        || h.name.eq_ignore_ascii_case("HandBrakeCLI")
        || p.contains("makemkvcon")
        || p.starts_with("/dev/disk")
        || p.starts_with("/dev/rdisk")
        || p.contains("BluRay Decrypted")
        || p.starts_with(source.to_string_lossy().as_ref())
}

pub fn print_eject_verdict(holders: &[Holder], source: &Path) {
    if is_safe_to_eject(holders, source) {
        println!();
        println!("SAFE TO EJECT. Run `bdmount eject` (Disk Utility is a backup). Do not unplug the drive.");
    } else {
        println!();
        println!("NOT safe to eject yet. Still holding the drive:");
        for h in holders {
            println!("  pid {:>6}  {:<16}  {}", h.pid, h.name, h.path);
        }
        println!("Quit HandBrake and retry `bdmount eject`. Do not unplug the USB enclosure.");
    }
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Option<std::process::Output> {
    let mut child = cmd.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
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

/// Parse `lsof -F pcn0` (NUL-terminated fields). Also accepts newline-separated
/// test fixtures.
pub fn parse_lsof_f(raw: &str) -> Vec<Holder> {
    let mut out = Vec::new();
    let mut pid = 0u32;
    let mut name = String::new();
    let mut path = String::new();
    let flush = |pid: u32, name: &str, path: &str, out: &mut Vec<Holder>| {
        if pid == 0 || path.is_empty() {
            return;
        }
        if name == "lsof" {
            return;
        }
        out.push(Holder {
            pid,
            name: name.to_string(),
            path: path.to_string(),
        });
    };
    for field in raw.split(|c| c == '\0' || c == '\n') {
        if field.is_empty() {
            continue;
        }
        let (tag, rest) = field.split_at(1);
        match tag {
            "p" => {
                flush(pid, &name, &path, &mut out);
                path.clear();
                pid = rest.parse().unwrap_or(0);
            }
            "c" => name = rest.to_string(),
            "n" => {
                if !path.is_empty() {
                    flush(pid, &name, &path, &mut out);
                }
                path = rest.to_string();
            }
            _ => {}
        }
    }
    flush(pid, &name, &path, &mut out);
    out
}

/// Build a snapshot from the live system (no running-daemon file required).
pub fn observe(source: Option<&Path>, mountpoint: Option<&Path>, raw_device: Option<&str>, state: State) -> Snapshot {
    let mut holders = makemkvcon_helpers();
    let mut paths = Vec::new();
    if let Some(s) = source {
        paths.extend(optical_paths(s, raw_device));
    } else {
        for m in crate::mount::mount_table() {
            if m.mount_point.starts_with("/Volumes") && matches!(m.fs_type.as_str(), "udf" | "cd9660") && m.from.starts_with("/dev/disk")
            {
                paths.push(m.mount_point.clone());
                paths.push(PathBuf::from(&m.from));
                if let Some(rest) = m.from.strip_prefix("/dev/") {
                    paths.push(PathBuf::from(format!("/dev/r{rest}")));
                }
            }
        }
    }
    if let Some(mp) = mountpoint {
        paths.push(mp.to_path_buf());
    }
    for h in holders_on(&paths) {
        if !holders.iter().any(|x| x.pid == h.pid && x.path == h.path) {
            holders.push(h);
        }
    }
    let source_s = source.map(|p| p.display().to_string());
    let optical_clear = match source {
        Some(s) => is_safe_to_eject(&holders, s),
        None => holders.iter().all(|h| h.name != "makemkvcon"),
    };
    let (state, safe) = match state {
        State::Opening | State::Serving => (state, false),
        State::Releasing if optical_clear => (State::SafeToEject, true),
        State::Releasing => (State::Stuck, false),
        State::SafeToEject => (State::SafeToEject, optical_clear),
        State::Stuck => (State::Stuck, false),
        State::Idle => (State::Idle, optical_clear),
    };
    Snapshot {
        state,
        safe_to_eject: safe,
        label: source.and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned())),
        source: source_s,
        mountpoint: mountpoint.map(|p| p.display().to_string()),
        holders,
        claimed_bsd: crate::da::all_claimed_bsd_names(),
        mount_pid: None,
        drives: crate::drives::drive_statuses(&[]),
    }
}

/// Refresh `drives` from hardware plus currently served discs.
pub fn attach_drives(snap: &mut Snapshot, live: &[(String, String, String, bool)]) {
    snap.drives = crate::drives::drive_statuses(live);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsof_fields() {
        let raw = "p1920\0cmakemkvcon\0n/dev/rdisk6\0p698\0cFinder\0n/Volumes/GRADUATE_THE\0";
        let h = parse_lsof_f(raw);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0], Holder { pid: 1920, name: "makemkvcon".into(), path: "/dev/rdisk6".into() });
        assert_eq!(h[1].name, "Finder");
    }

    #[test]
    fn makemkvcon_on_raw_device_is_not_safe() {
        let src = Path::new("/Volumes/GRADUATE_THE");
        let holders = vec![Holder { pid: 1, name: "makemkvcon".into(), path: "guiserver".into() }];
        assert!(!is_safe_to_eject(&holders, src));
        assert!(is_safe_to_eject(&[], src));
    }

    #[test]
    fn handbrake_on_nfs_folder_blocks_eject() {
        let src = Path::new("/dev/rdisk6");
        let holders = vec![Holder {
            pid: 42,
            name: "HandBrake".into(),
            path: "/Users/kevin/BluRay Decrypted/GRADUATE_THE".into(),
        }];
        assert!(!is_safe_to_eject(&holders, src));
    }

    #[test]
    fn finder_is_not_a_hard_udf_holder_handbrake_is() {
        let finder = Holder {
            pid: 1,
            name: "Finder".into(),
            path: "/Volumes/GRADUATE_THE".into(),
        };
        let hb = Holder {
            pid: 2,
            name: "HandBrake".into(),
            path: "/Volumes/GRADUATE_THE".into(),
        };
        assert!(!is_hard_os_udf_holder(&finder));
        assert!(is_hard_os_udf_holder(&hb));
    }

    #[test]
    fn optical_paths_include_block_and_raw() {
        let p = optical_paths(Path::new("/Volumes/X"), Some("/dev/rdisk6"));
        assert!(p.iter().any(|x| x == Path::new("/dev/rdisk6")));
        assert!(p.iter().any(|x| x == Path::new("/dev/disk6")));
    }

    #[test]
    fn does_not_claim_makemkv_gui_helper() {
        let gui = HelperProc {
            pid: 1923,
            ppid: 1922,
            cmd: "/Applications/MakeMKV.app/Contents/MacOS/makemkvcon guiserver A0001+shm".into(),
        };
        assert!(!gui.is_ours());
        let orphan = HelperProc {
            pid: 99,
            ppid: 1,
            cmd: "/Applications/MakeMKV.app/Contents/MacOS/makemkvcon guiserver A0001+std".into(),
        };
        assert!(orphan.is_ours());
    }

    #[test]
    fn old_snapshot_without_drives_still_decodes() {
        let json = r#"{
            "state":"idle",
            "safe_to_eject":true,
            "label":null,
            "source":null,
            "mountpoint":null,
            "holders":[],
            "claimed_bsd":[],
            "mount_pid":null
        }"#;
        let snap: Snapshot = serde_json::from_str(json).unwrap();
        assert!(snap.drives.is_empty());
        assert_eq!(snap.state, State::Idle);
    }
}
