//! DiskArbitration hooks and tray eject.
//!
//! **Mount claim:** while `bdmount` is running we dissent macOS mounting a
//! Blu-ray (`IOBDMedia`). DVD/CD media (`IODVDMedia` / `IOCDMedia`) is always
//! approved — including AVCHD (a BDMV tree on DVD media). Start `bdmount`
//! *before* inserting the Blu-ray.
//!
//! **Tray eject:** `DADiskEject` on a whole disk we claimed. Never eject a
//! pass-through DVD/CD. Do not go through Finder unmount of UDF.
//!
//! **Unmount approval:** only used by `watch` (disabled in `mount` mode).

use std::ffi::{CStr, CString, c_char, c_void};
use std::path::PathBuf;
use std::sync::{Mutex, Once};
use std::time::Duration;

use anyhow::{Result, bail};
use tracing::{debug, info, warn};

use crate::idle;
use crate::mount;
use crate::rawudf;

type CFTypeRef = *const c_void;
type CFStringRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFURLRef = *const c_void;
type DADiskRef = *const c_void;
type DASessionRef = *const c_void;
type DADissenterRef = *const c_void;
type DispatchQueue = *mut c_void;
type IoObject = libc::mach_port_t;

type ApprovalCallback = unsafe extern "C" fn(disk: DADiskRef, context: *mut c_void) -> DADissenterRef;
type EjectCallback = unsafe extern "C" fn(disk: DADiskRef, dissenter: DADissenterRef, context: *mut c_void);

const K_DA_RETURN_EXCLUSIVE_ACCESS: u32 = 0xF8DA_0007;
const K_DA_DISK_EJECT_OPTION_DEFAULT: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpticalClass {
    BluRay,
    Dvd,
    Cd,
    Unknown,
}

/// Whether we dissent a UDF/ISO mount. `has_bdmv` is consulted only when
/// the IOKit class is unknown. Known DVD/CD always pass through, even with BDMV.
pub fn should_dissent(kind: &str, class: OpticalClass, has_bdmv: bool) -> bool {
    if kind != "udf" && kind != "cd9660" {
        return false;
    }
    match class {
        OpticalClass::BluRay => true,
        OpticalClass::Dvd | OpticalClass::Cd => false,
        OpticalClass::Unknown => has_bdmv,
    }
}

#[link(name = "DiskArbitration", kind = "framework")]
unsafe extern "C" {
    fn DASessionCreate(allocator: CFTypeRef) -> DASessionRef;
    fn DASessionSetDispatchQueue(session: DASessionRef, queue: DispatchQueue);
    fn DARegisterDiskUnmountApprovalCallback(
        session: DASessionRef,
        matching: CFDictionaryRef,
        callback: ApprovalCallback,
        context: *mut c_void,
    );
    fn DARegisterDiskMountApprovalCallback(
        session: DASessionRef,
        matching: CFDictionaryRef,
        callback: ApprovalCallback,
        context: *mut c_void,
    );
    fn DADissenterCreate(allocator: CFTypeRef, status: u32, string: CFStringRef) -> DADissenterRef;
    fn DADissenterGetStatusString(dissenter: DADissenterRef) -> CFStringRef;
    fn DADiskCopyDescription(disk: DADiskRef) -> CFDictionaryRef;
    fn DADiskGetBSDName(disk: DADiskRef) -> *const c_char;
    fn DADiskCopyIOMedia(disk: DADiskRef) -> IoObject;
    fn DADiskCreateFromBSDName(allocator: CFTypeRef, session: DASessionRef, name: *const c_char) -> DADiskRef;
    fn DADiskEject(disk: DADiskRef, options: u32, callback: EjectCallback, context: *mut c_void);
    static kDADiskDescriptionVolumePathKey: CFStringRef;
    static kDADiskDescriptionVolumeKindKey: CFStringRef;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
    fn CFURLGetFileSystemRepresentation(url: CFURLRef, resolve: u8, buffer: *mut u8, max_len: isize) -> u8;
    fn CFStringGetCString(the_string: CFStringRef, buf: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFStringCreateWithCString(alloc: CFTypeRef, c_str: *const c_char, encoding: u32) -> CFStringRef;
    fn CFRelease(cf: CFTypeRef);
    static kCFAllocatorDefault: CFTypeRef;
}

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    static kIOMainPortDefault: libc::mach_port_t;
    fn IOBSDNameMatching(main_port: libc::mach_port_t, options: u32, bsd_name: *const c_char) -> CFDictionaryRef;
    fn IOServiceGetMatchingService(main_port: libc::mach_port_t, matching: CFDictionaryRef) -> IoObject;
    fn IOObjectConformsTo(object: IoObject, class_name: *const c_char) -> u32;
    fn IOObjectRelease(object: IoObject) -> i32;
    fn IORegistryEntryGetParentEntry(entry: IoObject, plane: *const c_char, parent: *mut IoObject) -> i32;
}

const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

unsafe extern "C" {
    fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueue;
}

static START: Once = Once::new();
static CLAIM: Once = Once::new();
static CLAIMED: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn claimed() -> std::sync::MutexGuard<'static, Vec<String>> {
    CLAIMED.lock().unwrap_or_else(|e| e.into_inner())
}

/// BSD names (`disk6`, `disk6s1`) whose UDF mount we refused in this process.
pub fn claimed_bsd_names() -> Vec<String> {
    claimed().clone()
}

/// Live claims plus names persisted so `bdmount eject` still knows the disk
/// after the mount process has exited.
pub fn all_claimed_bsd_names() -> Vec<String> {
    let mut v = claimed_bsd_names();
    for n in load_persisted_claimed() {
        if !v.contains(&n) {
            v.push(n);
        }
    }
    v
}

/// Whole-disk identifiers (`disk6`) we claimed. Empty ⇒ nothing to eject.
pub fn claimed_whole_disks() -> Vec<String> {
    let mut out = Vec::new();
    for bsd in all_claimed_bsd_names() {
        let Some(whole) = rawudf::bsd_whole_disk(&bsd) else { continue };
        if !out.contains(&whole) {
            out.push(whole);
        }
    }
    out
}

fn persist_claimed() {
    let names = claimed_bsd_names();
    let path = claimed_persist_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if names.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    if let Ok(text) = serde_json::to_string_pretty(&names) {
        let _ = std::fs::write(&path, text);
    }
}

fn claimed_persist_path() -> PathBuf {
    idle::status_path().with_file_name("claimed.json")
}

fn load_persisted_claimed() -> Vec<String> {
    let text = std::fs::read_to_string(claimed_persist_path()).ok().unwrap_or_default();
    serde_json::from_str(&text).unwrap_or_default()
}

pub fn clear_claimed() {
    claimed().clear();
    let _ = std::fs::remove_file(claimed_persist_path());
}

/// Record a BSD name we now own (dissent or take-over of a Finder UDF).
pub fn claim_bsd(bsd: impl Into<String>) {
    record_claim(bsd.into());
}

fn record_claim(bsd: String) {
    if bsd.is_empty() {
        return;
    }
    let mut g = claimed();
    if !g.contains(&bsd) {
        g.push(bsd);
    }
    drop(g);
    persist_claimed();
}

/// Refuse OS UDF/ISO mounts of Blu-ray media so the disc never appears
/// under `/Volumes`. DVD/CD (including AVCHD) are approved. Idempotent.
/// Must be running before the Blu-ray is inserted.
pub fn install_claim_hook() {
    CLAIM.call_once(|| unsafe {
        let session = DASessionCreate(std::ptr::null());
        if session.is_null() {
            warn!("DiskArbitration session could not be created; cannot claim the drive");
            return;
        }
        let queue = dispatch_queue_create(c"com.kevin.bdmount.claim".as_ptr(), std::ptr::null());
        DASessionSetDispatchQueue(session, queue);
        DARegisterDiskMountApprovalCallback(session, std::ptr::null(), on_mount_request, std::ptr::null_mut());
        info!("claiming IOBDMedia UDF mounts only; DVD/CD (including AVCHD) pass through to the OS");
    });
}

unsafe extern "C" fn on_mount_request(disk: DADiskRef, _context: *mut c_void) -> DADissenterRef {
    let dissent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let kind = volume_kind(disk).unwrap_or_default();
        if kind != "udf" && kind != "cd9660" {
            return false;
        }
        let bsd = bsd_name(disk);
        let class = optical_class_for_disk(disk);
        let has_bdmv = if class == OpticalClass::Unknown {
            raw_has_bdmv(&bsd)
        } else {
            false
        };
        if should_dissent(&kind, class, has_bdmv) {
            record_claim(bsd.clone());
            info!("dissenting OS mount of {bsd} (kind={kind} class={class:?})");
            true
        } else {
            info!("approving OS mount of {bsd} (kind={kind} class={class:?}; pass-through)");
            false
        }
    }))
    .unwrap_or(false);
    if dissent {
        unsafe {
            let msg = CFStringCreateWithCString(
                kCFAllocatorDefault,
                c"bdmount has exclusive access to this Blu-ray".as_ptr(),
                K_CF_STRING_ENCODING_UTF8,
            );
            let d = DADissenterCreate(kCFAllocatorDefault, K_DA_RETURN_EXCLUSIVE_ACCESS, msg);
            if !msg.is_null() {
                CFRelease(msg);
            }
            return d;
        }
    }
    std::ptr::null()
}

fn raw_has_bdmv(bsd: &str) -> bool {
    for p in rawudf::rdisk_paths_for_bsd(bsd) {
        match rawudf::RawUdf::open(&p) {
            Ok(mut u) => {
                if u.has_bdmv() {
                    return true;
                }
            }
            Err(e) => debug!("BDMV peek {}: {e:#}", p.display()),
        }
    }
    false
}

pub fn optical_class_for_bsd(bsd: &str) -> OpticalClass {
    let bsd = bsd.trim().trim_start_matches("/dev/r").trim_start_matches("/dev/");
    let Ok(name) = CString::new(bsd) else {
        return OpticalClass::Unknown;
    };
    unsafe {
        let matching = IOBSDNameMatching(kIOMainPortDefault, 0, name.as_ptr());
        if matching.is_null() {
            return OpticalClass::Unknown;
        }
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
        class_from_service(service)
    }
}

unsafe fn optical_class_for_disk(disk: DADiskRef) -> OpticalClass {
    unsafe {
        let media = DADiskCopyIOMedia(disk);
        if media != 0 {
            return class_from_service(media);
        }
        let bsd = bsd_name(disk);
        if bsd.is_empty() {
            OpticalClass::Unknown
        } else {
            optical_class_for_bsd(&bsd)
        }
    }
}

/// Walk the IOService plane from `service` (consumed) looking for optical media classes.
unsafe fn class_from_service(mut service: IoObject) -> OpticalClass {
    if service == 0 {
        return OpticalClass::Unknown;
    }
    unsafe {
        for _ in 0..16 {
            if IOObjectConformsTo(service, c"IOBDMedia".as_ptr()) != 0 {
                IOObjectRelease(service);
                return OpticalClass::BluRay;
            }
            if IOObjectConformsTo(service, c"IODVDMedia".as_ptr()) != 0 {
                IOObjectRelease(service);
                return OpticalClass::Dvd;
            }
            if IOObjectConformsTo(service, c"IOCDMedia".as_ptr()) != 0 {
                IOObjectRelease(service);
                return OpticalClass::Cd;
            }
            let mut parent: IoObject = 0;
            let kr = IORegistryEntryGetParentEntry(service, c"IOService".as_ptr(), &mut parent);
            IOObjectRelease(service);
            if kr != 0 || parent == 0 {
                return OpticalClass::Unknown;
            }
            service = parent;
        }
        IOObjectRelease(service);
    }
    OpticalClass::Unknown
}

unsafe fn volume_kind(disk: DADiskRef) -> Option<String> {
    unsafe {
        let desc = DADiskCopyDescription(disk);
        if desc.is_null() {
            return None;
        }
        let v = CFDictionaryGetValue(desc, kDADiskDescriptionVolumeKindKey);
        let s = cf_string(v);
        CFRelease(desc);
        s
    }
}

unsafe fn bsd_name(disk: DADiskRef) -> String {
    unsafe {
        let p = DADiskGetBSDName(disk);
        if p.is_null() {
            String::new()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

unsafe fn cf_string(s: CFTypeRef) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let mut buf = [0i8; 256];
    unsafe {
        if CFStringGetCString(s, buf.as_mut_ptr(), buf.len() as isize, K_CF_STRING_ENCODING_UTF8) == 0 {
            return None;
        }
        Some(CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned())
    }
}

/// Start listening for unmount requests. Idempotent; the session lives for
/// the rest of the process. Do not use in `mount` mode.
pub fn install_eject_hook() {
    START.call_once(|| unsafe {
        let session = DASessionCreate(std::ptr::null());
        if session.is_null() {
            warn!("DiskArbitration session could not be created; eject will not release the disc automatically");
            return;
        }
        let queue = dispatch_queue_create(c"com.kevin.bdmount.diskarbitration".as_ptr(), std::ptr::null());
        DASessionSetDispatchQueue(session, queue);
        DARegisterDiskUnmountApprovalCallback(session, std::ptr::null(), on_unmount_request, std::ptr::null_mut());
        // `session` and `queue` are intentionally leaked.
        debug!("DiskArbitration eject hook installed");
    });
}

unsafe fn volume_path(disk: DADiskRef) -> Option<PathBuf> {
    unsafe {
        let desc = DADiskCopyDescription(disk);
        if desc.is_null() {
            return None;
        }
        let url = CFDictionaryGetValue(desc, kDADiskDescriptionVolumePathKey);
        let path = if url.is_null() {
            None
        } else {
            let mut buf = vec![0u8; 4096];
            if CFURLGetFileSystemRepresentation(url, 1, buf.as_mut_ptr(), buf.len() as isize) != 0 {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                buf.truncate(len);
                let mut s = String::from_utf8_lossy(&buf).into_owned();
                while s.len() > 1 && s.ends_with('/') {
                    s.pop();
                }
                Some(PathBuf::from(s))
            } else {
                None
            }
        };
        CFRelease(desc);
        path
    }
}

unsafe extern "C" fn on_unmount_request(disk: DADiskRef, _context: *mut c_void) -> DADissenterRef {
    // Never let a panic unwind into DiskArbitration.
    let _ = std::panic::catch_unwind(|| unsafe {
        let Some(path) = volume_path(disk) else { return };
        let bsd = DADiskGetBSDName(disk);
        let bsd = if bsd.is_null() { String::new() } else { CStr::from_ptr(bsd).to_string_lossy().into_owned() };
        debug!("unmount requested for {} ({bsd})", path.display());

        let Some(md) = mount::find_by_path(&path) else { return };
        if path == md.source() {
            info!(
                "{} is being ejected; releasing the decrypted view at {} first",
                path.display(),
                md.mountpoint().display()
            );
            if let Err(e) = md.teardown(true) {
                warn!("teardown before eject: {e:#}");
            }
        } else {
            info!(
                "{} is being disconnected; releasing {} in MakeMKV",
                path.display(),
                md.source().display()
            );
            // DA is unmounting our view itself; just stop serving and free the drive.
            if let Err(e) = md.teardown(false) {
                warn!("teardown on disconnect: {e:#}");
            }
            let _ = std::fs::remove_dir(md.mountpoint());
        }
    });
    std::ptr::null() // approve
}

/// Unmount our NFS view, release our helper, wait idle, then eject trays we
/// claimed. `only` is a device or BSD name (`/dev/rdisk6`, `disk6`).
pub fn eject_after_release() -> Result<Vec<String>> {
    eject_after_release_filter(None)
}

pub fn eject_after_release_filter(only: Option<&str>) -> Result<Vec<String>> {
    let only_path = only.map(PathBuf::from);
    // Eject-all (or a dead engine) tears down every leftover view. A
    // per-device eject must leave the other discs serving.
    if only_path.is_none() {
        for mp in mount::active_mounts() {
            if let Err(e) = mount::unmount_path(&mp) {
                warn!("unmount {}: {e:#}", mp.display());
            }
            let _ = std::fs::remove_dir(&mp);
        }
        idle::release_our_helpers();
    }

    let mut disks = claimed_whole_disks();
    if let Some(only) = only {
        disks.retain(|bsd| {
            rawudf::devices_match(&PathBuf::from(format!("/dev/r{bsd}")), &PathBuf::from(only))
                || bsd == only
                || only.ends_with(bsd)
        });
    }
    if disks.is_empty() {
        bail!("no disc we claimed; a DVD/CD that macOS mounted is not ours to eject");
    }

    let source = rawudf::rdisk_paths_for_bsd(&disks[0])
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from(format!("/dev/r{}", disks[0])));
    let leftovers = idle::wait_until_idle(&source, source.to_str());
    if !idle::is_safe_to_eject(&leftovers, &source) {
        idle::print_eject_verdict(&leftovers, &source);
        bail!("holders remain; quit HandBrake and retry `bdmount eject`");
    }

    let mut ejected = Vec::new();
    for bsd in &disks {
        match optical_class_for_bsd(bsd) {
            OpticalClass::Dvd | OpticalClass::Cd => {
                warn!("refusing to eject pass-through disc {bsd}");
                continue;
            }
            OpticalClass::BluRay | OpticalClass::Unknown => {}
        }
        eject_whole_disk(bsd)?;
        ejected.push(bsd.clone());
    }
    if ejected.is_empty() {
        bail!("nothing to eject (claimed disks were pass-through DVD/CD)");
    }
    if only_path.is_none() {
        clear_claimed();
    } else {
        claimed().retain(|n| {
            !ejected.iter().any(|e| n == e || n.starts_with(&format!("{e}s")))
        });
        persist_claimed();
    }
    Ok(ejected)
}

/// `DADiskEject` the whole optical disk. No force / SCSI yank.
pub fn eject_whole_disk(bsd: &str) -> Result<()> {
    let whole = rawudf::bsd_whole_disk(bsd).unwrap_or_else(|| bsd.to_string());
    info!("ejecting {whole}");
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    unsafe {
        let session = DASessionCreate(std::ptr::null());
        if session.is_null() {
            bail!("DiskArbitration session could not be created");
        }
        let queue = dispatch_queue_create(c"com.kevin.bdmount.eject".as_ptr(), std::ptr::null());
        DASessionSetDispatchQueue(session, queue);
        let name = CString::new(whole.as_str())?;
        let disk = DADiskCreateFromBSDName(kCFAllocatorDefault, session, name.as_ptr());
        if disk.is_null() {
            bail!("no DiskArbitration disk for {whole}");
        }
        let ctx = Box::into_raw(Box::new(tx));
        DADiskEject(disk, K_DA_DISK_EJECT_OPTION_DEFAULT, on_ejected, ctx as *mut c_void);
    }
    match rx.recv_timeout(Duration::from_secs(45)) {
        Ok(Ok(())) => {
            info!("ejected {whole}");
            Ok(())
        }
        Ok(Err(e)) => bail!("eject {whole}: {e}"),
        Err(_) => bail!("eject {whole} timed out"),
    }
}

unsafe extern "C" fn on_ejected(_disk: DADiskRef, dissenter: DADissenterRef, context: *mut c_void) {
    let tx = unsafe { Box::from_raw(context as *mut std::sync::mpsc::Sender<Result<(), String>>) };
    if dissenter.is_null() {
        let _ = tx.send(Ok(()));
        return;
    }
    let msg = unsafe { cf_string(DADissenterGetStatusString(dissenter)) }.unwrap_or_else(|| "dissented".into());
    let _ = tx.send(Err(msg));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dissent_only_bluray_or_unknown_bdmv() {
        assert!(should_dissent("udf", OpticalClass::BluRay, false));
        assert!(should_dissent("udf", OpticalClass::BluRay, true));
        assert!(should_dissent("cd9660", OpticalClass::BluRay, false));
        assert!(!should_dissent("udf", OpticalClass::Dvd, true), "AVCHD on DVD must pass through");
        assert!(!should_dissent("udf", OpticalClass::Cd, true));
        assert!(should_dissent("udf", OpticalClass::Unknown, true));
        assert!(!should_dissent("udf", OpticalClass::Unknown, false));
        assert!(!should_dissent("hfs", OpticalClass::BluRay, true));
    }

    #[test]
    fn missing_disk_is_unknown_class() {
        assert_eq!(optical_class_for_bsd("disk999"), OpticalClass::Unknown);
    }
}
