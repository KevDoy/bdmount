//! Optical drive inventory for the menubar (internal + USB/Thunderbolt).
//!
//! Uses `diskutil info` `OpticalDeviceType` / `BusProtocol` plus IOKit class.
//! Empty drives are listed; DVD/CD media is marked so the GUI does not offer eject.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::da::{self, OpticalClass};
use crate::idle::DriveStatus;
use crate::rawudf;

#[derive(Debug, Clone)]
pub struct OpticalDrive {
    pub id: String,
    pub device: PathBuf,
    pub bus: String,
    pub class: OpticalClass,
    pub media: bool,
    pub bd_capable: bool,
}

fn plist_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let idx = text.find(&needle)?;
    let rest = &text[idx + needle.len()..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")? + start;
    let s = rest[start..end].trim();
    if s.is_empty() { None } else { Some(s.to_string()) }
}

fn diskutil_info(bsd: &str) -> Option<String> {
    let out = Command::new("/usr/sbin/diskutil").args(["info", "-plist", bsd]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn normalize_bus(proto: &str) -> String {
    match proto.to_ascii_lowercase().as_str() {
        "usb" => "usb".into(),
        "sata" | "serial ata" => "sata".into(),
        "thunderbolt" => "thunderbolt".into(),
        "atapi" | "ata" => "ata".into(),
        other => other.to_string(),
    }
}

fn class_from_optical_type(s: &str) -> Option<OpticalClass> {
    let u = s.to_ascii_uppercase();
    if u.contains("BD") || u.contains("BLU") {
        Some(OpticalClass::BluRay)
    } else if u.contains("DVD") {
        Some(OpticalClass::Dvd)
    } else if u.contains("CD") {
        Some(OpticalClass::Cd)
    } else {
        None
    }
}

/// Whole-disk identifiers that look like optical hardware.
pub fn list_drive_ids() -> Vec<String> {
    let mut ids = Vec::new();
    let Ok(out) = Command::new("/usr/sbin/diskutil").args(["list"]).output() else {
        return ids;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(rest) = line.strip_prefix("/dev/") {
            let id = rest.split_whitespace().next().unwrap_or("");
            if let Some(whole) = rawudf::bsd_whole_disk(id) {
                if whole != "disk0" && !ids.contains(&whole) {
                    ids.push(whole);
                }
            }
        }
        let optical = line.contains("CD_partition")
            || line.contains("CD_ROM")
            || line.contains("DVD_")
            || line.contains("BD_")
            || line.contains("Apple_UDF")
            || line.contains("CD_partition_scheme");
        if optical {
            if let Some(id) = line.split_whitespace().last() {
                if let Some(whole) = rawudf::bsd_whole_disk(id) {
                    if whole != "disk0" && !ids.contains(&whole) {
                        ids.push(whole);
                    }
                }
            }
        }
    }
    ids.retain(|id| {
        diskutil_info(id).is_some_and(|info| {
            info.contains("<key>OpticalDeviceType</key>")
                || info.contains("<key>OpticalMediaType</key>")
                || info.contains("CD_partition")
                || info.contains("Blu-ray")
        })
    });
    ids.sort();
    ids.dedup();
    ids
}

pub fn list_drives() -> Vec<OpticalDrive> {
    let mut out = Vec::new();
    for id in list_drive_ids() {
        let info = diskutil_info(&id).unwrap_or_default();
        let bus = plist_string(&info, "BusProtocol")
            .map(|s| normalize_bus(&s))
            .unwrap_or_else(|| "unknown".into());
        let iokit = da::optical_class_for_bsd(&id);
        let media_type = plist_string(&info, "OpticalMediaType");
        let device_type = plist_string(&info, "OpticalDeviceType");
        let media_class = media_type
            .as_deref()
            .and_then(class_from_optical_type)
            .unwrap_or(iokit);
        let bd_capable = device_type
            .as_deref()
            .and_then(class_from_optical_type)
            == Some(OpticalClass::BluRay)
            || iokit == OpticalClass::BluRay
            || device_type.as_deref().is_some_and(|s| s.to_ascii_uppercase().contains("BD"));
        let media = media_type.is_some() || !matches!(media_class, OpticalClass::Unknown);
        let device = PathBuf::from(format!("/dev/r{id}"));
        out.push(OpticalDrive {
            id,
            device,
            bus,
            class: media_class,
            media,
            bd_capable,
        });
    }
    out
}

pub fn media_class_name(class: OpticalClass, media: bool) -> &'static str {
    if !media {
        return "empty";
    }
    match class {
        OpticalClass::BluRay => "bluray",
        OpticalClass::Dvd => "dvd",
        OpticalClass::Cd => "cd",
        OpticalClass::Unknown => "unknown",
    }
}

pub fn drive_statuses(live: &[(String, String, String, bool)]) -> Vec<DriveStatus> {
    // live: (device, label, mountpoint, safe)
    let mut out = Vec::new();
    for d in list_drives() {
        let match_live = live.iter().find(|(dev, _, _, _)| {
            rawudf::devices_match(Path::new(dev), &d.device) || Path::new(dev).ends_with(&d.id)
        });
        let (label, mountpoint, state, safe) = if let Some((_, label, mp, safe)) = match_live {
            (Some(label.clone()), Some(mp.clone()), "serving".into(), *safe)
        } else if matches!(d.class, OpticalClass::Dvd | OpticalClass::Cd) && d.media {
            (None, None, "passthrough".into(), true)
        } else {
            (None, None, "waiting".into(), true)
        };
        out.push(DriveStatus {
            id: d.id.clone(),
            device: d.device.display().to_string(),
            bus: d.bus,
            media_class: media_class_name(d.class, d.media).into(),
            media: d.media,
            bd_capable: d.bd_capable,
            label,
            mountpoint,
            state,
            safe_to_eject: safe,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_normalizes() {
        assert_eq!(normalize_bus("USB"), "usb");
        assert_eq!(normalize_bus("SATA"), "sata");
        assert_eq!(normalize_bus("Thunderbolt"), "thunderbolt");
    }

    #[test]
    fn optical_type_to_class() {
        assert_eq!(class_from_optical_type("Blu-ray"), Some(OpticalClass::BluRay));
        assert_eq!(class_from_optical_type("DVD-R"), Some(OpticalClass::Dvd));
        assert_eq!(class_from_optical_type("CD-ROM"), Some(OpticalClass::Cd));
    }

    #[test]
    fn plist_string_reads_protocol() {
        let t = "<key>BusProtocol</key>\n<string>USB</string>";
        assert_eq!(plist_string(t, "BusProtocol").as_deref(), Some("USB"));
    }
}
