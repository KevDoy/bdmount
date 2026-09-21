//! Blu-ray volume discovery and the virtual (decrypted) directory tree.
//!
//! The virtual tree mirrors the disc as macOS mounts it under `/Volumes`,
//! minus the copy-protection directories (`AACS/`, `BDSVM/`, ...). Stream
//! files are tagged with the libmmbd name flags needed to decrypt them; every
//! other file is served as-is.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tracing::{debug, warn};

use crate::mmbd;

/// Directories at the disc root that must not appear in the decrypted view.
pub(crate) const HIDDEN_ROOT_DIRS: &[&str] = &[
    "AACS",
    "BDSVM",
    "MAKEMKV",
    ".Spotlight-V100",
    ".fseventsd",
    ".Trashes",
    ".TemporaryItems",
    ".DS_Store",
    "$RECYCLE.BIN",
    "System Volume Information",
];

pub type NodeId = u64;
pub const ROOT_ID: NodeId = 1;

#[derive(Debug, Clone)]
pub enum NodeKind {
    Dir { children: Vec<NodeId> },
    /// Served byte-for-byte from `path`.
    Passthrough,
    /// Served through libmmbd with the given name flags.
    Encrypted { name_flags: u32 },
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: NodeId,
    pub parent: NodeId,
    pub name: Vec<u8>,
    /// Path on the real (encrypted) volume.
    pub path: PathBuf,
    pub size: u64,
    pub mtime: SystemTime,
    pub kind: NodeKind,
}

impl Node {
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Dir { .. })
    }
}

/// In-memory snapshot of a disc's directory structure.
pub struct DiscTree {
    pub source: PathBuf,
    pub label: String,
    nodes: HashMap<NodeId, Node>,
    lookup: HashMap<(NodeId, Vec<u8>), NodeId>,
    pub encrypted_count: usize,
    pub file_count: usize,
}

impl DiscTree {
    /// Walk the volume at `source` once and build the tree.
    pub fn scan(source: &Path) -> Result<DiscTree> {
        let source = source
            .canonicalize()
            .with_context(|| format!("cannot access {}", source.display()))?;
        if !source.join("BDMV").join("index.bdmv").is_file() {
            bail!("{} does not look like a Blu-ray (no BDMV/index.bdmv)", source.display());
        }
        let label = source
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "BluRay".into());

        let root_meta = fs::metadata(&source)?;
        let mut tree = DiscTree {
            source: source.clone(),
            label,
            nodes: HashMap::new(),
            lookup: HashMap::new(),
            encrypted_count: 0,
            file_count: 0,
        };
        tree.nodes.insert(
            ROOT_ID,
            Node {
                id: ROOT_ID,
                parent: ROOT_ID,
                name: b"/".to_vec(),
                path: source.clone(),
                size: 0,
                mtime: root_meta.modified().unwrap_or(UNIX_EPOCH),
                kind: NodeKind::Dir { children: vec![] },
            },
        );
        let mut next_id = ROOT_ID + 1;
        tree.walk(ROOT_ID, &source, &source, &mut next_id)?;
        debug!(
            "scanned {}: {} files, {} encrypted streams",
            source.display(),
            tree.file_count,
            tree.encrypted_count
        );
        Ok(tree)
    }

    /// Walk a Blu-ray from a userspace UDF session (no `/Volumes`).
    pub fn scan_udf(udf: &std::sync::Mutex<crate::rawudf::RawUdf>) -> Result<DiscTree> {
        use crate::rawudf::sanitize_label;
        let mut g = udf.lock().unwrap();
        if !g.has_bdmv() {
            bail!("{} has no BDMV/index.bdmv", g.device.display());
        }
        let label = sanitize_label(&g.label);
        let source = g.device.clone();
        drop(g);

        let mut tree = DiscTree {
            source,
            label,
            nodes: HashMap::new(),
            lookup: HashMap::new(),
            encrypted_count: 0,
            file_count: 0,
        };
        tree.nodes.insert(
            ROOT_ID,
            Node {
                id: ROOT_ID,
                parent: ROOT_ID,
                name: b"/".to_vec(),
                path: PathBuf::from("/"),
                size: 0,
                mtime: UNIX_EPOCH,
                kind: NodeKind::Dir { children: vec![] },
            },
        );
        let mut next_id = ROOT_ID + 1;
        tree.walk_udf(udf, ROOT_ID, "", &mut next_id)?;
        debug!(
            "scanned UDF {}: {} files, {} encrypted streams",
            tree.source.display(),
            tree.file_count,
            tree.encrypted_count
        );
        Ok(tree)
    }

    fn walk_udf(
        &mut self,
        udf: &std::sync::Mutex<crate::rawudf::RawUdf>,
        parent: NodeId,
        rel: &str,
        next_id: &mut NodeId,
    ) -> Result<()> {
        let entries = udf.lock().unwrap().list_dir(rel)?;
        let is_root = rel.is_empty();
        let mut children = Vec::new();
        for e in entries {
            if is_root && HIDDEN_ROOT_DIRS.iter().any(|h| h.eq_ignore_ascii_case(&e.name)) {
                debug!("hiding {}", e.name);
                continue;
            }
            if e.name == ".DS_Store" {
                continue;
            }
            let child_rel = if rel.is_empty() {
                e.name.clone()
            } else {
                format!("{rel}/{}", e.name)
            };
            let id = *next_id;
            *next_id += 1;
            let path = PathBuf::from(&child_rel);
            if e.is_directory {
                self.nodes.insert(
                    id,
                    Node {
                        id,
                        parent,
                        name: e.name.as_bytes().to_vec(),
                        path: path.clone(),
                        size: 0,
                        mtime: UNIX_EPOCH,
                        kind: NodeKind::Dir { children: vec![] },
                    },
                );
                self.lookup.insert((parent, e.name.as_bytes().to_vec()), id);
                children.push(id);
                self.walk_udf(udf, id, &child_rel, next_id)?;
            } else {
                let size = udf.lock().unwrap().file_size(&child_rel).unwrap_or(0);
                let kind = classify(Path::new(""), &path, &e.name)
                    .map(|flags| NodeKind::Encrypted { name_flags: flags })
                    .unwrap_or(NodeKind::Passthrough);
                if matches!(kind, NodeKind::Encrypted { .. }) {
                    self.encrypted_count += 1;
                }
                self.file_count += 1;
                self.nodes.insert(
                    id,
                    Node {
                        id,
                        parent,
                        name: e.name.as_bytes().to_vec(),
                        path,
                        size,
                        mtime: UNIX_EPOCH,
                        kind,
                    },
                );
                self.lookup.insert((parent, e.name.as_bytes().to_vec()), id);
                children.push(id);
            }
        }
        if let Some(Node {
            kind: NodeKind::Dir { children: c },
            ..
        }) = self.nodes.get_mut(&parent)
        {
            *c = children;
        }
        Ok(())
    }

    fn walk(&mut self, parent: NodeId, dir: &Path, root: &Path, next_id: &mut NodeId) -> Result<()> {
        let mut entries: Vec<fs::DirEntry> = fs::read_dir(dir)
            .with_context(|| format!("read_dir {}", dir.display()))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        let is_root = dir == root;
        let mut children = Vec::with_capacity(entries.len());

        for entry in entries {
            let name_os = entry.file_name();
            let name = name_os.to_string_lossy().into_owned();
            if is_root && HIDDEN_ROOT_DIRS.iter().any(|h| h.eq_ignore_ascii_case(&name)) {
                debug!("hiding {name}");
                continue;
            }
            if name == ".DS_Store" {
                continue;
            }
            let path = entry.path();
            let meta = match fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    warn!("skipping {}: {e}", path.display());
                    continue;
                }
            };
            let id = *next_id;
            *next_id += 1;
            let mtime = meta.modified().unwrap_or(UNIX_EPOCH);

            if meta.is_dir() {
                self.nodes.insert(
                    id,
                    Node {
                        id,
                        parent,
                        name: name_os.as_encoded_bytes().to_vec(),
                        path: path.clone(),
                        size: 0,
                        mtime,
                        kind: NodeKind::Dir { children: vec![] },
                    },
                );
                self.lookup.insert((parent, name_os.as_encoded_bytes().to_vec()), id);
                children.push(id);
                self.walk(id, &path, root, next_id)?;
            } else if meta.is_file() {
                let kind = classify(root, &path, &name)
                    .map(|flags| NodeKind::Encrypted { name_flags: flags })
                    .unwrap_or(NodeKind::Passthrough);
                if matches!(kind, NodeKind::Encrypted { .. }) {
                    self.encrypted_count += 1;
                }
                self.file_count += 1;
                self.nodes.insert(
                    id,
                    Node {
                        id,
                        parent,
                        name: name_os.as_encoded_bytes().to_vec(),
                        path,
                        size: meta.len(),
                        mtime,
                        kind,
                    },
                );
                self.lookup.insert((parent, name_os.as_encoded_bytes().to_vec()), id);
                children.push(id);
            }
        }

        if let Some(Node {
            kind: NodeKind::Dir { children: c },
            ..
        }) = self.nodes.get_mut(&parent)
        {
            *c = children;
        }
        Ok(())
    }

    pub fn get(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    pub fn lookup(&self, parent: NodeId, name: &[u8]) -> Option<NodeId> {
        self.lookup.get(&(parent, name.to_vec())).copied()
    }

    pub fn children(&self, id: NodeId) -> &[NodeId] {
        match self.nodes.get(&id) {
            Some(Node {
                kind: NodeKind::Dir { children },
                ..
            }) => children,
            _ => &[],
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    /// The largest encrypted stream file (the main feature, usually).
    pub fn largest_encrypted(&self) -> Option<&Node> {
        self.nodes
            .values()
            .filter(|n| matches!(n.kind, NodeKind::Encrypted { .. }))
            .max_by_key(|n| n.size)
    }
}

/// Decide whether a file needs decryption and with which libmmbd name flags.
fn classify(root: &Path, path: &Path, name: &str) -> Option<u32> {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let comps: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_uppercase())
        .collect();
    let lower = name.to_ascii_lowercase();
    match comps.as_slice() {
        [bdmv, stream, _] if bdmv == "BDMV" && stream == "STREAM" && lower.ends_with(".m2ts") => {
            mmbd::clip_number(name).map(|n| mmbd::FILE_M2TS | n)
        }
        [bdmv, stream, ssif, _]
            if bdmv == "BDMV" && stream == "STREAM" && ssif == "SSIF" && lower.ends_with(".ssif") =>
        {
            mmbd::clip_number(name).map(|n| mmbd::FILE_SSIF | n)
        }
        _ => None,
    }
}

/// A mounted optical volume that looks like a Blu-ray.
#[derive(Debug, Clone)]
pub struct BdVolume {
    pub path: PathBuf,
    pub label: String,
    /// Has an `AACS/` directory, i.e. needs decryption.
    pub protected: bool,
}

/// Enumerate `/Volumes` for Blu-ray discs (BDMV/index.bdmv present).
pub fn find_bd_volumes() -> Vec<BdVolume> {
    find_bd_volumes_except(&[])
}

/// Like [`find_bd_volumes`] but never touches the volumes in `skip`.
///
/// Candidates come from the kernel mount table (optical filesystems under
/// `/Volumes`), so the only disc I/O is the `stat` of `BDMV/index.bdmv` on
/// volumes we are not already serving. A volume we *are* serving is never
/// stat'ed here: if it is mid-eject that stat can hang the caller.
pub fn find_bd_volumes_except(skip: &[PathBuf]) -> Vec<BdVolume> {
    let mut out = Vec::new();
    for m in crate::mount::mount_table() {
        if !m.mount_point.starts_with("/Volumes") {
            continue;
        }
        if !matches!(m.fs_type.as_str(), "udf" | "cd9660" | "hfs" | "apfs") {
            continue;
        }
        if skip.iter().any(|s| *s == m.mount_point) {
            continue;
        }
        // Local block devices only (discs, or mounted Blu-ray ISOs); never
        // stat into network shares such as our own NFS views.
        if !m.from.starts_with("/dev/disk") {
            continue;
        }
        if let Some(v) = inspect_volume(&m.mount_point) {
            out.push(v);
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub fn inspect_volume(path: &Path) -> Option<BdVolume> {
    if !path.join("BDMV").join("index.bdmv").is_file() {
        return None;
    }
    Some(BdVolume {
        path: path.to_path_buf(),
        label: path.file_name()?.to_string_lossy().into_owned(),
        protected: path.join("AACS").is_dir(),
    })
}

/// Resolve the whole-disk raw device (`/dev/rdiskN`) backing a mounted volume.
pub fn raw_device_for_volume(volume: &Path) -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/diskutil")
        .args(["info", "-plist"])
        .arg(volume)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Look for <key>ParentWholeDisk</key><string>diskN</string>
    let idx = text.find("<key>ParentWholeDisk</key>")?;
    let rest = &text[idx..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")? + start;
    Some(format!("/dev/r{}", rest[start..end].trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_streams() {
        let root = Path::new("/Volumes/X");
        assert_eq!(
            classify(root, &root.join("BDMV/STREAM/00012.m2ts"), "00012.m2ts"),
            Some(mmbd::FILE_M2TS | 12)
        );
        assert_eq!(
            classify(root, &root.join("BDMV/STREAM/SSIF/00003.ssif"), "00003.ssif"),
            Some(mmbd::FILE_SSIF | 3)
        );
        assert_eq!(classify(root, &root.join("BDMV/BACKUP/STREAM/00012.m2ts"), "00012.m2ts"), None);
        assert_eq!(classify(root, &root.join("BDMV/PLAYLIST/00000.mpls"), "00000.mpls"), None);
    }
}
