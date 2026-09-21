//! Userspace UDF reader on `/dev/rdiskN` so we never touch `/Volumes`.
//!
//! `oxideav-bluray`'s `UdfDisc::open` refuses commercial BD-ROM discs:
//! it compares the FSD `partition_ref` (an LVD **map index**) to the
//! Partition Descriptor's **partition number**. On a typical disc those
//! are `0` and `1`. Authored Blu-rays also put the FSD in a UDF 2.50
//! metadata partition. We parse the maps ourselves.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use oxideav_bluray::udf::{
    AdType, AnchorVolumeDescriptorPointer, DirEntry, FileEntry, FileIdentifierDescriptor,
    FileSetDescriptor, LongAd, LogicalVolumeDescriptor, PartitionDescriptor,
    PrimaryVolumeDescriptor, TagId,
};
use tracing::{info, warn};

use crate::da;

const SECTOR: u64 = 2048;
/// USB optical bridges often cap a single `pread`. Loop in 1 MiB
/// chunks so we do not issue dozens of 64 KiB commands per window.
const MAX_XFER: usize = 1024 * 1024;
/// Userspace stand-in for the kernel UDF readahead we lost by leaving `/Volumes`.
/// Paired with [`RawUdf::prefetch`] (16 MiB next-window slot) and, when the
/// optical geometry is 2048, payload I/O on buffered `/dev/diskN`.
pub const PREFETCH_WINDOW: usize = 16 * 1024 * 1024;
const READAHEAD: usize = PREFETCH_WINDOW;

#[derive(Clone)]
enum Space {
    Physical { start: u64 },
    /// Virtual partition: each logical block is a 2048-byte slot in these
    /// physical extents (`abs_sector`, `length_bytes`).
    Metadata { extents: Vec<(u64, u32)> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PartMap {
    Type1 { partition_number: u16 },
    Metadata {
        physical_partition_number: u16,
        metadata_file_loc: u32,
        mirror_file_loc: u32,
    },
    Other,
}

struct Ahead {
    rel: String,
    off: u64,
    buf: Vec<u8>,
}

pub struct RawUdf {
    file: File,
    spaces: Vec<Option<Space>>,
    root_icb: LongAd,
    pub label: String,
    pub device: PathBuf,
    files: HashMap<String, FileMeta>,
    ahead: Option<Ahead>,
    next: Option<Ahead>,
}

#[derive(Clone)]
struct FileMeta {
    size: u64,
    /// Absolute byte offset on the device + length.
    extents: Vec<(u64, u32)>,
    embedded: Option<Vec<u8>>,
}

fn read_sector(file: &File, lba: u64) -> Result<[u8; SECTOR as usize]> {
    let mut buf = [0u8; SECTOR as usize];
    let n = file
        .read_at(&mut buf, lba * SECTOR)
        .with_context(|| format!("read sector {lba}"))?;
    if n < buf.len() {
        bail!("short read at sector {lba} ({n} bytes)");
    }
    Ok(buf)
}

/// `/dev/rdisk` on optical media rejects `pread` unless offset and
/// length are multiples of 2048. Read the covering sectors, then slice.
/// Loops: a USB bridge that returns 64 KiB of a 4 MiB request is not EOF.
fn read_abs(file: &File, abs_byte: u64, count: usize) -> Result<Vec<u8>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let start = abs_byte / SECTOR * SECTOR;
    let skip = (abs_byte - start) as usize;
    let total = ((skip + count) as u64).div_ceil(SECTOR) * SECTOR;
    let mut buf = vec![0u8; total as usize];
    let mut done = 0usize;
    while done < buf.len() {
        let chunk = (buf.len() - done).min(MAX_XFER);
        let n = file
            .read_at(&mut buf[done..done + chunk], start + done as u64)
            .with_context(|| format!("pread {}+{chunk}", start + done as u64))?;
        if n == 0 {
            break;
        }
        done += n;
    }
    buf.truncate(done);
    let from = skip.min(buf.len());
    let to = (skip + count).min(buf.len());
    Ok(buf[from..to].to_vec())
}

fn enable_readahead(file: &File) {
    // F_RDAHEAD = 45 on Darwin. Best-effort; ignored if the fd is not a file.
    const F_RDAHEAD: libc::c_int = 45;
    unsafe {
        libc::fcntl(file.as_raw_fd(), F_RDAHEAD, 1);
    }
}

/// Prefer `/dev/diskN` (buffer cache + kernel readahead) when it has
/// the same 2048-byte optical geometry as `/dev/rdiskN`.
fn open_payload_file(rdisk: &Path, fallback: File) -> File {
    let Some(name) = rdisk.file_name() else {
        return fallback;
    };
    let name = name.to_string_lossy();
    let Some(rest) = name.strip_prefix('r') else {
        return fallback;
    };
    let block = rdisk.with_file_name(rest);
    let Ok(f) = File::open(&block) else {
        return fallback;
    };
    let mut bs: u32 = 0;
    // DKIOCGETBLOCKSIZE = _IOR('d', 24, uint32_t) → 0x40046418
    let ok = unsafe { libc::ioctl(f.as_raw_fd(), 0x4004_6418, &mut bs) == 0 };
    if ok && bs == SECTOR as u32 {
        info!("payload I/O via buffered {} ({}-byte blocks)", block.display(), bs);
        enable_readahead(&f);
        f
    } else {
        fallback
    }
}

fn read_fe(file: &File, lba: u64) -> Result<FileEntry> {
    let mut buf = vec![0u8; 8192];
    file.read_at(&mut buf, lba * SECTOR)
        .with_context(|| format!("read File Entry at LBA {lba}"))?;
    FileEntry::parse(&buf).map_err(|e| anyhow::anyhow!("parse File Entry at LBA {lba}: {e}"))
}

/// LVD partition-map table starts at byte 440 (§10.6).
fn parse_partition_maps(lvd_sector: &[u8]) -> Result<Vec<PartMap>> {
    if lvd_sector.len() < 440 {
        bail!("LVD truncated before partition maps");
    }
    let map_len = u32::from_le_bytes(lvd_sector[264..268].try_into()?) as usize;
    let nmaps = u32::from_le_bytes(lvd_sector[268..272].try_into()?) as usize;
    if nmaps == 0 {
        return Ok(Vec::new());
    }
    let end = 440usize.saturating_add(map_len).min(lvd_sector.len());
    let table = &lvd_sector[440..end];
    let mut off = 0;
    let mut maps = Vec::with_capacity(nmaps);
    for i in 0..nmaps {
        if off + 2 > table.len() {
            bail!("partition map {i} overruns table");
        }
        let len = table[off + 1] as usize;
        if len < 2 || off + len > table.len() {
            bail!("partition map {i} length {len} is invalid");
        }
        let raw = &table[off..off + len];
        maps.push(parse_one_map(raw));
        off += len;
    }
    Ok(maps)
}

fn parse_one_map(raw: &[u8]) -> PartMap {
    match raw[0] {
        1 if raw.len() >= 6 => PartMap::Type1 {
            partition_number: u16::from_le_bytes([raw[4], raw[5]]),
        },
        2 if raw.len() >= 64 && is_metadata_ident(&raw[4..36]) => PartMap::Metadata {
            physical_partition_number: u16::from_le_bytes([raw[38], raw[39]]),
            metadata_file_loc: u32::from_le_bytes([raw[40], raw[41], raw[42], raw[43]]),
            mirror_file_loc: u32::from_le_bytes([raw[44], raw[45], raw[46], raw[47]]),
        },
        _ => PartMap::Other,
    }
}

fn is_metadata_ident(regid: &[u8]) -> bool {
    // EntityID: flags (1) + 23-byte identifier. Look past the flags byte.
    let s = if regid.len() > 1 { &regid[1..] } else { regid };
    s.windows(b"Metadata".len()).any(|w| w == b"Metadata")
}

fn fe_physical_extents(fe: &FileEntry, phys_start: u64) -> Vec<(u64, u32)> {
    fe.extents()
        .into_iter()
        .filter(|e| e.extent_type == 0)
        .map(|e| (phys_start + e.block as u64, e.length))
        .collect()
}

impl RawUdf {
    pub fn open(device: &Path) -> Result<RawUdf> {
        let file = File::open(device).with_context(|| format!("open {}", device.display()))?;
        enable_readahead(&file);
        let avdp_buf = read_sector(&file, 256)?;
        let avdp = AnchorVolumeDescriptorPointer::parse(&avdp_buf)
            .map_err(|e| anyhow::anyhow!("AVDP: {e}"))?;
        let main = avdp.main_volume_descriptor_sequence;
        let max = (main.length as u64 / SECTOR).max(1);
        let mut pvd: Option<PrimaryVolumeDescriptor> = None;
        let mut pds: Vec<PartitionDescriptor> = Vec::new();
        let mut lvd: Option<LogicalVolumeDescriptor> = None;
        let mut lvd_raw: Option<[u8; SECTOR as usize]> = None;
        for i in 0..max {
            let buf = read_sector(&file, main.location as u64 + i)?;
            let id = u16::from_le_bytes([buf[0], buf[1]]);
            let Some(tag) = TagId::from_raw(id) else { continue };
            match tag {
                TagId::PrimaryVolume => {
                    pvd = Some(
                        PrimaryVolumeDescriptor::parse(&buf).map_err(|e| anyhow::anyhow!("PVD: {e}"))?,
                    );
                }
                TagId::Partition => {
                    pds.push(
                        PartitionDescriptor::parse(&buf).map_err(|e| anyhow::anyhow!("PD: {e}"))?,
                    );
                }
                TagId::LogicalVolume => {
                    lvd = Some(
                        LogicalVolumeDescriptor::parse(&buf).map_err(|e| anyhow::anyhow!("LVD: {e}"))?,
                    );
                    lvd_raw = Some(buf);
                }
                TagId::Terminating => break,
                _ => {}
            }
        }
        let pvd = pvd.ok_or_else(|| anyhow::anyhow!("no Primary Volume Descriptor"))?;
        let lvd = lvd.ok_or_else(|| anyhow::anyhow!("no Logical Volume Descriptor"))?;
        if pds.is_empty() {
            bail!("no Partition Descriptor");
        }
        if lvd.logical_block_size as u64 != SECTOR {
            bail!("logical_block_size {} (need 2048)", lvd.logical_block_size);
        }

        let maps = lvd_raw
            .as_ref()
            .map(|raw| parse_partition_maps(raw))
            .transpose()?
            .unwrap_or_default();
        let fsd_ref = lvd.file_set_descriptor_location.location.partition_ref;
        let spaces = build_spaces(&file, &pds, &maps, fsd_ref)?;

        let fsd_block = lvd.file_set_descriptor_location.location.block as u64;
        let fsd_lba = resolve(&spaces, fsd_ref, fsd_block)?;
        let fsd = FileSetDescriptor::parse(&read_sector(&file, fsd_lba)?)
            .map_err(|e| anyhow::anyhow!("FSD: {e}"))?;

        let label = if pvd.volume_identifier.trim().is_empty() {
            "BluRay".into()
        } else {
            pvd.volume_identifier.clone()
        };
        info!(
            "opened UDF on {} label={label:?} maps={} pds={} fsd_ref={fsd_ref} fsd_lba={fsd_lba}",
            device.display(),
            maps.len(),
            pds.len(),
        );
        let file = open_payload_file(device, file);
        Ok(RawUdf {
            file,
            spaces,
            root_icb: fsd.root_directory_icb,
            label,
            device: device.to_path_buf(),
            files: HashMap::new(),
            ahead: None,
            next: None,
        })
    }

    fn resolve(&self, part_ref: u16, block: u64) -> Result<u64> {
        resolve(&self.spaces, part_ref, block)
    }

    fn read_fe_at(&self, icb: LongAd) -> Result<FileEntry> {
        let lba = self.resolve(icb.location.partition_ref, icb.location.block as u64)?;
        read_fe(&self.file, lba)
    }

    fn lookup(&mut self, path: &str) -> Result<LongAd> {
        let mut cur = self.root_icb;
        let mut is_dir = true;
        for component in path.split('/').filter(|s| !s.is_empty()) {
            if !is_dir {
                bail!("path descends into a file at {component}");
            }
            let entries = self.read_directory(cur)?;
            let m = entries
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case(component))
                .ok_or_else(|| anyhow::anyhow!("no {component:?} in UDF directory"))?;
            cur = m.icb;
            is_dir = m.is_directory;
        }
        Ok(cur)
    }

    fn read_directory(&mut self, icb: LongAd) -> Result<Vec<DirEntry>> {
        let raw = self.read_file_bytes(icb)?;
        let mut out = Vec::new();
        let mut o = 0;
        while o + 38 <= raw.len() {
            let fid = FileIdentifierDescriptor::parse(&raw[o..])
                .map_err(|e| anyhow::anyhow!("FID at {o}: {e}"))?;
            o += fid.total_size;
            if fid.is_deleted() || fid.is_parent() {
                continue;
            }
            let is_directory = fid.is_directory();
            out.push(DirEntry {
                name: fid.identifier,
                icb: fid.icb,
                is_directory,
            });
        }
        Ok(out)
    }

    fn read_file_bytes(&mut self, icb: LongAd) -> Result<Vec<u8>> {
        let fe = self.read_fe_at(icb)?;
        let want = fe.information_length as usize;
        if fe.ad_type == AdType::EmbeddedInIcb {
            return Ok(fe.embedded_data[..want.min(fe.embedded_data.len())].to_vec());
        }
        let mut out = Vec::with_capacity(want);
        for (abs, len) in self.extents_abs(&fe, icb.location.partition_ref)? {
            out.extend_from_slice(&read_abs(&self.file, abs, len as usize)?);
            if out.len() >= want {
                break;
            }
        }
        out.truncate(want);
        Ok(out)
    }

    fn extents_abs(&self, fe: &FileEntry, implied_ref: u16) -> Result<Vec<(u64, u32)>> {
        let mut out = Vec::new();
        for e in fe.extents() {
            if e.extent_type != 0 {
                continue;
            }
            let pref = e.partition_ref.unwrap_or(implied_ref);
            let lba = self.resolve(pref, e.block as u64)?;
            out.push((lba * SECTOR, e.length));
        }
        Ok(out)
    }

    pub fn has_bdmv(&mut self) -> bool {
        self.lookup("BDMV/index.bdmv").is_ok()
    }

    pub fn list_dir(&mut self, rel: &str) -> Result<Vec<DirEntry>> {
        let icb = if rel.is_empty() || rel == "/" {
            self.root_icb
        } else {
            self.lookup(rel)?
        };
        self.read_directory(icb)
    }

    fn meta(&mut self, rel: &str) -> Result<FileMeta> {
        if let Some(m) = self.files.get(rel) {
            return Ok(m.clone());
        }
        let icb = self.lookup(rel)?;
        let fe = self.read_fe_at(icb)?;
        let m = if fe.ad_type == AdType::EmbeddedInIcb {
            let n = fe.information_length as usize;
            FileMeta {
                size: fe.information_length,
                extents: Vec::new(),
                embedded: Some(fe.embedded_data[..n.min(fe.embedded_data.len())].to_vec()),
            }
        } else {
            FileMeta {
                size: fe.information_length,
                extents: self.extents_abs(&fe, icb.location.partition_ref)?,
                embedded: None,
            }
        };
        self.files.insert(rel.to_string(), m.clone());
        Ok(m)
    }

    pub fn file_size(&mut self, rel: &str) -> Result<u64> {
        Ok(self.meta(rel)?.size)
    }

    fn slice_ahead(a: &Ahead, offset: u64, end: u64) -> Option<Vec<u8>> {
        let a_end = a.off + a.buf.len() as u64;
        if offset >= a.off && end <= a_end {
            let s = (offset - a.off) as usize;
            Some(a.buf[s..s + (end - offset) as usize].to_vec())
        } else {
            None
        }
    }

    pub fn read_at(&mut self, rel: &str, offset: u64, count: usize) -> Result<Vec<u8>> {
        let m = self.meta(rel)?;
        if offset >= m.size || count == 0 {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(count as u64).min(m.size);
        if let Some(emb) = &m.embedded {
            return Ok(emb[offset as usize..end as usize].to_vec());
        }
        if let Some(a) = &self.ahead {
            if a.rel == rel {
                if let Some(out) = Self::slice_ahead(a, offset, end) {
                    return Ok(out);
                }
            }
        }
        if let Some(n) = &self.next {
            if n.rel == rel {
                if let Some(out) = Self::slice_ahead(n, offset, end) {
                    self.ahead = self.next.take();
                    return Ok(out);
                }
            }
        }
        let pull = (end - offset).max(READAHEAD as u64).min(m.size - offset) as usize;
        let buf = self.read_extents(&m, offset, pull)?;
        let take = (end - offset) as usize;
        let out = buf[..take.min(buf.len())].to_vec();
        self.ahead = Some(Ahead {
            rel: rel.to_string(),
            off: offset,
            buf,
        });
        Ok(out)
    }

    /// Fill the next-window slot so the following sequential read does not
    /// wait on the drive. Safe to call from a background thread that holds
    /// the `RawUdf` mutex.
    pub fn prefetch(&mut self, rel: &str, offset: u64, count: usize) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        if let Some(a) = &self.ahead {
            if a.rel == rel && offset >= a.off && offset < a.off + a.buf.len() as u64 {
                return Ok(());
            }
        }
        if let Some(n) = &self.next {
            if n.rel == rel && n.off == offset {
                return Ok(());
            }
        }
        let m = self.meta(rel)?;
        if offset >= m.size {
            return Ok(());
        }
        let pull = (count as u64).min(m.size - offset) as usize;
        let buf = self.read_extents(&m, offset, pull)?;
        self.next = Some(Ahead {
            rel: rel.to_string(),
            off: offset,
            buf,
        });
        Ok(())
    }

    fn read_extents(&self, m: &FileMeta, offset: u64, count: usize) -> Result<Vec<u8>> {
        let end = offset.saturating_add(count as u64).min(m.size);
        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut pos = 0u64;
        for (abs, len) in &m.extents {
            let ext_end = pos + u64::from(*len);
            if end <= pos {
                break;
            }
            if offset >= ext_end {
                pos = ext_end;
                continue;
            }
            let start_in = offset.max(pos) - pos;
            let take = (end.min(ext_end) - pos - start_in) as usize;
            out.extend_from_slice(&read_abs(&self.file, abs + start_in, take)?);
            pos = ext_end;
        }
        Ok(out)
    }
}

fn resolve(spaces: &[Option<Space>], part_ref: u16, block: u64) -> Result<u64> {
    let space = spaces
        .get(part_ref as usize)
        .and_then(|s| s.as_ref())
        .ok_or_else(|| anyhow::anyhow!("no space for partition_ref {part_ref}"))?;
    match space {
        Space::Physical { start } => Ok(start + block),
        Space::Metadata { extents } => {
            let off = block * SECTOR;
            let mut pos = 0u64;
            for (abs_sec, len) in extents {
                let ext_end = pos + u64::from(*len);
                if off < ext_end {
                    return Ok(abs_sec + (off - pos) / SECTOR);
                }
                pos = ext_end;
            }
            bail!("metadata block {block} past end of metadata file");
        }
    }
}

fn pd_by_number(pds: &[PartitionDescriptor], number: u16) -> Result<&PartitionDescriptor> {
    pds.iter()
        .find(|p| p.partition_number == number)
        .ok_or_else(|| anyhow::anyhow!("no Partition Descriptor for partition {number}"))
}

fn build_spaces(
    file: &File,
    pds: &[PartitionDescriptor],
    maps: &[PartMap],
    fsd_ref: u16,
) -> Result<Vec<Option<Space>>> {
    if maps.is_empty() {
        let pd = pds
            .iter()
            .find(|p| p.partition_number == fsd_ref)
            .or(pds.last())
            .unwrap();
        let mut spaces = vec![None; (fsd_ref as usize).saturating_add(1).max(1)];
        spaces[fsd_ref as usize] = Some(Space::Physical {
            start: pd.partition_starting_location as u64,
        });
        return Ok(spaces);
    }

    let mut spaces: Vec<Option<Space>> = vec![None; maps.len()];
    for (i, m) in maps.iter().enumerate() {
        if let PartMap::Type1 { partition_number } = m {
            let pd = pd_by_number(pds, *partition_number)?;
            spaces[i] = Some(Space::Physical {
                start: pd.partition_starting_location as u64,
            });
        }
    }
    for (i, m) in maps.iter().enumerate() {
        let PartMap::Metadata {
            physical_partition_number,
            metadata_file_loc,
            mirror_file_loc,
        } = m
        else {
            continue;
        };
        let pd = pd_by_number(pds, *physical_partition_number)?;
        let phys = pd.partition_starting_location as u64;
        let fe = read_fe(file, phys + u64::from(*metadata_file_loc)).or_else(|e| {
            warn!("metadata file at {metadata_file_loc}: {e:#}; trying mirror");
            read_fe(file, phys + u64::from(*mirror_file_loc))
        })?;
        let extents = fe_physical_extents(&fe, phys);
        if extents.is_empty() {
            bail!("metadata file has no recorded extents");
        }
        info!(
            "UDF metadata partition map[{i}] via physical #{physical_partition_number} ({} extent(s))",
            extents.len()
        );
        spaces[i] = Some(Space::Metadata { extents });
    }
    if spaces[fsd_ref as usize].is_none() {
        bail!("FSD partition_ref {fsd_ref} did not resolve to a partition map");
    }
    Ok(spaces)
}

pub fn sanitize_label(s: &str) -> String {
    let s: String = s.chars().map(|c| if c == '/' || c == ':' { '_' } else { c }).collect();
    let s = s.trim();
    if s.is_empty() { "BluRay".into() } else { s.into() }
}

/// True if two paths name the same whole optical disk (`/dev/rdisk6` vs `disk6`).
pub fn devices_match(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    let na = a.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let nb = b.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let wa = bsd_whole_disk(na.trim_start_matches('r')).or_else(|| bsd_whole_disk(na));
    let wb = bsd_whole_disk(nb.trim_start_matches('r')).or_else(|| bsd_whole_disk(nb));
    match (wa, wb) {
        (Some(x), Some(y)) => x == y,
        _ => na.trim_start_matches('r') == nb.trim_start_matches('r'),
    }
}

/// `disk6` / `disk6s1` → `disk6`. Must not split on the letter `s` in `disk`.
pub fn bsd_whole_disk(id: &str) -> Option<String> {
    let rest = id.strip_prefix("disk")?;
    let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if n.is_empty() {
        None
    } else {
        Some(format!("disk{n}"))
    }
}

/// Whole-disk and first-slice raw nodes for a BSD name (`disk6` or `disk6s1`).
pub fn rdisk_paths_for_bsd(bsd: &str) -> Vec<PathBuf> {
    let Some(whole) = bsd_whole_disk(bsd) else {
        return Vec::new();
    };
    if whole == "disk0" {
        return Vec::new();
    }
    let mut v = vec![PathBuf::from(format!("/dev/r{bsd}"))];
    let whole_path = PathBuf::from(format!("/dev/r{whole}"));
    if !v.contains(&whole_path) {
        v.push(whole_path);
    }
    let slice = PathBuf::from(format!("/dev/r{whole}s1"));
    if !v.contains(&slice) {
        v.push(slice);
    }
    v
}

pub fn find_optical_rdisks() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for bsd in da::claimed_bsd_names() {
        for p in rdisk_paths_for_bsd(&bsd) {
            if !v.contains(&p) {
                v.push(p);
            }
        }
    }
    let Ok(out) = std::process::Command::new("/usr/sbin/diskutil").args(["list"]).output() else {
        return v;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let optical = line.contains("CD_partition")
            || line.contains("CD_ROM")
            || line.contains("DVD_")
            || line.contains("BD_")
            || line.contains("Apple_UDF")
            || line.contains("CD_partition_scheme");
        if !optical {
            continue;
        }
        let Some(id) = line.split_whitespace().last() else { continue };
        // DVD/CD (including AVCHD) stay with the OS. Do not open their rdisk.
        if let Some(whole) = bsd_whole_disk(id) {
            match da::optical_class_for_bsd(&whole) {
                da::OpticalClass::Dvd | da::OpticalClass::Cd => continue,
                da::OpticalClass::BluRay | da::OpticalClass::Unknown => {}
            }
        }
        for p in rdisk_paths_for_bsd(id) {
            if !v.contains(&p) {
                v.push(p);
            }
        }
    }
    v
}

/// After we unmount Finder's UDF, open this whole disk until BDMV is readable.
pub fn open_bd_rdisk_for_bsd(bsd: &str, timeout: Duration) -> Result<PathBuf> {
    let deadline = Instant::now() + timeout;
    let mut last: Option<String> = None;
    while Instant::now() < deadline {
        for p in rdisk_paths_for_bsd(bsd) {
            match try_bd(&p) {
                Ok(()) => {
                    info!("opened taken-over Blu-ray on {}", p.display());
                    return Ok(p);
                }
                Err(e) => last = Some(format!("{}: {e:#}", p.display())),
            }
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    bail!(
        "released the Finder mount of {bsd} but could not open BDMV ({})",
        last.as_deref().unwrap_or("no /dev/rdisk node yet")
    )
}

fn try_bd(dev: &Path) -> Result<()> {
    let mut u = RawUdf::open(dev)?;
    u.lookup("BDMV/index.bdmv")
        .with_context(|| format!("opened {} ({}) but BDMV/index.bdmv is missing", dev.display(), u.label))?;
    Ok(())
}

/// One pass: first raw optical device that is a Blu-ray and not in `skip`.
pub fn poll_bd_rdisk(skip: &[PathBuf], only: &[PathBuf]) -> Option<PathBuf> {
    for dev in find_optical_rdisks() {
        if !only.is_empty() && !only.iter().any(|o| devices_match(&dev, o)) {
            continue;
        }
        if skip.iter().any(|s| devices_match(&dev, s)) {
            continue;
        }
        if try_bd(&dev).is_ok() {
            return Some(dev);
        }
    }
    None
}

/// Wait until a Blu-ray shows up on a raw optical device. No overall timeout —
/// `bdmount mount` keeps this running until you quit. If we claimed
/// a disc but never found `BDMV/index.bdmv`, give up after two minutes.
pub fn wait_for_bd_rdisk() -> Result<PathBuf> {
    let mut claimed_at: Option<Instant> = None;
    let mut seen_err = HashSet::new();
    let mut last_err: Option<String> = None;
    info!("waiting for a Blu-ray (macOS will not mount it)…");
    loop {
        let claimed = da::claimed_bsd_names();
        if claimed.is_empty() {
            claimed_at = None;
        } else if claimed_at.is_none() {
            claimed_at = Some(Instant::now());
            info!("OS refused to mount {}; opening the raw device", claimed.join(", "));
        }
        for dev in find_optical_rdisks() {
            match try_bd(&dev) {
                Ok(()) => {
                    info!("found Blu-ray UDF on {}", dev.display());
                    return Ok(dev);
                }
                Err(e) => {
                    let key = format!("{}: {e:#}", dev.display());
                    if seen_err.insert(key.clone()) {
                        warn!("probe {key}");
                    }
                    last_err = Some(key);
                }
            }
        }
        if claimed_at.is_some_and(|t| t.elapsed() >= Duration::from_secs(120)) {
            let hint = last_err
                .as_deref()
                .unwrap_or("claimed a disc but never found BDMV/index.bdmv");
            bail!("no Blu-ray on a raw optical device ({hint})");
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devices_match_rdisk_and_disk() {
        assert!(devices_match(Path::new("/dev/rdisk6"), Path::new("/dev/disk6")));
        assert!(devices_match(Path::new("/dev/rdisk6"), Path::new("/dev/rdisk6s1")));
        assert!(!devices_match(Path::new("/dev/rdisk6"), Path::new("/dev/rdisk7")));
    }

    #[test]
    fn does_not_split_disk_on_the_letter_s() {
        assert_eq!(bsd_whole_disk("disk6").as_deref(), Some("disk6"));
        assert_eq!(bsd_whole_disk("disk6s1").as_deref(), Some("disk6"));
        assert_eq!(bsd_whole_disk("disk16s2").as_deref(), Some("disk16"));
        assert_eq!(bsd_whole_disk("rdi"), None);
    }

    #[test]
    fn rdisk_paths_include_slice_and_whole() {
        let p = rdisk_paths_for_bsd("disk6s1");
        assert!(p.iter().any(|x| x == Path::new("/dev/rdisk6s1")));
        assert!(p.iter().any(|x| x == Path::new("/dev/rdisk6")));
        assert!(!p.iter().any(|x| x == Path::new("/dev/rdi")));
    }

    #[test]
    #[ignore]
    fn live_rdisk6_lookup() {
        let mut u = RawUdf::open(Path::new("/dev/rdisk6")).expect("open");
        eprintln!("label={} root_icb={}/{}", u.label, u.root_icb.location.block, u.root_icb.location.partition_ref);
        match u.list_dir("") {
            Ok(e) => eprintln!("root: {:?}", e.iter().map(|x| format!("{}{}", x.name, if x.is_directory { "/" } else { "" })).collect::<Vec<_>>()),
            Err(e) => eprintln!("root list: {e:#}"),
        }
        match u.lookup("BDMV/index.bdmv") {
            Ok(icb) => eprintln!("lookup ok {}/{}", icb.location.block, icb.location.partition_ref),
            Err(e) => eprintln!("lookup: {e:#}"),
        }
        match u.read_at("BDMV/index.bdmv", 0, 64) {
            Ok(b) => eprintln!("index.bdmv head {:x?}", &b[..b.len().min(8)]),
            Err(e) => eprintln!("read_at: {e:#}"),
        }
    }

    #[test]
    fn prefetch_fills_next_slot_then_read_promotes_it() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("bdmount-prefetch-{}.bin", std::process::id()));
        let mut data = vec![0u8; 32 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        std::fs::write(&p, &data).unwrap();
        let f = File::open(&p).unwrap();
        // Exercise the same aligned fill used for /dev/diskN payload windows.
        let window = read_abs(&f, 0, READAHEAD.min(data.len())).unwrap();
        assert_eq!(window, data[..window.len()]);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn buffered_payload_falls_back_when_not_optical_2048() {
        let dir = std::env::temp_dir();
        let rdisk = dir.join(format!("rdisk-fake-{}", std::process::id()));
        std::fs::write(&rdisk, [0u8; 4096]).unwrap();
        let fallback = File::open(&rdisk).unwrap();
        let fd = fallback.as_raw_fd();
        let got = open_payload_file(&rdisk, fallback);
        // Regular files have no DKIOCGETBLOCKSIZE; stay on the rdisk fd.
        assert_eq!(got.as_raw_fd(), fd);
        let _ = std::fs::remove_file(rdisk);
    }

    #[test]
    fn read_abs_fills_short_preads() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let p = dir.join(format!("bdmount-read-abs-{}.bin", std::process::id()));
        let mut data = vec![0u8; 8192];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        std::fs::File::create(&p).unwrap().write_all(&data).unwrap();
        let f = File::open(&p).unwrap();
        let got = read_abs(&f, 100, 3000).unwrap();
        assert_eq!(got, data[100..3100]);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn parses_type1_and_metadata_maps() {
        let mut lvd = vec![0u8; 512];
        // map_table_length = 6+64, number_of_partition_maps = 2
        lvd[264..268].copy_from_slice(&70u32.to_le_bytes());
        lvd[268..272].copy_from_slice(&2u32.to_le_bytes());
        // type 1 → partition number 1
        lvd[440] = 1;
        lvd[441] = 6;
        lvd[444..446].copy_from_slice(&1u16.to_le_bytes());
        // type 2 metadata → physical partition 1, file loc 20
        lvd[446] = 2;
        lvd[447] = 64;
        lvd[446 + 5..446 + 5 + 8].copy_from_slice(b"Metadata");
        lvd[446 + 38..446 + 40].copy_from_slice(&1u16.to_le_bytes());
        lvd[446 + 40..446 + 44].copy_from_slice(&20u32.to_le_bytes());
        lvd[446 + 44..446 + 48].copy_from_slice(&21u32.to_le_bytes());
        let maps = parse_partition_maps(&lvd).unwrap();
        assert_eq!(
            maps,
            vec![
                PartMap::Type1 { partition_number: 1 },
                PartMap::Metadata {
                    physical_partition_number: 1,
                    metadata_file_loc: 20,
                    mirror_file_loc: 21,
                },
            ]
        );
    }
}
