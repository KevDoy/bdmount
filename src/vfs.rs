//! Read-only NFSv3 view of a [`DiscTree`], backed by [`DecryptEngine`].

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use nfsserve::nfs::{fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfstime3, sattr3, specdata3};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use tracing::{debug, warn};

use crate::decrypt::DecryptEngine;
use crate::disc::{DiscTree, Node, ROOT_ID};

pub struct BdFs {
    pub tree: Arc<DiscTree>,
    pub engine: Arc<DecryptEngine>,
    uid: u32,
    gid: u32,
    fsid: u64,
}

impl BdFs {
    pub fn new(tree: Arc<DiscTree>, engine: Arc<DecryptEngine>) -> BdFs {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        // Any stable non-zero number; derived from the label so two discs differ.
        let fsid = tree.label.bytes().fold(0x5bd0_0000u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64)) | 1;
        BdFs { tree, engine, uid, gid, fsid }
    }

    fn attr(&self, node: &Node) -> fattr3 {
        let t = to_nfstime(node.mtime);
        let (ftype, mode, nlink, size) = if node.is_dir() {
            (ftype3::NF3DIR, 0o555, 2 + self.tree.children(node.id).len() as u32, 4096)
        } else {
            (ftype3::NF3REG, 0o444, 1, node.size)
        };
        fattr3 {
            ftype,
            mode,
            nlink,
            uid: self.uid,
            gid: self.gid,
            size,
            used: size,
            rdev: specdata3::default(),
            fsid: self.fsid,
            fileid: node.id,
            atime: t,
            mtime: t,
            ctime: t,
        }
    }

    fn node(&self, id: fileid3) -> Result<&Node, nfsstat3> {
        self.tree.get(id).ok_or(nfsstat3::NFS3ERR_NOENT)
    }
}

fn to_nfstime(t: SystemTime) -> nfstime3 {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    nfstime3 {
        seconds: d.as_secs() as u32,
        nseconds: d.subsec_nanos(),
    }
}

#[async_trait]
impl NFSFileSystem for BdFs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadOnly
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_ID
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let dir = self.node(dirid)?;
        if !dir.is_dir() {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        }
        match filename.as_ref() {
            b"." => Ok(dirid),
            b".." => Ok(dir.parent),
            name => self.tree.lookup(dirid, name).ok_or(nfsstat3::NFS3ERR_NOENT),
        }
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        Ok(self.attr(self.node(id)?))
    }

    async fn setattr(&self, _id: fileid3, _setattr: sattr3) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn read(&self, id: fileid3, offset: u64, count: u32) -> Result<(Vec<u8>, bool), nfsstat3> {
        let node = self.node(id)?.clone();
        if node.is_dir() {
            return Err(nfsstat3::NFS3ERR_ISDIR);
        }
        let engine = self.engine.clone();
        let count = count as usize;
        let result = tokio::task::spawn_blocking(move || engine.read(&node, offset, count))
        .await
        .map_err(|e| {
            warn!("read task panicked: {e}");
            nfsstat3::NFS3ERR_IO
        })?;
        match result {
            Ok(data) => {
                let size = self.node(id)?.size;
                let eof = offset + data.len() as u64 >= size;
                Ok((data, eof))
            }
            Err(e) => {
                warn!("read(id={id}, offset={offset}, count={count}) failed: {e:#}");
                Err(nfsstat3::NFS3ERR_IO)
            }
        }
    }

    async fn write(&self, _id: fileid3, _offset: u64, _data: &[u8]) -> Result<fattr3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn create(&self, _dirid: fileid3, _filename: &filename3, _attr: sattr3) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn create_exclusive(&self, _dirid: fileid3, _filename: &filename3) -> Result<fileid3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn mkdir(&self, _dirid: fileid3, _dirname: &filename3) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn remove(&self, _dirid: fileid3, _filename: &filename3) -> Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn rename(
        &self,
        _from_dirid: fileid3,
        _from_filename: &filename3,
        _to_dirid: fileid3,
        _to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn readdir(&self, dirid: fileid3, start_after: fileid3, max_entries: usize) -> Result<ReadDirResult, nfsstat3> {
        let dir = self.node(dirid)?;
        if !dir.is_dir() {
            return Err(nfsstat3::NFS3ERR_NOTDIR);
        }
        let children = self.tree.children(dirid);
        let start = if start_after == 0 {
            0
        } else {
            match children.iter().position(|&c| c == start_after) {
                Some(p) => p + 1,
                None => return Err(nfsstat3::NFS3ERR_BAD_COOKIE),
            }
        };
        let mut entries = Vec::new();
        for &cid in children.iter().skip(start).take(max_entries) {
            if let Some(child) = self.tree.get(cid) {
                entries.push(DirEntry {
                    fileid: cid,
                    name: child.name.clone().into(),
                    attr: self.attr(child),
                });
            }
        }
        let end = start + entries.len() >= children.len();
        debug!("readdir(id={dirid}, after={start_after}) -> {} entries, end={end}", entries.len());
        Ok(ReadDirResult { entries, end })
    }

    async fn symlink(
        &self,
        _dirid: fileid3,
        _linkname: &filename3,
        _symlink: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        Err(nfsstat3::NFS3ERR_ROFS)
    }

    async fn readlink(&self, _id: fileid3) -> Result<nfspath3, nfsstat3> {
        Err(nfsstat3::NFS3ERR_NOTSUPP)
    }
}
