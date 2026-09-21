//! Background mode: watch `/Volumes` for protected Blu-rays, mount a
//! decrypted view when one appears and tear it down when it is ejected.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};

use crate::disc;
use crate::mount::{MountOptions, MountedDisc};

pub struct WatchOptions {
    pub poll: Duration,
    /// Also mount unprotected Blu-rays (usually pointless; HandBrake can read those directly).
    pub include_unprotected: bool,
    pub mount: MountOptions,
}

pub async fn run(opts: WatchOptions) -> Result<()> {
    let mut active: HashMap<PathBuf, MountedDisc> = HashMap::new();
    // Discs we failed to mount; retry with backoff so a bad disc does not spin.
    let mut failed: HashMap<PathBuf, Instant> = HashMap::new();
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    // A launchd agent never gets SIGHUP, but when run from a terminal that
    // closes we want to unmount cleanly instead of dying with mounts live.
    let mut sighup = signal(SignalKind::hangup())?;
    let mut tick = tokio::time::interval(opts.poll);

    info!(
        "watching /Volumes for Blu-ray discs (mounting under {})",
        opts.mount.base_dir.display()
    );
    crate::mount::reap_orphaned_helpers();
    // Release the disc *before* macOS unmounts it when the user presses Eject.
    crate::da::install_eject_hook();

    loop {
        tokio::select! {
            _ = sigint.recv() => { info!("SIGINT"); break; }
            _ = sigterm.recv() => { info!("SIGTERM"); break; }
            _ = sighup.recv() => { info!("SIGHUP"); break; }
            _ = tick.tick() => {}
        }

        // 1. Forget views the eject hook already tore down, and tear down
        //    views whose disc vanished without going through DiskArbitration
        //    (drive unplugged, power loss). Both checks are mount-table only.
        let gone: Vec<PathBuf> = active
            .iter()
            .filter(|(_, m)| !m.is_active() || !m.source_present())
            .map(|(k, _)| k.clone())
            .collect();
        for src in gone {
            if let Some(m) = active.remove(&src) {
                if m.is_active() {
                    info!("{} disappeared, unmounting {}", src.display(), m.mountpoint().display());
                    if let Err(e) = m.unmount().await {
                        error!("{e:#}");
                    }
                } else {
                    info!("{} was ejected; view at {} already released", src.display(), m.mountpoint().display());
                    let _ = std::fs::remove_dir(m.mountpoint());
                }
                crate::mount::mark_source_released(&src);
            }
        }

        // 2. Mount new discs. Never stat into volumes we already serve, and
        //    never remount a source we just released while macOS is still
        //    ejecting it (that SCSI-during-eject path wedged Finder twice).
        let base = opts.mount.base_dir.canonicalize().unwrap_or_else(|_| opts.mount.base_dir.clone());
        let mut skip = active.keys().cloned().collect::<Vec<_>>();
        skip.extend(crate::mount::held_off_sources());
        for vol in disc::find_bd_volumes_except(&skip) {
            let src = vol.path.canonicalize().unwrap_or_else(|_| vol.path.clone());
            if src.starts_with(&base) || active.contains_key(&src) {
                continue;
            }
            if !vol.protected && !opts.include_unprotected {
                continue;
            }
            if let Some(t) = failed.get(&src) {
                if t.elapsed() < Duration::from_secs(60) {
                    continue;
                }
            }
            info!("found {} ({}), mounting decrypted view", vol.label, src.display());
            match MountedDisc::mount(&src, &opts.mount).await {
                Ok(m) => {
                    failed.remove(&src);
                    info!("{} ready for HandBrake at {} (nfs port {})", m.label(), m.mountpoint().display(), m.port());
                    active.insert(src, m);
                }
                Err(e) => {
                    warn!("could not mount {}: {e:#} (will retry in 60s)", src.display());
                    failed.insert(src, Instant::now());
                }
            }
        }
    }

    for (_, m) in active.drain() {
        if let Err(e) = m.unmount().await {
            error!("{e:#}");
        }
    }
    Ok(())
}
