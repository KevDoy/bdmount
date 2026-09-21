//! `bdmount` – present an encrypted Blu-ray as a plain, decrypted BDMV folder
//! on a localhost NFS mount so HandBrake (or anything else) can read it
//! directly. Decryption is done on the fly through MakeMKV's libmmbd.

mod da;
mod decrypt;
mod disc;
mod drives;
mod idle;
mod mmbd;
mod mount;
mod rawudf;
mod vfs;
mod watch;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::mount::{MountOptions, MountedDisc};

#[derive(Parser)]
#[command(name = "bdmount", version, about = "On-the-fly decrypted Blu-ray mounts for HandBrake (macOS, via MakeMKV's libmmbd)")]
struct Cli {
    /// Verbose logging (-v info, -vv debug, -vvv trace). RUST_LOG overrides.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List Blu-ray volumes currently mounted by macOS and active decrypted mounts.
    List,
    /// Open a disc through libmmbd and decrypt a few units to prove the chain works.
    Probe {
        /// Volume path, e.g. /Volumes/MOVIE (defaults to the first protected BD found)
        volume: Option<PathBuf>,
        /// Number of 6144-byte units to decrypt from the largest stream
        #[arg(long, default_value_t = 256)]
        units: u64,
        /// Also decrypt from the start of every stream file (slow: seeks all over the disc)
        #[arg(long)]
        all_streams: bool,
    },
    /// Mount decrypted views. Waits forever; serves every Blu-ray drive at once.
    Mount {
        /// Restrict to these raw devices (`--device /dev/rdisk6`). Repeatable. Default: all drives.
        #[arg(long)]
        device: Vec<PathBuf>,
        /// Volume path, e.g. /Volumes/MOVIE (defaults to waiting for insert)
        volume: Option<PathBuf>,
        /// Mount here instead of ~/BluRay Decrypted/<label> (first disc only)
        #[arg(long)]
        mountpoint: Option<PathBuf>,
        /// Decrypted-unit cache size in MiB
        #[arg(long, default_value_t = 64)]
        cache_mib: usize,
    },
    /// Unmount a decrypted view (or all of them).
    Unmount {
        /// Mountpoint path
        mountpoint: Option<PathBuf>,
        #[arg(long)]
        all: bool,
    },
    /// Watch /Volumes and automatically mount/unmount decrypted views as discs come and go.
    Watch {
        /// Poll interval in seconds
        #[arg(long, default_value_t = 2)]
        poll: u64,
        /// Also mount Blu-rays that have no AACS protection
        #[arg(long)]
        include_unprotected: bool,
        /// Decrypted-unit cache size in MiB per disc
        #[arg(long, default_value_t = 64)]
        cache_mib: usize,
    },
    /// Show active decrypted mounts and whether the drive is safe to eject.
    Status {
        /// Machine-readable snapshot (for the menubar).
        #[arg(long)]
        json: bool,
    },
    /// Release our NFS view (if any) and eject a Blu-ray we claimed.
    /// Refuses if HandBrake or another holder is still on the folder.
    /// Never ejects a DVD/CD the OS mounted.
    Eject {
        /// Only this device (`/dev/rdisk6` or `disk6`). Default: every claimed drive.
        #[arg(long)]
        device: Option<PathBuf>,
    },
}

fn init_logging(verbose: u8) {
    let default = match verbose {
        0 => "bdmount=info,libmmbd=warn,nfsserve=warn",
        1 => "bdmount=info,libmmbd=info,nfsserve=info",
        2 => "bdmount=debug,libmmbd=debug,nfsserve=info",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(verbose >= 2)
        .compact()
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match cli.cmd {
        Cmd::List => cmd_list(),
        Cmd::Probe { volume, units, all_streams } => cmd_probe(volume, units, all_streams).await,
        Cmd::Mount { device, volume, mountpoint, cache_mib } => {
            cmd_mount(device, volume, mountpoint, cache_mib).await
        }
        Cmd::Unmount { mountpoint, all } => cmd_unmount(mountpoint, all),
        Cmd::Watch { poll, include_unprotected, cache_mib } => {
            watch::run(watch::WatchOptions {
                poll: Duration::from_secs(poll.max(1)),
                include_unprotected,
                mount: MountOptions {
                    cache_bytes: cache_mib * 1024 * 1024,
                    ..MountOptions::default()
                },
            })
            .await
        }
        Cmd::Status { json } => cmd_status(json),
        Cmd::Eject { device } => cmd_eject(device),
    }
}

fn pick_volume(volume: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(v) = volume {
        return Ok(v);
    }
    let vols = disc::find_bd_volumes();
    if let Some(v) = vols.iter().find(|v| v.protected).or(vols.first()) {
        info!("using {}", v.path.display());
        return Ok(v.path.clone());
    }
    bail!("no Blu-ray volume found under /Volumes; insert a disc or pass the path explicitly")
}

fn cmd_list() -> Result<()> {
    let drives = drives::list_drives();
    if drives.is_empty() {
        println!("No optical drives found.");
    } else {
        println!("Optical drives:");
        for d in &drives {
            let media = drives::media_class_name(d.class, d.media);
            println!(
                "  {:<14}  {:<12}  {media}{}",
                d.device.display(),
                d.bus,
                if d.bd_capable { "" } else { "  (no BD drive)" }
            );
        }
    }
    let vols = disc::find_bd_volumes();
    if !vols.is_empty() {
        println!("OS-mounted Blu-ray volumes:");
        for v in vols {
            println!(
                "  {:<40} {}",
                v.path.display(),
                if v.protected { "AACS protected" } else { "unprotected" }
            );
        }
    }
    cmd_status(false)
}

fn cmd_status(json: bool) -> Result<()> {
    let snap = idle::read_snapshot().unwrap_or_else(|| {
        let nfs = mount::active_mounts();
        let state = if !nfs.is_empty() {
            idle::State::Serving
        } else if !idle::makemkvcon_helpers().is_empty() {
            idle::State::Stuck
        } else {
            idle::State::Idle
        };
        idle::observe(None, nfs.first().map(|p| p.as_path()), None, state)
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&snap)?);
        return Ok(());
    }
    println!("state:           {:?}", snap.state);
    println!("safe_to_eject:   {}", snap.safe_to_eject);
    if let Some(s) = &snap.source {
        println!("source:          {s}");
    }
    if let Some(m) = &snap.mountpoint {
        println!("mountpoint:      {m}");
    }
    if snap.holders.is_empty() {
        println!("holders:         (none)");
    } else {
        println!("holders:");
        for h in &snap.holders {
            println!("  pid {:>6}  {:<16}  {}", h.pid, h.name, h.path);
        }
    }
    if !snap.claimed_bsd.is_empty() {
        println!("claimed:         {}", snap.claimed_bsd.join(", "));
    }
    if !snap.drives.is_empty() {
        println!("drives:");
        for d in &snap.drives {
            println!(
                "  {:<14}  {:<8}  {:<10}  {}{}",
                d.device,
                d.bus,
                d.media_class,
                d.state,
                d.label.as_deref().map(|l| format!("  {l}")).unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// Ask a still-running `bdmount mount` to release (per device or all), then eject.
fn cmd_eject(device: Option<PathBuf>) -> Result<()> {
    if let Some(snap) = idle::read_snapshot() {
        if let Some(pid) = snap.mount_pid {
            if pid != std::process::id() && process_alive(pid) {
                idle::write_eject_request(&idle::EjectRequest {
                    device: device.as_ref().map(|p| p.display().to_string()),
                    all: device.is_none(),
                });
                info!("asked bdmount mount (pid {pid}) to eject {}", device.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "all".into()));
                let deadline = Instant::now() + Duration::from_secs(45);
                while Instant::now() < deadline && process_alive(pid) {
                    std::thread::sleep(Duration::from_millis(200));
                    if let Some(s) = idle::read_snapshot() {
                        if device.is_none() && s.drives.iter().all(|d| d.state != "serving") {
                            break;
                        }
                        if let Some(dev) = &device {
                            let still = s.drives.iter().any(|d| {
                                d.state == "serving"
                                    && rawudf::devices_match(Path::new(&d.device), dev)
                            });
                            if !still {
                                break;
                            }
                        }
                    }
                }
                println!("eject requested");
                return Ok(());
            }
        }
    }
    if da::claimed_whole_disks().is_empty() {
        bail!("no disc we claimed; a DVD/CD that macOS mounted is not ours to eject");
    }
    let ejected = da::eject_after_release_filter(device.as_deref().and_then(|p| p.to_str()))?;
    println!("ejected {}", ejected.join(", "));
    Ok(())
}

/// Blu-ray volumes under `/Volumes` that we would claim (`IOBDMedia` or
/// unknown + BDMV). AVCHD on DVD/CD is ignored.
fn os_mounted_claimed_bds() -> Vec<disc::BdVolume> {
    let mut out = Vec::new();
    for v in disc::find_bd_volumes() {
        let Some(raw) = disc::raw_device_for_volume(&v.path) else {
            out.push(v);
            continue;
        };
        let rest = raw.trim_start_matches("/dev/r").trim_start_matches("/dev/");
        let bsd = rawudf::bsd_whole_disk(rest).unwrap_or_else(|| rest.to_string());
        match da::optical_class_for_bsd(&bsd) {
            da::OpticalClass::Dvd | da::OpticalClass::Cd => {}
            da::OpticalClass::BluRay | da::OpticalClass::Unknown => out.push(v),
        }
    }
    out
}

/// If Finder already mounted a movie BD, unmount it (no force) and return the
/// raw device so we serve it immediately — do not sit in the insert-wait loop.
fn take_over_os_bd_if_needed(only: &[PathBuf]) -> Result<Option<PathBuf>> {
    let mut taken = None;
    for v in os_mounted_claimed_bds() {
        let raw = disc::raw_device_for_volume(&v.path);
        if !only.is_empty() {
            let Some(r) = &raw else { continue };
            if !only.iter().any(|o| rawudf::devices_match(o, Path::new(r))) {
                continue;
            }
        }
        info!("Finder already mounted {}; taking over after a polite unmount", v.path.display());
        println!("Finder already mounted {}. Releasing it so we can claim the drive…", v.path.display());
        let bsd = raw.as_deref().and_then(|r| {
            let rest = r.trim_start_matches("/dev/r").trim_start_matches("/dev/");
            rawudf::bsd_whole_disk(rest).or_else(|| Some(rest.to_string()))
        });
        let mut paths = vec![v.path.clone()];
        if let Some(r) = &raw {
            paths.extend(idle::optical_paths(&v.path, Some(r)));
        }
        let holders = idle::holders_on(&paths);
        let hard: Vec<_> = holders.iter().filter(|h| idle::is_hard_os_udf_holder(h)).cloned().collect();
        if !hard.is_empty() {
            let list = hard
                .iter()
                .map(|h| format!("{} (pid {})", h.name, h.pid))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "{} is still in use by {list}. Quit those apps, then start bdmount mount again. \
                 We will not force-unmount a live UDF volume.",
                v.path.display()
            );
        }
        mount::unmount_os_volume_polite(&v.path)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while mount::is_volume_mounted(&v.path) {
            if Instant::now() >= deadline {
                bail!(
                    "unmount of {} did not finish. Eject in Disk Utility or reboot — do not unplug.",
                    v.path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let Some(bsd) = bsd else {
            bail!("released {} but could not resolve /dev/rdiskN", v.path.display());
        };
        da::claim_bsd(bsd.clone());
        let dev = rawudf::open_bd_rdisk_for_bsd(&bsd, Duration::from_secs(20))?;
        println!("Released {}. Opening {}.", v.path.display(), dev.display());
        taken = Some(dev);
    }
    Ok(taken)
}

fn cmd_unmount(mountpoint: Option<PathBuf>, all: bool) -> Result<()> {
    let targets: Vec<PathBuf> = if all {
        mount::active_mounts()
    } else {
        vec![mountpoint.context("pass a mountpoint or --all")?]
    };
    if targets.is_empty() {
        println!("Nothing to unmount.");
        return Ok(());
    }
    let mut failed = false;
    for mp in targets {
        match mount::unmount_path(&mp) {
            Ok(()) => {
                let _ = std::fs::remove_dir(&mp);
                println!("unmounted {}", mp.display());
            }
            Err(e) => {
                failed = true;
                eprintln!("{e:#}");
            }
        }
    }
    if failed {
        bail!("some unmounts failed");
    }
    Ok(())
}

async fn cmd_probe(volume: Option<PathBuf>, units: u64, all_streams: bool) -> Result<()> {
    let volume = pick_volume(volume)?;
    let tree = disc::DiscTree::scan(&volume)?;
    println!(
        "{}: {} files, {} encrypted stream files",
        tree.label, tree.file_count, tree.encrypted_count
    );

    let t0 = Instant::now();
    let mmbd = tokio::task::spawn_blocking(move || mount::open_disc(&volume)).await??;
    println!(
        "MakeMKV opened the disc in {:.1}s\n  engine:   {}\n  library:  {}\n  MKB:      v{}\n  bus enc:  {}\n  disc id:  {}",
        t0.elapsed().as_secs_f32(),
        mmbd.engine_version(),
        mmbd.library_version(),
        mmbd.mkb_version(),
        mmbd.bus_encrypted(),
        mmbd.disc_id()
            .map(|id| id.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .unwrap_or_default()
    );

    let engine = decrypt::DecryptEngine::new(mmbd, 8 * 1024 * 1024);

    let mut targets: Vec<&disc::Node> = Vec::new();
    if all_streams {
        targets.extend(tree.iter().filter(|n| matches!(n.kind, disc::NodeKind::Encrypted { .. })));
        targets.sort_by_key(|n| n.name.clone());
    } else if let Some(n) = tree.largest_encrypted() {
        targets.push(n);
    } else {
        bail!("no encrypted streams found on {}", tree.source.display());
    }

    let mut total_ok = 0u64;
    let mut total_bad = 0u64;
    for node in targets {
        let n_units = if all_streams { units.min(8) } else { units };
        let want = (n_units * mmbd::UNIT_SIZE as u64).min(node.size) as usize;
        let t = Instant::now();
        let data = engine.read(node, 0, want)?;
        let mut ok = 0u64;
        let mut bad = 0u64;
        for unit in data.chunks(mmbd::UNIT_SIZE) {
            if mmbd::unit_looks_like_clear_ts(unit) && !mmbd::unit_is_encrypted(unit) {
                ok += 1;
            } else {
                bad += 1;
            }
        }
        total_ok += ok;
        total_bad += bad;
        let secs = t.elapsed().as_secs_f64().max(1e-6);
        println!(
            "  {:<12} {:>8.1} MiB  {:>5} units clean, {:>3} bad  ({:.1} MiB/s)",
            String::from_utf8_lossy(&node.name),
            node.size as f64 / 1048576.0,
            ok,
            bad,
            (data.len() as f64 / 1048576.0) / secs
        );
    }
    println!();
    if total_bad == 0 {
        println!("OK: {total_ok} units decrypted to clean MPEG-TS. The libmmbd chain works.");
        Ok(())
    } else {
        warn!("{total_bad} of {} units did not decrypt cleanly", total_ok + total_bad);
        bail!("decryption check failed")
    }
}

fn publish_live(live: &[MountedDisc], state: idle::State) {
    let first = live.first();
    let mut snap = idle::observe(
        first.map(|m| m.source()),
        first.map(|m| m.mountpoint()),
        first.and_then(|m| m.raw_device()),
        if live.is_empty() { idle::State::Opening } else { state },
    );
    snap.mount_pid = Some(std::process::id());
    if live.len() > 1 {
        snap.label = Some(format!("{} discs", live.len()));
    }
    let tuples: Vec<(String, String, String, bool)> = live
        .iter()
        .map(|m| {
            (
                m.source().display().to_string(),
                m.label().to_string(),
                m.mountpoint().display().to_string(),
                false,
            )
        })
        .collect();
    idle::attach_drives(&mut snap, &tuples);
    idle::write_snapshot(&snap);
}

async fn cmd_mount(
    devices: Vec<PathBuf>,
    volume: Option<PathBuf>,
    mountpoint: Option<PathBuf>,
    cache_mib: usize,
) -> Result<()> {
    da::install_claim_hook();
    if let Some(v) = &volume {
        if !v.starts_with("/dev/") {
            bail!("pass a raw device (/dev/rdiskN) or nothing; do not pass /Volumes/…");
        }
    }
    let mut only = devices;
    if let Some(v) = volume {
        if !only.iter().any(|d| rawudf::devices_match(d, &v)) {
            only.push(v);
        }
    }
    let _ = take_over_os_bd_if_needed(&only)?;

    println!("Claimed Blu-ray mounts only: macOS will not mount a BD under /Volumes.");
    println!("A DVD or CD (including AVCHD) will appear under /Volumes as usual.");
    if only.is_empty() {
        println!("Watching every optical drive. Insert one or more Blu-rays.");
    } else {
        println!(
            "Watching {}.",
            only.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        );
    }

    let opts_base = MountOptions {
        cache_bytes: cache_mib * 1024 * 1024,
        mountpoint,
        ..MountOptions::default()
    };
    let mut live: Vec<MountedDisc> = Vec::new();
    publish_live(&live, idle::State::Opening);

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = sigint.recv() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => { warn!("SIGHUP: terminal went away, unmounting"); break; }
            _ = tick.tick() => {
                if let Some(req) = idle::take_eject_request() {
                    handle_eject_request(&mut live, &req).await;
                }
                live.retain(|m| m.is_active() && m.source_present());
                let skip: Vec<PathBuf> = live.iter().map(|m| m.source().to_path_buf()).collect();
                if let Some(dev) = rawudf::poll_bd_rdisk(&skip, &only) {
                    let mut opts = opts_base.clone();
                    if !live.is_empty() {
                        opts.mountpoint = None;
                    }
                    match MountedDisc::mount(&dev, &opts).await {
                        Ok(md) => {
                            println!("Decrypted view ready on {}: {}", dev.display(), md.mountpoint().display());
                            live.push(md);
                        }
                        Err(e) => warn!("mount {}: {e:#}", dev.display()),
                    }
                }
                publish_live(&live, if live.is_empty() { idle::State::Opening } else { idle::State::Serving });
            }
        }
    }
    for md in live {
        let src = md.source().to_path_buf();
        if let Err(e) = md.unmount().await {
            warn!("unmount {}: {e:#}", src.display());
        }
    }
    Ok(())
}

async fn handle_eject_request(live: &mut Vec<MountedDisc>, req: &idle::EjectRequest) {
    let mut remain = Vec::new();
    for md in live.drain(..) {
        let hit = req.all
            || req.device.as_ref().is_some_and(|d| rawudf::devices_match(md.source(), Path::new(d)));
        if !hit {
            remain.push(md);
            continue;
        }
        let src = md.source().to_path_buf();
        if let Err(e) = md.unmount().await {
            warn!("release {}: {e:#}", src.display());
            continue;
        }
        if let Err(e) = da::eject_after_release_filter(src.to_str()) {
            warn!("eject {}: {e:#}", src.display());
        }
    }
    *live = remain;
}
