# bdmount

Skip dumping a Blu-ray or UHD Blu-ray to MKV files on macOS. `bdmount` is a CLI app that presents the disc as a folder that encoders like HandBrake and ffmpeg can open so you can encode straight from the drive, **similar to how users on Windows use AnyDVD or XReveal**.

## How it Works 

Present an AACS-encrypted Blu-ray as a plain BDMV folder so the HandBrake GUI can Open Source it (presets and queue). Decryption is on the fly through MakeMKV’s `libmmbd`.

This does **not** replace MakeMKV. Install MakeMKV, put your evaluation or [beta key](https://forum.makemkv.com/forum/viewtopic.php?f=5&t=1053) in MakeMKV, then use `bdmount` to claim the drive and serve a folder. HandBrake stays the transcode UI.

We do **not** ship `libmmbd`. `bdmount` `dlopen`s it from `/Applications/MakeMKV.app`.

Exclusive-drive is the supported path: start **before** inserting the disc. We dissent the OS UDF mount of **Blu-ray** media (`IOBDMedia`). There is no `/Volumes/LABEL`. DVD and CD (including AVCHD) pass through to the OS.

## Requirements

- macOS 13+, an optical drive MakeMKV can use (LibreDrive helps)
- [MakeMKV](https://www.makemkv.com/) at `/Applications/MakeMKV.app` (already set up with a key)
- HandBrake.app for encode (warned, not required to mount)

Do not run MakeMKV.app and `bdmount` in the same session.

## Build

A [Rust toolchain](https://rustup.rs/) is required to compile from source.

```sh
cargo build --release
```

The binary is `target/release/bdmount`.

## Install

```sh
scripts/install.sh
```

This builds a release binary and copies it to `~/.local/bin/bdmount`. Add `~/.local/bin` to your `PATH` if it is not already there.

```sh
scripts/uninstall.sh    # unmount decrypted views and remove the binary
```

## Usage

```sh
bdmount -v mount                 # every drive; start before insert
bdmount -v mount --device /dev/rdisk6 --device /dev/rdisk8
bdmount eject                    # every disc we are serving
bdmount eject --device /dev/rdisk6
bdmount status
bdmount status --json            # includes drives[]
bdmount unmount --all
bdmount list
bdmount probe [/dev/rdiskN]
```

`watch` is engine-only. Do not use it as the product.

## Happy path

1. Leave the disc **out**. Quit MakeMKV. If `/Volumes` already shows a movie Blu-ray, eject it first.
2. Run `bdmount -v mount` in Terminal.app. The claim hook is already running; insert when it says waiting. If a movie BD is already under `/Volumes`, we politely unmount it (never force) and take over — unless HandBrake/MakeMKV still has it open.
3. Insert the Blu-ray. You should **not** get `/Volumes/<LABEL>`. The decrypted view is `~/BluRay Decrypted/<LABEL>`.
4. HandBrake → File → Open Source… → that folder.
5. Quit HandBrake, then `bdmount eject` (unmount + tray). Ctrl-C only releases the folder. **Never unplug** the USB enclosure while the drive is busy.

A DVD or camcorder AVCHD disc inserted while waiting appears under `/Volumes` in macOS as usual. We interfere with these.

## Throughput

Userspace UDF has no kernel UDF cache. The reader uses a 16 MiB sequential window, a 16 MiB prefetch slot, and buffered `/dev/diskN` when the block size is 2048.

## Safety

| Do | Do not |
|---|---|
| Start `bdmount mount` before inserting a Blu-ray | Insert first and hope we steal `/Volumes` |
| Quit HandBrake, then `bdmount eject` | USB-yank a busy drive |
| Use Disk Utility if eject is refused | `umount -f` on OS UDF |
| Power-button reboot if Finder is stuck | Share the drive with MakeMKV.app in the same session |
