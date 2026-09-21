//! Thin safe wrapper around MakeMKV's `libmmbd` (see `vendor/mmbd.h`).
//!
//! The library is loaded at runtime with `dlopen`, so this binary has no
//! link-time dependency on MakeMKV. `libmmbd` itself spawns
//! `makemkvcon guiserver` in the background and talks to it over pipes; that
//! child process is what performs the AACS / BD+ key work (and, with a
//! LibreDrive drive, the raw disc access). Per-unit decryption happens in
//! process: `libmmbd` asks `makemkvcon` for the unit key and then runs
//! AES-CBC locally.
//!
//! A single `MMBD` context is **not** thread-safe: it polls a job flag with
//! `usleep` and shares one IPC channel. Callers must serialize access, which
//! [`Mmbd`] enforces by only exposing `&mut self` methods; wrap it in a
//! `Mutex` to share between threads.

// This module mirrors the C header; not every constant/accessor is used yet.
#![allow(dead_code)]

use std::ffi::{CStr, CString, c_char, c_void};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use libloading::Library;
use tracing::{debug, error, info, warn};

/// Size of a BD "aligned unit": 32 TS packets of 192 bytes.
pub const UNIT_SIZE: usize = 6144;

/// Name flag: object is an M2TS file. The clip number goes in the low bits.
pub const FILE_M2TS: u32 = 0;
/// Name flag: object is an SSIF (3D) file. The clip number goes in the low bits.
pub const FILE_SSIF: u32 = 0x8000_0000;
/// Only apply AACS decryption, skip BD+.
pub const FLAG_AACS_ONLY: u32 = 0x0010_0000;
/// Only apply BD+ transform.
pub const FLAG_BDPLUS_ONLY: u32 = 0x0020_0000;
/// Only remove bus encryption.
pub const FLAG_BUS_ONLY: u32 = 0x0040_0000;
/// libaacs compatibility: let the engine figure out the CPS unit.
pub const FLAG_AUTO_CPSID: u32 = 0x1000_0000;

const MSG_FLAG_WARNING: u32 = 0x1000_0000;
const MSG_FLAG_ERROR: u32 = 0x2000_0000;
const MSG_FLAG_MMBD_ERROR: u32 = 0x4000_0000;

/// Default location of the library inside the MakeMKV bundle.
pub const DEFAULT_LIB_PATH: &str = "/Applications/MakeMKV.app/Contents/lib/libmmbd_new.dylib";
/// Environment variable that overrides [`DEFAULT_LIB_PATH`].
pub const LIB_PATH_ENV: &str = "BDMOUNT_LIBMMBD";

#[repr(C)]
struct RawContext {
    _private: [u8; 0],
}

type OutputProc =
    unsafe extern "C" fn(user: *mut c_void, flags: u32, utf8: *const c_char, unused: *const c_void);

type FnGetVersionString = unsafe extern "C" fn() -> *const c_char;
type FnCreateContext = unsafe extern "C" fn(
    user: *mut c_void,
    output: Option<OutputProc>,
    argp: *const *const c_char,
) -> *mut RawContext;
type FnDestroyContext = unsafe extern "C" fn(ctx: *mut RawContext);
type FnGetEngineVersion = unsafe extern "C" fn(ctx: *mut RawContext) -> *const c_char;
type FnOpen = unsafe extern "C" fn(ctx: *mut RawContext, locator: *const c_char) -> i32;
type FnClose = unsafe extern "C" fn(ctx: *mut RawContext) -> i32;
type FnGetMkbVersion = unsafe extern "C" fn(ctx: *mut RawContext) -> u32;
type FnGetDiscId = unsafe extern "C" fn(ctx: *mut RawContext) -> *const u8;
type FnDecryptUnit =
    unsafe extern "C" fn(ctx: *mut RawContext, name_flags: u32, file_offset: u64, buf: *mut u8) -> i32;
type FnGetBusenc = unsafe extern "C" fn(ctx: *mut RawContext) -> i32;

struct Api {
    get_version_string: FnGetVersionString,
    create_context: FnCreateContext,
    destroy_context: FnDestroyContext,
    /// Not exported by the libmmbd 1.8.x shipped with MakeMKV 1.18.
    get_engine_version_string: Option<FnGetEngineVersion>,
    open: FnOpen,
    close: FnClose,
    get_mkb_version: FnGetMkbVersion,
    get_disc_id: FnGetDiscId,
    decrypt_unit: FnDecryptUnit,
    get_busenc: FnGetBusenc,
}

macro_rules! sym {
    ($lib:expr, $name:literal, $ty:ty) => {{
        let s: libloading::Symbol<$ty> = unsafe { $lib.get(concat!($name, "\0").as_bytes()) }
            .with_context(|| format!("libmmbd is missing symbol {}", $name))?;
        *s
    }};
}

impl Api {
    fn load(lib: &Library) -> Result<Api> {
        Ok(Api {
            get_version_string: sym!(lib, "mmbd_get_version_string", FnGetVersionString),
            create_context: sym!(lib, "mmbd_create_context", FnCreateContext),
            destroy_context: sym!(lib, "mmbd_destroy_context", FnDestroyContext),
            get_engine_version_string: unsafe { lib.get::<FnGetEngineVersion>(b"mmbd_get_engine_version_string\0") }
                .ok()
                .map(|s| *s),
            open: sym!(lib, "mmbd_open", FnOpen),
            close: sym!(lib, "mmbd_close", FnClose),
            get_mkb_version: sym!(lib, "mmbd_get_mkb_version", FnGetMkbVersion),
            get_disc_id: sym!(lib, "mmbd_get_disc_id", FnGetDiscId),
            decrypt_unit: sym!(lib, "mmbd_decrypt_unit", FnDecryptUnit),
            get_busenc: sym!(lib, "mmbd_get_busenc", FnGetBusenc),
        })
    }
}

/// Diagnostic callback handed to libmmbd; forwards messages to `tracing`.
unsafe extern "C" fn output_proc(_user: *mut c_void, flags: u32, utf8: *const c_char, _unused: *const c_void) {
    if utf8.is_null() {
        return;
    }
    let msg = unsafe { CStr::from_ptr(utf8) }.to_string_lossy();
    let code = flags & 0x000f_ffff;
    if flags & (MSG_FLAG_ERROR | MSG_FLAG_MMBD_ERROR) != 0 {
        error!(target: "libmmbd", code, "{msg}");
    } else if flags & MSG_FLAG_WARNING != 0 {
        warn!(target: "libmmbd", code, "{msg}");
    } else {
        info!(target: "libmmbd", code, "{msg}");
    }
}

/// Resolve the path of `libmmbd_new.dylib`, honoring [`LIB_PATH_ENV`].
pub fn library_path() -> PathBuf {
    std::env::var_os(LIB_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LIB_PATH))
}

/// An owned libmmbd context with (at most) one disc open.
pub struct Mmbd {
    api: Api,
    ctx: *mut RawContext,
    // Keep the dylib mapped for as long as we hold function pointers into it.
    _lib: Library,
    disc_open: bool,
}

// The raw pointer is only ever used through `&mut self`, so moving the
// context to another thread is fine as long as access stays serialized.
unsafe impl Send for Mmbd {}

impl Mmbd {
    /// Load the library and create a context. This launches `makemkvcon`
    /// in the background and performs the version handshake, so it can take
    /// a couple of seconds and fails if MakeMKV is missing or unregistered.
    pub fn new() -> Result<Mmbd> {
        Self::with_library(&library_path())
    }

    pub fn with_library(path: &Path) -> Result<Mmbd> {
        if !path.exists() {
            bail!(
                "libmmbd not found at {} (is MakeMKV installed? override with {}=/path/to/libmmbd_new.dylib)",
                path.display(),
                LIB_PATH_ENV
            );
        }
        let lib = unsafe { Library::new(path) }
            .with_context(|| format!("failed to dlopen {}", path.display()))?;
        let api = Api::load(&lib)?;

        let lib_version = unsafe { CStr::from_ptr((api.get_version_string)()) }
            .to_string_lossy()
            .into_owned();
        debug!("loaded {} from {}", lib_version, path.display());

        let ctx = unsafe { (api.create_context)(std::ptr::null_mut(), Some(output_proc), std::ptr::null()) };
        if ctx.is_null() {
            bail!(
                "mmbd_create_context failed: could not start makemkvcon in the background \
                 (check that MakeMKV is installed at /Applications/MakeMKV.app and is registered; \
                 set MAKEMKVCON=/path/to/makemkvcon to override, MMBD_TRACE=1 for details)"
            );
        }

        let mmbd = Mmbd {
            api,
            ctx,
            _lib: lib,
            disc_open: false,
        };
        info!("libmmbd ready: {} / engine {}", lib_version, mmbd.engine_version());
        Ok(mmbd)
    }

    /// Version string reported by the library itself.
    pub fn library_version(&self) -> String {
        unsafe { CStr::from_ptr((self.api.get_version_string)()) }
            .to_string_lossy()
            .into_owned()
    }

    /// Version / registration string of the MakeMKV engine behind this context.
    pub fn engine_version(&self) -> String {
        let Some(f) = self.api.get_engine_version_string else {
            return String::from("<not reported by this libmmbd>");
        };
        let p = unsafe { f(self.ctx) };
        if p.is_null() {
            return String::from("<unknown>");
        }
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    /// Open a disc. `locator` may be a path to the disc root (e.g.
    /// `/Volumes/MOVIE`), its `BDMV`/`AACS` directory, any `.m2ts` file on
    /// it, a raw device (`/dev/rdisk4`), or a MakeMKV locator (`disc:0`,
    /// `dev:/dev/rdisk4`, `iso:/path.iso`).
    ///
    /// This makes MakeMKV fully open and scan the disc, so it takes as long
    /// as opening the disc in the MakeMKV GUI does.
    pub fn open(&mut self, locator: &str) -> Result<()> {
        let c = CString::new(locator).context("locator contains NUL")?;
        info!("libmmbd: opening {locator}");
        let r = unsafe { (self.api.open)(self.ctx, c.as_ptr()) };
        if r != 0 {
            return Err(anyhow!("mmbd_open({locator}) failed with code {r}{}", describe_open_error(r)));
        }
        self.disc_open = true;
        Ok(())
    }

    pub fn close(&mut self) {
        if self.disc_open {
            unsafe { (self.api.close)(self.ctx) };
            self.disc_open = false;
        }
    }

    pub fn is_open(&self) -> bool {
        self.disc_open
    }

    /// AACS MKB version of the open disc (0 if none).
    pub fn mkb_version(&self) -> u32 {
        unsafe { (self.api.get_mkb_version)(self.ctx) }
    }

    /// 20-byte libaacs-style disc id of the open disc.
    pub fn disc_id(&self) -> Option<[u8; 20]> {
        let p = unsafe { (self.api.get_disc_id)(self.ctx) };
        if p.is_null() {
            return None;
        }
        let mut id = [0u8; 20];
        unsafe { std::ptr::copy_nonoverlapping(p, id.as_mut_ptr(), 20) };
        Some(id)
    }

    /// Whether the open disc uses AACS bus encryption.
    pub fn bus_encrypted(&self) -> bool {
        unsafe { (self.api.get_busenc)(self.ctx) != 0 }
    }

    /// Decrypt one 6144-byte aligned unit in place.
    ///
    /// * `name_flags` – [`FILE_M2TS`] or [`FILE_SSIF`] OR-ed with the clip
    ///   number (the digits of the file name), plus optional `FLAG_*`.
    /// * `file_offset` – byte offset of this unit inside the file (BD+ needs it).
    ///
    /// Bus encryption, AACS and BD+ are all handled based on the disc's flags.
    pub fn decrypt_unit(&mut self, name_flags: u32, file_offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.len() != UNIT_SIZE {
            bail!("decrypt_unit needs exactly {UNIT_SIZE} bytes, got {}", buf.len());
        }
        let r = unsafe { (self.api.decrypt_unit)(self.ctx, name_flags, file_offset, buf.as_mut_ptr()) };
        if r != 0 {
            bail!(
                "mmbd_decrypt_unit(name_flags={name_flags:#x}, offset={file_offset}) failed: {}",
                describe_decrypt_error(r)
            );
        }
        Ok(())
    }
}

impl Drop for Mmbd {
    fn drop(&mut self) {
        self.close();
        unsafe { (self.api.destroy_context)(self.ctx) };
    }
}

fn describe_open_error(code: i32) -> &'static str {
    match code {
        -2 => " (context not active: makemkvcon exited?)",
        -3 => " (could not enumerate drives)",
        -4 => " (MakeMKV could not open the disc at that locator)",
        -5 => " (disc opened but no titles found)",
        -6 | -7 => " (failed to retrieve disc/clip info)",
        _ => "",
    }
}

fn describe_decrypt_error(code: i32) -> &'static str {
    match code {
        -2 => "no disc open / context inactive",
        -3 => "buffer is not an aligned unit (byte 4 is not 0x47)",
        -4 => "engine refused to return a unit key",
        _ => "unknown error",
    }
}

/// Clip number from a `xxxxx.m2ts` / `xxxxx.ssif` file name, if it has the
/// standard five-digit form.
pub fn clip_number(file_name: &str) -> Option<u32> {
    let stem = file_name.rsplit_once('.').map(|(s, _)| s).unwrap_or(file_name);
    if stem.len() != 5 || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok()
}

/// Check that every 192-byte packet in a unit starts with a TS sync byte.
pub fn unit_looks_like_clear_ts(unit: &[u8]) -> bool {
    unit.len() == UNIT_SIZE && (0..32).all(|i| unit[i * 192 + 4] == 0x47)
}

/// Whether the unit carries the AACS "encrypted" copy-permission bits.
pub fn unit_is_encrypted(unit: &[u8]) -> bool {
    !unit.is_empty() && (unit[0] & 0xC0) != 0
}
