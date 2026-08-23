//! Runtime symbol loading over the libitb shared library.
//!
//! The library is loaded once per process behind a `OnceLock` and
//! never unloaded, so the raw `extern "C"` function pointers cached
//! here stay valid for the process lifetime (the `Library` value is
//! stored in the same struct, declared last so it drops after every
//! pointer field). Search order:
//!
//! 1. `ITB_LIBITB_PATH` environment variable (path to the shared
//!    library file).
//! 2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up
//!    from the crate manifest directory (in-repo builds).
//! 3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
//!    `DYLD_LIBRARY_PATH`, `PATH`).
//!
//! A resolve failure surfaces as `ItbError::LibraryLoad` at the first
//! FFI call rather than a panic at process startup.

#![allow(non_snake_case)]

use std::ffi::{c_char, c_int, c_void};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use libloading::Library;

use crate::error::{ItbError, ItbResult};

// Function-pointer typedefs. Every signature mirrors a prototype in
// cmd/cshared/libitb.h; C size_t / uintptr_t map to usize. Buffer
// parameters cross as (ptr, len) pairs in the header's argument order.
pub(crate) type FnCStrOut = unsafe extern "C" fn(*mut c_char, usize, *mut usize) -> c_int;
pub(crate) type FnSetMemoryLimit = unsafe extern "C" fn(i64) -> i64;
pub(crate) type FnSetGCPercent = unsafe extern "C" fn(c_int) -> c_int;
// (profile, opts, blobOut, blobCap, *blobLen, *outHandle)
pub(crate) type FnTripleInit = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *mut c_void,
    usize,
    *mut usize,
    *mut usize,
) -> c_int;
// (profile, blob, blobLen, opts, permMaster, permMasterLen,
//  wrapMaster, wrapMasterLen, mastersCount, *outHandle)
pub(crate) type FnTripleOpen = unsafe extern "C" fn(
    *const c_char,
    *const c_void,
    usize,
    *const c_char,
    *const c_void,
    usize,
    *const c_void,
    usize,
    usize,
    *mut usize,
) -> c_int;
// (handle, permMaster, permMasterLen, wrapMaster, wrapMasterLen,
//  blobOut, blobCap, *blobLen)
pub(crate) type FnTripleRekey = unsafe extern "C" fn(
    usize,
    *const c_void,
    usize,
    *const c_void,
    usize,
    *mut c_void,
    usize,
    *mut usize,
) -> c_int;
pub(crate) type FnHandleOnly = unsafe extern "C" fn(usize) -> c_int;
// (handle, src, srcLen, out, outCap, *outLen)
pub(crate) type FnTripleCipher =
    unsafe extern "C" fn(usize, *const c_void, usize, *mut c_void, usize, *mut usize) -> c_int;
pub(crate) type FnTripleRegisterProfile =
    unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
pub(crate) type FnTripleStreamBegin = unsafe extern "C" fn(usize, *mut usize) -> c_int;
pub(crate) type FnTripleStreamWrite = unsafe extern "C" fn(usize, *const c_void, usize) -> c_int;
// (stream, out, outCap, *outLen, *finished)
pub(crate) type FnTripleStreamRead =
    unsafe extern "C" fn(usize, *mut c_void, usize, *mut usize, *mut c_int) -> c_int;

/// Cached function pointers plus the Library that keeps them valid.
pub(crate) struct Syms {
    pub(crate) ITB_Version: FnCStrOut,
    pub(crate) ITB_LastError: FnCStrOut,
    pub(crate) ITB_SetMemoryLimit: FnSetMemoryLimit,
    pub(crate) ITB_SetGCPercent: FnSetGCPercent,

    pub(crate) ITB_Triple_Init: FnTripleInit,
    pub(crate) ITB_Triple_Open: FnTripleOpen,
    pub(crate) ITB_Triple_Rekey: FnTripleRekey,
    pub(crate) ITB_Triple_Close: FnHandleOnly,
    pub(crate) ITB_Triple_Free: FnHandleOnly,
    pub(crate) ITB_Triple_EncryptStream: FnTripleCipher,
    pub(crate) ITB_Triple_DecryptStream: FnTripleCipher,
    pub(crate) ITB_Triple_EncryptMessage: FnTripleCipher,
    pub(crate) ITB_Triple_DecryptMessage: FnTripleCipher,
    pub(crate) ITB_Triple_RegisterProfile: FnTripleRegisterProfile,
    pub(crate) ITB_Triple_EncryptStreamBegin: FnTripleStreamBegin,
    pub(crate) ITB_Triple_DecryptStreamBegin: FnTripleStreamBegin,
    pub(crate) ITB_Triple_StreamWrite: FnTripleStreamWrite,
    pub(crate) ITB_Triple_StreamEnd: FnHandleOnly,
    pub(crate) ITB_Triple_StreamRead: FnTripleStreamRead,
    pub(crate) ITB_Triple_StreamFree: FnHandleOnly,

    // Keeps the raw fn pointers above valid for the process lifetime.
    // Declared last so it drops after every pointer field.
    _lib: Library,
}

// SAFETY: every field is an immutable `unsafe extern "C" fn` pointer
// cached once at load time; libitb itself is documented safe for
// concurrent use across OS threads.
unsafe impl Send for Syms {}
unsafe impl Sync for Syms {}

static SYMS: OnceLock<Result<Syms, Arc<libloading::Error>>> = OnceLock::new();

/// Returns the process-wide symbol bundle, loading the library on
/// first use. Load failures are cached and re-reported on every call.
pub(crate) fn syms() -> ItbResult<&'static Syms> {
    match SYMS.get_or_init(|| unsafe { Syms::load() }.map_err(Arc::new)) {
        Ok(s) => Ok(s),
        Err(e) => Err(ItbError::LibraryLoad(Arc::clone(e))),
    }
}

impl Syms {
    unsafe fn load() -> Result<Self, libloading::Error> {
        // SAFETY: loading libitb runs its Go runtime initialiser, which
        // is the documented way to bring the library up.
        let lib = unsafe { Library::new(resolve_library_path())? };
        macro_rules! sym {
            ($name:literal) => {{
                // SAFETY: the target field's fn-pointer type matches the
                // C prototype in libitb.h; dereferencing the Symbol
                // yields a raw fn pointer that stays valid while `lib`
                // (stored in this struct) remains loaded.
                let s: libloading::Symbol<'_, _> = unsafe { lib.get($name)? };
                *s
            }};
        }
        Ok(Self {
            ITB_Version: sym!(b"ITB_Version"),
            ITB_LastError: sym!(b"ITB_LastError"),
            ITB_SetMemoryLimit: sym!(b"ITB_SetMemoryLimit"),
            ITB_SetGCPercent: sym!(b"ITB_SetGCPercent"),
            ITB_Triple_Init: sym!(b"ITB_Triple_Init"),
            ITB_Triple_Open: sym!(b"ITB_Triple_Open"),
            ITB_Triple_Rekey: sym!(b"ITB_Triple_Rekey"),
            ITB_Triple_Close: sym!(b"ITB_Triple_Close"),
            ITB_Triple_Free: sym!(b"ITB_Triple_Free"),
            ITB_Triple_EncryptStream: sym!(b"ITB_Triple_EncryptStream"),
            ITB_Triple_DecryptStream: sym!(b"ITB_Triple_DecryptStream"),
            ITB_Triple_EncryptMessage: sym!(b"ITB_Triple_EncryptMessage"),
            ITB_Triple_DecryptMessage: sym!(b"ITB_Triple_DecryptMessage"),
            ITB_Triple_RegisterProfile: sym!(b"ITB_Triple_RegisterProfile"),
            ITB_Triple_EncryptStreamBegin: sym!(b"ITB_Triple_EncryptStreamBegin"),
            ITB_Triple_DecryptStreamBegin: sym!(b"ITB_Triple_DecryptStreamBegin"),
            ITB_Triple_StreamWrite: sym!(b"ITB_Triple_StreamWrite"),
            ITB_Triple_StreamEnd: sym!(b"ITB_Triple_StreamEnd"),
            ITB_Triple_StreamRead: sym!(b"ITB_Triple_StreamRead"),
            ITB_Triple_StreamFree: sym!(b"ITB_Triple_StreamFree"),
            _lib: lib,
        })
    }
}

fn lib_filename() -> &'static str {
    if cfg!(target_os = "windows") {
        "libitb.dll"
    } else if cfg!(target_os = "macos") {
        "libitb.dylib"
    } else {
        "libitb.so"
    }
}

fn dist_subdir() -> String {
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        std::env::consts::ARCH
    };
    format!("{os}-{arch}")
}

fn resolve_library_path() -> PathBuf {
    if let Ok(p) = std::env::var("ITB_LIBITB_PATH")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(repo) = manifest.parent().and_then(|p| p.parent()) {
        let cand = repo.join("dist").join(dist_subdir()).join(lib_filename());
        if cand.is_file() {
            return cand;
        }
    }
    PathBuf::from(lib_filename())
}
