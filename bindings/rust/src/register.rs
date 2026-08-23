//! User-defined profile registration.

use std::ffi::CString;

use crate::error::{ItbError, ItbResult, check};
use crate::ffi;
use crate::opts::OptsBuilder;

/// Registers a user-defined Triple profile under `name` so subsequent
/// [`crate::Pipeline::init`] / [`crate::Pipeline::open`] calls resolve
/// it. The opts follow the register-profile grammar validated by Go
/// (`mode`, `width`, `innerHash` / `innerHashes`, `keyBits`,
/// `macName`, `outerCipher`, `parallaxPalette`,
/// `parallaxSegmentSize`, `chunkSize`, `parallaxOn`, `wrapperOn`) —
/// build them with [`OptsBuilder::with_raw`] plus the typed setters
/// where key names coincide. A duplicate name fails with
/// [`crate::ItbStatus::ProfileExists`].
pub fn register_profile(name: &str, opts: &OptsBuilder) -> ItbResult<()> {
    let s = ffi::syms()?;
    let name_c = CString::new(name).map_err(|_| ItbError::Ffi("profile name contains NUL"))?;
    let opts_c = opts.build();
    // SAFETY: both pointers are NUL-terminated strings live for the
    // duration of the call.
    check(unsafe { (s.ITB_Triple_RegisterProfile)(name_c.as_ptr(), opts_c.as_ptr()) })
}
