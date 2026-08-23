//! RAII wrapper around the Triple Pipeline handle.

use std::ffi::CString;
use std::io::{Read, Write};

use crate::error::{ItbError, ItbResult, check};
use crate::ffi::{self, FnTripleCipher, Syms};
use crate::opts::OptsBuilder;
use crate::status::ItbStatus;
use crate::stream::{DecryptStream, EncryptStream};

/// Floor capacity for blob output buffers (Init / Rekey).
const BLOB_CAP: usize = 64 * 1024;

/// Pre-allocation formula for Message / one-shot stream outputs:
/// `max(131072, payload * 5/4 + 131072)`.
fn out_cap(payload: usize) -> usize {
    (payload + payload / 4 + 131_072).max(131_072)
}

/// Single retry-once dispatch site for every variable-size output
/// buffer: pre-allocate `cap`, and on `BufferTooSmall` retry once
/// with the exact size the FFI reported through the length out-param.
fn retry_once(
    cap: usize,
    mut call: impl FnMut(&mut [u8], &mut usize) -> i32,
) -> ItbResult<Vec<u8>> {
    let mut buf = vec![0u8; cap];
    let mut len = 0usize;
    let mut rc = call(&mut buf, &mut len);
    if rc == ItbStatus::BufferTooSmall as i32 {
        buf = vec![0u8; len];
        rc = call(&mut buf, &mut len);
    }
    check(rc)?;
    buf.truncate(len);
    Ok(buf)
}

/// A Triple Pipeline session plus its exported blob bytes.
///
/// The blob carries the session bundle the receiver feeds to
/// [`Pipeline::open`]; [`Pipeline::rekey`] refreshes it. Dropping the
/// Pipeline frees the handle (libitb zeroes key material internally).
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
pub struct Pipeline {
    handle: usize,
    blob: Vec<u8>,
}

impl Pipeline {
    /// Constructs a fresh Pipeline against the named profile. On a
    /// blob-buffer retry the Init re-runs and yields a fresh session
    /// (the undersized attempt is closed by libitb before returning).
    pub fn init(profile: &str, opts: &OptsBuilder) -> ItbResult<Self> {
        let s = ffi::syms()?;
        let profile_c = cstr(profile, "profile name contains NUL")?;
        let opts_c = opts.build();
        let mut handle = 0usize;
        let blob = retry_once(BLOB_CAP, |buf, len| {
            // SAFETY: all pointers reference live buffers for the
            // duration of the call; len / handle are valid out-params.
            unsafe {
                (s.ITB_Triple_Init)(
                    profile_c.as_ptr(),
                    opts_c.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    len,
                    &mut handle,
                )
            }
        })?;
        Ok(Self { handle, blob })
    }

    /// Reconstructs a Pipeline from a blob produced by [`Pipeline::init`]
    /// or [`Pipeline::rekey`]. `masters` is `None` to use the
    /// blob-embedded masters, or `Some((perm, wrap))` to override them.
    pub fn open(
        profile: &str,
        blob: &[u8],
        opts: &OptsBuilder,
        masters: Option<(&[u8], &[u8])>,
    ) -> ItbResult<Self> {
        let s = ffi::syms()?;
        let profile_c = cstr(profile, "profile name contains NUL")?;
        let opts_c = opts.build();
        let (pm, wm, count) = match masters {
            None => (&[][..], &[][..], 0usize),
            Some((pm, wm)) => {
                if pm.is_empty() || wm.is_empty() {
                    return Err(ItbError::Ffi("master override slices must be non-empty"));
                }
                (pm, wm, 2usize)
            }
        };
        let mut handle = 0usize;
        // SAFETY: all pointers reference live buffers for the duration
        // of the call; handle is a valid out-param. Empty slices cross
        // as (dangling, 0), which the Go side treats as absent.
        let rc = unsafe {
            (s.ITB_Triple_Open)(
                profile_c.as_ptr(),
                blob.as_ptr().cast(),
                blob.len(),
                opts_c.as_ptr(),
                pm.as_ptr().cast(),
                pm.len(),
                wm.as_ptr().cast(),
                wm.len(),
                count,
                &mut handle,
            )
        };
        check(rc)?;
        Ok(Self {
            handle,
            blob: blob.to_vec(),
        })
    }

    /// The exported session bundle bytes for the receiver side.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// Rotates the parallax + wrapper masters and refreshes
    /// [`Pipeline::blob`]. Must not run concurrently with cipher calls
    /// or open stream sessions on the same Pipeline.
    pub fn rekey(&mut self, perm: &[u8], wrap: &[u8]) -> ItbResult<()> {
        let s = ffi::syms()?;
        self.blob = retry_once(BLOB_CAP.max(self.blob.len()), |buf, len| {
            // SAFETY: all pointers reference live buffers for the
            // duration of the call; len is a valid out-param.
            unsafe {
                (s.ITB_Triple_Rekey)(
                    self.handle,
                    perm.as_ptr().cast(),
                    perm.len(),
                    wrap.as_ptr().cast(),
                    wrap.len(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    len,
                )
            }
        })?;
        Ok(())
    }

    /// Zeroes the Pipeline's key material and marks it closed.
    /// Idempotent; subsequent cipher calls return
    /// [`ItbStatus::TripleClosed`].
    pub fn close(&mut self) -> ItbResult<()> {
        let s = ffi::syms()?;
        // SAFETY: handle-only call, idempotent on the Go side.
        check(unsafe { (s.ITB_Triple_Close)(self.handle) })
    }

    /// Single Message encrypt: one call, one self-contained wire.
    pub fn encrypt_message(&self, plain: &[u8]) -> ItbResult<Vec<u8>> {
        self.cipher(|s| s.ITB_Triple_EncryptMessage, plain)
    }

    /// Receive-side counterpart of [`Pipeline::encrypt_message`].
    pub fn decrypt_message(&self, wire: &[u8]) -> ItbResult<Vec<u8>> {
        self.cipher(|s| s.ITB_Triple_DecryptMessage, wire)
    }

    /// One-shot stream encrypt for callers holding the whole plaintext
    /// in memory. For bounded-memory streaming use
    /// [`Pipeline::encrypt_stream`] / [`Pipeline::encrypt_stream_pump`].
    pub fn encrypt_stream_one_shot(&self, plain: &[u8]) -> ItbResult<Vec<u8>> {
        self.cipher(|s| s.ITB_Triple_EncryptStream, plain)
    }

    /// Receive-side counterpart of [`Pipeline::encrypt_stream_one_shot`].
    pub fn decrypt_stream_one_shot(&self, wire: &[u8]) -> ItbResult<Vec<u8>> {
        self.cipher(|s| s.ITB_Triple_DecryptStream, wire)
    }

    /// Opens an incremental encrypt session (plaintext in, wire out).
    pub fn encrypt_stream(&self) -> ItbResult<EncryptStream<'_>> {
        EncryptStream::begin(self)
    }

    /// Opens an incremental decrypt session (wire in, plaintext out).
    pub fn decrypt_stream(&self) -> ItbResult<DecryptStream<'_>> {
        DecryptStream::begin(self)
    }

    /// Pumps `src` through an encrypt session into `dst` with bounded
    /// memory: feed a slice, drain available wire, repeat; end + final
    /// drain on source EOF. The session is freed on return.
    pub fn encrypt_stream_pump<R: Read, W: Write>(&self, src: R, dst: W) -> ItbResult<()> {
        self.encrypt_stream()?.pump(src, dst)
    }

    /// Receive-side counterpart of [`Pipeline::encrypt_stream_pump`].
    pub fn decrypt_stream_pump<R: Read, W: Write>(&self, src: R, dst: W) -> ItbResult<()> {
        self.decrypt_stream()?.pump(src, dst)
    }

    pub(crate) fn raw_handle(&self) -> usize {
        self.handle
    }

    /// Shared body for the four buffer-in / buffer-out cipher entries.
    fn cipher(
        &self,
        pick: impl Fn(&'static Syms) -> FnTripleCipher,
        src: &[u8],
    ) -> ItbResult<Vec<u8>> {
        let f = pick(ffi::syms()?);
        retry_once(out_cap(src.len()), |buf, len| {
            // SAFETY: src / buf reference live buffers for the duration
            // of the call; len is a valid out-param.
            unsafe {
                f(
                    self.handle,
                    src.as_ptr().cast(),
                    src.len(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    len,
                )
            }
        })
    }
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The blob bytes are elided — session-bundle material does not
        // belong in debug logs.
        f.debug_struct("Pipeline")
            .field("blob_len", &self.blob.len())
            .finish_non_exhaustive()
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        if self.handle == 0 {
            return;
        }
        if let Ok(s) = ffi::syms() {
            // SAFETY: Free closes then releases the handle; safe from
            // any state. The status is deliberately ignored on the
            // drop path.
            let _ = unsafe { (s.ITB_Triple_Free)(self.handle) };
        }
        self.handle = 0;
    }
}

fn cstr(s: &str, msg: &'static str) -> ItbResult<CString> {
    CString::new(s).map_err(|_| ItbError::Ffi(msg))
}
