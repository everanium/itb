//! File-like streaming wrappers over the one-shot ITB encrypt /
//! decrypt API.
//!
//! ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
//! container size limit). Streaming larger payloads simply means
//! slicing the input into chunks at the binding layer, encrypting
//! each chunk through the regular FFI path, and concatenating the
//! results. The reverse operation walks a concatenated chunk stream
//! by reading the chunk header, calling [`crate::parse_chunk_len`] to
//! learn the chunk's body length, reading that many bytes, and
//! decrypting the single chunk.
//!
//! Both struct-based wrappers ([`StreamEncryptor`], [`StreamDecryptor`]
//! and their Triple counterparts) and free-function convenience
//! wrappers ([`encrypt_stream`], [`decrypt_stream`], plus Triple
//! variants) are provided. Memory peak is bounded by `chunk_size`
//! (default 16 MB), regardless of the total payload length.
//!
//! The Triple-Ouroboros (7-seed) variants share the same I/O contract
//! and only differ in the seed list passed to the constructor.
//!
//! # Warning
//!
//! Do not call [`crate::set_nonce_bits`] between writes on the same
//! stream. The chunks are encrypted under the active nonce-size at
//! the moment each chunk is flushed; switching nonce-bits mid-stream
//! produces a chunk header layout the paired decryptor (which
//! snapshots [`crate::header_size`] at construction) cannot parse.

use std::io::{Read, Write};

use crate::encrypt::{
    decrypt as low_decrypt, decrypt_triple as low_decrypt_triple,
    encrypt as low_encrypt, encrypt_triple as low_encrypt_triple,
};
use crate::error::ITBError;
use crate::ffi;
use crate::registry::{header_size, parse_chunk_len};
use crate::seed::Seed;

/// Default chunk size — matches `itb.DefaultChunkSize` on the Go side
/// (16 MB), the size at which ITB's barrier-encoded container layout
/// stays well within the per-chunk pixel cap.
pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;

fn io_err(e: std::io::Error) -> ITBError {
    ITBError::with_message(ffi::STATUS_INTERNAL, format!("io: {e}"))
}

// --------------------------------------------------------------------
// Single Ouroboros — chunked writer.
// --------------------------------------------------------------------

/// Chunked encrypt writer: buffers plaintext until at least
/// `chunk_size` bytes are available, then encrypts and emits one
/// chunk to the output sink. The trailing partial buffer is flushed
/// as a final chunk on [`StreamEncryptor::close`] (so the on-the-wire
/// chunk count is `ceil(total / chunk_size)`).
///
/// Usage:
///
/// ```no_run
/// use itb::{Seed, StreamEncryptor};
///
/// let n = Seed::new("blake3", 1024).unwrap();
/// let d = Seed::new("blake3", 1024).unwrap();
/// let s = Seed::new("blake3", 1024).unwrap();
/// let mut sink: Vec<u8> = Vec::new();
/// {
///     let mut enc = StreamEncryptor::new(&n, &d, &s, &mut sink, 1 << 16).unwrap();
///     enc.write(b"chunk one").unwrap();
///     enc.write(b"chunk two").unwrap();
///     enc.close().unwrap();
/// }
/// ```
pub struct StreamEncryptor<'a, W: Write> {
    noise: &'a Seed,
    data: &'a Seed,
    start: &'a Seed,
    fout: W,
    chunk_size: usize,
    buf: Vec<u8>,
    closed: bool,
}

impl<'a, W: Write> StreamEncryptor<'a, W> {
    /// Constructs a fresh stream encryptor wrapping the given output
    /// writer. `chunk_size` must be positive.
    pub fn new(
        noise: &'a Seed,
        data: &'a Seed,
        start: &'a Seed,
        fout: W,
        chunk_size: usize,
    ) -> Result<Self, ITBError> {
        if chunk_size == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "chunk_size must be positive",
            ));
        }
        Ok(Self {
            noise,
            data,
            start,
            fout,
            chunk_size,
            buf: Vec::new(),
            closed: false,
        })
    }

    /// Appends `data` to the internal buffer, encrypting and emitting
    /// every full `chunk_size`-sized slice that becomes available.
    /// Returns the number of bytes consumed (always equal to
    /// `data.len()` on success).
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "write on closed StreamEncryptor",
            ));
        }
        self.buf.extend_from_slice(data);
        while self.buf.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buf.drain(..self.chunk_size).collect();
            let ct = low_encrypt(self.noise, self.data, self.start, &chunk)?;
            self.fout.write_all(&ct).map_err(io_err)?;
        }
        Ok(data.len())
    }

    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent — a second call is a no-op.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            let ct = low_encrypt(self.noise, self.data, self.start, &chunk)?;
            self.fout.write_all(&ct).map_err(io_err)?;
        }
        self.closed = true;
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamEncryptor<'a, W> {
    fn drop(&mut self) {
        // Best-effort flush; errors during drop are swallowed because
        // there is no path to surface them. Callers that need to see
        // close-time errors must call `close()` explicitly.
        let _ = self.close();
    }
}

// --------------------------------------------------------------------
// Single Ouroboros — chunked reader.
// --------------------------------------------------------------------

/// Chunked decrypt writer: accumulates ciphertext bytes via
/// [`StreamDecryptor::feed`] until a full chunk (header + body) is
/// available, then decrypts the chunk and writes the plaintext to
/// the output sink. Multiple full chunks in one feed call are
/// processed sequentially.
///
/// Usage:
///
/// ```no_run
/// use itb::{Seed, StreamDecryptor};
///
/// # let ciphertext: Vec<u8> = vec![];
/// let n = Seed::new("blake3", 1024).unwrap();
/// let d = Seed::new("blake3", 1024).unwrap();
/// let s = Seed::new("blake3", 1024).unwrap();
/// let mut sink: Vec<u8> = Vec::new();
/// {
///     let mut dec = StreamDecryptor::new(&n, &d, &s, &mut sink).unwrap();
///     dec.feed(&ciphertext).unwrap();
///     dec.close().unwrap();
/// }
/// ```
pub struct StreamDecryptor<'a, W: Write> {
    noise: &'a Seed,
    data: &'a Seed,
    start: &'a Seed,
    fout: W,
    buf: Vec<u8>,
    closed: bool,
    header_size: usize,
}

impl<'a, W: Write> StreamDecryptor<'a, W> {
    /// Constructs a fresh stream decryptor wrapping the given output
    /// writer. The chunk-header size is snapshotted at construction
    /// so the decryptor uses the same header layout the matching
    /// encryptor saw — changing [`crate::set_nonce_bits`] mid-stream
    /// would break decoding anyway.
    pub fn new(
        noise: &'a Seed,
        data: &'a Seed,
        start: &'a Seed,
        fout: W,
    ) -> Result<Self, ITBError> {
        Ok(Self {
            noise,
            data,
            start,
            fout,
            buf: Vec::new(),
            closed: false,
            header_size: header_size() as usize,
        })
    }

    /// Appends `data` to the internal buffer and drains every
    /// complete chunk that has become available, writing decrypted
    /// plaintext to the output sink.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "feed on closed StreamDecryptor",
            ));
        }
        self.buf.extend_from_slice(data);
        self.drain()?;
        Ok(data.len())
    }

    fn drain(&mut self) -> Result<(), ITBError> {
        loop {
            if self.buf.len() < self.header_size {
                return Ok(());
            }
            let chunk_len = parse_chunk_len(&self.buf[..self.header_size])?;
            if self.buf.len() < chunk_len {
                return Ok(());
            }
            let chunk: Vec<u8> = self.buf.drain(..chunk_len).collect();
            let pt = low_decrypt(self.noise, self.data, self.start, &chunk)?;
            self.fout.write_all(&pt).map_err(io_err)?;
        }
    }

    /// Finalises the decryptor. Errors when leftover bytes do not
    /// form a complete chunk — streaming ITB ciphertext cannot have a
    /// half-chunk tail.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if !self.buf.is_empty() {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                format!(
                    "StreamDecryptor: trailing {} bytes do not form a complete chunk",
                    self.buf.len()
                ),
            ));
        }
        self.closed = true;
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamDecryptor<'a, W> {
    fn drop(&mut self) {
        // Mark closed without raising on partial input — Drop has no
        // path to surface errors. Callers who need to detect a
        // half-chunk tail must call `close()` explicitly.
        self.closed = true;
    }
}

// --------------------------------------------------------------------
// Triple Ouroboros — chunked writer.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) counterpart of [`StreamEncryptor`].
pub struct StreamEncryptor3<'a, W: Write> {
    noise: &'a Seed,
    data1: &'a Seed,
    data2: &'a Seed,
    data3: &'a Seed,
    start1: &'a Seed,
    start2: &'a Seed,
    start3: &'a Seed,
    fout: W,
    chunk_size: usize,
    buf: Vec<u8>,
    closed: bool,
}

impl<'a, W: Write> StreamEncryptor3<'a, W> {
    /// Constructs a fresh Triple-Ouroboros stream encryptor.
    /// `chunk_size` must be positive.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        noise: &'a Seed,
        data1: &'a Seed,
        data2: &'a Seed,
        data3: &'a Seed,
        start1: &'a Seed,
        start2: &'a Seed,
        start3: &'a Seed,
        fout: W,
        chunk_size: usize,
    ) -> Result<Self, ITBError> {
        if chunk_size == 0 {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "chunk_size must be positive",
            ));
        }
        Ok(Self {
            noise,
            data1,
            data2,
            data3,
            start1,
            start2,
            start3,
            fout,
            chunk_size,
            buf: Vec::new(),
            closed: false,
        })
    }

    /// Appends `data` to the internal buffer, encrypting and emitting
    /// every full `chunk_size`-sized slice that becomes available.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "write on closed StreamEncryptor3",
            ));
        }
        self.buf.extend_from_slice(data);
        while self.buf.len() >= self.chunk_size {
            let chunk: Vec<u8> = self.buf.drain(..self.chunk_size).collect();
            let ct = low_encrypt_triple(
                self.noise,
                self.data1,
                self.data2,
                self.data3,
                self.start1,
                self.start2,
                self.start3,
                &chunk,
            )?;
            self.fout.write_all(&ct).map_err(io_err)?;
        }
        Ok(data.len())
    }

    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            let ct = low_encrypt_triple(
                self.noise,
                self.data1,
                self.data2,
                self.data3,
                self.start1,
                self.start2,
                self.start3,
                &chunk,
            )?;
            self.fout.write_all(&ct).map_err(io_err)?;
        }
        self.closed = true;
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamEncryptor3<'a, W> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// --------------------------------------------------------------------
// Triple Ouroboros — chunked reader.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) counterpart of [`StreamDecryptor`].
pub struct StreamDecryptor3<'a, W: Write> {
    noise: &'a Seed,
    data1: &'a Seed,
    data2: &'a Seed,
    data3: &'a Seed,
    start1: &'a Seed,
    start2: &'a Seed,
    start3: &'a Seed,
    fout: W,
    buf: Vec<u8>,
    closed: bool,
    header_size: usize,
}

impl<'a, W: Write> StreamDecryptor3<'a, W> {
    /// Constructs a fresh Triple-Ouroboros stream decryptor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        noise: &'a Seed,
        data1: &'a Seed,
        data2: &'a Seed,
        data3: &'a Seed,
        start1: &'a Seed,
        start2: &'a Seed,
        start3: &'a Seed,
        fout: W,
    ) -> Result<Self, ITBError> {
        Ok(Self {
            noise,
            data1,
            data2,
            data3,
            start1,
            start2,
            start3,
            fout,
            buf: Vec::new(),
            closed: false,
            header_size: header_size() as usize,
        })
    }

    /// Appends `data` to the internal buffer and drains every
    /// complete chunk that has become available.
    pub fn feed(&mut self, data: &[u8]) -> Result<usize, ITBError> {
        if self.closed {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                "feed on closed StreamDecryptor3",
            ));
        }
        self.buf.extend_from_slice(data);
        self.drain()?;
        Ok(data.len())
    }

    fn drain(&mut self) -> Result<(), ITBError> {
        loop {
            if self.buf.len() < self.header_size {
                return Ok(());
            }
            let chunk_len = parse_chunk_len(&self.buf[..self.header_size])?;
            if self.buf.len() < chunk_len {
                return Ok(());
            }
            let chunk: Vec<u8> = self.buf.drain(..chunk_len).collect();
            let pt = low_decrypt_triple(
                self.noise,
                self.data1,
                self.data2,
                self.data3,
                self.start1,
                self.start2,
                self.start3,
                &chunk,
            )?;
            self.fout.write_all(&pt).map_err(io_err)?;
        }
    }

    /// Finalises the decryptor. Errors when leftover bytes do not
    /// form a complete chunk.
    pub fn close(&mut self) -> Result<(), ITBError> {
        if self.closed {
            return Ok(());
        }
        if !self.buf.is_empty() {
            return Err(ITBError::with_message(
                ffi::STATUS_BAD_INPUT,
                format!(
                    "StreamDecryptor3: trailing {} bytes do not form a complete chunk",
                    self.buf.len()
                ),
            ));
        }
        self.closed = true;
        Ok(())
    }
}

impl<'a, W: Write> Drop for StreamDecryptor3<'a, W> {
    fn drop(&mut self) {
        self.closed = true;
    }
}

// --------------------------------------------------------------------
// Functional convenience wrappers.
// --------------------------------------------------------------------

/// Reads plaintext from `fin` until EOF, encrypts in chunks of
/// `chunk_size`, and writes concatenated ITB chunks to `fout`.
pub fn encrypt_stream<R: Read, W: Write>(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mut fin: R,
    fout: W,
    chunk_size: usize,
) -> Result<(), ITBError> {
    let mut enc = StreamEncryptor::new(noise, data, start, fout, chunk_size)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        enc.write(&buf[..n])?;
    }
    enc.close()
}

/// Reads concatenated ITB chunks from `fin` until EOF and writes the
/// recovered plaintext to `fout`.
pub fn decrypt_stream<R: Read, W: Write>(
    noise: &Seed,
    data: &Seed,
    start: &Seed,
    mut fin: R,
    fout: W,
    read_size: usize,
) -> Result<(), ITBError> {
    if read_size == 0 {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            "read_size must be positive",
        ));
    }
    let mut dec = StreamDecryptor::new(noise, data, start, fout)?;
    let mut buf = vec![0u8; read_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        dec.feed(&buf[..n])?;
    }
    dec.close()
}

/// Triple-Ouroboros (7-seed) counterpart of [`encrypt_stream`].
#[allow(clippy::too_many_arguments)]
pub fn encrypt_stream_triple<R: Read, W: Write>(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mut fin: R,
    fout: W,
    chunk_size: usize,
) -> Result<(), ITBError> {
    let mut enc = StreamEncryptor3::new(
        noise, data1, data2, data3, start1, start2, start3, fout, chunk_size,
    )?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        enc.write(&buf[..n])?;
    }
    enc.close()
}

/// Triple-Ouroboros (7-seed) counterpart of [`decrypt_stream`].
#[allow(clippy::too_many_arguments)]
pub fn decrypt_stream_triple<R: Read, W: Write>(
    noise: &Seed,
    data1: &Seed,
    data2: &Seed,
    data3: &Seed,
    start1: &Seed,
    start2: &Seed,
    start3: &Seed,
    mut fin: R,
    fout: W,
    read_size: usize,
) -> Result<(), ITBError> {
    if read_size == 0 {
        return Err(ITBError::with_message(
            ffi::STATUS_BAD_INPUT,
            "read_size must be positive",
        ));
    }
    let mut dec = StreamDecryptor3::new(
        noise, data1, data2, data3, start1, start2, start3, fout,
    )?;
    let mut buf = vec![0u8; read_size];
    loop {
        let n = fin.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        dec.feed(&buf[..n])?;
    }
    dec.close()
}
