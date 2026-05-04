"""File-like streaming wrappers over the one-shot ITB encrypt/decrypt
API.

ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
container size limit). Streaming larger payloads simply means
slicing the input into chunks at the binding layer, encrypting each
chunk through the regular FFI path, and concatenating the results.
The reverse operation walks a concatenated chunk stream by reading
the chunk header, calling :func:`itb.parse_chunk_len` to learn the
chunk's body length, reading that many bytes, and decrypting the
single chunk.

Both classes accept any binary file-like object for the ``fout`` /
``fin`` arguments (open files, ``io.BytesIO``, sockets wrapped in
``socket.makefile('wb')`` etc.). Memory peak per call is bounded
by ``chunk_size`` (default 16 MB), regardless of the total payload
length.

The Triple-Ouroboros (7-seed) variants share the same I/O contract
and only differ in the seed list passed to the constructor.
"""

from __future__ import annotations

from typing import IO, Optional

from . import _ffi
from ._ffi import (
    Seed,
    MAC,
    ITBError,
    STATUS_BAD_INPUT,
    encrypt as _encrypt,
    decrypt as _decrypt,
    encrypt_triple as _encrypt_triple,
    decrypt_triple as _decrypt_triple,
    parse_chunk_len,
    header_size,
)

# Default chunk size matches itb.DefaultChunkSize on the Go side
# (16 MB) — the size at which ITB's barrier-encoded container
# layout stays well within the per-chunk pixel cap.
DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024


class StreamEncryptor:
    """File-like writer that encrypts a stream of plaintext bytes
    chunk by chunk and writes each ciphertext chunk to an output
    binary file object.

    Usage:

        with itb.StreamEncryptor(ns, ds, ss, fout) as enc:
            while data := fin.read(1 << 20):
                enc.write(data)
        # closing the context flushes the trailing partial chunk

    The class accumulates `write()` input until at least
    ``chunk_size`` bytes are buffered, then encrypts and emits one
    chunk. ``close()`` flushes any tail < chunk_size as a final
    chunk (so the on-the-wire chunk count is `ceil(total / chunk)`).

    .. warning::
       Do not call :func:`itb.set_nonce_bits` between writes on the
       same stream. The chunks are encrypted under the active
       nonce-size at the moment each chunk is flushed; switching
       nonce-bits mid-stream produces a chunk header layout the
       paired :class:`StreamDecryptor` (which snapshots
       :func:`itb.header_size` at construction) cannot parse.
    """

    __slots__ = ("_seeds", "_fout", "_chunk_size", "_buf", "_closed")

    def __init__(
        self,
        noise: Seed,
        data: Seed,
        start: Seed,
        fout: IO[bytes],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        if chunk_size <= 0:
            raise ITBError(STATUS_BAD_INPUT, "chunk_size must be positive")
        self._seeds = (noise, data, start)
        self._fout = fout
        self._chunk_size = chunk_size
        self._buf = bytearray()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("write on closed StreamEncryptor")
        self._buf.extend(data)
        while len(self._buf) >= self._chunk_size:
            chunk = bytes(self._buf[: self._chunk_size])
            ct = _encrypt(*self._seeds, chunk)
            self._fout.write(ct)
            del self._buf[: self._chunk_size]
        return len(data)

    def close(self) -> None:
        if self._closed:
            return
        if self._buf:
            ct = _encrypt(*self._seeds, bytes(self._buf))
            self._fout.write(ct)
            self._buf.clear()
        self._closed = True

    def __enter__(self) -> "StreamEncryptor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class StreamDecryptor:
    """File-like writer that decrypts a stream of ITB ciphertext
    chunks into the original plaintext, written to ``fout``.

    Usage:

        with itb.StreamDecryptor(ns, ds, ss, fout) as dec:
            while data := fin.read(1 << 20):
                dec.feed(data)

    The class accumulates `feed()` input until a full chunk
    (header + body) is available, then decrypts the chunk and
    writes the plaintext to ``fout``. Multiple full chunks in one
    feed call are processed sequentially.

    When :meth:`__exit__` is called during exception propagation,
    the partial-tail check is skipped so the original exception is
    not masked. Callers who need partial-tail detection during
    exception paths should call :meth:`close` explicitly.
    """

    __slots__ = ("_seeds", "_fout", "_buf", "_closed", "_header_size")

    def __init__(
        self,
        noise: Seed,
        data: Seed,
        start: Seed,
        fout: IO[bytes],
    ):
        self._seeds = (noise, data, start)
        self._fout = fout
        self._buf = bytearray()
        self._closed = False
        # Snapshot at construction so the decryptor uses the same
        # header layout the matching encryptor saw. Changing
        # SetNonceBits mid-stream would break decoding anyway.
        self._header_size = header_size()

    def feed(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("feed on closed StreamDecryptor")
        self._buf.extend(data)
        self._drain()
        return len(data)

    def _drain(self) -> None:
        while True:
            if len(self._buf) < self._header_size:
                return
            chunk_len = parse_chunk_len(bytes(self._buf[: self._header_size]))
            if len(self._buf) < chunk_len:
                return
            chunk = bytes(self._buf[:chunk_len])
            pt = _decrypt(*self._seeds, chunk)
            self._fout.write(pt)
            del self._buf[:chunk_len]

    def close(self) -> None:
        if self._closed:
            return
        # Any leftover bytes that did not assemble into a full
        # chunk are a structural error: streaming ITB ciphertext
        # cannot have a half-chunk tail.
        if self._buf:
            raise ValueError(
                f"StreamDecryptor: trailing {len(self._buf)} bytes do not "
                "form a complete chunk"
            )
        self._closed = True

    def __enter__(self) -> "StreamDecryptor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Suppress close-time errors only when an earlier exception
        # is propagating (otherwise close raises on partial input).
        if exc_type is None:
            self.close()
        else:
            self._closed = True


class StreamEncryptor3:
    """Triple-Ouroboros (7-seed) counterpart of :class:`StreamEncryptor`.

    .. warning::
       Do not call :func:`itb.set_nonce_bits` between writes on the
       same stream — see :class:`StreamEncryptor` for the rationale.
    """

    __slots__ = ("_seeds", "_fout", "_chunk_size", "_buf", "_closed")

    def __init__(
        self,
        noise: Seed,
        data1: Seed,
        data2: Seed,
        data3: Seed,
        start1: Seed,
        start2: Seed,
        start3: Seed,
        fout: IO[bytes],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        if chunk_size <= 0:
            raise ITBError(STATUS_BAD_INPUT, "chunk_size must be positive")
        self._seeds = (noise, data1, data2, data3, start1, start2, start3)
        self._fout = fout
        self._chunk_size = chunk_size
        self._buf = bytearray()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("write on closed StreamEncryptor3")
        self._buf.extend(data)
        while len(self._buf) >= self._chunk_size:
            chunk = bytes(self._buf[: self._chunk_size])
            ct = _encrypt_triple(*self._seeds, chunk)
            self._fout.write(ct)
            del self._buf[: self._chunk_size]
        return len(data)

    def close(self) -> None:
        if self._closed:
            return
        if self._buf:
            ct = _encrypt_triple(*self._seeds, bytes(self._buf))
            self._fout.write(ct)
            self._buf.clear()
        self._closed = True

    def __enter__(self) -> "StreamEncryptor3":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class StreamDecryptor3:
    """Triple-Ouroboros (7-seed) counterpart of :class:`StreamDecryptor`.

    When :meth:`__exit__` is called during exception propagation,
    the partial-tail check is skipped so the original exception is
    not masked. Callers who need partial-tail detection during
    exception paths should call :meth:`close` explicitly.
    """

    __slots__ = ("_seeds", "_fout", "_buf", "_closed", "_header_size")

    def __init__(
        self,
        noise: Seed,
        data1: Seed,
        data2: Seed,
        data3: Seed,
        start1: Seed,
        start2: Seed,
        start3: Seed,
        fout: IO[bytes],
    ):
        self._seeds = (noise, data1, data2, data3, start1, start2, start3)
        self._fout = fout
        self._buf = bytearray()
        self._closed = False
        self._header_size = header_size()

    def feed(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("feed on closed StreamDecryptor3")
        self._buf.extend(data)
        self._drain()
        return len(data)

    def _drain(self) -> None:
        while True:
            if len(self._buf) < self._header_size:
                return
            chunk_len = parse_chunk_len(bytes(self._buf[: self._header_size]))
            if len(self._buf) < chunk_len:
                return
            chunk = bytes(self._buf[:chunk_len])
            pt = _decrypt_triple(*self._seeds, chunk)
            self._fout.write(pt)
            del self._buf[:chunk_len]

    def close(self) -> None:
        if self._closed:
            return
        if self._buf:
            raise ValueError(
                f"StreamDecryptor3: trailing {len(self._buf)} bytes do not "
                "form a complete chunk"
            )
        self._closed = True

    def __enter__(self) -> "StreamDecryptor3":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.close()
        else:
            self._closed = True


# ─── Functional convenience wrappers ───────────────────────────────────


def encrypt_stream(
    noise: Seed,
    data: Seed,
    start: Seed,
    fin: IO[bytes],
    fout: IO[bytes],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Reads plaintext from ``fin`` until EOF, encrypts in chunks of
    ``chunk_size``, and writes concatenated ITB chunks to ``fout``.
    """
    with StreamEncryptor(noise, data, start, fout, chunk_size) as enc:
        while True:
            buf = fin.read(chunk_size)
            if not buf:
                break
            enc.write(buf)


def decrypt_stream(
    noise: Seed,
    data: Seed,
    start: Seed,
    fin: IO[bytes],
    fout: IO[bytes],
    read_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Reads concatenated ITB chunks from ``fin`` until EOF and writes
    the recovered plaintext to ``fout``."""
    if read_size <= 0:
        raise ITBError(STATUS_BAD_INPUT, "read_size must be positive")
    with StreamDecryptor(noise, data, start, fout) as dec:
        while True:
            buf = fin.read(read_size)
            if not buf:
                break
            dec.feed(buf)


def encrypt_stream_triple(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    fin: IO[bytes],
    fout: IO[bytes],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Triple-Ouroboros (7-seed) counterpart of :func:`encrypt_stream`."""
    with StreamEncryptor3(
        noise, data1, data2, data3, start1, start2, start3, fout, chunk_size
    ) as enc:
        while True:
            buf = fin.read(chunk_size)
            if not buf:
                break
            enc.write(buf)


def decrypt_stream_triple(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    fin: IO[bytes],
    fout: IO[bytes],
    read_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Triple-Ouroboros (7-seed) counterpart of :func:`decrypt_stream`."""
    if read_size <= 0:
        raise ITBError(STATUS_BAD_INPUT, "read_size must be positive")
    with StreamDecryptor3(
        noise, data1, data2, data3, start1, start2, start3, fout
    ) as dec:
        while True:
            buf = fin.read(read_size)
            if not buf:
                break
            dec.feed(buf)
