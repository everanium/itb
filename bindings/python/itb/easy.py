"""High-level Encryptor wrapper over the libitb C ABI.

Mirrors the github.com/everanium/itb/easy Go sub-package: one
constructor call replaces the existing 7-line setup ceremony (hash
factory, three or seven seeds, MAC closure, container-config wiring)
and returns an :class:`Encryptor` object that owns its own
per-instance configuration. Two encryptors with different settings
can be used in parallel without cross-contamination of the
process-wide ITB configuration.

Quick start (Single Ouroboros + KMAC256):

    >>> from itb import Encryptor
    >>> with Encryptor("blake3", 1024, "kmac256") as enc:
    ...     ct = enc.encrypt_auth(b"hello world")
    ...     pt = enc.decrypt_auth(ct)
    ...     assert pt == b"hello world"

Triple Ouroboros (7 seeds, mode=3):

    >>> with Encryptor("areion512", 2048, "kmac256", mode=3) as enc:
    ...     ct = enc.encrypt(b"large payload" * 1000)
    ...     pt = enc.decrypt(ct)

Cross-process persistence (encrypt today / decrypt tomorrow):

    >>> blob = enc.export()                # bytes (JSON-encoded)
    >>> # ... save blob to disk / KMS / wire ...
    >>> primitive, key_bits, mode, mac = peek_config(blob)
    >>> with Encryptor(primitive, key_bits, mac, mode=mode) as dec:
    ...     dec.import_state(blob)         # rebuild the seed material
    ...     pt = dec.decrypt_auth(ct)

Streaming. Chunking lives on the binding side (same pattern as
:class:`itb.StreamEncryptor`): slice the plaintext into chunks of
``chunk_size`` bytes and call :meth:`encrypt` per chunk; on the
decrypt side walk the concatenated stream by reading the chunk
header, calling :func:`itb.parse_chunk_len`, and feeding the chunk
to :meth:`decrypt`. The encryptor's chunk size knob (set via
:meth:`set_chunk_size`) is consumed only by the Go-side
EncryptStream entry point; one-shot :meth:`encrypt` honours the
container-cap heuristic in itb.ChunkSize.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ._ffi import (
    _ffi,
    _lib,
    _last_error,
    _raise,
    ITBError,
    STATUS_OK,
    STATUS_BUFFER_TOO_SMALL,
    STATUS_BAD_INPUT,
    STATUS_EASY_CLOSED,
    STATUS_EASY_MALFORMED,
    STATUS_EASY_VERSION_TOO_NEW,
    STATUS_EASY_UNKNOWN_PRIMITIVE,
    STATUS_EASY_UNKNOWN_MAC,
    STATUS_EASY_BAD_KEY_BITS,
    STATUS_EASY_MISMATCH,
    STATUS_EASY_LOCKSEED_AFTER_ENCRYPT,
)


class EasyMismatchError(ITBError):
    """Raised when :meth:`Encryptor.import_state` rejects a state blob
    because one of the four bound dimensions (primitive / key_bits /
    mode / mac) disagrees with the receiver. The offending JSON field
    name is exposed on the ``.field`` attribute so callers can map
    onto a typed remediation path."""

    def __init__(self, code: int, message: str, field: str):
        super().__init__(code, message)
        self.field = field


def _last_mismatch_field() -> str:
    """Reads the offending JSON field name from the most recent
    ITB_Easy_Import call that returned STATUS_EASY_MISMATCH on this
    thread. Empty string when the most recent failure was not a
    mismatch."""
    out_len = _ffi.new("size_t*")
    rc = _lib.ITB_Easy_LastMismatchField(_ffi.NULL, 0, out_len)
    if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
        return ""
    cap = int(out_len[0])
    if cap <= 1:
        return ""
    buf = _ffi.new("char[]", cap)
    rc = _lib.ITB_Easy_LastMismatchField(buf, cap, out_len)
    if rc != STATUS_OK:
        return ""
    return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")


def _raise_easy(code: int):
    """Raises the most specific exception subclass for a non-OK Easy
    status code. STATUS_EASY_MISMATCH attaches the offending field via
    EasyMismatchError; everything else falls through to ITBError with
    the LastError message."""
    if code == STATUS_EASY_MISMATCH:
        raise EasyMismatchError(code, _last_error(), _last_mismatch_field())
    raise ITBError(code, _last_error())


def peek_config(blob: bytes) -> Tuple[str, int, int, str]:
    """Parses a state blob's metadata (primitive, key_bits, mode, mac)
    without performing full validation, allowing a caller to inspect a
    saved blob before constructing a matching encryptor.

    Returns the four-tuple on success; raises ITBError(STATUS_EASY_MALFORMED)
    on JSON parse failure / kind mismatch / too-new version / unknown
    mode value."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise TypeError("blob must be bytes-like")
    blob_bytes = bytes(blob)

    # Probe both string sizes first.
    prim_len = _ffi.new("size_t*")
    mac_len = _ffi.new("size_t*")
    kb_out = _ffi.new("int*")
    mode_out = _ffi.new("int*")
    rc = _lib.ITB_Easy_PeekConfig(
        blob_bytes, len(blob_bytes),
        _ffi.NULL, 0, prim_len,
        kb_out, mode_out,
        _ffi.NULL, 0, mac_len,
    )
    if rc != STATUS_OK and rc != STATUS_BUFFER_TOO_SMALL:
        _raise_easy(rc)

    prim_cap = int(prim_len[0])
    mac_cap = int(mac_len[0])
    prim_buf = _ffi.new("char[]", prim_cap)
    mac_buf = _ffi.new("char[]", mac_cap)
    rc = _lib.ITB_Easy_PeekConfig(
        blob_bytes, len(blob_bytes),
        prim_buf, prim_cap, prim_len,
        kb_out, mode_out,
        mac_buf, mac_cap, mac_len,
    )
    if rc != STATUS_OK:
        _raise_easy(rc)

    primitive = _ffi.string(prim_buf, int(prim_len[0]) - 1).decode("utf-8")
    mac_name = _ffi.string(mac_buf, int(mac_len[0]) - 1).decode("utf-8")
    return primitive, int(kb_out[0]), int(mode_out[0]), mac_name


class Encryptor:
    """High-level Encryptor over the libitb C ABI.

    Parameters
    ----------
    primitive:
        Canonical hash name from :func:`itb.list_hashes` —
        "areion256", "areion512", "siphash24", "aescmac",
        "blake2b256", "blake2b512", "blake2s", "blake3", "chacha20".
        Default ``None`` selects the package default ("areion512").
    key_bits:
        ITB key width in bits (512, 1024, 2048; multiple of the
        primitive's native hash width). Default ``None`` selects 1024.
    mac:
        Canonical MAC name from :func:`itb.list_macs` — "kmac256",
        "hmac-sha256", or "hmac-blake3". Default ``None`` selects
        "kmac256".
    mode:
        1 = Single Ouroboros (3 seeds — noise, data, start);
        3 = Triple Ouroboros (7 seeds — noise + 3 pairs of data /
        start). Default 1.

    Construction is the heavy step — generates fresh PRF keys, fresh
    seed components, fresh MAC key from /dev/urandom. Reusing one
    Encryptor instance across many encrypt / decrypt calls amortises
    the cost across the lifetime of a session.

    Use as a context manager (``with Encryptor(...) as enc:``) or call
    :meth:`close` explicitly to zero PRF / MAC / seed material when
    the session ends. The :meth:`free` alias is kept for parity with
    the lower-level :class:`itb.Seed` / :class:`itb.MAC` lifecycle.
    """

    __slots__ = ("_handle",)

    def __init__(
        self,
        primitive: Optional[str] = None,
        key_bits: Optional[int] = None,
        mac: Optional[str] = None,
        mode: int = 1,
    ):
        if mode not in (1, 3):
            raise ValueError(f"mode must be 1 (Single) or 3 (Triple), got {mode}")
        prim_arg = (primitive.encode("utf-8") if primitive else _ffi.NULL)
        mac_arg = (mac.encode("utf-8") if mac else _ffi.NULL)
        kb_arg = int(key_bits) if key_bits else 0

        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_Easy_New(prim_arg, kb_arg, mac_arg, int(mode), h)
        if rc != STATUS_OK:
            _raise_easy(rc)
        self._handle = int(h[0])

    # ─── Read-only field properties ────────────────────────────────

    @property
    def handle(self) -> int:
        """Opaque libitb handle id (uintptr). Useful for diagnostics
        and FFI-level interop; bindings should not rely on its
        numerical value."""
        return self._handle

    @property
    def primitive(self) -> str:
        return _read_str(lambda buf, cap, ol:
                         _lib.ITB_Easy_Primitive(self._handle, buf, cap, ol))

    @property
    def key_bits(self) -> int:
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_KeyBits(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    @property
    def mode(self) -> int:
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_Mode(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    @property
    def mac_name(self) -> str:
        return _read_str(lambda buf, cap, ol:
                         _lib.ITB_Easy_MACName(self._handle, buf, cap, ol))

    @property
    def nonce_bits(self) -> int:
        """Returns the nonce size in bits configured for this
        encryptor — either the value from the most recent
        :meth:`set_nonce_bits` call, or the process-wide
        :func:`itb.get_nonce_bits` reading at construction time when
        no per-instance override has been issued. Reads the live
        cfg.NonceBits via ``ITB_Easy_NonceBits`` so a setter call on
        the Go side is reflected immediately."""
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_NonceBits(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    @property
    def header_size(self) -> int:
        """Returns the per-instance ciphertext-chunk header size in
        bytes (nonce + 2-byte width + 2-byte height). Tracks this
        encryptor's own :attr:`nonce_bits`, NOT the process-wide
        :func:`itb.header_size` reading — important when the
        encryptor has called :meth:`set_nonce_bits` to override the
        default. Use this when slicing a chunk header off the front
        of a ciphertext stream produced by this encryptor or when
        sizing a tamper region for an authenticated-decrypt test."""
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_HeaderSize(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    def parse_chunk_len(self, header: bytes) -> int:
        """Per-instance counterpart of :func:`itb.parse_chunk_len`.
        Inspects a chunk header (the fixed-size [nonce(N) ||
        width(2) || height(2)] prefix where N comes from this
        encryptor's :attr:`nonce_bits`) and returns the total chunk
        length on the wire.

        Use this when walking a concatenated chunk stream produced
        by this encryptor: read :attr:`header_size` bytes from the
        wire, call ``enc.parse_chunk_len(buf[:enc.header_size])``,
        read the remaining ``chunk_len - header_size`` bytes, and
        feed the full chunk to :meth:`decrypt` / :meth:`decrypt_auth`.

        The buffer must contain at least :attr:`header_size` bytes;
        only the header is consulted, the body bytes do not need to
        be present. Raises :class:`itb.ITBError` with code
        :data:`itb._ffi.STATUS_BAD_INPUT` on too-short buffer, zero
        dimensions, or width × height overflow against the
        container pixel cap."""
        if not isinstance(header, (bytes, bytearray, memoryview)):
            raise TypeError("header must be bytes-like")
        hdr = bytes(header)
        out = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_ParseChunkLen(self._handle, hdr, len(hdr), out)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return int(out[0])

    # ─── Cipher entry points ──────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts plaintext using the encryptor's configured
        primitive / key_bits / mode and per-instance Config snapshot.
        Plain mode — does not attach a MAC tag; for authenticated
        encryption use :meth:`encrypt_auth`."""
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("plaintext must be bytes-like")
        return self._cipher_call(_lib.ITB_Easy_Encrypt, bytes(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts ciphertext produced by :meth:`encrypt` under the
        same encryptor."""
        if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
            raise TypeError("ciphertext must be bytes-like")
        return self._cipher_call(_lib.ITB_Easy_Decrypt, bytes(ciphertext))

    def encrypt_auth(self, plaintext: bytes) -> bytes:
        """Encrypts plaintext and attaches a MAC tag using the
        encryptor's bound MAC closure."""
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("plaintext must be bytes-like")
        return self._cipher_call(_lib.ITB_Easy_EncryptAuth, bytes(plaintext))

    def decrypt_auth(self, ciphertext: bytes) -> bytes:
        """Verifies and decrypts ciphertext produced by
        :meth:`encrypt_auth`. Raises :class:`itb.ITBError` with code
        :data:`itb._ffi.STATUS_MAC_FAILURE` on tampered ciphertext /
        wrong MAC key."""
        if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
            raise TypeError("ciphertext must be bytes-like")
        return self._cipher_call(_lib.ITB_Easy_DecryptAuth, bytes(ciphertext))

    def _cipher_call(self, fn, payload: bytes) -> bytes:
        """Common buffer-convention dispatcher: probe required size →
        allocate → retry. Identical pattern to the lower-level
        ``_encrypt_or_decrypt`` helper in :mod:`itb._ffi`."""
        out_len = _ffi.new("size_t*")
        rc = fn(self._handle, payload, len(payload), _ffi.NULL, 0, out_len)
        if rc != STATUS_BUFFER_TOO_SMALL:
            if rc == STATUS_OK:
                return b""
            _raise_easy(rc)
        need = int(out_len[0])
        out_buf = _ffi.new("unsigned char[]", need)
        rc = fn(self._handle, payload, len(payload), out_buf, need, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(out_buf, int(out_len[0])))

    # ─── Per-instance configuration setters ───────────────────────

    def set_nonce_bits(self, n: int) -> None:
        """Override the nonce size for this encryptor's subsequent
        encrypt / decrypt calls. Valid values: 128, 256, 512.
        Mutates only this encryptor's Config copy; process-wide
        :func:`itb.set_nonce_bits` is unaffected. The
        :attr:`nonce_bits` / :attr:`header_size` properties read
        through to the live Go-side cfg.NonceBits, so they reflect
        the new value automatically on the next access."""
        rc = _lib.ITB_Easy_SetNonceBits(self._handle, int(n))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_barrier_fill(self, n: int) -> None:
        """Override the CSPRNG barrier-fill margin for this encryptor.
        Valid values: 1, 2, 4, 8, 16, 32. Asymmetric — receiver does
        not need the same value as sender."""
        rc = _lib.ITB_Easy_SetBarrierFill(self._handle, int(n))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_bit_soup(self, mode: int) -> None:
        """0 = byte-level split (default); non-zero = bit-level Bit Soup
        split."""
        rc = _lib.ITB_Easy_SetBitSoup(self._handle, int(mode))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_lock_soup(self, mode: int) -> None:
        """0 = off (default); non-zero = on. Auto-couples ``BitSoup=1``
        on this encryptor."""
        rc = _lib.ITB_Easy_SetLockSoup(self._handle, int(mode))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_lock_seed(self, mode: int) -> None:
        """0 = off; 1 = on (allocates a dedicated lockSeed and routes
        the bit-permutation overlay through it; auto-couples
        ``LockSoup=1 + BitSoup=1`` on this encryptor). Calling after
        the first encrypt raises ITBError(STATUS_EASY_LOCKSEED_AFTER_ENCRYPT)."""
        rc = _lib.ITB_Easy_SetLockSeed(self._handle, int(mode))
        if rc != STATUS_OK:
            _raise_easy(rc)

    def set_chunk_size(self, n: int) -> None:
        """Per-instance streaming chunk-size override (0 = auto-detect
        via :data:`itb.ChunkSize` on the Go side)."""
        rc = _lib.ITB_Easy_SetChunkSize(self._handle, int(n))
        if rc != STATUS_OK:
            _raise_easy(rc)

    # ─── Material getters (defensive copies) ──────────────────────

    @property
    def seed_count(self) -> int:
        """Number of seed slots: 3 (Single without LockSeed),
        4 (Single with LockSeed), 7 (Triple without LockSeed),
        8 (Triple with LockSeed)."""
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_SeedCount(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v

    def seed_components(self, slot: int) -> List[int]:
        """Returns the uint64 components of one seed slot (defensive
        copy). Slot index follows the canonical ordering:
        Single = ``[noise, data, start]``; Triple = ``[noise, data1,
        data2, data3, start1, start2, start3]``; the dedicated
        lockSeed slot is appended at the end (index 3 / 7) when
        :attr:`lock_seed_active` is True."""
        out_len = _ffi.new("int*")
        rc = _lib.ITB_Easy_SeedComponents(self._handle, int(slot), _ffi.NULL, 0, out_len)
        if rc != STATUS_BAD_INPUT:
            if rc == STATUS_OK:
                return []
            _raise_easy(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned long long[{n}]")
        rc = _lib.ITB_Easy_SeedComponents(self._handle, int(slot), buf, n, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return [int(buf[i]) for i in range(int(out_len[0]))]

    @property
    def has_prf_keys(self) -> bool:
        """``True`` when the encryptor's primitive uses fixed PRF keys
        per seed slot (every shipped primitive except siphash24)."""
        st = _ffi.new("int*")
        v = int(_lib.ITB_Easy_HasPRFKeys(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise_easy(int(st[0]))
        return v != 0

    def prf_key(self, slot: int) -> bytes:
        """Returns the fixed PRF key bytes for one seed slot
        (defensive copy). Raises ITBError(STATUS_BAD_INPUT) when the
        primitive has no fixed PRF keys (siphash24 — caller should
        consult :attr:`has_prf_keys` first) or when ``slot`` is out
        of range."""
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_PRFKey(self._handle, int(slot), _ffi.NULL, 0, out_len)
        # Probe pattern: zero-length key → STATUS_OK + outLen=0
        # (e.g. siphash24); non-zero length → STATUS_BAD_INPUT with
        # outLen carrying the required size.
        if rc == STATUS_OK and int(out_len[0]) == 0:
            return b""
        if rc != STATUS_BAD_INPUT:
            _raise_easy(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned char[{n}]")
        rc = _lib.ITB_Easy_PRFKey(self._handle, int(slot), buf, n, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    @property
    def mac_key(self) -> bytes:
        """Returns a defensive copy of the encryptor's bound MAC fixed
        key. Save these bytes alongside the seed material for
        cross-process restore via :meth:`export` / :meth:`import_state`."""
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_MACKey(self._handle, _ffi.NULL, 0, out_len)
        if rc != STATUS_BAD_INPUT:
            if rc == STATUS_OK and int(out_len[0]) == 0:
                return b""
            _raise_easy(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned char[{n}]")
        rc = _lib.ITB_Easy_MACKey(self._handle, buf, n, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    # ─── State serialization ──────────────────────────────────────

    def export(self) -> bytes:
        """Serialises the encryptor's full state (PRF keys, seed
        components, MAC key, dedicated lockSeed material when active)
        as a JSON blob. The caller saves the bytes as it sees fit
        (disk, KMS, wire) and later passes them back to
        :meth:`import_state` on a fresh encryptor to reconstruct the
        exact state.

        Per-instance configuration knobs (NonceBits, BarrierFill,
        BitSoup, LockSoup, ChunkSize) are NOT carried in the v1 blob
        — both sides communicate them via deployment config.
        LockSeed is carried because activating it changes the
        structural seed count."""
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_Easy_Export(self._handle, _ffi.NULL, 0, out_len)
        if rc != STATUS_BUFFER_TOO_SMALL:
            if rc == STATUS_OK:
                return b""
            _raise_easy(rc)
        need = int(out_len[0])
        buf = _ffi.new("unsigned char[]", need)
        rc = _lib.ITB_Easy_Export(self._handle, buf, need, out_len)
        if rc != STATUS_OK:
            _raise_easy(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    def import_state(self, blob: bytes) -> None:
        """Replaces the encryptor's PRF keys, seed components, MAC
        key, and (optionally) dedicated lockSeed material with the
        values carried in a JSON blob produced by a prior
        :meth:`export` call.

        On any failure the encryptor's pre-import state is unchanged
        (the underlying Go-side Encryptor.Import is transactional).
        Mismatch on primitive / key_bits / mode / mac raises
        :class:`EasyMismatchError` carrying the offending field name
        in the ``.field`` attribute."""
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            raise TypeError("blob must be bytes-like")
        blob_bytes = bytes(blob)
        rc = _lib.ITB_Easy_Import(self._handle, blob_bytes, len(blob_bytes))
        if rc != STATUS_OK:
            _raise_easy(rc)

    # ─── Lifecycle ────────────────────────────────────────────────

    def close(self) -> None:
        """Zeroes the encryptor's PRF keys, MAC key, and seed
        components, and marks the encryptor as closed. Idempotent —
        multiple :meth:`close` calls return without raising."""
        if self._handle:
            rc = _lib.ITB_Easy_Close(self._handle)
            # Close is documented as idempotent on the Go side; treat
            # any non-OK return after close as a bug.
            if rc != STATUS_OK:
                _raise_easy(rc)

    def free(self) -> None:
        """Releases the underlying libitb handle slot. Calls
        :meth:`close` first (so key material is zeroed even if the
        binding consumer never called close explicitly) and then
        deletes the FFI handle. Subsequent method calls on this
        instance raise an :class:`AttributeError` (the cffi handle
        is gone)."""
        if self._handle:
            rc = _lib.ITB_Easy_Free(self._handle)
            self._handle = 0
            if rc != STATUS_OK:
                _raise_easy(rc)

    def __enter__(self) -> "Encryptor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.free()

    def __del__(self):
        # Best-effort GC release; ignore any error since interpreter
        # shutdown ordering is unpredictable.
        try:
            if self._handle:
                _lib.ITB_Easy_Free(self._handle)
                self._handle = 0
        except Exception:
            pass


def _read_str(call) -> str:
    """Common idiom for size-out-param string accessors on the
    Encryptor: probe required length with NULL/0, allocate, retry.
    Mirrors the same helper in :mod:`itb._ffi` for the lower-level
    Seed / MAC accessors."""
    out_len = _ffi.new("size_t*")
    rc = call(_ffi.NULL, 0, out_len)
    if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
        _raise_easy(rc)
    cap = int(out_len[0])
    buf = _ffi.new("char[]", cap)
    rc = call(buf, cap, out_len)
    if rc != STATUS_OK:
        _raise_easy(rc)
    return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")
