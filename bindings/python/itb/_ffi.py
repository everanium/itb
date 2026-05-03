"""Cffi-based binding over libitb's C ABI.

Loads libitb.so / .dll / .dylib via cffi ABI mode (no C compiler at
install time). The shared library is searched in this order:

  1. ``ITB_LIBRARY_PATH`` environment variable (absolute path).
  2. ``<repo>/dist/<os>-<arch>/libitb.<ext>`` resolved from this file
     by walking four directory levels up
     (bindings/python/itb/_ffi.py → repo root → dist/...).
  3. system loader path (``ldconfig`` / ``DYLD_LIBRARY_PATH`` / ``PATH``).

Status codes returned by every entry point are translated to Python
exceptions (``ITBError``) so callers do not have to inspect integers.

Threading note. ``ITB_LastError`` and ``ITB_Easy_LastMismatchField``
read process-global atomics that follow the C ``errno`` discipline:
the most recent non-OK Status across the whole process wins, and a
sibling thread that calls into libitb between the failing call and
the diagnostic read overwrites the message. Multi-threaded Python
applications that need reliable diagnostic attribution should
serialise FFI calls under a process-wide lock or accept that the
textual message returned by ``ITBError`` may belong to a different
call. The structural Status code on the failing call's return
value is unaffected — only the textual diagnostic is racy.

Lock-seed lifecycle. ``Seed.attach_lock_seed`` records the lock
seed pointer on the noiseSeed but does not bump a refcount on the
Python object. Releasing the lock seed via ``lockSeed.free()``
before the noiseSeed has finished its useful lifetime invalidates
the bit-permutation overlay derivation; subsequent encrypt calls
panic via ``ErrLockSeedOverlayOff`` or use zeroed components.
Standard pairing: keep the lock seed alive at least as long as the
noiseSeed.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import List, Tuple

import cffi

# Status codes — must mirror cmd/cshared/internal/capi/errors.go
STATUS_OK = 0
STATUS_BAD_HASH = 1
STATUS_BAD_KEY_BITS = 2
STATUS_BAD_HANDLE = 3
STATUS_BAD_INPUT = 4
STATUS_BUFFER_TOO_SMALL = 5
STATUS_ENCRYPT_FAILED = 6
STATUS_DECRYPT_FAILED = 7
STATUS_SEED_WIDTH_MIX = 8
STATUS_BAD_MAC = 9
STATUS_MAC_FAILURE = 10
# Easy encryptor (itb/easy sub-package) sentinel codes — block 11..18
# is dedicated to the Encryptor surface so the lower codes 0..10
# remain reserved for the low-level Encrypt / Decrypt path.
STATUS_EASY_CLOSED = 11
STATUS_EASY_MALFORMED = 12
STATUS_EASY_VERSION_TOO_NEW = 13
STATUS_EASY_UNKNOWN_PRIMITIVE = 14
STATUS_EASY_UNKNOWN_MAC = 15
STATUS_EASY_BAD_KEY_BITS = 16
STATUS_EASY_MISMATCH = 17
STATUS_EASY_LOCKSEED_AFTER_ENCRYPT = 18
# Native Blob (itb.Blob128 / 256 / 512) sentinel codes — block 19..22
# is dedicated to the low-level state-blob surface so the lower codes
# 0..18 remain reserved for the seed-handle / Encrypt / Decrypt /
# Encryptor paths.
STATUS_BLOB_MODE_MISMATCH = 19
STATUS_BLOB_MALFORMED = 20
STATUS_BLOB_VERSION_TOO_NEW = 21
STATUS_BLOB_TOO_MANY_OPTS = 22
STATUS_INTERNAL = 99


class ITBError(RuntimeError):
    """Raised on any non-OK status from the libitb C ABI."""

    def __init__(self, code: int, message: str = ""):
        self.code = code
        super().__init__(f"itb: status={code} ({message})" if message else f"itb: status={code}")


# C ABI integer-typedef widths track the host word size — uintptr_t
# and size_t are 8 bytes on 64-bit systems and 4 bytes on 32-bit
# systems. cffi ABI mode resolves typedefs literally, so the CDEF
# string must declare the right width for the target Python build.
# sys.maxsize crosses 2**31 on 64-bit Pythons (typically ~2**63 - 1)
# and stays below it on 32-bit Pythons (~2**31 - 1), giving a
# reliable proxy for the host's C-side word size.
if sys.maxsize > 2**31:
    _PTR_TYPE = "unsigned long long"
    _SIZE_TYPE = "unsigned long long"
else:
    _PTR_TYPE = "unsigned int"
    _SIZE_TYPE = "unsigned int"

_CDEF = f"""
typedef {_PTR_TYPE} uintptr_t;
typedef {_SIZE_TYPE} size_t;

extern int ITB_Version(char* out, size_t capBytes, size_t* outLen);
extern int ITB_HashCount(void);
extern int ITB_HashName(int i, char* out, size_t capBytes, size_t* outLen);
extern int ITB_HashWidth(int i);
extern int ITB_LastError(char* out, size_t capBytes, size_t* outLen);

extern int ITB_NewSeed(char* hashName, int keyBits, uintptr_t* outHandle);
extern int ITB_FreeSeed(uintptr_t handle);
extern int ITB_SeedWidth(uintptr_t handle, int* outStatus);
extern int ITB_SeedHashName(uintptr_t handle, char* out, size_t capBytes, size_t* outLen);

extern int ITB_AttachLockSeed(uintptr_t noiseHandle, uintptr_t lockHandle);

extern int ITB_NewSeedFromComponents(
    char* hashName,
    unsigned long long* components, int componentsLen,
    unsigned char* hashKey, int hashKeyLen,
    uintptr_t* outHandle);
extern int ITB_GetSeedHashKey(
    uintptr_t handle,
    unsigned char* out, size_t capBytes, size_t* outLen);
extern int ITB_GetSeedComponents(
    uintptr_t handle,
    unsigned long long* out, int capCount, int* outLen);

extern int ITB_Encrypt(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Decrypt(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_Encrypt3(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Decrypt3(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_MACCount(void);
extern int ITB_MACName(int i, char* out, size_t capBytes, size_t* outLen);
extern int ITB_MACKeySize(int i);
extern int ITB_MACTagSize(int i);
extern int ITB_MACMinKeyBytes(int i);
extern int ITB_NewMAC(char* macName, void* key, size_t keyLen, uintptr_t* outHandle);
extern int ITB_FreeMAC(uintptr_t handle);

extern int ITB_EncryptAuth(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_DecryptAuth(
    uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_EncryptAuth3(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_DecryptAuth3(
    uintptr_t noiseHandle,
    uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3,
    uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3,
    uintptr_t macHandle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_SetBitSoup(int mode);
extern int ITB_GetBitSoup(void);
extern int ITB_SetLockSoup(int mode);
extern int ITB_GetLockSoup(void);
extern int ITB_SetMaxWorkers(int n);
extern int ITB_GetMaxWorkers(void);
extern int ITB_SetNonceBits(int n);
extern int ITB_GetNonceBits(void);
extern int ITB_SetBarrierFill(int n);
extern int ITB_GetBarrierFill(void);

extern int ITB_MaxKeyBits(void);
extern int ITB_Channels(void);
extern int ITB_HeaderSize(void);

extern int ITB_ParseChunkLen(void* header, size_t headerLen, size_t* outChunkLen);

/* Easy encryptor surface — wraps github.com/everanium/itb/easy. */

extern int ITB_Easy_New(
    char* primitive, int keyBits, char* macName, int mode,
    uintptr_t* outHandle);
extern int ITB_Easy_NewMixed(
    char* primN, char* primD, char* primS, char* primL,
    int keyBits, char* macName,
    uintptr_t* outHandle);
extern int ITB_Easy_NewMixed3(
    char* primN,
    char* primD1, char* primD2, char* primD3,
    char* primS1, char* primS2, char* primS3,
    char* primL,
    int keyBits, char* macName,
    uintptr_t* outHandle);
extern int ITB_Easy_Free(uintptr_t handle);
extern int ITB_Easy_PrimitiveAt(
    uintptr_t handle, int slot,
    char* out, size_t capBytes, size_t* outLen);
extern int ITB_Easy_IsMixed(uintptr_t handle, int* outStatus);

extern int ITB_Easy_Encrypt(
    uintptr_t handle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_Decrypt(
    uintptr_t handle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_EncryptAuth(
    uintptr_t handle,
    void* plaintext, size_t ptlen,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_DecryptAuth(
    uintptr_t handle,
    void* ciphertext, size_t ctlen,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_Easy_SetNonceBits(uintptr_t handle, int n);
extern int ITB_Easy_SetBarrierFill(uintptr_t handle, int n);
extern int ITB_Easy_SetBitSoup(uintptr_t handle, int mode);
extern int ITB_Easy_SetLockSoup(uintptr_t handle, int mode);
extern int ITB_Easy_SetLockSeed(uintptr_t handle, int mode);
extern int ITB_Easy_SetChunkSize(uintptr_t handle, int n);

extern int ITB_Easy_Primitive(uintptr_t handle, char* out, size_t capBytes, size_t* outLen);
extern int ITB_Easy_KeyBits(uintptr_t handle, int* outStatus);
extern int ITB_Easy_Mode(uintptr_t handle, int* outStatus);
extern int ITB_Easy_MACName(uintptr_t handle, char* out, size_t capBytes, size_t* outLen);

extern int ITB_Easy_SeedCount(uintptr_t handle, int* outStatus);
extern int ITB_Easy_SeedComponents(
    uintptr_t handle, int slot,
    unsigned long long* out, int capCount, int* outLen);
extern int ITB_Easy_HasPRFKeys(uintptr_t handle, int* outStatus);
extern int ITB_Easy_PRFKey(
    uintptr_t handle, int slot,
    unsigned char* out, size_t capBytes, size_t* outLen);
extern int ITB_Easy_MACKey(
    uintptr_t handle,
    unsigned char* out, size_t capBytes, size_t* outLen);

extern int ITB_Easy_Close(uintptr_t handle);

extern int ITB_Easy_Export(
    uintptr_t handle,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Easy_Import(
    uintptr_t handle,
    void* blob, size_t blobLen);
extern int ITB_Easy_PeekConfig(
    void* blob, size_t blobLen,
    char* primOut, size_t primCap, size_t* primLen,
    int* keyBitsOut, int* modeOut,
    char* macOut, size_t macCap, size_t* macLen);
extern int ITB_Easy_LastMismatchField(char* out, size_t capBytes, size_t* outLen);

extern int ITB_Easy_NonceBits(uintptr_t handle, int* outStatus);
extern int ITB_Easy_HeaderSize(uintptr_t handle, int* outStatus);
extern int ITB_Easy_ParseChunkLen(
    uintptr_t handle,
    void* header, size_t headerLen,
    size_t* outChunkLen);

/* Native Blob — low-level state persistence (itb.Blob128/256/512). */

extern int ITB_Blob128_New(uintptr_t* outHandle);
extern int ITB_Blob256_New(uintptr_t* outHandle);
extern int ITB_Blob512_New(uintptr_t* outHandle);
extern int ITB_Blob_Free(uintptr_t handle);

extern int ITB_Blob_Width(uintptr_t handle, int* outStatus);
extern int ITB_Blob_Mode(uintptr_t handle, int* outStatus);

extern int ITB_Blob_SetKey(
    uintptr_t handle, int slot,
    void* key, size_t keyLen);
extern int ITB_Blob_GetKey(
    uintptr_t handle, int slot,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_Blob_SetComponents(
    uintptr_t handle, int slot,
    unsigned long long* comps, size_t count);
extern int ITB_Blob_GetComponents(
    uintptr_t handle, int slot,
    unsigned long long* out, size_t outCap, size_t* outCount);

extern int ITB_Blob_SetMACKey(
    uintptr_t handle,
    void* key, size_t keyLen);
extern int ITB_Blob_GetMACKey(
    uintptr_t handle,
    void* out, size_t outCap, size_t* outLen);

extern int ITB_Blob_SetMACName(
    uintptr_t handle,
    char* name, size_t nameLen);
extern int ITB_Blob_GetMACName(
    uintptr_t handle,
    char* out, size_t outCap, size_t* outLen);

extern int ITB_Blob_Export(
    uintptr_t handle, int optsBitmask,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Blob_Export3(
    uintptr_t handle, int optsBitmask,
    void* out, size_t outCap, size_t* outLen);
extern int ITB_Blob_Import(
    uintptr_t handle,
    void* blob, size_t blobLen);
extern int ITB_Blob_Import3(
    uintptr_t handle,
    void* blob, size_t blobLen);
"""


def _platform_lib_dir() -> str:
    """Maps Python platform.system() / machine() to the dist/ subfolder
    naming convention used by cmd/cshared builds."""
    sysname = {
        "Linux": "linux",
        "Darwin": "darwin",
        "Windows": "windows",
        "FreeBSD": "freebsd",
    }.get(platform.system(), platform.system().lower())
    arch = {
        "x86_64": "amd64",
        "AMD64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine(), platform.machine().lower())
    return f"{sysname}-{arch}"


def _lib_filename() -> str:
    return {
        "Linux": "libitb.so",
        "Darwin": "libitb.dylib",
        "Windows": "libitb.dll",
        "FreeBSD": "libitb.so",
    }.get(platform.system(), "libitb.so")


def _resolve_library_path() -> str:
    env = os.environ.get("ITB_LIBRARY_PATH")
    if env:
        return env

    here = Path(__file__).resolve()
    repo_root = here.parents[3]
    candidate = repo_root / "dist" / _platform_lib_dir() / _lib_filename()
    if candidate.exists():
        return str(candidate)

    return _lib_filename()


_ffi = cffi.FFI()
_ffi.cdef(_CDEF)
_lib = _ffi.dlopen(_resolve_library_path())


def _read_str(call) -> str:
    """Common idiom for size-out-param string accessors:
    first call reports required size, second call writes."""
    out_len = _ffi.new("size_t*")
    rc = call(_ffi.NULL, 0, out_len)
    if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
        _raise(rc)
    cap = int(out_len[0])
    buf = _ffi.new("char[]", cap)
    rc = call(buf, cap, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")


def _last_error() -> str:
    out_len = _ffi.new("size_t*")
    rc = _lib.ITB_LastError(_ffi.NULL, 0, out_len)
    if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
        return ""
    cap = int(out_len[0])
    if cap <= 1:
        return ""
    buf = _ffi.new("char[]", cap)
    rc = _lib.ITB_LastError(buf, cap, out_len)
    if rc != STATUS_OK:
        return ""
    return _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")


def _raise(code: int):
    raise ITBError(code, _last_error())


def version() -> str:
    """Returns the libitb library version string."""
    return _read_str(_lib.ITB_Version)


def list_hashes() -> List[Tuple[str, int]]:
    """Returns ``[(name, native_width_bits), ...]`` in canonical order."""
    n = _lib.ITB_HashCount()
    out: List[Tuple[str, int]] = []
    out_len = _ffi.new("size_t*")
    for i in range(n):
        # First call to discover required size.
        rc = _lib.ITB_HashName(i, _ffi.NULL, 0, out_len)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise(rc)
        cap = int(out_len[0])
        buf = _ffi.new("char[]", cap)
        rc = _lib.ITB_HashName(i, buf, cap, out_len)
        if rc != STATUS_OK:
            _raise(rc)
        name = _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")
        width = int(_lib.ITB_HashWidth(i))
        out.append((name, width))
    return out


def max_key_bits() -> int:
    return int(_lib.ITB_MaxKeyBits())


def channels() -> int:
    return int(_lib.ITB_Channels())


def header_size() -> int:
    """Returns the current ciphertext-chunk header size in bytes
    (nonce + width(2) + height(2)). Tracks the active SetNonceBits
    configuration: 20 by default, 36 under set_nonce_bits(256), 68
    under set_nonce_bits(512). Used by streaming consumers to know
    how many bytes to read from disk / wire before calling
    parse_chunk_len on each chunk."""
    return int(_lib.ITB_HeaderSize())


def parse_chunk_len(header: bytes) -> int:
    """Inspects a chunk header (the fixed-size [nonce || width(2) ||
    height(2)] prefix at the start of a ciphertext chunk) and
    returns the total chunk length on the wire.

    The buffer must contain at least header_size() bytes; only the
    header is consulted, the body bytes do not need to be present.
    Raises ITBError on too-short buffer, zero dimensions, or
    overflow.
    """
    if not isinstance(header, (bytes, bytearray, memoryview)):
        raise TypeError("header must be bytes-like")
    hdr = bytes(header)
    out = _ffi.new("size_t*")
    rc = _lib.ITB_ParseChunkLen(hdr, len(hdr), out)
    if rc != STATUS_OK:
        _raise(rc)
    return int(out[0])


def set_bit_soup(mode: int) -> None:
    rc = _lib.ITB_SetBitSoup(int(mode))
    if rc != STATUS_OK:
        _raise(rc)


def get_bit_soup() -> int:
    return int(_lib.ITB_GetBitSoup())


def set_lock_soup(mode: int) -> None:
    rc = _lib.ITB_SetLockSoup(int(mode))
    if rc != STATUS_OK:
        _raise(rc)


def get_lock_soup() -> int:
    return int(_lib.ITB_GetLockSoup())


def set_max_workers(n: int) -> None:
    rc = _lib.ITB_SetMaxWorkers(int(n))
    if rc != STATUS_OK:
        _raise(rc)


def get_max_workers() -> int:
    return int(_lib.ITB_GetMaxWorkers())


def set_nonce_bits(n: int) -> None:
    """Accepts 128, 256, or 512. Other values raise ITBError(STATUS_BAD_INPUT)."""
    rc = _lib.ITB_SetNonceBits(int(n))
    if rc != STATUS_OK:
        _raise(rc)


def get_nonce_bits() -> int:
    return int(_lib.ITB_GetNonceBits())


def set_barrier_fill(n: int) -> None:
    """Accepts 1, 2, 4, 8, 16, 32. Other values raise ITBError(STATUS_BAD_INPUT)."""
    rc = _lib.ITB_SetBarrierFill(int(n))
    if rc != STATUS_OK:
        _raise(rc)


def get_barrier_fill() -> int:
    return int(_lib.ITB_GetBarrierFill())


class Seed:
    """A handle to one ITB seed.

    Parameters
    ----------
    hash_name:
        Canonical hash name from list_hashes(), e.g. "blake3", "areion256".
    key_bits:
        ITB key width in bits — 512, 1024, or 2048 (multiple of 64).

    The native hash width (128 / 256 / 512) is determined by hash_name.
    All three seeds passed to encrypt() / decrypt() must share the same
    hash_name (or at least the same native width); mixing widths raises
    ITBError(STATUS_SEED_WIDTH_MIX).
    """

    __slots__ = ("_handle", "_hash_name")

    def __init__(self, hash_name: str, key_bits: int):
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_NewSeed(hash_name.encode("utf-8"), int(key_bits), h)
        if rc != STATUS_OK:
            _raise(rc)
        self._handle = int(h[0])
        self._hash_name = hash_name

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def hash_name(self) -> str:
        return self._hash_name

    @property
    def width(self) -> int:
        st = _ffi.new("int*")
        w = int(_lib.ITB_SeedWidth(self._handle, st))
        if int(st[0]) != STATUS_OK:
            _raise(int(st[0]))
        return w

    @property
    def hash_key(self) -> bytes:
        """Returns the fixed key the underlying hash closure is bound
        to (16 / 32 / 64 bytes depending on the primitive). Save these
        bytes alongside ``components`` for cross-process persistence —
        the pair fully reconstructs the seed via ``Seed.from_components``.

        ``siphash24`` returns an empty ``bytes`` since SipHash-2-4 has
        no internal fixed key (its keying material is the seed
        components themselves)."""
        # Two-call pattern: first probe length (cap=0), then allocate.
        out_len = _ffi.new("size_t*")
        rc = _lib.ITB_GetSeedHashKey(self._handle, _ffi.NULL, 0, out_len)
        # Probing returns BUFFER_TOO_SMALL when the key is non-empty
        # (no buffer to write into); empty key is OK.
        if rc == STATUS_OK and int(out_len[0]) == 0:
            return b""
        if rc != STATUS_BUFFER_TOO_SMALL:
            _raise(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned char[{n}]")
        rc = _lib.ITB_GetSeedHashKey(self._handle, buf, n, out_len)
        if rc != STATUS_OK:
            _raise(rc)
        return bytes(_ffi.buffer(buf, int(out_len[0])))

    @property
    def components(self) -> List[int]:
        """Returns the seed's underlying uint64 components (8..32
        elements). Save these alongside ``hash_key`` for cross-process
        persistence — the pair fully reconstructs the seed via
        ``Seed.from_components``."""
        out_len = _ffi.new("int*")
        rc = _lib.ITB_GetSeedComponents(self._handle, _ffi.NULL, 0, out_len)
        if rc != STATUS_BUFFER_TOO_SMALL:
            _raise(rc)
        n = int(out_len[0])
        buf = _ffi.new(f"unsigned long long[{n}]")
        rc = _lib.ITB_GetSeedComponents(self._handle, buf, n, out_len)
        if rc != STATUS_OK:
            _raise(rc)
        return [int(buf[i]) for i in range(int(out_len[0]))]

    @classmethod
    def from_components(
        cls,
        hash_name: str,
        components,
        hash_key: bytes = b"",
    ) -> "Seed":
        """Builds a seed deterministically from caller-supplied uint64
        components and an optional fixed hash key. Use this on the
        persistence-restore path (encrypt today, decrypt tomorrow);
        leave ``hash_key=b""`` for a CSPRNG-generated key (still
        useful when only the components need to be deterministic).

        ``components`` accepts any iterable of int (length 8..32,
        multiple of 8). ``hash_key`` length, when non-empty, must
        match the primitive's native fixed-key size: 16 (aescmac),
        32 (areion256 / blake2{s,b256} / blake3 / chacha20),
        64 (areion512 / blake2b512). Pass ``b""`` for ``siphash24``
        (no internal fixed key)."""
        comps = list(components)
        comps_arr = _ffi.new("unsigned long long[]", comps)
        if len(hash_key) > 0:
            key_arr = _ffi.new("unsigned char[]", bytes(hash_key))
            key_len = len(hash_key)
        else:
            key_arr = _ffi.NULL
            key_len = 0
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_NewSeedFromComponents(
            hash_name.encode("utf-8"),
            comps_arr, len(comps),
            key_arr, key_len,
            h,
        )
        if rc != STATUS_OK:
            _raise(rc)
        # Allocate Seed without going through __init__ (which would
        # call ITB_NewSeed). Bypass __slots__ assignment via direct
        # attribute setting, which __slots__ permits for declared
        # slot names.
        inst = object.__new__(cls)
        inst._handle = int(h[0])
        inst._hash_name = hash_name
        return inst

    def free(self) -> None:
        if self._handle:
            rc = _lib.ITB_FreeSeed(self._handle)
            self._handle = 0
            if rc != STATUS_OK:
                _raise(rc)

    def attach_lock_seed(self, lock_seed: "Seed") -> None:
        """Wires a dedicated lockSeed onto this noise seed. The
        per-chunk PRF closure for the bit-permutation overlay
        captures BOTH the lockSeed's components AND its hash
        function — keying-material isolation plus algorithm
        diversity (the lockSeed primitive may legitimately differ
        from the noise-seed primitive within the same native hash
        width) for defence-in-depth on the overlay channel. Both
        seeds must share the same native hash width.

        The dedicated lockSeed has no observable effect on the wire
        output unless the bit-permutation overlay is engaged via
        :func:`itb.set_bit_soup` ``(1)`` or :func:`itb.set_lock_soup`
        ``(1)`` before the first ``encrypt`` / ``decrypt`` call. The
        Go-side build-PRF guard panics on encrypt-time when an
        attach is present without either flag, surfacing as
        :class:`ITBError`.

        Misuse paths surface as ``ITBError(STATUS_BAD_INPUT)``:
        self-attach (passing the same seed twice), component-array
        aliasing (two distinct Seed handles whose components share
        the same backing array — only reachable via raw FFI), and
        post-encrypt switching (calling ``attach_lock_seed`` on a
        noise seed that has already produced ciphertext). Width
        mismatch surfaces as ``ITBError(STATUS_SEED_WIDTH_MIX)``.

        The dedicated lockSeed remains owned by the caller —
        attach only records the pointer on the noise seed, so
        keep the lockSeed alive for the lifetime of the noise seed
        (do not call ``lock_seed.free()`` before encrypt finishes).
        """
        if not isinstance(lock_seed, Seed):
            raise TypeError("lock_seed must be an itb.Seed instance")
        rc = _lib.ITB_AttachLockSeed(self._handle, lock_seed.handle)
        if rc != STATUS_OK:
            _raise(rc)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.free()

    def __del__(self):
        # Best-effort GC release; ignore any error since interpreter
        # shutdown ordering is unpredictable.
        try:
            if self._handle:
                _lib.ITB_FreeSeed(self._handle)
                self._handle = 0
        except Exception:
            pass


def list_macs() -> List[Tuple[str, int, int, int]]:
    """Returns ``[(name, key_size, tag_size, min_key_bytes), ...]`` in
    canonical FFI order (kmac256, hmac-sha256, hmac-blake3)."""
    n = _lib.ITB_MACCount()
    out: List[Tuple[str, int, int, int]] = []
    out_len = _ffi.new("size_t*")
    for i in range(n):
        rc = _lib.ITB_MACName(i, _ffi.NULL, 0, out_len)
        if rc not in (STATUS_OK, STATUS_BUFFER_TOO_SMALL):
            _raise(rc)
        cap = int(out_len[0])
        buf = _ffi.new("char[]", cap)
        rc = _lib.ITB_MACName(i, buf, cap, out_len)
        if rc != STATUS_OK:
            _raise(rc)
        name = _ffi.string(buf, int(out_len[0]) - 1).decode("utf-8")
        out.append((
            name,
            int(_lib.ITB_MACKeySize(i)),
            int(_lib.ITB_MACTagSize(i)),
            int(_lib.ITB_MACMinKeyBytes(i)),
        ))
    return out


class MAC:
    """A handle to one keyed MAC.

    Parameters
    ----------
    mac_name:
        Canonical MAC name from list_macs(): "kmac256", "hmac-sha256",
        or "hmac-blake3".
    key:
        Bytes-like key. Length must be at least the primitive's
        min_key_bytes (16 for kmac256/hmac-sha256, 32 for hmac-blake3).
    """

    __slots__ = ("_handle", "_name")

    def __init__(self, mac_name: str, key: bytes):
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        kb = bytes(key)
        h = _ffi.new("uintptr_t*")
        rc = _lib.ITB_NewMAC(mac_name.encode("utf-8"), kb, len(kb), h)
        if rc != STATUS_OK:
            _raise(rc)
        self._handle = int(h[0])
        self._name = mac_name

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def name(self) -> str:
        return self._name

    def free(self) -> None:
        if self._handle:
            rc = _lib.ITB_FreeMAC(self._handle)
            self._handle = 0
            if rc != STATUS_OK:
                _raise(rc)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.free()

    def __del__(self):
        try:
            if self._handle:
                _lib.ITB_FreeMAC(self._handle)
                self._handle = 0
        except Exception:
            pass


def encrypt_auth(
    noise: Seed, data: Seed, start: Seed, mac: MAC, plaintext: bytes,
) -> bytes:
    """Authenticated single-Ouroboros encrypt with MAC-Inside-Encrypt."""
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    return _enc_dec_auth(_lib.ITB_EncryptAuth, noise, data, start, mac, bytes(plaintext))


def decrypt_auth(
    noise: Seed, data: Seed, start: Seed, mac: MAC, ciphertext: bytes,
) -> bytes:
    """Authenticated single-Ouroboros decrypt. Raises ITBError with
    code STATUS_MAC_FAILURE on tampered ciphertext / wrong MAC key."""
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("ciphertext must be bytes-like")
    return _enc_dec_auth(_lib.ITB_DecryptAuth, noise, data, start, mac, bytes(ciphertext))


def encrypt_auth_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    mac: MAC, plaintext: bytes,
) -> bytes:
    """Authenticated Triple Ouroboros encrypt (7 seeds + MAC)."""
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    return _enc_dec_auth_triple(
        _lib.ITB_EncryptAuth3,
        noise, data1, data2, data3, start1, start2, start3, mac,
        bytes(plaintext),
    )


def decrypt_auth_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    mac: MAC, ciphertext: bytes,
) -> bytes:
    """Authenticated Triple Ouroboros decrypt."""
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("ciphertext must be bytes-like")
    return _enc_dec_auth_triple(
        _lib.ITB_DecryptAuth3,
        noise, data1, data2, data3, start1, start2, start3, mac,
        bytes(ciphertext),
    )


def _enc_dec_auth(fn, noise: Seed, data: Seed, start: Seed, mac: MAC, payload: bytes) -> bytes:
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle, data.handle, start.handle, mac.handle,
            payload, len(payload), _ffi.NULL, 0, out_len)
    if rc != STATUS_BUFFER_TOO_SMALL:
        if rc == STATUS_OK:
            return b""
        _raise(rc)
    need = int(out_len[0])
    out_buf = _ffi.new("unsigned char[]", need)
    rc = fn(noise.handle, data.handle, start.handle, mac.handle,
            payload, len(payload), out_buf, need, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def _enc_dec_auth_triple(
    fn, noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    mac: MAC, payload: bytes,
) -> bytes:
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            mac.handle, payload, len(payload),
            _ffi.NULL, 0, out_len)
    if rc != STATUS_BUFFER_TOO_SMALL:
        if rc == STATUS_OK:
            return b""
        _raise(rc)
    need = int(out_len[0])
    out_buf = _ffi.new("unsigned char[]", need)
    rc = fn(noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            mac.handle, payload, len(payload),
            out_buf, need, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def encrypt(noise: Seed, data: Seed, start: Seed, plaintext: bytes) -> bytes:
    """Encrypts plaintext under the (noise, data, start) seed trio.

    All three seeds must share the same native hash width.
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    pt = bytes(plaintext)
    return _encrypt_or_decrypt(_lib.ITB_Encrypt, noise, data, start, pt)


def decrypt(noise: Seed, data: Seed, start: Seed, ciphertext: bytes) -> bytes:
    """Decrypts ciphertext produced by encrypt() under the same seed trio."""
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("ciphertext must be bytes-like")
    ct = bytes(ciphertext)
    return _encrypt_or_decrypt(_lib.ITB_Decrypt, noise, data, start, ct)


def encrypt_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    plaintext: bytes,
) -> bytes:
    """Triple Ouroboros encrypt over seven seeds.

    Splits plaintext across three interleaved snake payloads. The
    on-wire ciphertext format is the same shape as encrypt() — only
    the internal split / interleave differs. All seven seeds must
    share the same native hash width and be pairwise distinct
    handles (the underlying ITB API enforces seven-seed isolation).
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    return _encrypt_or_decrypt_triple(
        _lib.ITB_Encrypt3,
        noise, data1, data2, data3, start1, start2, start3,
        bytes(plaintext),
    )


def decrypt_triple(
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    ciphertext: bytes,
) -> bytes:
    """Inverse of encrypt_triple()."""
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("ciphertext must be bytes-like")
    return _encrypt_or_decrypt_triple(
        _lib.ITB_Decrypt3,
        noise, data1, data2, data3, start1, start2, start3,
        bytes(ciphertext),
    )


def _encrypt_or_decrypt(fn, noise: Seed, data: Seed, start: Seed, payload: bytes) -> bytes:
    out_len = _ffi.new("size_t*")
    # Probe first to discover required size.
    rc = fn(noise.handle, data.handle, start.handle,
            payload, len(payload),
            _ffi.NULL, 0, out_len)
    if rc != STATUS_BUFFER_TOO_SMALL:
        if rc == STATUS_OK:
            return b""
        _raise(rc)
    need = int(out_len[0])
    out_buf = _ffi.new("unsigned char[]", need)
    rc = fn(noise.handle, data.handle, start.handle,
            payload, len(payload),
            out_buf, need, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))


def _encrypt_or_decrypt_triple(
    fn,
    noise: Seed,
    data1: Seed, data2: Seed, data3: Seed,
    start1: Seed, start2: Seed, start3: Seed,
    payload: bytes,
) -> bytes:
    out_len = _ffi.new("size_t*")
    rc = fn(noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            payload, len(payload),
            _ffi.NULL, 0, out_len)
    if rc != STATUS_BUFFER_TOO_SMALL:
        if rc == STATUS_OK:
            return b""
        _raise(rc)
    need = int(out_len[0])
    out_buf = _ffi.new("unsigned char[]", need)
    rc = fn(noise.handle,
            data1.handle, data2.handle, data3.handle,
            start1.handle, start2.handle, start3.handle,
            payload, len(payload),
            out_buf, need, out_len)
    if rc != STATUS_OK:
        _raise(rc)
    return bytes(_ffi.buffer(out_buf, int(out_len[0])))
