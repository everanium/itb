"""ITB — Python binding over libitb shared library.

The package wraps the C ABI exported by cmd/cshared (libitb.so / .dll /
.dylib) through ``cffi`` in ABI mode (no compile step on install). The
public surface is intentionally narrow:

    >>> import itb
    >>> seeds = [itb.Seed("blake3", 1024) for _ in range(3)]
    >>> ct = itb.encrypt(*seeds, b"hello world")
    >>> pt = itb.decrypt(*seeds, ct)
    >>> assert pt == b"hello world"

Authenticated variants take an additional MAC handle:

    >>> mac = itb.MAC("hmac-sha256", os.urandom(32))
    >>> ct = itb.encrypt_auth(*seeds, mac, b"integrity-protected")
    >>> pt = itb.decrypt_auth(*seeds, mac, ct)

Hash names match the canonical FFI registry (see hashes/registry.go):
``areion256``, ``areion512``, ``siphash24``, ``aescmac``, ``blake2b256``,
``blake2b512``, ``blake2s``, ``blake3``, ``chacha20``.

MAC names: ``kmac256``, ``hmac-sha256``, ``hmac-blake3``.
"""

from ._ffi import (
    Seed,
    MAC,
    encrypt,
    decrypt,
    encrypt_triple,
    decrypt_triple,
    encrypt_auth,
    decrypt_auth,
    encrypt_auth_triple,
    decrypt_auth_triple,
    list_hashes,
    list_macs,
    version,
    set_bit_soup,
    set_lock_soup,
    set_max_workers,
    set_nonce_bits,
    set_barrier_fill,
    get_bit_soup,
    get_lock_soup,
    get_max_workers,
    get_nonce_bits,
    get_barrier_fill,
    max_key_bits,
    channels,
    header_size,
    parse_chunk_len,
    ITBError,
)
from .streams import (
    StreamEncryptor,
    StreamDecryptor,
    StreamEncryptor3,
    StreamDecryptor3,
    encrypt_stream,
    decrypt_stream,
    encrypt_stream_triple,
    decrypt_stream_triple,
    DEFAULT_CHUNK_SIZE,
)
from .easy import (
    Encryptor,
    EasyMismatchError,
    peek_config,
)
from .blob import (
    Blob128,
    Blob256,
    Blob512,
    BlobModeMismatchError,
    BlobMalformedError,
    BlobVersionTooNewError,
)

__all__ = [
    "Seed",
    "MAC",
    "encrypt",
    "decrypt",
    "encrypt_triple",
    "decrypt_triple",
    "encrypt_auth",
    "decrypt_auth",
    "encrypt_auth_triple",
    "decrypt_auth_triple",
    "StreamEncryptor",
    "StreamDecryptor",
    "StreamEncryptor3",
    "StreamDecryptor3",
    "encrypt_stream",
    "decrypt_stream",
    "encrypt_stream_triple",
    "decrypt_stream_triple",
    "DEFAULT_CHUNK_SIZE",
    "list_hashes",
    "list_macs",
    "version",
    "set_bit_soup",
    "set_lock_soup",
    "set_max_workers",
    "set_nonce_bits",
    "set_barrier_fill",
    "get_bit_soup",
    "get_lock_soup",
    "get_max_workers",
    "get_nonce_bits",
    "get_barrier_fill",
    "max_key_bits",
    "channels",
    "header_size",
    "parse_chunk_len",
    "ITBError",
    "Encryptor",
    "EasyMismatchError",
    "peek_config",
    "Blob128",
    "Blob256",
    "Blob512",
    "BlobModeMismatchError",
    "BlobMalformedError",
    "BlobVersionTooNewError",
]
