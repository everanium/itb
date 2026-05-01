# itb — Python binding for ITB

Cffi-based Python wrapper over the libitb shared library
(`cmd/cshared`). ABI mode — no C compiler at install time, just
``cffi``.

## Build the shared library

From the repo root:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

## Install requirements

```bash
pip install cffi
```

## Run tests

```bash
python -m unittest discover bindings/python/tests
```

## Library lookup order

1. `ITB_LIBRARY_PATH` environment variable (absolute path).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking four
   directory levels up from `bindings/python/itb/_ffi.py`.
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Quick example

```python
import itb

# Inspect shipped primitives:
for name, width in itb.list_hashes():
    print(name, width)
for name, key_size, tag_size, min_key in itb.list_macs():
    print(name, key_size, tag_size, min_key)

# Encrypt / decrypt under three independent seeds:
with itb.Seed("blake3", 1024) as ns, \
     itb.Seed("blake3", 1024) as ds, \
     itb.Seed("blake3", 1024) as ss:
    ct = itb.encrypt(ns, ds, ss, b"hello world")
    pt = itb.decrypt(ns, ds, ss, ct)
    assert pt == b"hello world"
```

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry:
`areion256`, `areion512`, `siphash24`, `aescmac`, `blake2b256`,
`blake2b512`, `blake2s`, `blake3`, `chacha20`.

All seeds passed to one `encrypt` / `decrypt` call must share the
same native hash width. Mixing widths raises
`ITBError(STATUS_SEED_WIDTH_MIX)`.

Triple Ouroboros uses seven seeds (one shared `noiseSeed` plus
three `dataSeed` and three `startSeed`):

```python
seeds = [itb.Seed("blake3", 1024) for _ in range(7)]
ct = itb.encrypt_triple(*seeds, b"plaintext")
pt = itb.decrypt_triple(*seeds, ct)
```

## Authenticated encryption (MAC-Inside-Encrypt)

`itb.MAC` is a handle to one keyed MAC primitive. Names
(`kmac256`, `hmac-sha256`, `hmac-blake3`) match the canonical
`macs/` registry. Tag size is 32 bytes for every shipped MAC.

```python
import os

mac = itb.MAC("hmac-sha256", os.urandom(32))
with itb.Seed("blake3", 1024) as ns, \
     itb.Seed("blake3", 1024) as ds, \
     itb.Seed("blake3", 1024) as ss:
    ct = itb.encrypt_auth(ns, ds, ss, mac, b"integrity-protected")
    pt = itb.decrypt_auth(ns, ds, ss, mac, ct)
mac.free()
```

`encrypt_auth_triple` / `decrypt_auth_triple` extend the same
pattern to seven seeds. A tampered ciphertext raises
`ITBError(STATUS_MAC_FAILURE)` on decrypt.

## Streaming

The streaming API processes plaintext in independent ITB chunks
(default 16 MB each), bounding peak memory regardless of total
payload size. Two equivalent flavours:

**Class form** — file-like `write` / `feed`:

```python
with open("plain.bin", "rb") as fin, open("cipher.itb", "wb") as fout:
    seeds = [itb.Seed("blake3", 1024) for _ in range(3)]
    try:
        with itb.StreamEncryptor(*seeds, fout) as enc:
            while buf := fin.read(1 << 20):
                enc.write(buf)
    finally:
        for s in seeds: s.free()
```

**Functional form** — file-to-file in one call:

```python
seeds = [itb.Seed("blake3", 1024) for _ in range(3)]
try:
    with open("plain.bin", "rb") as fin, open("cipher.itb", "wb") as fout:
        itb.encrypt_stream(*seeds, fin, fout)
finally:
    for s in seeds: s.free()
```

Triple variants: `StreamEncryptor3` / `StreamDecryptor3` /
`encrypt_stream_triple` / `decrypt_stream_triple` with seven
seeds.

For low-level chunk parsing (e.g. when implementing custom
file formats around ITB chunks): `itb.parse_chunk_len(header)`
inspects the fixed-size chunk header and returns the chunk's total
on-the-wire length; `itb.header_size()` returns the active header
byte count (20 / 36 / 68 for nonce sizes 128 / 256 / 512 bits).

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt
calls in the process. Out-of-range values raise
`ITBError(STATUS_BAD_INPUT)` rather than crashing.

| Function | Accepted values | Default |
|---|---|---|
| `set_max_workers(n)` | non-negative int | 0 (auto) |
| `set_nonce_bits(n)` | 128, 256, 512 | 128 |
| `set_barrier_fill(n)` | 1, 2, 4, 8, 16, 32 | 1 |
| `set_bit_soup(mode)` | 0 (off), non-zero (on) | 0 |
| `set_lock_soup(mode)` | 0 (off), non-zero (on) | 0 |

Read-only constants: `itb.max_key_bits()`, `itb.channels()`,
`itb.header_size()`, `itb.version()`.

## Error model

Every failure surfaces as `itb.ITBError` with two fields:

```python
try:
    itb.MAC("nonsense", b"\0" * 32)
except itb.ITBError as e:
    print(e.code, e)  # e.code == itb._ffi.STATUS_BAD_MAC
```

Status codes are documented in `cmd/cshared/internal/capi/errors.go`
and mirrored in `_ffi.STATUS_*` constants. Type / value-input
errors raise `TypeError` / `ValueError` (e.g. `plaintext` not
bytes-like, `chunk_size` ≤ 0).
