# ITB Python binding

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

## Quick Start — Areion-SoEM-512 (recommended, no MAC)

```python
# Sender

import itb

# Optional: global configuration (all process-wide, atomic)
itb.set_max_workers(8)   # limit to 8 CPU cores (default: 0 = all CPUs)
itb.set_nonce_bits(512)  # 512-bit nonce (default: 128-bit)
itb.set_barrier_fill(4)  # CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

itb.set_bit_soup(1)      # optional bit-level split ("bit-soup"; default: 0 = byte-level)
                          # automatically enabled for Single Ouroboros if
                          # itb.set_lock_soup(1) is enabled or vice versa

itb.set_lock_soup(1)     # optional Insane Interlocked Mode: per-chunk PRF-keyed
                          # bit-permutation overlay on top of bit-soup;
                          # automatically enabled for Single Ouroboros if
                          # itb.set_bit_soup(1) is enabled or vice versa

# Three independent CSPRNG-keyed Areion-SoEM-512 seeds. Each Seed
# pre-keys its primitive once at construction; the C ABI / FFI
# layer auto-wires the AVX-512 + VAES + ILP + ZMM-batched chain-
# absorb dispatch through Seed.BatchHash — no manual batched-arm
# attachment is required on the Python side.
ns = itb.Seed("areion512", 2048)  # random noise CSPRNG seeds + hash key generated
ds = itb.Seed("areion512", 2048)  # random data  CSPRNG seeds + hash key generated
ss = itb.Seed("areion512", 2048)  # random start CSPRNG seeds + hash key generated

# For cross-process persistence: seed.hash_key (64-byte PRF fixed
# key per seed) and seed.components (list of uint64 seed components)
# carry the entire reconstruction state. Capture these and ship
# alongside the ciphertext (or out-of-band).
key_n,  key_d,  key_s  = ns.hash_key,  ds.hash_key,  ss.hash_key
comps_n, comps_d, comps_s = ns.components, ds.components, ss.components
print(f"noise PRF key: {key_n.hex()}")
print(f"data  PRF key: {key_d.hex()}")
print(f"start PRF key: {key_s.hex()}")
print(f"noise seed components: {comps_n}")
print(f"data  seed components: {comps_d}")
print(f"start seed components: {comps_s}")

plaintext = b"any text or binary data - including 0x00 bytes"
#chunk_size = 4 * 1024 * 1024  # 4 MB - bulk local crypto, not small-frame network streaming
#read_size  = 64 * 1024        # app-driven feed granularity (independent of chunk_size)

try:
    # Encrypt into RGBWYOPA container
    encrypted = itb.encrypt(ns, ds, ss, plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Streaming alternative — the application drives chunk
    # boundaries through StreamEncryptor.write(); the encryptor
    # buffers up to chunk_size bytes before emitting one ITB
    # chunk to fout, with the tail flushed on close().
    #from io import BytesIO
    #fout = BytesIO()
    #with itb.StreamEncryptor(ns, ds, ss, fout, chunk_size=chunk_size) as enc:
    #    for i in range(0, len(plaintext), read_size):
    #        enc.write(plaintext[i:i+read_size])
    #ciphertext = fout.getvalue()

    # Send encrypted payload
finally:
    ns.free(); ds.free(); ss.free()


# Receiver

import itb

itb.set_max_workers(8)
itb.set_nonce_bits(512)
itb.set_barrier_fill(4)
itb.set_bit_soup(1)
itb.set_lock_soup(1)

# Receive encrypted payload
# encrypted = ...

# Reconstruct from saved 64-byte PRF fixed keys + saved seed
# components. The persisted material was captured Sender-side via
# the seed.hash_key and seed.components properties printed above.
# key_n  = ...; key_d  = ...; key_s  = ...
# comps_n = ...; comps_d = ...; comps_s = ...

ns = itb.Seed.from_components("areion512", comps_n, key_n)
ds = itb.Seed.from_components("areion512", comps_d, key_d)
ss = itb.Seed.from_components("areion512", comps_s, key_s)

#read_size = 64 * 1024  # app-driven feed granularity

try:
    # Decrypt from RGBWYOPA container
    decrypted = itb.decrypt(ns, ds, ss, encrypted)
    print(f"decrypted: {decrypted.decode()}")

    # Streaming alternative — the application drives chunk
    # boundaries through StreamDecryptor.feed(); the decryptor
    # parses ITB chunk headers from the fed stream and emits
    # plaintext to fout as each chunk completes.
    #from io import BytesIO
    #fout = BytesIO()
    #with itb.StreamDecryptor(ns, ds, ss, fout) as dec:
    #    for i in range(0, len(encrypted), read_size):
    #        dec.feed(encrypted[i:i+read_size])
    #decrypted = fout.getvalue()
finally:
    ns.free(); ds.free(); ss.free()
```

## Quick Start — Areion-SoEM-512 + KMAC-256 (authenticated)

```python
# Sender

import itb
import secrets

itb.set_max_workers(8)
itb.set_nonce_bits(512)
itb.set_barrier_fill(4)
itb.set_bit_soup(1)
itb.set_lock_soup(1)

ns = itb.Seed("areion512", 2048)
ds = itb.Seed("areion512", 2048)
ss = itb.Seed("areion512", 2048)

# KMAC-256 — NIST SP 800-185 keyed XOF, 32-byte CSPRNG key, 32-byte tag.
mac_key = secrets.token_bytes(32)
mac = itb.MAC("kmac256", mac_key)

# For cross-process persistence: seed.hash_key (64-byte PRF fixed
# keys), seed.components (list of uint64 seed components), and
# mac_key (32-byte MAC key).
key_n,  key_d,  key_s  = ns.hash_key,  ds.hash_key,  ss.hash_key
comps_n, comps_d, comps_s = ns.components, ds.components, ss.components
print(f"noise PRF key: {key_n.hex()}")
print(f"data  PRF key: {key_d.hex()}")
print(f"start PRF key: {key_s.hex()}")
print(f"MAC key:       {mac_key.hex()}")
print(f"noise seed components: {comps_n}")
print(f"data  seed components: {comps_d}")
print(f"start seed components: {comps_s}")

plaintext = b"any text or binary data - including 0x00 bytes"

try:
    # Authenticated encrypt — 32-byte tag is computed across the
    # entire decrypted capacity and embedded inside the RGBWYOPA
    # container, preserving oracle-free deniability.
    encrypted = itb.encrypt_auth(ns, ds, ss, mac, plaintext)
    print(f"encrypted: {len(encrypted)} bytes")
    # Send encrypted payload
finally:
    mac.free()
    ns.free(); ds.free(); ss.free()


# Receiver

import itb

itb.set_max_workers(8)
itb.set_nonce_bits(512)
itb.set_barrier_fill(4)
itb.set_bit_soup(1)
itb.set_lock_soup(1)

# Receive encrypted payload
# encrypted = ...

# Reconstruct from saved 64-byte PRF fixed keys + saved seed
# components + saved 32-byte MAC key.
# key_n  = ...; key_d  = ...; key_s  = ...; mac_key = ...
# comps_n = ...; comps_d = ...; comps_s = ...

ns = itb.Seed.from_components("areion512", comps_n, key_n)
ds = itb.Seed.from_components("areion512", comps_d, key_d)
ss = itb.Seed.from_components("areion512", comps_s, key_s)

mac = itb.MAC("kmac256", mac_key)

try:
    # Authenticated decrypt — any single-bit tamper triggers MAC
    # failure (no oracle leak about which byte was tampered).
    decrypted = itb.decrypt_auth(ns, ds, ss, mac, encrypted)
    print(f"decrypted: {decrypted.decode()}")
finally:
    mac.free()
    ns.free(); ds.free(); ss.free()
```

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry: `areion256`,
`areion512`, `siphash24`, `aescmac`, `blake2b256`, `blake2b512`,
`blake2s`, `blake3`, `chacha20`. Triple Ouroboros (3× security)
takes seven seeds (one shared `noiseSeed` plus three `dataSeed`
and three `startSeed`) via `itb.encrypt_triple` /
`itb.decrypt_triple` and the authenticated counterparts
`itb.encrypt_auth_triple` / `itb.decrypt_auth_triple`. Streaming
counterparts: `itb.StreamEncryptor3` / `itb.StreamDecryptor3` /
`itb.encrypt_stream_triple` / `itb.decrypt_stream_triple`.

All seeds passed to one `encrypt` / `decrypt` call must share the
same native hash width. Mixing widths raises
`ITBError(STATUS_SEED_WIDTH_MIX)`.

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

For low-level chunk parsing (e.g. when implementing custom file
formats around ITB chunks): `itb.parse_chunk_len(header)` inspects
the fixed-size chunk header and returns the chunk's total
on-the-wire length; `itb.header_size()` returns the active header
byte count (20 / 36 / 68 for nonce sizes 128 / 256 / 512 bits).

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
