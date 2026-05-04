# ITB Python Binding

Cffi-based Python wrapper over the libitb shared library
(`cmd/cshared`). ABI mode — no C compiler at install time, just
``cffi``.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools python python-cffi
```

## Build the shared library

From the repo root:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

### Build tags governing hash-kernel selection

| Build flag | ITB chain-absorb asm | Upstream hash asm | Use case |
|---|---|---|---|
| (none) | engaged | engaged | Default — full asm stack |
| <code>‑tags=noitbasm</code> | off | engaged | Hosts without AVX-512+VL where the 4-lane chain-absorb wrapper is dead weight; the encrypt path falls into `process_cgo`'s nil-`BatchHash` branch and drives 4 single-call invocations through the upstream asm directly |

For hosts without AVX-512+VL CPUs, build with the `-tags=noitbasm`
flag:

```bash
go build -trimpath -tags=noitbasm -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

Passing `-tags=noitbasm` does not disable upstream asm in
`zeebo/blake3`, `golang.org/x/crypto`, or `jedisct1/go-aes`.

## Run tests

```bash
python -m unittest discover bindings/python/tests
```

## Library lookup order

1. `ITB_LIBRARY_PATH` environment variable (absolute path).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking four
   directory levels up from `bindings/python/itb/_ffi.py`.
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Quick Start — `itb.Encryptor` (recommended high-level surface, no MAC)

The high-level :class:`itb.Encryptor` (mirroring the
``github.com/everanium/itb/easy`` Go sub-package) replaces the
seven-line setup ceremony of the lower-level
``Seed`` / ``encrypt`` / ``decrypt`` path with one constructor call:
the encryptor allocates its own three (Single) or seven (Triple)
seeds + MAC closure, snapshots the global configuration into a
per-instance Config, and exposes setters that mutate only its own
state without touching the process-wide ``itb.set_*`` accessors.
Two encryptors with different settings can run concurrently without
cross-contamination.

```python
# Sender

import itb

# Per-instance configuration — mutates only this encryptor's Config.
# Two encryptors built side-by-side carry independent settings;
# process-wide itb.set_* accessors are NOT consulted after
# construction.
with itb.Encryptor("areion512", 2048, "hmac-blake3") as enc:
    enc.set_nonce_bits(512)   # 512-bit nonce (default: 128-bit)
    enc.set_barrier_fill(4)   # CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)
    enc.set_bit_soup(1)       # optional bit-level split ("bit-soup"; default: 0 = byte-level)
                              # auto-enabled for Single Ouroboros if set_lock_soup(1) is on
    enc.set_lock_soup(1)      # optional Insane Interlocked Mode: per-chunk PRF-keyed
                              # bit-permutation overlay on top of bit-soup;
                              # auto-enabled for Single Ouroboros if set_bit_soup(1) is on

    #enc.set_lock_seed(1)     # optional dedicated lockSeed for the bit-permutation
                              # derivation channel — separates that PRF's keying material
                              # from the noiseSeed-driven noise-injection channel; auto-
                              # couples set_lock_soup(1) + set_bit_soup(1). Adds one
                              # extra seed slot (3 → 4 for Single, 7 → 8 for Triple).
                              # Must be called BEFORE the first encrypt — switching
                              # mid-session raises ITBError(STATUS_EASY_LOCKSEED_AFTER_ENCRYPT).

    # For cross-process persistence: enc.export() returns a single
    # JSON blob carrying PRF keys, seed components, MAC key, and
    # (when active) the dedicated lockSeed material. Ship it
    # alongside the ciphertext or out-of-band.
    blob = enc.export()
    print(f"state blob: {len(blob)} bytes")
    print(f"primitive: {enc.primitive}, key_bits: {enc.key_bits}, "
          f"mode: {enc.mode}, mac: {enc.mac_name}")

    plaintext = b"any text or binary data - including 0x00 bytes"
    #chunk_size = 4 * 1024 * 1024  # 4 MB - bulk local crypto, not small-frame network streaming
    #read_size  = 64 * 1024        # app-driven feed granularity (independent of chunk_size)

    # One-shot encrypt into RGBWYOPA container.
    encrypted = enc.encrypt(plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Streaming alternative — the application drives chunk boundaries
    # by slicing plaintext into chunk_size pieces and calling
    # enc.encrypt() per chunk. enc.header_size + enc.parse_chunk_len
    # are per-instance accessors (track this encryptor's own
    # nonce_bits, NOT the process-wide itb.header_size).
    #from io import BytesIO
    #cbuf = BytesIO()
    #for i in range(0, len(plaintext), chunk_size):
    #    cbuf.write(enc.encrypt(plaintext[i:i+chunk_size]))
    #encrypted = cbuf.getvalue()

    # Send encrypted payload + state blob


# Receiver

import itb

# Receive encrypted payload + state blob
# encrypted = ...
# blob = ...

# Optional: peek at the blob's metadata before constructing a
# matching encryptor. Useful when the receiver multiplexes blobs
# of different shapes (different primitive / mode / MAC choices).
prim, key_bits, mode, mac = itb.peek_config(blob)
print(f"peek: primitive={prim}, key_bits={key_bits}, mode={mode}, mac={mac}")

with itb.Encryptor(prim, key_bits, mac, mode=mode) as dec:
    # dec.import_state(blob) below automatically restores the full
    # per-instance configuration (nonce_bits, barrier_fill, bit_soup,
    # lock_soup, and the dedicated lockSeed material when sender's
    # set_lock_seed(1) was active). The set_*() lines below are kept
    # for documentation — they show the knobs available for explicit
    # pre-Import override. barrier_fill is asymmetric: a receiver-set
    # value > 1 takes priority over the blob's barrier_fill (the
    # receiver's heavier CSPRNG margin is preserved across Import).
    dec.set_nonce_bits(512)
    dec.set_barrier_fill(4)
    dec.set_bit_soup(1)
    dec.set_lock_soup(1)
    #dec.set_lock_seed(1)     # optional — Import below restores the dedicated
                              # lockSeed slot from the blob's lock_seed:true.

    # Restore PRF keys, seed components, MAC key, and the per-instance
    # configuration overrides (nonce_bits / barrier_fill / bit_soup /
    # lock_soup / lock_seed) from the saved blob.
    dec.import_state(blob)

    #read_size = 64 * 1024  # app-driven feed granularity

    # One-shot decrypt from RGBWYOPA container.
    decrypted = dec.decrypt(encrypted)
    print(f"decrypted: {decrypted.decode()}")

    # Streaming alternative — walk concatenated chunks by reading
    # dec.header_size bytes, calling dec.parse_chunk_len(buf), reading
    # the remaining body, and feeding the full chunk to dec.decrypt().
    #from io import BytesIO
    #cin = BytesIO(encrypted)
    #pbuf = BytesIO()
    #accumulator = bytearray()
    #while True:
    #    buf = cin.read(read_size)
    #    if not buf: break
    #    accumulator.extend(buf)
    #    while len(accumulator) >= dec.header_size:
    #        chunk_len = dec.parse_chunk_len(bytes(accumulator[:dec.header_size]))
    #        if len(accumulator) < chunk_len: break
    #        pbuf.write(dec.decrypt(bytes(accumulator[:chunk_len])))
    #        del accumulator[:chunk_len]
    #decrypted = pbuf.getvalue()
```

## Quick Start — `itb.Encryptor` + HMAC-BLAKE3 (recommended, authenticated)

The MAC primitive is bound at construction time — the third positional
argument to :class:`itb.Encryptor` selects one of the registry names
(``hmac-blake3`` — recommended default, ``kmac256``, ``hmac-sha256``).
The encryptor
allocates a fresh 32-byte CSPRNG MAC key alongside the per-seed PRF
keys; ``enc.export()`` carries all of them in a single JSON blob. On
the receiver side, ``dec.import_state(blob)`` restores the MAC key
together with the seeds, so the encrypt-today / decrypt-tomorrow flow
is one method call per side.

```python
# Sender

import itb

with itb.Encryptor("areion512", 2048, "hmac-blake3") as enc:
    enc.set_nonce_bits(512)   # per-instance — does NOT touch process-wide state
    enc.set_barrier_fill(4)
    enc.set_bit_soup(1)
    enc.set_lock_soup(1)

    #enc.set_lock_seed(1)     # optional dedicated lockSeed for the bit-permutation
                              # derivation channel — auto-couples set_lock_soup(1) +
                              # set_bit_soup(1). Adds one extra seed slot
                              # (3 → 4 for Single, 7 → 8 for Triple). Must be
                              # called BEFORE the first encrypt_auth — switching
                              # mid-session raises ITBError(STATUS_EASY_LOCKSEED_AFTER_ENCRYPT).

    # Persistence blob — carries seeds + PRF keys + MAC key (and the
    # dedicated lockSeed material when set_lock_seed(1) is active).
    blob = enc.export()
    print(f"state blob: {len(blob)} bytes")

    plaintext = b"any text or binary data - including 0x00 bytes"
    #chunk_size = 4 * 1024 * 1024

    # Authenticated encrypt — 32-byte tag is computed across the
    # entire decrypted capacity and embedded inside the RGBWYOPA
    # container, preserving oracle-free deniability.
    encrypted = enc.encrypt_auth(plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Streaming alternative — slice plaintext into chunk_size pieces
    # and call enc.encrypt_auth() per chunk; each chunk carries its
    # own MAC tag. enc.header_size + enc.parse_chunk_len are
    # per-instance accessors.
    #from io import BytesIO
    #cbuf = BytesIO()
    #for i in range(0, len(plaintext), chunk_size):
    #    cbuf.write(enc.encrypt_auth(plaintext[i:i+chunk_size]))
    #encrypted = cbuf.getvalue()

    # Send encrypted payload + state blob


# Receiver

import itb

# Receive encrypted payload + state blob
# encrypted = ...
# blob = ...

itb.set_max_workers(8)        # limit to 8 CPU cores (default: 0 = all CPUs)

prim, key_bits, mode, mac = itb.peek_config(blob)

with itb.Encryptor(prim, key_bits, mac, mode=mode) as dec:
    # dec.import_state(blob) below automatically restores the full
    # per-instance configuration (nonce_bits, barrier_fill, bit_soup,
    # lock_soup, and the dedicated lockSeed material when sender's
    # set_lock_seed(1) was active). The set_*() lines below are kept
    # for documentation — they show the knobs available for explicit
    # pre-Import override. barrier_fill is asymmetric: a receiver-set
    # value > 1 takes priority over the blob's barrier_fill (the
    # receiver's heavier CSPRNG margin is preserved across Import).
    dec.set_nonce_bits(512)
    dec.set_barrier_fill(4)
    dec.set_bit_soup(1)
    dec.set_lock_soup(1)
    #dec.set_lock_seed(1)     # optional — Import below restores the dedicated
                              # lockSeed slot from the blob's lock_seed:true.

    dec.import_state(blob)

    # Authenticated decrypt — any single-bit tamper triggers MAC
    # failure (no oracle leak about which byte was tampered).
    # Mismatch surfaces as ITBError(STATUS_MAC_FAILURE), not a
    # corrupted plaintext.
    try:
        decrypted = dec.decrypt_auth(encrypted)
        print(f"decrypted: {decrypted.decode()}")
    except itb.ITBError as e:
        if e.code == itb._ffi.STATUS_MAC_FAILURE:
            print("MAC verification failed — tampered or wrong key")
        else:
            raise

    # Streaming alternative — walk the chunk stream, decrypt_auth
    # each chunk; any tamper inside any chunk surfaces as
    # ITBError(STATUS_MAC_FAILURE) on that chunk.
    #from io import BytesIO
    #cin = BytesIO(encrypted)
    #pbuf = BytesIO()
    #accumulator = bytearray()
    #while True:
    #    buf = cin.read(64 * 1024)
    #    if not buf: break
    #    accumulator.extend(buf)
    #    while len(accumulator) >= dec.header_size:
    #        chunk_len = dec.parse_chunk_len(bytes(accumulator[:dec.header_size]))
    #        if len(accumulator) < chunk_len: break
    #        pbuf.write(dec.decrypt_auth(bytes(accumulator[:chunk_len])))
    #        del accumulator[:chunk_len]
    #decrypted = pbuf.getvalue()
```

## Quick Start — Mixed primitives (different PRF per seed slot)

`itb.Encryptor.mixed_single` and `itb.Encryptor.mixed_triple`
classmethods accept per-slot primitive names — the noise / data /
start (and optional dedicated lockSeed) seed slots can use
different PRF primitives within the same native hash width. The
mix-and-match-PRF freedom of the lower-level path, surfaced
through the high-level :class:`itb.Encryptor` without forcing
the caller off the Easy Mode constructor. The state blob carries
per-slot primitives + per-slot PRF keys; the receiver constructs
a matching encryptor with the same arguments and calls
``import_state`` to restore.

```python
# Sender

import itb

# Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
# Every name must share the same native hash width — mixing widths
# raise ITBError at construction time.
# Triple Ouroboros mirror — itb.Encryptor.mixed_triple takes seven
# per-slot names (noise + 3 data + 3 start) plus the optional
# primitive_l lockSeed.
enc = itb.Encryptor.mixed_single(
    primitive_n="blake3",       # noiseSeed:  BLAKE3
    primitive_d="blake2s",      # dataSeed:   BLAKE2s
    primitive_s="areion256",    # startSeed:  Areion-SoEM-256
    primitive_l="blake2b256",   # dedicated lockSeed (optional;
                                #   omit for no lockSeed slot)
    key_bits=1024,
    mac="hmac-blake3",
)
try:
    # Per-instance configuration applies as for itb.Encryptor(...).
    enc.set_nonce_bits(512)
    enc.set_barrier_fill(4)
    # BitSoup + LockSoup are auto-coupled on the on-direction by
    # primitive_l above; explicit calls below are unnecessary but
    # harmless if added.
    #enc.set_bit_soup(1)
    #enc.set_lock_soup(1)

    # Per-slot introspection — primitive returns "mixed" literal,
    # primitive_at(slot) returns each slot's name, is_mixed is the
    # typed predicate. Slot ordering is canonical: 0 = noiseSeed,
    # 1 = dataSeed, 2 = startSeed, 3 = lockSeed (Single); Triple
    # grows the middle range to 7 slots + lockSeed.
    print(f"mixed={enc.is_mixed} primitive={enc.primitive!r}")
    for i in range(4):
        print(f"  slot {i}: {enc.primitive_at(i)}")

    blob = enc.export()
    print(f"state blob: {len(blob)} bytes")

    plaintext = b"mixed-primitive Easy Mode payload"

    # Authenticated encrypt — 32-byte tag is computed across the
    # entire decrypted capacity and embedded inside the RGBWYOPA
    # container, preserving oracle-free deniability.
    encrypted = enc.encrypt_auth(plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Send encrypted payload + state blob
finally:
    enc.close()


# Receiver

import itb

# Receive encrypted payload + state blob
# encrypted = ...
# blob = ...

# Receiver constructs a matching mixed encryptor — every per-slot
# primitive name plus key_bits and mac must agree with the sender.
# import_state validates each per-slot primitive against the
# receiver's bound spec; mismatches raise ITBError with the
# "primitive" field tag.
dec = itb.Encryptor.mixed_single(
    primitive_n="blake3",
    primitive_d="blake2s",
    primitive_s="areion256",
    primitive_l="blake2b256",
    key_bits=1024,
    mac="hmac-blake3",
)
try:
    # Restore PRF keys, seed components, MAC key, and the per-
    # instance configuration overrides from the saved blob. Mixed
    # blobs carry mixed:true plus a primitives array; import_state
    # on a single-primitive receiver (or vice versa) is rejected as
    # a primitive mismatch.
    dec.import_state(blob)

    decrypted = dec.decrypt_auth(encrypted)
    print(f"decrypted: {decrypted.decode()}")
finally:
    dec.close()
```

## Quick Start — Areion-SoEM-512 (low-level, no MAC)

```python
# Sender

import itb

# Optional: global configuration (all process-wide, atomic)
itb.set_max_workers(8)        # limit to 8 CPU cores (default: 0 = all CPUs)
itb.set_nonce_bits(512)       # 512-bit nonce (default: 128-bit)
itb.set_barrier_fill(4)       # CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

itb.set_bit_soup(1)           # optional bit-level split ("bit-soup"; default: 0 = byte-level)
                              # automatically enabled for Single Ouroboros if
                              # itb.set_lock_soup(1) is enabled or vice versa

itb.set_lock_soup(1)          # optional Insane Interlocked Mode: per-chunk PRF-keyed
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

# Optional: dedicated lockSeed for the bit-permutation derivation
# channel. Separates that PRF's keying material from the noiseSeed-
# driven noise-injection channel without changing the public encrypt
# / decrypt signatures. The bit-permutation overlay must be engaged
# (itb.set_bit_soup(1) or itb.set_lock_soup(1) — both already on
# above) before the first encrypt; the build-PRF guard panics on
# encrypt-time when an attach is present without either flag.
ls = itb.Seed("areion512", 2048)  # random lock CSPRNG seeds + hash key generated
ns.attach_lock_seed(ls)

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

    # For cross-process persistence: itb.Blob512 packs every seed's
    # hash key + components and the captured process-wide globals
    # (nonce_bits / barrier_fill / bit_soup / lock_soup) into one
    # JSON blob — the Sender ships blob_bytes alongside the
    # ciphertext (or out-of-band). The receiver round-trips back
    # to working seeds via Blob512.import_blob below.
    with itb.Blob512() as blob:
        blob.set_key("n", ns.hash_key); blob.set_components("n", ns.components)
        blob.set_key("d", ds.hash_key); blob.set_components("d", ds.components)
        blob.set_key("s", ss.hash_key); blob.set_components("s", ss.components)
        blob.set_key("l", ls.hash_key); blob.set_components("l", ls.components)
        blob_bytes = blob.export(lockseed=True)
    print(f"persistence blob: {len(blob_bytes)} bytes")

    # Send encrypted payload + blob_bytes
finally:
    ns.free(); ds.free(); ss.free(); ls.free()


# Receiver

import itb

itb.set_max_workers(8)        # deployment knob — not serialised by Blob512

# Receive encrypted payload + blob_bytes
# encrypted = ...; blob_bytes = ...

# Blob512.import_blob applies the captured globals (nonce_bits /
# barrier_fill / bit_soup / lock_soup) via the process-wide setters
# AND populates per-slot hash keys + components. The Receiver does
# NOT need to set these four globals manually — the blob is the
# single source of truth for both the encryptor material and the
# runtime configuration that produced the ciphertext.
restored = itb.Blob512()
restored.import_blob(blob_bytes)

ns = itb.Seed.from_components("areion512", restored.get_components("n"), restored.get_key("n"))
ds = itb.Seed.from_components("areion512", restored.get_components("d"), restored.get_key("d"))
ss = itb.Seed.from_components("areion512", restored.get_components("s"), restored.get_key("s"))
ls = itb.Seed.from_components("areion512", restored.get_components("l"), restored.get_key("l"))
restored.free()
ns.attach_lock_seed(ls)

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
    ns.free(); ds.free(); ss.free(); ls.free()
```

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (low-level, authenticated)

```python
# Sender

import itb
import secrets

# Optional: global configuration (all process-wide, atomic)
itb.set_max_workers(8)        # limit to 8 CPU cores (default: 0 = all CPUs)
itb.set_nonce_bits(512)       # 512-bit nonce (default: 128-bit)
itb.set_barrier_fill(4)       # CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

itb.set_bit_soup(1)           # optional bit-level split ("bit-soup"; default: 0 = byte-level)
                              # automatically enabled for Single Ouroboros if
                              # itb.set_lock_soup(1) is enabled or vice versa

itb.set_lock_soup(1)          # optional Insane Interlocked Mode: per-chunk PRF-keyed
                              # bit-permutation overlay on top of bit-soup;
                              # automatically enabled for Single Ouroboros if
                              # itb.set_bit_soup(1) is enabled or vice versa

ns = itb.Seed("areion512", 2048)
ds = itb.Seed("areion512", 2048)
ss = itb.Seed("areion512", 2048)

# Optional: dedicated lockSeed for the bit-permutation derivation
# channel — same pattern as the no-MAC quick-start above.
ls = itb.Seed("areion512", 2048)
ns.attach_lock_seed(ls)

# HMAC-BLAKE3 — 32-byte CSPRNG key, 32-byte tag.
mac_key = secrets.token_bytes(32)
mac = itb.MAC("hmac-blake3", mac_key)

plaintext = b"any text or binary data - including 0x00 bytes"

try:
    # Authenticated encrypt — 32-byte tag is computed across the
    # entire decrypted capacity and embedded inside the RGBWYOPA
    # container, preserving oracle-free deniability.
    encrypted = itb.encrypt_auth(ns, ds, ss, mac, plaintext)
    print(f"encrypted: {len(encrypted)} bytes")

    # Cross-process persistence: itb.Blob512 packs every seed's
    # hash key + components, the optional dedicated lockSeed, and
    # the MAC key + name into one JSON blob alongside the captured
    # process-wide globals. lockseed=True / mac=True opt the
    # corresponding sections in.
    with itb.Blob512() as blob:
        blob.set_key("n", ns.hash_key); blob.set_components("n", ns.components)
        blob.set_key("d", ds.hash_key); blob.set_components("d", ds.components)
        blob.set_key("s", ss.hash_key); blob.set_components("s", ss.components)
        blob.set_key("l", ls.hash_key); blob.set_components("l", ls.components)
        blob.set_mac_key(mac_key); blob.set_mac_name("hmac-blake3")
        blob_bytes = blob.export(lockseed=True, mac=True)
    print(f"persistence blob: {len(blob_bytes)} bytes")

    # Send encrypted payload + blob_bytes
finally:
    mac.free()
    ns.free(); ds.free(); ss.free(); ls.free()


# Receiver

import itb

itb.set_max_workers(8)        # deployment knob — not serialised by Blob512

# Receive encrypted payload + blob_bytes
# encrypted = ...; blob_bytes = ...

# Blob512.import_blob restores per-slot hash keys + components AND
# applies the captured globals (nonce_bits / barrier_fill / bit_soup
# / lock_soup) via the process-wide setters.
restored = itb.Blob512()
restored.import_blob(blob_bytes)

ns = itb.Seed.from_components("areion512", restored.get_components("n"), restored.get_key("n"))
ds = itb.Seed.from_components("areion512", restored.get_components("d"), restored.get_key("d"))
ss = itb.Seed.from_components("areion512", restored.get_components("s"), restored.get_key("s"))
ls = itb.Seed.from_components("areion512", restored.get_components("l"), restored.get_key("l"))
ns.attach_lock_seed(ls)

mac = itb.MAC(restored.get_mac_name(), restored.get_mac_key())
restored.free()

try:
    # Authenticated decrypt — any single-bit tamper triggers MAC
    # failure (no oracle leak about which byte was tampered).
    decrypted = itb.decrypt_auth(ns, ds, ss, mac, encrypted)
    print(f"decrypted: {decrypted.decode()}")
finally:
    mac.free()
    ns.free(); ds.free(); ss.free(); ls.free()
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

## Benchmarks

A custom Go-bench-style harness lives under `easy/benchmarks/`
and covers the four ops (`encrypt`, `decrypt`, `encrypt_auth`,
`decrypt_auth`) across the nine PRF-grade primitives plus one
mixed-primitive variant for both Single and Triple Ouroboros at
1024-bit ITB key width and 16 MiB payload. See
[`easy/benchmarks/README.md`](easy/benchmarks/README.md) for
invocation / environment variables / output format and
[`easy/benchmarks/BENCH.md`](easy/benchmarks/BENCH.md) for
recorded throughput results across the canonical pass matrix.
