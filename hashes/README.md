# hashes — cached PRF-grade hash factories for ITB

Drop-in factories that produce `itb.HashFunc{128|256|512}` closures
for the nine PRF-grade primitives ITB ships with as built-in
factories for the C / FFI / mobile shared-library distribution.

Every factory pre-keys its primitive once at construction (random
fixed key from `crypto/rand`), reuses a `sync.Pool` of scratch
buffers, and is safe to call concurrently from multiple goroutines.
Without this caching, per-pixel hashing would re-key the underlying
primitive on every call — the dominant cost in ITB's encrypt /
decrypt path.

## Canonical primitives

In FFI-stable index order:

| # | Name (FFI) | Native width | itb type |
|---|---|---|---|
| 0 | `areion256` | 256 | `HashFunc256` (paired with `BatchHashFunc256`) |
| 1 | `areion512` | 512 | `HashFunc512` (paired with `BatchHashFunc512`) |
| 2 | `siphash24` | 128 | `HashFunc128` (uncached — pure function) |
| 3 | `aescmac` | 128 | `HashFunc128` (cached AES-NI block) |
| 4 | `blake2b256` | 256 | `HashFunc256` |
| 5 | `blake2b512` | 512 | `HashFunc512` |
| 6 | `blake2s` | 256 | `HashFunc256` |
| 7 | `blake3` | 256 | `HashFunc256` |
| 8 | `chacha20` | 256 | `HashFunc256` |

The order is FFI-stable; index 0..8 is exposed through
`ITB_HashName(idx)` in the shared library and re-ordering would
break the ABI.

## Usage

Native Go API — pick a factory directly:

```go
ns, _ := itb.NewSeed256(2048, hashes.BLAKE3())
ds, _ := itb.NewSeed256(2048, hashes.BLAKE3())
ss, _ := itb.NewSeed256(2048, hashes.BLAKE3())
encrypted, _ := itb.Encrypt256(ns, ds, ss, plaintext)
```

Name-keyed dispatch (used by the FFI layer; works for any code
that selects the primitive at runtime):

```go
h, _ := hashes.Make256("blake3")
ns, _ := itb.NewSeed256(2048, h)
```

Areion has paired (single, batched) constructors so the AVX-512
batched dispatch path is reachable:

```go
h, b := hashes.Areion256Pair()
seed, _ := itb.NewSeed256(2048, h)
seed.BatchHash = b
```

## Keyed variants

The pluggable PRF wrappers — `AESCMAC`, `BLAKE2b256`, `BLAKE2b512`,
`BLAKE2s`, `BLAKE3`, `ChaCha20` — each have a `WithKey` counterpart
accepting the primitive's native fixed-key length. These are
intended for serialization / deserialization of long-lived seeds
across processes — encrypt today, decrypt tomorrow.

`SipHash24` has no `WithKey` because the seed components themselves
are the entire SipHash key; serializing the seed components is
sufficient.

`Areion256Pair` and `Areion512Pair` likewise have no `WithKey`
counterpart in this package: they delegate to the in-package
`itb.MakeAreionSoEM{256,512}Hash` factories which generate a fresh
random fixed key on every call. Long-lived Areion seeds need a
persistence story added at the `itb` level (out of scope here).

## Below-spec primitives

CRC128, FNV-1a, MD5 — the lab stress controls used in REDTEAM.md
and SCIENCE.md to surface algebraic and broken-PRF leakage — are
intentionally absent. They are research instruments, not shippable
cipher primitives.
