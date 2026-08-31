# hashes — Cached PRF-grade hash factories for ITB

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

> **See [CONSTRUCTIONS.md](CONSTRUCTIONS.md) for the per-primitive construction descriptions.** Several wrappers diverge from the canonical RFC / NIST form of the underlying primitive in deliberate, documented ways — the registry names (`aescmac`, `chacha20`, `blake2b256`, ...) are short identifiers, not assertions of conformance with the RFC / NIST specification of the same name. Read CONSTRUCTIONS.md before assuming RFC compatibility.

Drop-in factories that produce `itb.HashFunc{128|256|512}` closures
for the PRF-grade primitives ITB ships with as built-in factories for
the C / FFI / mobile shared-library distribution.

Every factory pre-keys its primitive once at construction, reuses a
`sync.Pool` of scratch buffers, and is safe to call concurrently from
multiple goroutines. Without this caching, per-pixel hashing would
re-key the underlying primitive on every call — the dominant cost in
ITB's encrypt / decrypt path.

Each factory accepts a variadic optional fixed key:
- pass nothing → CSPRNG-generated key (returned alongside the closure
  for the caller to save — required for cross-process persistence);
- pass a saved key → restore-side reconstruction of the same closure.

`SipHash24` is the one exception: its keying material is the per-call
seed components themselves, so it has no internal fixed key and no
variadic key argument.

## Canonical primitives

In FFI-stable index order:

| # | Name (FFI) | Native width | itb type |
|---|---|---|---|
| 0 | `areion256` | 256 | `HashFunc256` (paired with `BatchHashFunc256`) |
| 1 | `areion512` | 512 | `HashFunc512` (paired with `BatchHashFunc512`) |
| 2 | `blake2b256` | 256 | `HashFunc256` |
| 3 | `blake2b512` | 512 | `HashFunc512` |
| 4 | `blake2s` | 256 | `HashFunc256` |
| 5 | `blake3` | 256 | `HashFunc256` |
| 6 | `aescmac` | 128 | `HashFunc128` (cached AES-NI block) |
| 7 | `siphash24` | 128 | `HashFunc128` (uncached — pure function) |
| 8 | `chacha20` | 256 | `HashFunc256` |

The order is FFI-stable; index 0..8 is exposed through
`ITB_HashName(idx)` in the shared library and re-ordering would
break the ABI.

## Custom user-primitive builders

Beyond the shipped primitives, the package exposes three builder families that wrap a user-supplied PRF into an `itb.HashFunc{128|256|512}` closure **with correct ITB nonce width preservation by construction**. These are for "I want to plug in SHA-256 / Ascon-PRF / Camellia-CMAC / My Own Custom hash primitive as the ITB PRF" use cases.

| Builder | Wraps | Use when |
|---|---|---|
| `BuildCBCMACChainAbsorb{128,256,512}` | `crypto/cipher.Block` (caller-keyed) | Caller has a block cipher (AES, Camellia, ARIA, SM4, ...) and wants CBC-MAC chain-absorb |
| `BuildSpongeChainAbsorb{128,256,512}` | `Permute` + `(rate, capacity, fixedKey)` | Caller has an unkeyed permutation (Keccak-f, Ascon-PRF, ...) and wants a keyed sponge |
| `BuildARXChainAbsorb{128,256,512}` | `Hash256Fn` / `Hash512Fn` (full hash one-shot) | Caller has a full hash function (SHA-256, SM3, SHA-512, ...) and wants safe absorption |

**Why these matter for ITB security.** ITB supports nonce widths of 128, 256 or 512 bits via `Config.NonceBits` (threaded through any Cfg-suffixed entry point). The per-call buffer presented to a `HashFunc` closure carries a domain-tag byte plus the configured nonce material — 20, 36, or 68 bytes for the three nonce widths respectively. Every byte of the `data` parameter must reach the digest for ITB's advertised nonce strength to hold.

A naive user-written wrapper can silently truncate the ITB nonce in several ways:

- **`crypto/sha256.Sum256(data)` wrapped naively into `HashFunc512`** — SHA-256 output is 32 bytes; the upper 32 bytes of any returned `[8]uint64` get zero-padded by naive repacking. ChainHash's per-call XOR-chain consumes the full 64-byte intermediate state, so a constant upper half across calls destroys half the entropy.
- **`aes.NewCipher(key).Encrypt(iv, plaintext)` with the ITB nonce as `iv`** — AES IV is 16 bytes regardless of how long the ITB nonce is. `Config.NonceBits=512` → effective 128-bit nonce. The advertised property is broken silently.
- **`chacha20.NewUnauthenticatedCipher(key, nonce)` with the ITB nonce as `nonce`** — ChaCha20 nonce slot is 12 bytes. Same trap.

The builders sidestep all three traps by construction: the user supplies the primitive in its natural form, the builder absorbs the full `data` parameter through the appropriate chain pattern, the resulting closure preserves the full ITB nonce width by construction. No caller-side knowledge of the chain-absorb pattern is required.

### When the builder is required vs optional

The builders close the silent-truncation trap **constructively**, but they are not always strictly required. A user primitive is safely pluggable as a hand-written closure **without** a builder when **both** of these hold:

1. The primitive has **native variable-length absorb** (Merkle-Damgard tree like BLAKE3, MD chaining like SHA-256/512, sponge with internal absorb loop like Keccak/Ascon — i.e. the primitive's own API accepts arbitrary input length and processes every byte).
2. The primitive's **native output width is at least the required HashFunc width** (32 bytes for `HashFunc256`, 64 bytes for `HashFunc512`).

The custom-primitive pattern in the main repo [README — "Custom user-supplied primitives"](../README.md#custom-user-supplied-primitives) is the canonical reference for this case: BLAKE3 via `blake3.NewKeyed` + `h.Write(mixed)` satisfies both conditions, so all four seed components are XOR'd into a zero-padded data buffer that BLAKE3 absorbs natively. No chain-absorb needed. The same pattern transfers to BLAKE2b/2s, SHA-256 (for HashFunc256), SHA-512 (for HashFunc512), KangarooTwelve, etc.

A user primitive **requires** a builder when **at least one** of these holds:

1. **Output-width upscaling**: primitive native output is narrower than the required HashFunc width. SHA-256 (32 bytes) → `HashFunc512` (64 bytes) is the classic trap — naive zero-padding of the upper half destroys half the intermediate-state entropy. The builder calls the underlying hash twice with domain separation to fill the full output width safely.
2. **No native variable-length absorb**: primitive only handles fixed-width input in isolation. Raw `cipher.Block` (16-byte block), raw permutation function (320-bit Ascon-p state), block cipher used as a primitive rather than via a higher-level AEAD wrapper. The CBC-MAC or sponge builder constructs the chain externally so all input bytes reach the digest.
3. **Defence against caller-side mistakes**: even when (1) and (2) of the "safe handwritten" conditions hold, a builder removes the opportunity to forget seed-component XOR or output-width matching. Useful for casual users / quick experiments / audit-friendly code.

| Scenario | Builder required? | Why |
|---|---|---|
| BLAKE3 → `HashFunc256` (handwritten via `Write`) | No | Native variable-length absorb + native output 32 B matches |
| BLAKE2b → `HashFunc{256,512}` (handwritten via `Sum`) | No | Same — native variable-length absorb, output width matches |
| SHA-256 → `HashFunc256` | No (but builder simplifies) | Native MD absorb + 32 B output matches; builder still removes seed-injection responsibility |
| SHA-256 → `HashFunc512` | **Yes** | Output-width upscaling — without builder, upper 32 B silently zero-padded |
| SHA-512 → `HashFunc512` | No (but builder simplifies) | Native MD absorb + 64 B output matches |
| AES block cipher → `HashFunc{128,256,512}` | **Yes** | Raw block cipher has no native variable-length absorb |
| Ascon-p / Keccak-f (raw permutation) → `HashFunc{128,256,512}` | **Yes** | Raw permutation has no native variable-length absorb; sponge wrapper needed externally |
| Camellia / SM4 / ARIA block cipher | **Yes** | Same as AES — raw block cipher needs CBC-MAC chain |

### Example — SHA-256 via the ARX builder

```go
import (
    "crypto/rand"
    "crypto/sha256"

    "github.com/everanium/itb"
    "github.com/everanium/itb/hashes"
)

func main() {
    // Long-lived fixed key (persist alongside ITB seeds for cross-process restore).
    var fixedKey [32]byte
    if _, err := rand.Read(fixedKey[:]); err != nil {
        panic(err)
    }

    // SHA-256 wrapped safely. The builder folds {fixedKey, seed,
    // length, domain} into the absorb buffer so the full ITB nonce
    // (up to 64 bytes for Config.NonceBits=512) reaches the digest.
    sha256Hash := hashes.BuildARXChainAbsorb256(sha256.Sum256, fixedKey[:])

    // Build the 8-seed constellation. Each seed uses the same wrapped
    // SHA-256 closure here for brevity; in production the 8 seeds
    // may use independent primitives from the hashes registry.
    cfg := &itb.Config{NonceBits: 512, BarrierFill: 4}
    noise, _ := itb.NewSeed256(1024, sha256Hash)
    lock,  _ := itb.NewSeed256(1024, sha256Hash)
    data1, _ := itb.NewSeed256(1024, sha256Hash)
    data2, _ := itb.NewSeed256(1024, sha256Hash)
    data3, _ := itb.NewSeed256(1024, sha256Hash)
    start1, _ := itb.NewSeed256(1024, sha256Hash)
    start2, _ := itb.NewSeed256(1024, sha256Hash)
    start3, _ := itb.NewSeed256(1024, sha256Hash)

    plaintext := []byte("hello SHA-256 via ITB builder")
    ct, _ := itb.Encrypt3x256Cfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, plaintext)
    pt, _ := itb.Decrypt3x256Cfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, ct)

    _ = pt // round-trip; bit-exact recovery of plaintext.
}
```

The same pattern works for any 32-byte hash. `SM3` swap-in: substitute `sha256.Sum256` with `func(d []byte) [32]byte { return sm3.Sum(d) }` (using any SM3 implementation that exposes a one-shot 32-byte digest). For 64-byte digests like SHA-512, use `BuildARXChainAbsorb512(sha512.Sum512, fixedKey[:])`.

### Performance note for builders

Builders dispatch through interface callbacks (`cipher.Block.Encrypt`) and `[]byte` state buffers, costing 5-15% throughput vs the inline per-primitive closures shipped here (`aescmac.go`, `chacha20.go`, ...). The built-in closures use stack-allocated fixed-size state arrays (`var state [32]byte`), inlined permutation calls, and `unsafe.Pointer` escape-analysis tricks. The builders are intentionally simpler — they target correctness-by-construction for user primitives, not peak throughput. Callers who need both correctness **and** peak throughput for a specific primitive write a dedicated closure following the `hashes/*.go` patterns.

`BatchHash` (4-pixel batched SIMD asm) is **not** provided by these builders — the batched arm is inherently primitive-specific (VAES for AES, multi-buffer SHA-NI for SHA-256, etc.) and cannot be templated. Seeds constructed from builder closures leave `BatchHash = nil`, which makes ITB fall back silently to the per-pixel scalar loop (`process_generic.go`). Correctness is preserved; throughput on AVX-512 hosts is left on the table.

## Runtime primitive selection

A user primitive is pluggable at the Low-Level surface in two shapes:

- **Closure-directly-passed.** Construct the `itb.HashFunc{N}` (and optional `itb.BatchHashFunc{N}`) closures — for instance via the builders above — and pass the resulting `*itb.Seed{N}` handles through the Cfg-suffixed entry points. Nothing is registered; only the caller holds a reference to the primitive.
- **Registered by name via `hashes.Register(spec Spec) error`.** The custom primitive gains a canonical name that the `hashes.Find` / `hashes.Make{N}` / `hashes.Make{N}Pair` dispatchers resolve alongside shipped entries. The registration is process-wide, appended after the shipped Registry in `hashes.AllPrimitives`, and immutable — a second `Register(sameName)` returns `hashes.ErrHashExists`. The Spec is validated on entry (non-empty lowercase-alphanumeric-plus-underscore name capped at `hashes.MaxNameLen = 12` characters, `Width` of W128 / W256 / W512, exactly one `Make{N}Pair` factory field matching the Width). The 12-char cap matches `parallax.MaxCipherNameLen` so a registered primitive that a caller later plugs into a parallax palette entry fits the `"<name>:<index>"` derivation label inside a 16-byte 128-bit-PRF input block.

```go
import (
    "crypto/sha256"

    "github.com/everanium/itb"
    "github.com/everanium/itb/hashes"
)

func init() {
    // One-shot at process init. The factory follows the same
    // variadic-key contract as the shipped Make{N}Pair functions:
    // no key argument for a fresh random key, one 32-byte []byte
    // for explicit-key restoration.
    factory := func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
        var fixedKey [32]byte
        if len(key) > 0 {
            copy(fixedKey[:], key[0])
        } // else fill from crypto/rand.Read(fixedKey[:])
        h := hashes.BuildARXChainAbsorb256(sha256.Sum256, fixedKey[:])
        return h, nil, fixedKey[:], nil
    }
    _ = hashes.Register(hashes.Spec{
        Name:        "sha256_arx",
        Width:       hashes.W256,
        Make256Pair: factory,
    })
}

// Elsewhere — the registered name resolves through the standard
// name-keyed dispatcher exactly like a shipped primitive.
h, _, keyBytes, _ := hashes.Make256Pair("sha256_arx")
seed, _ := itb.NewSeed256(1024, h)
_ = keyBytes // persist alongside the seed for cross-process restore
_ = seed
```

The shipped `Registry` itself is immutable — user entries live in a separate mutex-guarded slice — so the FFI iteration surface (`ITB_HashName` / `ITB_HashWidth`) is unaffected by runtime registrations. `hashes.Register` is a Go-native API only. Bindings are triple-only and do not expose custom-primitive plug; a binding caller who needs a custom PRF wires the Go-native surface directly.

The `triple.Pipeline` facade selects primitives by name from `hashes.Find`, so a registered primitive is reachable through `triple.Init(profile, opts)` provided the profile's chosen inner-hash name resolves to the registered Spec. Custom primitives supplied directly as closures do not appear in `Find` and are not reachable through the Pipeline facade; use either the Register path or the Low-Level `*Cfg` entry points depending on which shape the surrounding call site prefers.

## Usage

Native Go API — the 8-seed Triple constellation is instantiated once per shipped hash primitive factory and threaded through `itb.Encrypt3xNNNCfg` / `itb.Decrypt3xNNNCfg` (or the authenticated / streaming counterparts). Cross-process persistence is via `itb.Blob{128,256,512}` — each `Blob*.Export3Cfg` packs the per-seed hash keys, `Components`, dedicated lockSeed, optional MAC key, and captured `*itb.Config` into a self-describing JSON blob; the receiver rebuilds the constellation via `Blob{N}.Import3Cfg` followed by per-slot factory rewiring.

Areion-SoEM-512 with the shipped paired (single, batched, fixedKey) constructor:

```go
package main

import (
    "fmt"

    "github.com/everanium/itb"
    "github.com/everanium/itb/hashes"
)

func main() {
    cfg := &itb.Config{
        NonceBits:   512,
        BarrierFill: 4,
        MaxWorkers:  8, // 0 (default) uses every available CPU
    }

    // The 48-bit Interlocked Barrier overlay is always engaged for
    // Triple Ouroboros and non-disableable by construction. The eight
    // seeds carry (noise, lock, data1..3, start1..3) — each with its
    // own independent hash-key + Components.
    fnN, batchN, keyN := hashes.Areion512Pair()
    fnL, batchL, keyL := hashes.Areion512Pair()
    fnD1, batchD1, keyD1 := hashes.Areion512Pair()
    fnD2, batchD2, keyD2 := hashes.Areion512Pair()
    fnD3, batchD3, keyD3 := hashes.Areion512Pair()
    fnS1, batchS1, keyS1 := hashes.Areion512Pair()
    fnS2, batchS2, keyS2 := hashes.Areion512Pair()
    fnS3, batchS3, keyS3 := hashes.Areion512Pair()

    ns, _ := itb.NewSeed512(2048, fnN); ns.BatchHash = batchN
    ls, _ := itb.NewSeed512(2048, fnL); ls.BatchHash = batchL
    d1, _ := itb.NewSeed512(2048, fnD1); d1.BatchHash = batchD1
    d2, _ := itb.NewSeed512(2048, fnD2); d2.BatchHash = batchD2
    d3, _ := itb.NewSeed512(2048, fnD3); d3.BatchHash = batchD3
    s1, _ := itb.NewSeed512(2048, fnS1); s1.BatchHash = batchS1
    s2, _ := itb.NewSeed512(2048, fnS2); s2.BatchHash = batchS2
    s3, _ := itb.NewSeed512(2048, fnS3); s3.BatchHash = batchS3

    plaintext := []byte("any text or binary data - including 0x00 bytes")

    encrypted, err := itb.Encrypt3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
    if err != nil {
        panic(err)
    }
    fmt.Printf("encrypted: %d bytes\n", len(encrypted))

    // Cross-process persistence — Blob512 packs every seed's [64]byte
    // hash key + Components plus the captured *itb.Config into one
    // self-describing JSON blob. The lockSeed slot rides in the
    // trailing Blob512Opts.
    bSrc := &itb.Blob512{}
    blob, _ := bSrc.Export3Cfg(cfg, keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
        ns, d1, d2, d3, s1, s2, s3,
        itb.Blob512Opts{KeyL: keyL, LS: ls})
    _ = blob // ship alongside the ciphertext
}
```

`Blob{N}.Import3Cfg` on the receiver restores per-slot hash keys + Components AND returns the captured `*itb.Config`. `Hash` / `BatchHash` on each restored seed stay nil so the caller wires them from the saved `Key*` bytes through the matching factory (`Areion512PairWithKey` / `BLAKE2b512PairWithKey` / etc.). See the `itb.Blob512` doc-comment for the receiver-side wiring pattern.

SipHash-2-4 has no internal fixed key — the paired (single, batched) constructor returns a 2-tuple without a key element; the caller passes `nil` for every `KeyN..KeyS3` argument when exporting via `Blob128.Export3Cfg`. BLAKE2b-512, BLAKE3, AES-CMAC, ChaCha20, and the remaining registry primitives all follow the shipped paired-factory shape used above.

Name-keyed dispatch (used by the FFI layer; works for any code that
selects the primitive at runtime). Same variadic key pattern, but key
is `[]byte` (size validated against the primitive's native length):

```go
fn, hashKey, _ := hashes.Make256("blake3") // random
fn, _, _       := hashes.Make256("blake3", saved) // explicit
```

## High-level facade — `triple.Pipeline`

Callers who want the 8-seed constellation, MAC, parallax layer, and outer cipher wrapper composed for them in one step use the [`triple.Pipeline`](../triple/) facade. `triple.Init(profileName, opts)` allocates the full stack around one primitive selected by name from the registry above; the [top-level ITB README](https://github.com/everanium/itb#readme) hosts the canonical Pipeline examples across the four cipher shapes (Single Message MAC / Single Message No MAC / Streaming AEAD / Streaming Non-AEAD).

## Keyed variants

Every cached factory ships a paired `*WithKey` form that takes the
fixed key as a single non-variadic argument and returns just the
closure (no key tuple element):

| variadic-short                | explicit `WithKey`              |
|-------------------------------|---------------------------------|
| `Areion256Pair(...key)`       | `Areion256PairWithKey(key)`     |
| `Areion512Pair(...key)`       | `Areion512PairWithKey(key)`     |
| `BLAKE2s(...key)`             | `BLAKE2sWithKey(key)`           |
| `BLAKE2b256(...key)`          | `BLAKE2b256WithKey(key)`        |
| `BLAKE2b512(...key)`          | `BLAKE2b512WithKey(key)`        |
| `BLAKE3(...key)`              | `BLAKE3WithKey(key)`            |
| `AESCMAC(...key)`             | `AESCMACWithKey(key)`           |
| `ChaCha20(...key)`            | `ChaCha20WithKey(key)`          |

The variadic short form delegates to `WithKey` (Go inliner removes
the wrapper at compile time), so semantics are identical. Either
reads cleanly at the call site — the two are interchangeable:

- **variadic** when the same call site handles both random-key and
  explicit-key paths (e.g. a config-driven factory that defaults to
  random when no key is in the config);
- **`WithKey`** when the call site is unambiguously explicit-key
  (restore path with the key already in scope) and the bare key
  return value would be redundant noise.

`SipHash24` has no `WithKey` because the seed components themselves
are the entire SipHash key; serializing the seed components is
sufficient.
