# macs — Cached PRF-grade MAC factories for ITB Authenticated Encryption

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

> **See [CONSTRUCTIONS.md](CONSTRUCTIONS.md) for the per-MAC construction descriptions.** Two names are exact (`kmac256` per NIST SP 800-185, `hmac-sha256` per RFC 2104); `hmac-blake3` is BLAKE3 native keyed mode, **not** RFC 2104 HMAC — the `hmac-` name is kept for registry symmetry with `hmac-sha256` and for FFI stability. Read CONSTRUCTIONS.md before assuming a particular standard's exact construction.

Drop-in factories that produce `itb.MACFunc` closures for the three
shipped MAC primitives. All three produce a 32-byte tag and accept
a 32-byte (or longer for the HMAC variants) key. The fixed 32-byte
tag size lets bindings size their authenticated payload buffer the
same way regardless of which MAC was selected.

Every factory pre-keys its primitive once at construction and is
safe to call concurrently from multiple goroutines.

## Canonical primitives

In FFI-stable index order:

| # | Name (FFI)    | Key size | Tag size | Caching |
|---|---------------|---------:|---------:|---------|
| 0 | `kmac256`     | ≥16 B    | 32 B     | cSHAKE256 template with key absorbed once, `Clone()` per call |
| 1 | `hmac-sha256` | ≥16 B    | 32 B     | `sync.Pool` of `hmac.New(sha256.New, key)` instances |
| 2 | `hmac-blake3` | 32 B     | 32 B     | `blake3.NewKeyed(key)` template with `Clone()` per call |

`kmac256` follows NIST SP 800-185 with output length L = 256 bits.
`hmac-sha256` follows RFC 2104 with SHA-256. `hmac-blake3` uses
BLAKE3's native keyed mode (no nested HMAC wrapper — BLAKE3-keyed
is itself a sound keyed PRF; see BLAKE3 spec section 6).

## Usage

Native Go API — the 8-seed Triple constellation is instantiated once per shipped hash primitive factory and threaded through `itb.EncryptAuthenticated3xNNNCfg` / `itb.DecryptAuthenticated3xNNNCfg` (or the streaming counterparts) alongside the `itb.MACFunc` returned by one of the factories in this package. Cross-process persistence is via `itb.Blob{128,256,512}` — `Blob*.Export3Cfg` packs the per-seed hash keys, `Components`, dedicated lockSeed, MAC key, and captured `*itb.Config` into a self-describing JSON blob; the receiver rebuilds the constellation via `Blob{N}.Import3Cfg` followed by per-slot factory rewiring + `macs.Make(blob.MACName, blob.MACKey)`.

Areion-SoEM-512 paired with HMAC-BLAKE3 — the fastest AVX-512 hash + MAC combination:

```go
package main

import (
    "crypto/rand"
    "fmt"

    "github.com/everanium/itb"
    "github.com/everanium/itb/hashes"
    "github.com/everanium/itb/macs"
)

func main() {
    cfg := &itb.Config{
        NonceBits:   512,
        BarrierFill: 4,
        MaxWorkers:  8, // 0 (default) uses every available CPU
    }

    // Eight independent CSPRNG-keyed Areion-SoEM-512 paired closures
    // (noise, lock, data1..3, start1..3). Each Pair returns
    // (single, batched, [64]byte fixedKey). The 48-bit Interlocked
    // Barrier overlay is always engaged for Triple Ouroboros and
    // non-disableable by construction.
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

    // HMAC-BLAKE3 — fastest of the three MACs through the AVX-512 ASM kernel.
    var macKey [32]byte
    if _, err := rand.Read(macKey[:]); err != nil {
        panic(err)
    }
    mac, _ := macs.HMACBLAKE3(macKey[:])

    plaintext := []byte("any text or binary data - including 0x00 bytes")

    // Authenticated encrypt — 32-byte tag is computed across the entire
    // decrypted capacity and embedded inside the RGBWYOPA container,
    // preserving oracle-free deniability.
    encrypted, err := itb.EncryptAuthenticated3x512Cfg(cfg,
        ns, ls, d1, d2, d3, s1, s2, s3, plaintext, mac)
    if err != nil {
        panic(err)
    }
    fmt.Printf("encrypted: %d bytes\n", len(encrypted))

    // Cross-process persistence — Blob512 packs every seed's [64]byte
    // hash key + Components AND the MAC key + name into one self-
    // describing JSON blob alongside the captured *itb.Config. The
    // lockSeed slot rides in the trailing Blob512Opts.
    bSrc := &itb.Blob512{}
    blob, _ := bSrc.Export3Cfg(cfg, keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
        ns, d1, d2, d3, s1, s2, s3,
        itb.Blob512Opts{KeyL: keyL, LS: ls, MACKey: macKey[:], MACName: "hmac-blake3"})
    _ = blob // ship alongside the ciphertext
}
```

On the receiver, `Blob512.Import3Cfg` restores per-slot hash keys + Components + the MAC key + name AND returns the captured `*itb.Config`. `Hash` / `BatchHash` on each restored seed stay nil so the caller wires them from the saved `Key*` bytes through the matching factory (`Areion512PairWithKey`), then rebuilds the MAC via `macs.Make(bDst.MACName, bDst.MACKey)` and decrypts with `itb.DecryptAuthenticated3x512Cfg`.

BLAKE2b-512 paired with HMAC-SHA256 (universal interoperability standard, RFC 4231) follows the same shape — swap `hashes.Areion512Pair()` for `hashes.BLAKE2b512Pair()`, swap the MAC factory for `macs.HMACSHA256(macKey[:])`, and keep the rest identical. SipHash-2-4 has no internal fixed key (the seed components are the entire SipHash key), so its paired constructor `hashes.SipHash24Pair()` returns just `(single, batched)`; every `Key*` argument passed to `Blob128.Export3Cfg` is a zero `[16]byte`.

Name-keyed dispatch (used by the FFI layer; works for any code that
selects the MAC primitive at runtime). The key is `[]byte` (size
validated against the primitive's minimum / fixed length):

```go
mac, _ := macs.Make("hmac-sha256", key)
```

Every shipped MAC additionally provides an incremental constructor
(`KMAC256Incremental` / `HMACSHA256Incremental` / `HMACBLAKE3Incremental`,
name-keyed via `macs.MakeIncremental`) returning an
`itb.MACIncrementalFunc` — the multi-slice arm accepting the MAC input
as ordered chunks. The authenticated entry points consume it through
`itb.Config.MACIncremental` to skip the payload-concatenation copy;
the tag is byte-for-byte identical to the `itb.MACFunc` over the
concatenation (pinned per primitive by a 100-fixture parity test).
`MACFunc` remains the primary type; the incremental arm is additive.

`KMAC256` has a `WithCustomization` counterpart for domain
separation across distinct usages of the same key. `HMAC-SHA256`
and `HMAC-BLAKE3` take the key as their only argument — there is
no separate `WithKey` variant since the key is already the only
state the factory holds.

On amd64 hosts with the AVX-512 F/BW/VL/DQ baseline, `KMAC256`
routes through a vendored AVX-512 Keccak-f[1600] kernel in
`macs/internal/keccakasm/` (Tier A only; other hosts and
`-tags noitbasm` builds keep the stdlib-backed scalar cSHAKE256).
Both tiers produce byte-identical tags — pinned by a 200-fixture
parity oracle and the bit-exact KAT.

## High-level facade — `triple.Pipeline`

Callers who want the 8-seed constellation, MAC, parallax layer, and outer cipher wrapper composed for them in one step use the [`triple.Pipeline`](../triple/) facade. `triple.Init(profileName, opts)` allocates the full stack around one primitive selected by name; the MAC choice rides in `triple.Opts.MacName` (defaults to `hmac-blake3`). The [top-level ITB README](https://github.com/everanium/itb#readme) hosts the canonical Pipeline examples across the four cipher shapes (Single Message MAC / Single Message No MAC / Streaming AEAD / Streaming Non-AEAD).

## Why these three

ITB's MAC-Inside-Encrypt construction places the 32-byte tag inside
the encrypted container. The barrier dispersal
(`process128 / 256 / 512`) destroys the plaintext / tag boundary an
attacker could otherwise observe; the always-on 48-bit Interlocked
Barrier overlay further obscures the payload region. So the MAC
primitive itself only has to be a sound keyed PRF — the surrounding
ITB construction handles placement-hiding, replay-resistance
(per-message nonce), and CCA-resistance.

Three primitives keep the choice tractable:

- **`kmac256`** — modern NIST-standard keyed XOF (SP 800-185), based
  on the well-vetted Keccak permutation. But slowest.
- **`hmac-sha256`** — universal interoperability standard,
  hardware-accelerated through SHA-NI on amd64 / arm64 where the
  underlying CPU exposes the SHA-256 round instructions.
- **`hmac-blake3`** — fastest of the three through BLAKE3's
  AVX-512 ASM kernel.

## Validation

- `hmac-sha256` is bit-exactly cross-checked against
  RFC 4231 test vectors in `macs_test.go`.
- `hmac-blake3` rests on the upstream `github.com/zeebo/blake3`
  project's own keyed-mode KAT.
- `kmac256` is bit-exactly cross-checked against four KAT
  vectors generated from pycryptodome 3.23.0
  (`Crypto.Hash.KMAC256`, an audited NIST SP 800-185 reference
  implementation): three are L = 256 analogues of NIST SP 800-185
  Annex A samples 4 / 5 / 6 (sample 4 message
  `00 01 02 03`, sample 5 with customization
  `My Tagged Application`, sample 6 with the 200-byte
  `0x00..0xC7` message), plus a degenerate empty-message case.
  Reproduce via the python snippet shown in the test file.
- All three primitives pass `TestITBAuthIntegration` (3 MACs × 3
  hash widths × encrypt/decrypt round trip + bit-flip tamper
  rejection).

## User-pluggable custom MACs

`macs.Register` adds a user-supplied custom MAC primitive to the
runtime registry under a caller-chosen name. A registered primitive
resolves through `Find` / `Make` / `MakeIncremental` / `MakeMACPair`
exactly like a shipped one and — transitively — through every consumer
that resolves MACs by name, including `triple.Profile.MacName` and the
`triple.Opts.MacName` override. The shipped `Registry` array is not
extended — user entries live in a separate mutex-guarded store — so
the FFI iteration surface (`ITB_MACCount` / `ITB_MACName`) is
unaffected.

### Spec fields and validation

```go
type Spec struct {
    Name        string // [a-z0-9_]{1,12} for custom entries
    KeySize     int    // recommended key size; ≥ MinKeyBytes
    TagSize     int    // constant tag length in bytes; in [16, 64]
    MinKeyBytes int    // minimum acceptable key length; ≥ 16
    MakeMAC            func(key []byte) (itb.MACFunc, error)            // required
    MakeIncrementalMAC func(key []byte) (itb.MACIncrementalFunc, error) // optional
}
```

`Register(spec Spec) error` validates:

- **Name** — non-empty, lowercase letters / digits / underscores only
  (no dashes), at most `macs.MaxNameLen = 12` bytes; not already
  present in the shipped `Registry` or among prior registrations
  (`macs.ErrMACExists`, shipped-name shadowing included).
- **Sizes** — `KeySize ≥ MinKeyBytes ≥ 16` and `TagSize` in
  `[16, 64]`. The tag size is variable per Spec: the Low-Level
  authenticated paths probe the closure's tag length at construction,
  so a custom primitive is not bound to the shipped 32-byte tag. The
  ceiling covers the longest realistic MAC tag (64 bytes, e.g.
  HMAC-SHA-512) and keeps the range symmetric with the wire-shape
  pinning knobs, so every registrable tag length has a pinnable
  No MAC stub. The No MAC
  envelope's stub reservation adapts to the tag size as well: a
  MAC-carrying `triple.Pipeline` probes its profile's MAC tag length
  at construction and populates `itb.Config.TagStubSize`
  automatically, so envelope-shape indistinguishability between the
  authenticated and No MAC paths holds for any registered `TagSize`
  across both the Single Message and Streaming pipelines. Pairing a
  No MAC surface with a custom-tag-size authenticated peer pins the
  stub explicitly — see the wire-shape pinning subsection below.
- **Factories** — `MakeMAC` non-nil. `MakeIncrementalMAC` is
  optional: when nil, `Register` synthesizes a concatenate-then-MAC
  wrapper around `MakeMAC` (byte-for-byte equivalent per the
  `itb.MACIncrementalFunc` contract, at one concat copy per call).
- **Smoke validation** — both arms are built with a throwaway random
  key of `KeySize` bytes and probed before the Spec is accepted:
  tag length on two input lengths, determinism across repeated
  calls, and cross-arm equivalence on a fixed two-chunk split. Contract violations fail registration loudly instead of
  corrupting authenticated containers at encrypt time.

Registration is process-wide, append-only, and immutable — a name
cannot be re-registered, so a downstream `Find` / `Make` caller can
never observe a silently swapped factory. `Register` is safe for
concurrent use with itself and with the dispatchers.

### Wire-shape pinning across the API layers

The No MAC envelope reserves a CSPRNG dummy stub sized to a MAC tag
length so a wire observer cannot distinguish the No MAC envelope from
its MAC-carrying counterpart. The zero-value default reserves for a
32-byte tag, matching every shipped MAC; pairing with a
custom-tag-size MAC pins the stub explicitly at whichever layer the
No MAC side is driven from:

- **`itb.Config.TagStubSize`** (Low-Level) — a No MAC caller on the
  `Encrypt3x{N}Cfg` / `EncryptStream3x{N}Cfg` surface sets the field
  to the peer's MAC tag length.
- **`triple.Profile.TagStubSize`** (custom profile registration) — a
  registered No MAC profile carries the pin as part of its shape, so
  every Pipeline built against it inherits the reservation.
- **`triple.Opts.TagStubSize`** (per-instance override) — overrides
  the profile default at `triple.Init` time.

Resolution order per Pipeline: Opts > Profile > MacName auto-probe >
32-byte default. Accepted values at every layer: 0 (defer) or
16..64 inclusive — the floor matches the `Register` TagSize ≥ 16
constraint, the ceiling covers the longest realistic MAC tag;
out-of-range values are rejected fail-fast. MAC-carrying profiles
need no pinning — the tag length is probed from the profile's MAC
automatically.

Example — a custom No MAC profile paired with a custom 16-byte-tag
MAC AEAD profile, wire-shape aligned:

```go
// Hand-rolled 16-byte-tag Spec (the builders emit full-width tags;
// a truncated tag needs a caller-written factory).
_ = macs.Register(macs.Spec{
    Name: "tag16mac", KeySize: 32, TagSize: 16, MinKeyBytes: 16,
    MakeMAC: func(key []byte) (itb.MACFunc, error) {
        k := append([]byte(nil), key...)
        return func(data []byte) []byte {
            h := hmac.New(sha256.New, k)
            h.Write(data)
            return h.Sum(nil)[:16]
        }, nil
    },
})

_ = triple.Register("acme-aead-tag16-v1", triple.Profile{
    Mode: "singlemsg-mac", Width: 512, InnerHash: "areion512",
    KeyBits: 1024, MacName: "tag16mac",
    OuterCipher: "chacha20",
    ParallaxPalette: []string{"aescmac", "chacha20", "blake3"},
    Parallax: true, Wrapper: true,
})
_ = triple.Register("acme-nomac-tag16-v1", triple.Profile{
    Mode: "singlemsg-nomac", Width: 512, InnerHash: "areion512",
    KeyBits: 1024,
    TagStubSize: 16, // pin the stub to the paired profile's tag length
    OuterCipher: "chacha20",
    ParallaxPalette: []string{"aescmac", "chacha20", "blake3"},
    Parallax: true, Wrapper: true,
})
```

Messages of equal plaintext length produced under the two profiles
emit byte-count-equal wires across both the Single Message and
Streaming pipelines.

### Closure contracts

Every registered factory must honour the contracts the shipped
factories honour (the builders below satisfy all of them by
construction):

- **Determinism** — same key + same input → same tag, byte-for-byte.
  Decrypt recomputes the tag and compares; a randomized construction
  always fails verification.
- **Constant tag length** — exactly `TagSize` bytes on every call,
  independent of input length. The authenticated container is sized
  from the probed tag length; an input-dependent length corrupts it.
- **Cross-arm equivalence** — `incremental(a, b, c)` equals
  `single(concat(a, b, c))` byte-for-byte over any chunk split,
  whether the incremental arm is user-provided or synthesized.
- **Parallel-safety** — concurrent goroutines may call the returned
  closures simultaneously.
- **Fresh output slice** — every call returns a newly allocated tag,
  never a shared buffer; a shared buffer corrupts under the
  parallel-thirds encrypt path.

### Builders

Two builders produce a `Spec` ready for `Register` from a
hash-registry primitive name. The name resolves through
`hashes.Find`, so shipped primitives and user-registered custom
primitives added via `hashes.Register` qualify uniformly:

- **`BuildHMAC(hashName string, spec HMACSpec) (Spec, error)`** —
  wraps the primitive's unkeyed `hash.Hash` form in the HMAC
  construction (RFC 2104 / FIPS 198-1). Available for the primitives
  exposing a general-purpose `hash.Hash` form (among the shipped
  entries, the BLAKE family). Keys of arbitrary length are accepted
  per RFC 2104; `KeySize` defaults to 32 and `MinKeyBytes` to 16.
- **`BuildKeyedHash(hashName string, spec KeyedHashSpec) (Spec, error)`**
  — uses the primitive's native keyed mode directly as the MAC, for
  primitives whose keyed form is itself a sound PRF (among the
  shipped entries, the BLAKE2 variants, BLAKE3, SipHash-2-4). Avoids
  the double-invocation HMAC envelope; key geometry follows the
  primitive (BLAKE3 takes an exactly-32-byte key, SipHash-2-4 an
  exactly-16-byte key, the BLAKE2 variants a variable-length key up
  to their block-size ceiling).

**When to use which:** for a primitive with a sound native keyed
mode, `BuildKeyedHash` is the direct construction — one primitive
invocation per tag. `BuildHMAC` is the standard envelope for
primitives whose keyed-mode soundness is not established, at the
cost of the nested HMAC invocation. `TagSize` on either builder
defaults to the primitive's native output size; truncation is
unsupported.

Both builders share one pre-keyed construction between the
single-call and incremental arms (a `sync.Pool` of pre-keyed hasher instances,
reset to the keyed initial state per call), so cross-arm
equivalence, determinism, constant tag length, parallel-safety, and
fresh-slice output hold by construction, and per-call invocation
carries no key-derivation overhead.

### Builder requirements — `hashes.Spec.HashHash` / `hashes.Spec.KeyedHash`

Each builder requires the resolved primitive's `hashes.Spec` to
carry the matching optional composition field:

- **`BuildHMAC(hashName, ...)`** requires a non-nil
  **`HashHash func() hash.Hash`** — a constructor returning a fresh
  instance of the primitive's general-purpose unkeyed `hash.Hash`
  form (standard `Write` / `Sum` / `Reset` / `Size` / `BlockSize`
  semantics), the shape the HMAC inner / outer pad passes wrap.
  Populated on the shipped entries built over a general-purpose hash
  (the BLAKE family); nil where no such form exists — the Areion
  SoEM constructions, AES-CMAC, SipHash-2-4, and ChaCha20 are not
  general-purpose hashes.
- **`BuildKeyedHash(hashName, ...)`** requires a non-nil
  **`KeyedHash func(key []byte) (hash.Hash, error)`** — the
  primitive's native keyed mode, pre-keyed with `key`. The
  constructor is the single source of truth for accepted key
  lengths: it must return an error (never panic) for a key length
  the primitive does not support. Populated on the shipped
  keyed-form entries (the BLAKE2 variants, BLAKE3, SipHash-2-4);
  nil where no native keyed `hash.Hash` mode exists.

When the required field is nil the builder fails with a clear error
naming the missing form (`has no unkeyed hash.Hash form` /
`has no native keyed-hash form`); nothing is registered. A custom
primitive registered via `hashes.Register` opts into either builder
by populating the corresponding field; a primitive without either
form remains MAC-capable through the fully hand-rolled `Register`
path (Example 3 below).

Key geometry under `BuildKeyedHash` is caller-explicit: `KeySize` is
required — a zero value returns a directive error, since implicit
key-size discovery was removed to avoid hidden key-size selection in
a cryptographic construction. The caller supplies a `KeySize` a
length the primitive's keyed constructor accepts (BLAKE3's 32,
SipHash-2-4's 16, BLAKE2b-256 up to 64, BLAKE2b-512 up to 64,
HMAC-SHA-512-shaped primitives keyed at the hash's 128-byte block
size, and so on). A zero `MinKeyBytes` defaults to 16 when the
constructor accepts a 16-byte key and to `KeySize` otherwise
(exact-length key contracts); explicit `KeySize` / `MinKeyBytes`
values the constructor rejects fail eagerly at build time.

### Three registration paths

#### Example 1 — shipped hash via `BuildHMAC`

The default path: pick a shipped hash-registry primitive with a
`hash.Hash` form and let the builder produce the `Spec`.

```go
spec, err := macs.BuildHMAC("blake2b256", macs.HMACSpec{Name: "team_hmac"})
if err != nil {
    panic(err)
}
if err := macs.Register(spec); err != nil {
    panic(err)
}

key := make([]byte, spec.KeySize)
rand.Read(key)
mac, _ := macs.Make("team_hmac", key)
tag := mac([]byte("message")) // HMAC-BLAKE2b-256, 32-byte tag
```

`BuildKeyedHash` follows the same shape for the keyed-form
primitives (see the complete Triple round-trip example below).

#### Example 2 — custom user hash via `BuildHMAC`

The cross-package path: a custom primitive registered via
`hashes.Register` with the optional `HashHash` field populated
composes through `BuildHMAC` with no additional wiring.

```go
// The custom primitive registers its pixel-hash arm (Make256Pair)
// as usual, plus the optional HashHash composition arm — the hook
// macs.BuildHMAC resolves through hashes.Find.
err := hashes.Register(hashes.Spec{
    Name:        "mycrypto",
    Width:       hashes.W256,
    Make256Pair: myMake256Pair, // the custom primitive's factory
    HashHash: func() hash.Hash {
        return myNewHash() // fresh general-purpose hash.Hash instance
    },
})
if err != nil {
    panic(err)
}

// The builder now composes with the custom hash by name.
spec, err := macs.BuildHMAC("mycrypto", macs.HMACSpec{Name: "mycrypto_mac"})
if err != nil {
    panic(err)
}
if err := macs.Register(spec); err != nil {
    panic(err)
}
// "mycrypto_mac" resolves through macs.Make / triple.Profile.MacName.
```

A custom primitive with a native keyed mode populates `KeyedHash`
instead (or additionally) and composes through `BuildKeyedHash` the
same way.

#### Example 3 — fully hand-rolled MAC (no builder)

The escape hatch: a primitive without a `hash.Hash` form — or any
construction the builders do not cover — registers a caller-written
factory directly, subject to the closure contracts above.

```go
macs.Register(macs.Spec{
    Name:        "hmac_sha3",
    KeySize:     32,
    MinKeyBytes: 16,
    TagSize:     32,
    MakeMAC: func(key []byte) (itb.MACFunc, error) {
        keyCopy := append([]byte(nil), key...)
        return func(data []byte) []byte {
            h := hmac.New(sha3.New256, keyCopy)
            h.Write(data)
            return h.Sum(nil)
        }, nil
    },
    // MakeIncrementalMAC omitted — Register synthesizes the
    // concatenate-then-MAC arm, equivalent by construction.
})
```

The closure above allocates a fresh HMAC instance per call — always
contract-correct; a production factory amortises with a `sync.Pool`
of pre-keyed instances the way the shipped builders do.

**When to use each path:** Example 1 when a shipped primitive fits —
least code, pooled factories for free. Example 2 when a custom hash
primitive already registered for pixel hashing should also back the
MAC — one registration serves both roles. Example 3 when the
primitive has no `hash.Hash` form, or the MAC construction itself is
custom (a national-standard MAC, a truncating construction wrapped
to a constant tag, an HSM-backed keyed transform).

### MakeMACPair

`MakeMACPair(name string, key []byte) (itb.MACFunc,
itb.MACIncrementalFunc, Spec, error)` resolves both arms plus the
resolved `Spec` in one call — the convenience dispatcher over
`Find` + `Make` + `MakeIncremental`, with identical name and
key-length validation. Works for shipped and user-registered
primitives alike.

### Complete example

Registration through Triple round-trip:

```go
package main

import (
    "fmt"

    "github.com/everanium/itb/macs"
    "github.com/everanium/itb/triple"
)

func main() {
    // Build + register a keyed-BLAKE2s custom MAC.
    spec, err := macs.BuildKeyedHash("blake2s", macs.KeyedHashSpec{Name: "b2s_mac", KeySize: 32})
    if err != nil {
        panic(err)
    }
    if err := macs.Register(spec); err != nil {
        panic(err)
    }

    // A registered profile referencing the custom name.
    err = triple.Register("team-b2s-v1", triple.Profile{
        Mode: "singlemsg-mac", Width: 256, InnerHash: "blake3",
        KeyBits: 512, MacName: "b2s_mac",
    })
    if err != nil {
        panic(err)
    }

    p, blob, err := triple.Init("team-b2s-v1", triple.Opts{})
    if err != nil {
        panic(err)
    }
    defer p.Close()
    // Persist the session bundle for a receiver:
    //   _ = p.SaveF("team-b2s-v1.json")
    // The receiver reopens with:
    //   dec, _ := triple.LoadF("team-b2s-v1.json")

    wire, _ := p.EncryptMessage([]byte("custom-MAC Single Message"))
    plain, _ := p.DecryptMessage(wire)
    fmt.Printf("round-trip: %s (blob %d bytes)\n", plain, len(blob))
}
```

### Cross-process blob contract

A seed blob exported under a custom MAC name records the **name**,
not the construction — the name is a promise. Opening the blob in
another process requires that process to have registered the same
name with the same construction before `triple.Load` /
`triple.LoadF` (or `Blob{N}.Import3Cfg` + `macs.Make`). A missing
registration fails blob open with `triple.ErrRecipePrimitiveUnknown`;
a divergent construction under the same name surfaces as a MAC
failure at decrypt — indistinguishable from tampering by design.

### Scope

Runtime MAC registration is a **Go-native API only**. The bindings
surface is triple-only over the frozen FFI shim: `ITB_MACCount` /
`ITB_MACName` iterate the shipped `Registry` exclusively, and no
binding exposes custom-primitive plug. Custom MACs are therefore
invisible to every binding by construction.
