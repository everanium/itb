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

Native Go API — the eight-seed Triple constellation is instantiated once per shipped hash primitive factory and threaded through `itb.EncryptAuthenticated3xNNNCfg` / `itb.DecryptAuthenticated3xNNNCfg` (or the streaming counterparts) alongside the `itb.MACFunc` returned by one of the factories in this package. Cross-process persistence is via `itb.Blob{128,256,512}` — `Blob*.Export3Cfg` packs the per-seed hash keys, `Components`, dedicated lockSeed, MAC key, and captured `*itb.Config` into a self-describing JSON blob; the receiver rebuilds the constellation via `Blob{N}.Import3Cfg` followed by per-slot factory rewiring + `macs.Make(blob.MACName, blob.MACKey)`.

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

Callers who want the eight-seed constellation, MAC, parallax layer, and outer cipher wrapper composed for them in one step use the [`triple.Pipeline`](../triple/) facade. `triple.Init(profileName, opts)` allocates the full stack around one primitive selected by name; the MAC choice rides in `triple.Opts.MacName` (defaults to `hmac-blake3`). The [top-level ITB README](https://github.com/everanium/itb#readme) hosts the canonical Pipeline examples across the four cipher shapes (Single Message MAC / Single Message No MAC / Streaming AEAD / Streaming Non-AEAD).

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
