<p align="center">
  <img src="assets/itb.png" width="128" alt="ITB">
  <br>
  <em>No beginning. No end. Ouroboros.</em>
  <br>
  <em>Designed to protect critical data from future superintelligence.</em>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/everanium/itb"><img src="https://pkg.go.dev/badge/github.com/everanium/itb.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/everanium/itb"><img src="https://goreportcard.com/badge/github.com/everanium/itb" alt="Go Report Card"></a>
  <a href="https://github.com/everanium/itb"><img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"></a>
</p>

# ITB — Information-Theoretic Barrier with Ambiguity-Based Security

> **v0.3.0 development snapshot — at a glance.** This is the one place in
> the corpus where the v0.2 → v0.3 pivot is framed historically. Every
> other section of this README (and every other Markdown file) reads as
> if the current construction was always the case.
>
> 1. **Triple-only Ouroboros.** The Single Ouroboros mode has been
>    retired; the 3-snake payload split is the only cipher mode. Every
>    encrypt / decrypt entry point takes the eight-seed bundle.
> 2. **Always-on non-disableable Interlocked Barrier.** A 48-bit-chunk
>    keyed permutation over three snakes is engaged unconditionally on
>    every call. Per-chunk mask space is roughly 2^70.20 balanced
>    partitions.
> 3. **Eight mandatory seeds per session.** noiseSeed, lockSeed,
>    dataSeed1..3, startSeed1..3. Pointer-identity distinctness is
>    enforced at the API surface.
> 4. **`triple/` package facade.** The shipped user-facing entry point.
>    One `Pipeline` bundles the eight-seed state, an optional parallax
>    layer, an optional wrapper (Outer cipher) layer, and an optional
>    MAC into a small lifecycle API.
> 5. **Cfg-only Low-Level surface.** Every Low-Level entry takes an
>    explicit `*itb.Config`. The pre-v0.3.0 process-wide setter surface
>    is gone; per-Pipeline configuration replaces it.
> 6. **Five shipped profiles with parallax + wrapper on by default.**
>    Toggle via `triple.Opts`. See the [Quick Start](#quick-start).
> 7. **Wire hard-fork.** The v0.3.0 wire format is not backwards
>    compatible: v0.2.x ciphertexts do not decrypt on v0.3.0 and vice
>    versa. Both sides of every deployment upgrade together.
> 8. **capi ABI break.** `ITB_HeaderSize` / `ITB_ParseChunkLen` take a
>    `nonce_bytes` parameter; the retired setter surface is gone; new
>    `ITB_Triple_*` exports carry the shipped surface.
> 9. **33-binding fleet plan.** Bindings are being reworked as thin
>    proxies over the `ITB_Triple_*` exports (nine Tier 1 Native, five
>    Thin, nineteen Tier 2 relays over four backends — C / Java / C# /
>    BEAM). Docs describe them at the architectural level while the
>    rework lands.
> 10. **Empirical suite re-run planned.** REDTEAM.md and HARNESS.md
>     updates ship separately after the adversarial re-verification
>     phase against the 48-bit always-on line. The barrier's KPA / CPA
>     closure is currently an architectural claim under the PRF
>     assumption, corroborated by pre-v0.3.0 empirical evidence for the
>     shared pixel construction.

---

> **Security notice.** ITB is an experimental symmetric cipher
> construction without prior peer review, independent cryptanalysis, or
> formal certification. The construction's security properties have
> **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

A parameterized symmetric cipher construction library for Go that makes hash output unobservable under passive observation through independent barrier mechanisms: **noise absorption** (a CSPRNG random container makes hash output unobservable), **encoding ambiguity** (secret rotation yields 7^P unverifiable configurations that survive CCA), and the **Interlocked Barrier** (a per-chunk PRF-keyed 48-bit permutation over three snakes, with a per-chunk mask space of ≈ 2^70.20 balanced partitions). Eight-seed isolation ensures compromise of any one domain provides zero information about the others.

**Ambiguity-Based Security.** Uncertainty about the correct configuration grows with data size, inverting Shannon's classical relationship. The Interlocked Barrier converts known-plaintext cryptanalysis from a computational-hardness problem into an instance-formulation one under the PRF assumption: a known-plaintext crib does not fix any bit-position-to-lane mapping for a solver to anchor on.

**[How the barrier works — accessible explanation](ITB.md)**

**[Why known-plaintext and advanced attacks are addressed by the barrier](SCIENCE.md)**

**[Empirical Red-Team validation](REDTEAM.md)** — 12 hash primitives (including CRC128, FNV-1a lo-lane and MD5 for positive control) exercised across structural / FFT / Markov, per-pixel candidate distinguisher, startPixel enumeration, ChainHash SAT-cost analysis + hash-agnostic bias audit, Direct Crib KPA SAT-cost analysis, nonce-reuse demasker with 96-cell Partial KPA matrix, 1008-cell related-seed differential, and rotation-invariant edge case surfaces. All PRF-grade primitives held under the tested conditions on the shared pixel construction; the 48-bit always-on line's empirical re-verification is a separate phase.

**[Discord](https://discord.gg/wRYF8shHpd)** — invite to chat with developer.

**[Scientific paper (Preprint)](https://doi.org/10.5281/zenodo.19229395)** — A. Kuvshinov, "A Symmetric Cipher Construction with Ambiguity-Based Security"

**No direct external dependencies** beyond ABI contracts and fallbacks with standard PRF primitives; the chain-absorb hot path is hand-written ZMM AVX-512 assembly and the barrier's per-chunk rank-unrank kernel is hand-written BMI2 / AVX-512F assembly.

## Status

The core API and the Go C ABI are being consolidated around the `triple/` facade and the Cfg-only Low-Level surface. The construction is being validated afresh against the 48-bit always-on barrier; the paper-facing empirical suite is scheduled to re-run after the follow-up push.

### Library

| Native | Status | Features | Tests | Packages |
|---|---|---|---|---|
| Go Native | Under consolidation for v0.3.0 | `triple/` facade + Cfg-only Low-Level | Passing on Intel Rocket Lake reference host | TBD |
| C ABI (`cmd/cshared`) | Under consolidation for v0.3.0 | `ITB_Triple_*` exports + Cfg-aware capi header | Passing on Intel Rocket Lake reference host | TBD |

<!-- preserved-verbatim: cross-platform verification block; do not paraphrase; re-runs after bindings rework produce fresh numbers -->

**Cross-platform verified.** Encrypt / Decrypt round-trip validated between x86_64 (Intel / AMD) and AArch64 (Graviton 4).

**Cross-binding interop verified.** All 10 implementations (Go Core + 9 bindings) produce byte-identical wire format and decrypt every other implementation's output.

Full matrix:
- 10 × 10 (Go Core + 9 bindings) = 100 pairs
- 16 modes (8 base + 8 outer cipher wraps AES-128-CTR)
- 3 sizes (1 B / 1 MiB / 64 MiB)
- **4000 cells PASS**

**All features fully implemented.** Where a binding's surface diverges from the Go Native library (e.g. no `io.Reader` / `io.Writer` adapter for Non-AEAD streaming — only User-Driven Loop), the asymmetry is intentional and follows per-language idiom rather than incomplete coverage.

**Maintenance path.** Subsequent open-source work covers bug fixes, documentation, and additional bindings only. Custom closed encryption constructions and downstream software stacks are available on commercial request.

<!-- /preserved-verbatim -->

## Why ITB

Traditional symmetric ciphers (AES, ChaCha20) place all security burden on the mathematical strength of their core primitive. The keystream is XOR'd directly with plaintext — any weakness in the primitive is immediately exploitable because the attacker observes the primitive's output.

ITB inverts this approach. The construction interposes a **random container** (generated from `crypto/rand`) between the hash output and the observer, then re-maps each 48-bit chunk of the interleaved payload through a per-chunk PRF-keyed permutation drawn from a space of roughly 2^70.20 balanced partitions. The hash output is consumed by modifying random bytes that the attacker never sees; the mapping from plaintext bit to observed lane is itself a per-chunk secret. Two structural facts follow, both conditional on the PRF assumption and fresh per-message nonces:

- **Under the PRF assumption and with fresh per-message nonces, each 48-bit chunk of the payload is re-mapped by a per-chunk, PRF-keyed mask triple drawn from a space of roughly 2^70.20 balanced partitions, so a known-plaintext crib does not fix any bit-position-to-lane mapping for a solver to anchor on.** The Interlocked Barrier is the always-on primary component of the construction.
- **Because the mask of each chunk is keyed independently of every other chunk, additional crib chunks multiply the attacker's enumeration rather than contributing constraints that couple chunks — the known-plaintext instance stays under-determined regardless of how much plaintext the attacker holds.** The Interlocked Barrier is designed to turn known-plaintext cryptanalysis from a computational-hardness problem into an instance-formulation one: under the PRF assumption there is no unique solution for a faster solver to discover.

**Why the math is simple.** The construction uses only elementary operations: XOR, bitwise AND, modulo, bit shifts, and the per-chunk rank-unrank pair that produces the mask triple. There are no Galois fields, no S-boxes, no polynomial multiplication. This is not a weakness — it is a consequence of the design. The security comes from the **architecture** — random container, eight-seed isolation, per-bit XOR, noise embedding, and the per-chunk keyed permutation — not from the complexity of the math. Each architectural layer addresses a specific attack vector:

- **Random container** — hash output unobservable under passive observation (COA, KPA).
- **Per-bit XOR (1:1)** — 56 independent mask bits per pixel; every observation consistent with any plaintext.
- **Interlocked Barrier** — per-chunk PRF-keyed 48-bit permutation over three snakes; ≈ 2^70.20 mask space per chunk.
- **Eight-seed isolation** — noiseSeed, lockSeed, dataSeed1..3, startSeed1..3 drawn as independent CSPRNG components and keyed into separate channels, so a structural shortcut against one primitive channel cannot leak into another's derivation.
- **Noise bit embedding** — no bit position is deterministically data from the public format.

**Why the barrier and the PRF are complementary.** In traditional ciphers the attacker directly observes the primitive's output (keystream XOR plaintext), so any weakness in the primitive is immediately exploitable. In ITB the hash output is absorbed by a random-container modification, and each 48-bit chunk of the interleaved payload is re-mapped through the barrier's keyed permutation — the attacker sees modified random bytes routed through a hidden per-chunk permutation, not hash outputs. PRF closes the candidate-verification step; the barrier and the surrounding architectural layers deny the point of application. Neither is sufficient alone: the architectural layers cannot resist total inversion of the primitive, and without the barrier the attacker would observe the keystream directly.

**The two-step reduction and the gcd anti-collapse trap.** The two-step reduction that draws each mask triple reaches the full partition space; the rejected same-rank alternative would have confined the draw to 1 / 66861 of that space, so full-space coverage is a deliberate property of the construction, not an accident. The reduction is deterministic and constant-time, carrying a fixed, publicly-known per-chunk deviation of about 2^-57.8 that accumulates to about 2^-34.4 over a maximum-size message; distinguishing this granularity would require on the order of 2^115.6 chunk samples, well beyond any attainable budget.

**Triple Ouroboros split.** The plaintext is split across three interleaved snakes with independent per-snake offsets and configurations, so a single known crib maps onto three unknown-offset streams whose per-snake boundaries are not recoverable from the interleaved container. This is a distinct, composable barrier from the per-chunk mask space: the split raises the enumeration dimension while the mask space raises the per-chunk floor.

**Empirical footing.** Across a broad primitive spectrum spanning deliberately broken lab controls through paper-grade PRFs, the underlying pixel construction produced ciphertext with no distinguishable signal at the tested sample sizes on every statistical surface measured — evidence for the barrier's absorption of primitive weakness on the shared pixel construction, not a proof that no distinguisher exists.

**Threat model boundary.** The closure of the known-plaintext and chosen-plaintext families is conditional on the configured primitive behaving as a secure PRF and on fresh per-message nonces; total inversion of the primitive, or a reused nonce, is outside what the barrier is designed to close. The security properties described here are architectural arguments and self-audit evidence, not independent cryptanalysis: ITB has had no external review or formal certification, and the strong claims are stated conditionally for that reason. See [PROOFS.md](PROOFS.md), [SCIENCE.md](SCIENCE.md), and [SECURITY.md](SECURITY.md) for the full treatment.

> **Important.** ITB is an experimental construction without peer review or independent cryptanalysis. The information-theoretic barrier is a **software-level property**, reinforced by the noise absorption channel, the always-on Interlocked Barrier, and the encoding-ambiguity channel; the CCA leak surface is bounded to the noise-position channel under MAC + Reveal (see [Proof 6](PROOFS.md)). It provides no guarantees against hardware-level attacks. All security claims are under the random-container plus PRF model and have not been independently verified.

## Installation

```bash
go get github.com/everanium/itb@latest
```

## Building

ITB ships two pixel-processing backends selected automatically at compile time, plus a fallback build tag for hosts that lack the assembly kernels' baseline features:

| Mode | Command | Pixel Processing | Requirements |
|---|---|---|---|
| **CGO (default)** | <code>-buildmode=c-shared</code> | C with SIMD auto-vectorization | C compiler (GCC/Clang) + AVX-512 baseline |
| **No ITB ASM** (CGO) | <code>-buildmode=c-shared&nbsp;-tags=noitbasm</code> | C with SIMD auto-vectorization; ITB chain-absorb / Interlocked Barrier / Areion permutation ASM disabled; upstream stdlib ASM (`zeebo/blake3`, `golang.org/x/crypto`, `jedisct1/go-aes`) stays engaged | C compiler (GCC/Clang) |
| **Pure Go** | `CGO_ENABLED=0 ...` | Portable Go pipeline (`process_generic.go`) | None (any GOOS / GOARCH the Go compiler supports) |

### CPU baseline for the shipped assembly kernels

The shipped `_amd64.s` kernels target a modern x86_64 baseline. The exact CPU feature each kernel needs is detected once at package init via `golang.org/x/sys/cpu` and dispatched from there:

| Kernel | Required CPU feature | Runtime capability flag |
|---|---|---|
| Interlocked Barrier — scalar rank-unrank | BMI2 (PEXTQ / PDEPQ) | `interlock.HasBMI2` |
| Interlocked Barrier — batched rank-unrank | AVX-512F (VPERMI2Q, VPCMPUQ, VPSRLVQ, mask-merged VPSUBQ on ZMM) | `interlock.HasAVX512RankMask` |
| Areion-SoEM — top-tier batched permute + fused chain | VAES + AVX-512 | `areionasm.HasVAESAVX512` |
| Areion-SoEM — mid-tier per-half permute | VAES + AVX2 | `areionasm.HasVAESAVX2NoAVX512` |
| AES-CMAC — batched CBC-MAC / fused chain | VAES + AVX-512 | `aescmacasm.HasVAESAVX512` |
| BLAKE2b / BLAKE2s / BLAKE3 / ChaCha20 — 4-lane ZMM chain-absorb + fused chain | AVX-512F | primitive-local `HasAVX512Fused` |
| SipHash-2-4 — 4-lane ZMM chain-absorb + fused chain | AVX-512F | `siphashasm.HasAVX512Fused` |

Cross-referenced to shipping x86 microarchitectures:

- **Intel** — the assembly kernels are exercised end-to-end from **Rocket Lake (11th-gen, e.g. i7-11700K)** onward. Ice Lake mobile parts carry the required flags but are not the reference host.
- **AMD** — exercised end-to-end from **Zen 3+** onward (Ryzen 5000 desktop, Zen 4 / Zen 5 servers). VAES on Zen 3 activates the mid-tier per-half permute path; the top-tier fused chain requires AVX-512, i.e. Zen 4+ or newer.
- **Older or narrower x86_64 hosts** — build with `-tags noitbasm` to skip the ITB-native assembly entirely; the upstream primitive libraries' own ASM (`crypto/aes`, `dchest/siphash`, `golang.org/x/crypto`, `zeebo/blake3`) stays engaged.
- **ARM64** — scalar path only today. The construction runs correctly on aarch64 (Graviton 4 has been the reference validation host); no Go assembly for NEON / SVE2 ships yet. The upstream primitive libraries' own ARM Crypto Extension assembly stays engaged where present (Areion-SoEM's `internal/areionasm/areion_arm64.s` uses `AESE`/`AESMC`).
- **Every other Go target** — the pure-Go pipeline via `CGO_ENABLED=0` runs on any GOOS / GOARCH the Go compiler supports; throughput drops but correctness is preserved.

### Usage

```bash
# Build shared library
git clone https://github.com/everanium/itb && cd itb

# CGO backend (default)
cd cmd/cshared && go build -buildmode=c-shared -o ../../dist/linux-amd64/libitb.so .

# CGO backend without ITB-native ASM (portable, audit-grade deterministic)
cd cmd/cshared && go build -buildmode=c-shared -tags=noitbasm -o ../../dist/linux-amd64/libitb.so .
```

### Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```go
itb.SetMemoryLimit(512 << 20)
itb.SetGCPercent(20)
```

### Nonce width

`ITB_NONCE_BITS=256` sets the default on-wire nonce width in bits at process init (accepted values: `128` / `256` / `512`). It is the sole environment-variable knob. Per-Pipeline overrides live in `triple.Opts.NonceBits` on the facade side and in the `*itb.Config.NonceBits` field on the Low-Level side; the env value is the compile-in default when neither override is supplied.

### Tests

```bash
# CGO backend (default)
go test -timeout=3600s -race ./...

# CGO backend without ITB-native ASM
go test -tags=noitbasm -timeout=3600s -race ./...

# Pure Go
CGO_ENABLED=0 go test -timeout=3600s . ./triple ./hashes ./macs ./internal/...
CGO_ENABLED=0 go test -tags=noitbasm -timeout=3600s . ./triple ./hashes ./macs ./internal/...
```

### Benchmarks

```bash
# CGO backend (default)
go test -bench='Benchmark*' -run='^$' -benchtime=5s -count=1 .

# CGO backend without ITB-native ASM
go test -tags=noitbasm -bench='Benchmark*' -run='^$' -benchtime=5s -count=1 .

# Pure Go
CGO_ENABLED=0 go test -bench='Benchmark*' -run='^$' -benchtime=5s -count=1 .
```

### Coverage

```bash
go test -coverprofile=coverage.out $(go list ./... | grep -vE 'tools/eitb|cmd/cshared$')
```

### Performance

Full benchmark results across ITB key sizes, hash primitives, and CPUs: **[BENCH3.md](BENCH3.md)**.

Throughput scales with data size due to goroutine parallelism across CPU cores. CGO mode uses the C pixel kernel on top of ZMM-batched chain-absorb hash kernels for every PRF-grade primitive (`hashes/internal/<primitive>asm` plus `internal/areionasm` for Areion-SoEM); `CGO_ENABLED=0` swaps only the C pixel kernel for the portable Go pipeline, while the ZMM-batched hash ASM stays engaged via Go assembly. Decrypt does not require `crypto/rand` and scales further on high-core-count CPUs.

### Concurrency

A single `triple.Pipeline` is safe for concurrent `EncryptStream` / `DecryptStream` / `EncryptMessage` / `DecryptMessage` calls: post-`Init` and post-`Open`, all Pipeline state relevant to encryption is read-only, and per-call state (readers, writers, per-chunk scratch inside the itb IO entry) lives on the caller's stack. `Rekey` mutates Pipeline state and must be serialised against concurrent cipher calls by the caller (see [`triple/rekey.go`](triple/rekey.go)); `Close` wipes secret material atomically and subsequent method calls return `triple.ErrClosed`.

The Low-Level free functions (`itb.EncryptAuthenticated3x{128,256,512}Cfg`, `itb.EncryptStreamAuth3x{128,256,512}Cfg`, `itb.EncryptStreamAuth3xCfg`, and the decrypt counterparts) take read-only seed pointers and a `*itb.Config` and allocate output per call — they are thread-safe under concurrent invocation on the same seeds. Concurrent mutation of the shared `*itb.Config` by other goroutines must be serialised by the caller.

## Quick Start

Six worked examples cover the surface. Four use the `triple/` facade (the shipped user-facing entry point); two use the Low-Level `*Cfg` free functions directly. Every example runs against one of the five shipped profiles listed in [`triple/profile.go`](triple/profile.go):

- `singlemsg-triple-mac-v1` — Single Message Triple with MAC.
- `singlemsg-triple-nomac-v1` — Single Message Triple No MAC.
- `streaming-aead-triple-mac-v1` — Streaming AEAD Triple with MAC.
- `streaming-noaead-triple-v1` — Streaming Non-AEAD Triple.
- `blob-triple-mac-v1` — MAC-authenticated blob-only bundle (no cipher surface; used by `Init` / `Rekey` to bundle session state).

All shipped profiles default to **parallax on + wrapper (Outer cipher) on**; both toggles are opt-out via `triple.Opts`. Every seed component, PRF key, MAC key, and wrapper master is drawn from `crypto/rand` at `Init` time.

**The user's story.** Call `triple.Init(profile, opts)` to receive a `*triple.Pipeline` plus a `blob` byte slice. **The blob is the full session bundle** — profile identifier, both masters, and the inner Blob{N} carrying the eight seed components + per-slot PRF keys + optional MAC material. Ship the blob to the receiver out-of-band; the receiver calls `triple.Open(profile, blob, opts)` and reconstructs the same Pipeline. Both sides then encrypt / decrypt against their Pipeline.

### Triple 1 — Single Message with MAC

```go
package main

import (
    "bytes"
    "fmt"

    "github.com/everanium/itb"
    "github.com/everanium/itb/triple"
)

func main() {
    // Runtime tuning — process-global, one-shot at startup. Affects the
    // whole Go runtime including any concurrent triple.Pipeline instances.
    itb.SetMemoryLimit(512 << 20) // 512 MiB soft heap cap
    itb.SetGCPercent(20)          // aggressive GC to keep working-set tight

    // Sender.
    enc, blob, err := triple.Init(triple.ProfileSingleMsgTripleMACV1, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer enc.Close()

    wire, err := enc.EncryptMessage([]byte("any text or binary data - including 0x00 bytes"))
    if err != nil {
        panic(err)
    }
    fmt.Printf("blob: %d bytes; wire: %d bytes\n", len(blob), len(wire))

    // Receiver — ship the blob out-of-band, then reconstruct.
    dec, err := triple.Open(triple.ProfileSingleMsgTripleMACV1, blob, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer dec.Close()

    plain, err := dec.DecryptMessage(wire)
    if err != nil {
        panic(err)
    }
    if !bytes.Equal(plain, []byte("any text or binary data - including 0x00 bytes")) {
        panic("round-trip mismatch")
    }
    fmt.Printf("decrypted: %s\n", string(plain))
}
```

### Triple 2 — Single Message No MAC

```go
package main

import (
    "bytes"
    "fmt"

    "github.com/everanium/itb"
    "github.com/everanium/itb/triple"
)

func main() {
    // Runtime tuning — process-global, one-shot at startup.
    itb.SetMemoryLimit(512 << 20)
    itb.SetGCPercent(20)

    enc, blob, err := triple.Init(triple.ProfileSingleMsgTripleNoMACV1, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer enc.Close()

    wire, err := enc.EncryptMessage([]byte("plaintext bytes"))
    if err != nil {
        panic(err)
    }

    dec, err := triple.Open(triple.ProfileSingleMsgTripleNoMACV1, blob, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer dec.Close()

    plain, err := dec.DecryptMessage(wire)
    if err != nil {
        panic(err)
    }
    if !bytes.Equal(plain, []byte("plaintext bytes")) {
        panic("round-trip mismatch")
    }
    fmt.Printf("decrypted: %s\n", string(plain))
}
```

### Triple 3 — Streaming AEAD (MAC Authenticated, IO-Driven)

The Streaming AEAD IO-Driven surface is the primary use case for bulk payloads. `EncryptStream` reads plaintext from an `io.Reader` and writes wire bytes to an `io.Writer`; `DecryptStream` mirrors the direction.

```go
package main

import (
    "bufio"
    "os"

    "github.com/everanium/itb/triple"
)

func main() {
    const (
        srcPath = "/tmp/64mb.src"
        encPath = "/tmp/64mb.enc"
        dstPath = "/tmp/64mb.dst"
    )

    // Runtime tuning — process-global, one-shot at startup.
    itb.SetMemoryLimit(512 << 20)
    itb.SetGCPercent(20)

    enc, blob, err := triple.Init(triple.ProfileStreamingAEADTripleMACV1, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer enc.Close()

    // Encrypt: plainSrc -> wireDst.
    fin, _ := os.Open(srcPath)
    fout, _ := os.Create(encPath)
    br, bw := bufio.NewReader(fin), bufio.NewWriter(fout)
    if err := enc.EncryptStream(br, bw); err != nil {
        panic(err)
    }
    bw.Flush()
    fin.Close()
    fout.Close()

    // Ship blob out-of-band, then reconstruct on the receiver.
    dec, err := triple.Open(triple.ProfileStreamingAEADTripleMACV1, blob, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer dec.Close()

    fin, _ = os.Open(encPath)
    fout, _ = os.Create(dstPath)
    br, bw = bufio.NewReader(fin), bufio.NewWriter(fout)
    if err := dec.DecryptStream(br, bw); err != nil {
        panic(err)
    }
    bw.Flush()
    fin.Close()
    fout.Close()
}
```

### Triple 4 — Streaming Non-AEAD (No MAC, IO-Driven)

Same shape as the AEAD variant; the profile switch replaces the MAC-bearing pipeline with the plain (unauthenticated) one. Wrong-seed input produces random-looking plaintext rather than an error; truncate-tail / reorder are not detected on this surface.

```go
package main

import (
    "bufio"
    "os"

    "github.com/everanium/itb/triple"
)

func main() {
    const (
        srcPath = "/tmp/64mb.src"
        encPath = "/tmp/64mb.enc"
        dstPath = "/tmp/64mb.dst"
    )

    // Runtime tuning — process-global, one-shot at startup.
    itb.SetMemoryLimit(512 << 20)
    itb.SetGCPercent(20)

    enc, blob, err := triple.Init(triple.ProfileStreamingNoAEADTripleV1, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer enc.Close()

    fin, _ := os.Open(srcPath)
    fout, _ := os.Create(encPath)
    br, bw := bufio.NewReader(fin), bufio.NewWriter(fout)
    if err := enc.EncryptStream(br, bw); err != nil {
        panic(err)
    }
    bw.Flush()
    fin.Close()
    fout.Close()

    dec, err := triple.Open(triple.ProfileStreamingNoAEADTripleV1, blob, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer dec.Close()

    fin, _ = os.Open(encPath)
    fout, _ = os.Create(dstPath)
    br, bw = bufio.NewReader(fin), bufio.NewWriter(fout)
    if err := dec.DecryptStream(br, bw); err != nil {
        panic(err)
    }
    bw.Flush()
    fin.Close()
    fout.Close()
}
```

### Overriding profile defaults via `Opts`

Every profile-supplied default is overridable on both `Init` and `Open`. Typical overrides:

```go
withParallax := false
withWrapper := true

enc, blob, err := triple.Init(triple.ProfileStreamingAEADTripleMACV1, triple.Opts{
    NonceBits:    256,          // per-Pipeline nonce width (default: itb.DefaultNonceBits)
    BarrierFill:  4,            // per-Pipeline CSPRNG barrier fill margin
    MaxWorkers:   8,            // per-Pipeline worker cap
    ChunkSize:    16 << 20,     // streaming chunk-size budget
    WithParallax: &withParallax, // opt out of parallax
    WithWrapper:  &withWrapper,  // keep wrapper on (would default on anyway)
    OuterCipher:  "aes128ctr",   // pick a specific outer cipher
})
```

`WithParallax` and `WithWrapper` are `*bool` so a nil pointer defers to the profile default while a non-nil pointer forces the chosen setting. Every other field takes its zero value to mean "inherit the profile default".

## Advanced — Low-Level `*Cfg` surface

The `triple/` facade is the recommended entry point. Callers who need the raw eight-seed handoff — for custom key management, unusual PRF combinations, or in-process integration with existing seed material — consume the Low-Level `*Cfg` free functions directly. Every Low-Level entry takes an explicit `*itb.Config` (`nil` accepts all compile-in defaults); the process-wide setter surface has been retired.

### Low-Level 1 — Message-shape, MAC Authenticated

Message-shape variant using `itb.EncryptAuthenticated3x256Cfg` / `itb.DecryptAuthenticated3x256Cfg`. The pattern mirrors the 256-bit-width variant; substitute `128Cfg` or `512Cfg` when the primitive width changes. Eight typed seeds map to the canonical slot order (noise, lock, data1..3, start1..3); pointer-identity distinctness is enforced at the call site.

```go
package main

import (
    "bytes"
    "crypto/rand"
    "fmt"

    "github.com/everanium/itb"
    "github.com/everanium/itb/hashes"
    "github.com/everanium/itb/macs"
)

func main() {
    // Runtime tuning — process-global, one-shot at startup.
    itb.SetMemoryLimit(512 << 20) // 512 MiB soft heap cap
    itb.SetGCPercent(20)          // aggressive GC to keep working-set tight

    cfg := &itb.Config{NonceBits: 512, BarrierFill: 4, MaxWorkers: 4}

    // Eight independent CSPRNG-keyed Areion-SoEM-256 paired closures.
    // Each *Pair() returns (single, batched, [32]byte-key, error).
    fnN,  batchN,  _, _ := hashes.Areion256Pair()
    fnL,  batchL,  _, _ := hashes.Areion256Pair()
    fnD1, batchD1, _, _ := hashes.Areion256Pair()
    fnD2, batchD2, _, _ := hashes.Areion256Pair()
    fnD3, batchD3, _, _ := hashes.Areion256Pair()
    fnS1, batchS1, _, _ := hashes.Areion256Pair()
    fnS2, batchS2, _, _ := hashes.Areion256Pair()
    fnS3, batchS3, _, _ := hashes.Areion256Pair()

    ns,  _ := itb.NewSeed256(1024, fnN);  ns.BatchHash  = batchN
    ls,  _ := itb.NewSeed256(1024, fnL);  ls.BatchHash  = batchL
    ds1, _ := itb.NewSeed256(1024, fnD1); ds1.BatchHash = batchD1
    ds2, _ := itb.NewSeed256(1024, fnD2); ds2.BatchHash = batchD2
    ds3, _ := itb.NewSeed256(1024, fnD3); ds3.BatchHash = batchD3
    ss1, _ := itb.NewSeed256(1024, fnS1); ss1.BatchHash = batchS1
    ss2, _ := itb.NewSeed256(1024, fnS2); ss2.BatchHash = batchS2
    ss3, _ := itb.NewSeed256(1024, fnS3); ss3.BatchHash = batchS3

    macKey := make([]byte, 32)
    rand.Read(macKey)
    macFunc, err := macs.Make("hmac-blake3", macKey)
    if err != nil {
        panic(err)
    }

    plaintext := []byte("Low-Level Message-shape round-trip")

    wire, err := itb.EncryptAuthenticated3x256Cfg(
        cfg,
        ns, ls, ds1, ds2, ds3, ss1, ss2, ss3,
        plaintext, macFunc,
    )
    if err != nil {
        panic(err)
    }

    plain, err := itb.DecryptAuthenticated3x256Cfg(
        cfg,
        ns, ls, ds1, ds2, ds3, ss1, ss2, ss3,
        wire, macFunc,
    )
    if err != nil {
        panic(err)
    }
    if !bytes.Equal(plain, plaintext) {
        panic("round-trip mismatch")
    }
    fmt.Printf("wire: %d bytes; plain: %s\n", len(wire), string(plain))
}
```

### Low-Level 2 — IO-Driven Stream-shape, MAC Authenticated

Stream-shape variant using the `any`-seed IO-Driven entry `itb.EncryptStreamAuth3xCfg` / `itb.DecryptStreamAuth3xCfg`. The eight seeds pass in as `any` handles — the entry point dispatches on width internally, so `*itb.Seed128`, `*itb.Seed256`, and `*itb.Seed512` seeds all flow through the same IO surface.

```go
package main

import (
    "bufio"
    "crypto/rand"
    "os"

    "github.com/everanium/itb"
    "github.com/everanium/itb/hashes"
    "github.com/everanium/itb/macs"
)

func main() {
    const (
        srcPath   = "/tmp/64mb.src"
        encPath   = "/tmp/64mb.enc"
        dstPath   = "/tmp/64mb.dst"
        chunkSize = 16 * 1024 * 1024
    )

    // Runtime tuning — process-global, one-shot at startup.
    itb.SetMemoryLimit(512 << 20) // 512 MiB soft heap cap
    itb.SetGCPercent(20)          // aggressive GC to keep working-set tight

    cfg := &itb.Config{NonceBits: 512, BarrierFill: 4, MaxWorkers: 4}

    fnN,  batchN,  _, _ := hashes.Areion512Pair()
    fnL,  batchL,  _, _ := hashes.Areion512Pair()
    fnD1, batchD1, _, _ := hashes.Areion512Pair()
    fnD2, batchD2, _, _ := hashes.Areion512Pair()
    fnD3, batchD3, _, _ := hashes.Areion512Pair()
    fnS1, batchS1, _, _ := hashes.Areion512Pair()
    fnS2, batchS2, _, _ := hashes.Areion512Pair()
    fnS3, batchS3, _, _ := hashes.Areion512Pair()

    ns,  _ := itb.NewSeed512(1024, fnN);  ns.BatchHash  = batchN
    ls,  _ := itb.NewSeed512(1024, fnL);  ls.BatchHash  = batchL
    ds1, _ := itb.NewSeed512(1024, fnD1); ds1.BatchHash = batchD1
    ds2, _ := itb.NewSeed512(1024, fnD2); ds2.BatchHash = batchD2
    ds3, _ := itb.NewSeed512(1024, fnD3); ds3.BatchHash = batchD3
    ss1, _ := itb.NewSeed512(1024, fnS1); ss1.BatchHash = batchS1
    ss2, _ := itb.NewSeed512(1024, fnS2); ss2.BatchHash = batchS2
    ss3, _ := itb.NewSeed512(1024, fnS3); ss3.BatchHash = batchS3

    macKey := make([]byte, 32)
    rand.Read(macKey)
    macFunc, err := macs.Make("hmac-blake3", macKey)
    if err != nil {
        panic(err)
    }

    // Encrypt IO-Driven.
    fin, _ := os.Open(srcPath)
    fout, _ := os.Create(encPath)
    br, bw := bufio.NewReader(fin), bufio.NewWriter(fout)
    if err := itb.EncryptStreamAuth3xCfg(
        cfg,
        ns, ls, ds1, ds2, ds3, ss1, ss2, ss3,
        br, bw, macFunc, chunkSize,
    ); err != nil {
        panic(err)
    }
    bw.Flush()
    fin.Close()
    fout.Close()

    // Decrypt IO-Driven mirror.
    fin, _ = os.Open(encPath)
    fout, _ = os.Create(dstPath)
    br, bw = bufio.NewReader(fin), bufio.NewWriter(fout)
    if err := itb.DecryptStreamAuth3xCfg(
        cfg,
        ns, ls, ds1, ds2, ds3, ss1, ss2, ss3,
        br, bw, macFunc,
    ); err != nil {
        panic(err)
    }
    bw.Flush()
    fin.Close()
    fout.Close()
}
```

**User-Driven Loop counterpart.** Callers who prefer to drive the read / write loop from their own code (external control over chunk granularity, back-pressure, or interleaved work between chunks) use the typed User-Driven Loop entries `itb.EncryptStreamAuth3x{128,256,512}Cfg(cfg, 8 seeds, data, chunkSize, mac, emit func([]byte) error)` and their decrypt counterparts. The `emit` callback receives each wire chunk as it lands; the caller is responsible for framing, back-pressure, and disposition. The IO-Driven and User-Driven Loop variants produce identical on-wire bytes.

### Custom user-supplied primitives

The shipped `hashes/` registry does not accept runtime registrations. Users who want to plug their own inner primitive construct `itb.HashFunc{N}` (single-call) and `itb.BatchHashFunc{N}` (batched-arm) closures per seed slot and pass them directly to the `*Cfg` Low-Level entry point. The primitive is responsible for its own keying and pooling; ITB's per-pixel dispatcher wires both arms through the seed's `Hash` and `BatchHash` fields.

## Hash primitives (`hashes/`)

The `hashes/` subpackage ships **paired** cached factories for every PRF-grade primitive on the FFI surface. Each `<Primitive>Pair()` factory pre-keys its primitive once at construction and returns a `(single, batched, key)` triple. The batched arm wires the AVX-512 ZMM-batched chain-absorb dispatch through `Seed.BatchHash` automatically; a `sync.Pool` amortises per-call scratch allocation. A `<Primitive>PairWithKey` counterpart takes the fixed key as a single non-variadic argument for explicit-key call sites.

Name-keyed dispatch is used by the FFI layer and by any code that selects the primitive at runtime. `Make<N>Pair` returns the batched arm alongside the single arm; `Make<N>` (no `Pair` suffix) is the single-arm-only convenience:

| Function | Returns | Covers |
|---|---|---|
| `Make128(name, key ...[]byte)` | `(HashFunc128, []byte, error)` | 128-bit primitives |
| `Make128Pair(name, key ...[]byte)` | `(HashFunc128, BatchHashFunc128, []byte, error)` | 128-bit primitives |
| `Make256(name, key ...[]byte)` | `(HashFunc256, []byte, error)` | 256-bit primitives |
| `Make256Pair(name, key ...[]byte)` | `(HashFunc256, BatchHashFunc256, []byte, error)` | 256-bit primitives |
| `Make512(name, key ...[]byte)` | `(HashFunc512, []byte, error)` | 512-bit primitives |
| `Make512Pair(name, key ...[]byte)` | `(HashFunc512, BatchHashFunc512, []byte, error)` | 512-bit primitives |
| `Find(name)` | `(Spec, bool)` | Spec lookup for key-size / native-width metadata |

Per-primitive technical notes:

- **Areion-SoEM-256** and **Areion-SoEM-512** are formally-proven beyond-birthday-bound PRFs built over the AES round function. ITB ships a 4-way batched dispatch that runs on x86_64 hardware with VAES + AVX-512 (top tier) or VAES + AVX2 (mid tier); on hosts without VAES the primitive falls back to scalar AES-NI via `github.com/jedisct1/go-aes`. `MakeAreionSoEM256Hash` / `MakeAreionSoEM512Hash` (root-package convenience) return `(HashFunc, BatchHashFunc, fixedKey)`.
- **BLAKE2b-256**, **BLAKE2b-512**, **BLAKE2s**, and **BLAKE3** ship AVX-512 ZMM ARX kernels (4-lane chain-absorb) and fall back to the upstream `golang.org/x/crypto` / `github.com/zeebo/blake3` scalar paths on hosts without AVX-512F.
- **AES-CMAC** ships a VAES + AVX-512 ZMM 4-lane CBC-MAC kernel and falls back to `crypto/aes` scalar on hosts without VAES.
- **SipHash-2-4** is the one primitive with no internal fixed key — its keying material is the seed components themselves. `SipHash24Pair()` takes no arguments and returns a `(single, batched)` pair without a third key element.
- **ChaCha20** ships a 4-lane AVX-512 ZMM ARX kernel and falls back to `golang.org/x/crypto/chacha20` on hosts without AVX-512F.

See [hashes/CONSTRUCTIONS.md](hashes/CONSTRUCTIONS.md) for per-primitive construction descriptions (how each registry name wraps its underlying RFC / NIST primitive, where the wrappers diverge from the canonical specification, and why).

## MACs (`macs/`)

The `macs/` subpackage ships three MAC primitives with a fixed 32-byte tag and FFI-stable index order. All three pre-key the primitive once at construction and are safe to call concurrently:

| # | Factory | Returns | Key size | Tag size |
|---|---|---|---|---|
| 0 | `KMAC256(key []byte)` | `(MACFunc, error)` | ≥ 16 B | 32 B |
|   | `KMAC256WithCustomization(key, customization []byte)` | `(MACFunc, error)` | ≥ 16 B | 32 B |
| 1 | `HMACSHA256(key []byte)` | `(MACFunc, error)` | ≥ 16 B | 32 B |
| 2 | `HMACBLAKE3(key []byte)` | `(MACFunc, error)` | 32 B | 32 B |

Name-keyed dispatch:

| Function | Returns | Purpose |
|---|---|---|
| `Make(name, key []byte)` | `(MACFunc, error)` | Name-keyed dispatch (FFI / runtime selection) |
| `Find(name)` | `(Spec, bool)` | Spec lookup for key-size metadata |

See [macs/CONSTRUCTIONS.md](macs/CONSTRUCTIONS.md) for per-MAC construction descriptions and the MAC-Inside-Encrypt placement-hiding rationale.

## ChainHash — local key evolution

**Warning.** A 512-bit primitive keyed with a 512-bit ITB width mode folds into a single ChainHash round, so the feedforward chain is absent and the primitive output is used directly. Recommended minimum: 1024-bit ITB mode.

ChainHash is the small construction that sits between ITB's seed material and the underlying PRF. It is what lets a fixed-width hash (128 / 256 / 512-bit native state) be keyed by an arbitrarily wide key — the source of ITB's advertised **512 / 1024 / 2048-bit** key sizes. ChainHash takes a key (the seed components) and one fixed input (the per-pixel buffer) and returns a single fixed-width block.

In plain terms: the key is a list of 64-bit components, consumed a round at a time. The first round hashes the input under the first group of components. Every later round re-hashes the same input under the next group of components, each component first XORed with the matching word of the previous round's output.

```
h = Hash(data, S[0 .. w-1])                 # round 1
h = Hash(data, S[w .. 2w-1]  XOR  h)        # round 2 (feedforward)
h = Hash(data, S[2w .. 3w-1] XOR  h)        # round 3
...                                          # w = native words per round (2 / 4 / 8)
```

Two properties matter. First, the input `data` never changes across rounds; only the effective key changes. Second, each round's key is the next slice of fresh key material XORed with the entire previous output — a **feedforward** step — and the intermediate blocks between rounds are never emitted. The output depends on every key component conjunctively, and because each round's effective key embeds the previous, unobserved block, the chain cannot be peeled one round at a time. Even with an invertible primitive, inverting the last round recovers only the XOR of that round's key slice with the hidden previous block; reconstructing a hidden intermediate by search instead means enumerating a full native-width block, a meet-in-the-middle barrier the width of the primitive at every round.

This is best read as **local key evolution** — each round derives a fresh effective key from the previous state plus new key material and re-keys the same PRF over the same input. The number of rounds is the key width divided by the native state width, so a 2048-bit key folds into 16 rounds at 128-bit, 8 rounds at 256-bit, or 4 rounds at 512-bit. The wider the primitive, the fewer rounds — which is why a wider PRF is both faster and gives a wider MITM bottleneck.

| Hash width | Components/round | Rounds (at 512-bit key) | Hash calls/pixel |
|---|---|---|---|
| 128-bit | 2 | 4 | 4 |
| 256-bit | 4 | **2** | **2** |
| 512-bit | 8 | **1** | **1** |

**What ChainHash does and does not include.** ChainHash returns the full native-width block. The narrowing to 64 bits is not part of ChainHash: the per-pixel encoder consumes only the low word (`hLo` / `h[0]`) and discards the rest, and the Interlocked Barrier's per-chunk mask draw likewise keys its per-chunk PRF from the low word only. So the output narrowing at 128 / 256 / 512-bit is an encoder-layer and barrier-layer choice layered on top of ChainHash, not a property of ChainHash itself. Under the PRF assumption any consistent subset of a PRF's output is itself a PRF on those bits; the discarded portion carries no information the encoder needs.

## How it works

ITB encrypts data into raw RGBWYOPA pixel containers (8 channels per pixel: Red, Green, Blue, White, Yellow, Orange, Purple, Alpha — mnemonic labels for an 8-byte unit; the format is not tied to image processing) generated from `crypto/rand`. Each 8-bit channel carries 7 data bits and 1 noise bit, yielding 56 data bits per pixel at 1.14× overhead. Each pixel's bit-plane selection and per-channel XOR masks are derived from a ChainHash of the seed and a per-message nonce.

The data is embedded starting at a seed-dependent pixel offset with wrap-around — the physical layout in the container is completely non-sequential. The interleaved payload is then routed through the Interlocked Barrier: every 48-bit (6-byte) chunk of the payload is re-mapped into three 16-of-48 lanes by a per-chunk mask triple drawn from the ≈ 2^70.20 balanced-partition space, keyed by the lockSeed and the nonce. An observer sees uniformly random pixel values with no way to determine which pixels carry data, in what order, what bit-plane is used, or which bits of a given chunk feed which snake.

## Hash width variants

The library provides three parallel API sets for different hash output widths. All share the same pixel format, framing, and security properties — the difference is in ChainHash intermediate state width.

| API | Seeds | Hash Type | State | Effective Max Key |
|---|---|---|---|---|
| `EncryptAuthenticated3x256Cfg` / `DecryptAuthenticated3x256Cfg` | 8 | `HashFunc256` (256-bit) | 256-bit | 1024 bits |
| `EncryptAuthenticated3x512Cfg` / `DecryptAuthenticated3x512Cfg` | 8 | `HashFunc512` (512-bit) | 512-bit | 2048 bits |
| `EncryptAuthenticated3x128Cfg` / `DecryptAuthenticated3x128Cfg` | 8 | `HashFunc128` (128-bit) | 128-bit | 1024 bits |

Streaming counterparts follow the same shape with a `Stream` prefix; the width-agnostic `EncryptStreamAuth3xCfg` / `DecryptStreamAuth3xCfg` and `EncryptStream3xCfg` / `DecryptStream3xCfg` accept `any`-typed seeds and dispatch on width internally.

## Wire format

```
Offset  Size     Content
0       N        Nonce (crypto/rand, public; N = 16/32/64 bytes for 128/256/512-bit nonce)
N       2        Width (uint16 big-endian)
N+2     2        Height (uint16 big-endian)
N+4     W×H×8    Raw RGBWYOPA pixel data with embedded encrypted payload,
                 routed through the Interlocked Barrier
```

Default nonce size is 512 bits (64 bytes) — chosen so the birthday-bound on collision is beyond any realistic deployment volume without the caller having to override. Configurable down to 128 or 256 bits via `triple.Opts.NonceBits` or `*itb.Config.NonceBits`; the process-wide default lives in `itb.DefaultNonceBits` (compile-in) and is optionally overridden at process init by `ITB_NONCE_BITS`. The wire format is identical across all three hash width variants and across Single Message vs Streaming shapes at the byte level — a single-chunk stream is byte-shape-identical to a Single Message wire.

## Minimum container size

The unified CCA-resistant envelope floor `MinPixels := MinPixelsAuth` applies across both the authenticated and non-authenticated surfaces: the minimum container is `ceil(keyBits / log₂(7))` pixels, so the 7^P encoding-ambiguity floor exceeds the key space at the smallest container size, and envelope length does not distinguish the authenticated from the non-authenticated surface at the floor.

| Key size | Min pixels → container | Noise barrier |
|---|---|---|
| 1024 bits | 365 → 400 (20×20) | 2^3200 ≥ 2^1024 |
| 2048 bits | 730 → 784 (28×28) | 2^6272 ≥ 2^2048 |

## Integrity (MAC-Inside-Encrypt)

The core construction provides confidentiality only. For integrity protection against bit-flipping attacks, use the MAC-Inside-Encrypt pattern — the MAC is encrypted inside the container, preserving oracle-free deniability. On the `triple/` facade this is opt-in by profile selection (`singlemsg-triple-mac-v1` or `streaming-aead-triple-mac-v1`); on the Low-Level surface it is opt-in by choosing the `EncryptAuthenticated*` entry over the plain `Encrypt*` one.

**Important.** Never place a MAC outside the encrypted container in cleartext — this creates a verification oracle that breaks deniability.

## Eight-seed isolation

The eight mandatory seeds are drawn as independent CSPRNG components; the API surface enforces pointer-identity distinctness across all eight slots. Passing the same seed handle in two positions returns an error at call entry. The eight-seed layout is what lets the security argument treat each channel's entropy source as disjoint: mutual information between independently-drawn seeds is zero, so a structural shortcut against one primitive channel cannot leak into another's derivation.

## Security summary

| Property | ITB |
|---|---|
| Key space | Up to 2^2048 |
| Grover resistance | √P × 2^keyBits (Core / MAC + Silent Drop) to √P × 2^(keyBits/2) (MAC + Reveal) |
| Plausible deniability | Every mode (wrong seed → garbage indistinguishable from valid plaintext) |
| Encoding ambiguity | Every mode (7^P unverifiable rotation combinations, surviving CCA; CSPRNG residue adds independent ambiguity in data positions) |
| Interlocked Barrier | Always on; per-chunk 48-bit keyed permutation over three snakes; per-chunk mask space ≈ 2^70.20 balanced partitions |
| Eight-seed isolation | Every mode (noiseSeed, lockSeed, dataSeed1..3, startSeed1..3 independent) |
| Oracle-free deniability | Core ITB / MAC + Silent Drop; MAC + Reveal has a CCA oracle bounded to the noise-position channel (Proof 6) |
| Known-plaintext resistance (Crib / Full / Partial KPA) | Under the PRF assumption and fresh nonces, closed at the instance-formulation layer by the barrier's per-chunk ≈ 2^70.20 mask space + per-chunk PRF independence + 3-snake enumeration dimension + 8-seed isolation (architectural claim; empirical re-verification against the 48-bit line pending) |
| Chosen-plaintext resistance | Under the PRF assumption and fresh nonces, the always-on keyed permutation plus fresh per-message draws leave ciphertext at the statistical floor (corroborated by the pre-v0.3.0 empirical record on the shared pixel construction; empirical re-verification against the 48-bit line pending) |
| Noise absorption | Core ITB / MAC + Silent Drop; bypassed via CCA in MAC + Reveal (CSPRNG residue in data positions survives) |
| Hash function requirement | PRF required; PRF and barrier are complementary — neither sufficient alone |
| Nonce | 128/256/512-bit per-message nonce, drawn internally from `crypto/rand` on every call (default 512-bit) |
| Nonce reuse | Not architecturally closed by the barrier; closure of the CPA / KPA families is conditional on fresh nonces. The shipped API generates the nonce internally per call, which prevents caller-side reuse |
| Storage overhead | 1.14× (56 data bits per 64-bit pixel) |

## Formal security model

A simulation-based proof is a purely mathematical construction: "for every adversary A in the real world, there exists a simulator S in the ideal world such that the outputs of A and S are indistinguishable." This is proven logically, not computationally. It is independent of hardware, logic system, or computational model.

ITB does not fit cleanly into the standard binary security model:

- **Standard model.** The adversary either distinguishes (break) or does not (secure). Binary.
- **ITB.** The adversary always receives output. The output is always "valid." There is no point where the system returns accept/reject. Instead, the result is a **spectrum of plausibility** — every key produces output, and there is no way to rank candidates without external context.

The semantics of decryption are ternary:
1. Correct key → correct plaintext.
2. Wrong key → garbage indistinguishable from plaintext.
3. Observer → cannot determine which of the two cases is present.

Possible formalization paths:
- **Indistinguishability-based** definitions (standard in cryptography, binary logic — sufficient).
- **Simulation-based** proof with an ideal functionality that always returns random bytes (this is the "ideal world" of ITB — the real-world output is indistinguishable from random).
- **Quantitative information flow** (how many bits leak — the per-byte barrier shows 0 bits leaked per observation).

All three approaches use standard mathematics. The formal relationship between ITB's Ambiguity-Based Security and Shannon's framework remains an open research question (see [SCIENCE.md](SCIENCE.md)).

## Bindings

The binding surface is the **eight `ITB_Triple_*` capi exports** (see `cmd/cshared/main.go`). Every binding is a thin proxy over that surface: an FFI-stable handle table on top of `ITB_Triple_Init` / `ITB_Triple_Open` / `ITB_Triple_Close` plus the four cipher entry points (`ITB_Triple_EncryptMessage` / `ITB_Triple_DecryptMessage` / `ITB_Triple_EncryptStream` / `ITB_Triple_DecryptStream`), an error-code mapping, and an optional URL-query-style opts-string parser for the per-Pipeline overrides. The Cfg-suffixed Low-Level Go surface does **not** ship in any binding — it remains Go-native for callers who need the raw eight-seed handoff.

### Fleet plan (33 bindings)

The binding fleet lands in three logical bands. Every band consumes the same eight-export surface; the differentiation is only in transport (in-process CGO vs a small out-of-process relay).

- **Tier 1 Native (9 bindings)** — direct in-process consumers of the C shared library. C, C++, Fortran, Ada, D, Rust, C#, Python, Node.js. Each binding owns its own idiomatic surface (Streams / async / GC integration) on top of the same eight exports.
- **Tier 1 Thin (5 bindings)** — thin object-based facades over one of the Tier 1 Native bindings, adding a language-idiomatic surface with no extra ITB logic. Includes the primary BEAM binding (Erlang) plus four small companion facades.
- **Tier 2 Relay (19 bindings)** — a small out-of-process relay speaks the eight exports over one of four backends (C / Java / C# / BEAM) and hands them to a language runtime that cannot embed the C shared library directly. Every relay is a thin proxy; ITB's construction logic never lives outside the shipped Go core.

Docs describe the fleet at the architectural level while the per-binding rework lands. Every binding's public surface will read as "call Init to receive a `Pipeline` handle plus a blob byte slice, ship the blob to the receiver, both sides encrypt / decrypt" — the same user-story the Go `triple/` facade tells. Per-binding examples ship in each binding's own directory once the rework lands.

## See also

- [ITB.md](ITB.md) — How the barrier works (accessible explanation).
- [FEATURES.md](FEATURES.md) — Complete feature list and security properties.
- [PROOFS.md](PROOFS.md) — Formal security proofs.
- [SCIENCE.md](SCIENCE.md) — Scientific analysis and formal security arguments.
- [SECURITY.md](SECURITY.md) — Security reference tables.
- [HWTHREATS.md](HWTHREATS.md) — Hardware-level threat analysis (Spectre, Meltdown, Rowhammer, etc.).
- [HARNESS.md](HARNESS.md) — Adversarial testing methodology and calibration.
- [REDTEAM.md](REDTEAM.md) — Empirical Red Team validation.
- [BENCH3.md](BENCH3.md) — Benchmark tables across primitives and CPUs.
- [hashes/CONSTRUCTIONS.md](hashes/CONSTRUCTIONS.md) — Per-primitive construction descriptions.
- [macs/CONSTRUCTIONS.md](macs/CONSTRUCTIONS.md) — Per-MAC construction descriptions and the MAC-Inside-Encrypt placement argument.
- [ctr/CONSTRUCTIONS.md](ctr/CONSTRUCTIONS.md) — Per-primitive counter-mode keystream constructions.
- [kdf/CONSTRUCTIONS.md](kdf/CONSTRUCTIONS.md) — Per-primitive subkey-derivation constructions.

## License

MIT — see [LICENSE](LICENSE).
