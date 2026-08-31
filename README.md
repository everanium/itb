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

> **Security notice.** ITB is an experimental symmetric cipher
> construction without prior peer review, independent cryptanalysis, or
> formal certification. The construction's security properties have
> **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

---

A parameterized symmetric cipher construction library for Go that makes hash output unobservable under passive observation through independent barrier mechanisms: **noise absorption** (a CSPRNG random container makes hash output unobservable), **encoding ambiguity** (secret rotation yields 7^P unverifiable configurations that survive CCA), and the **Interlocked Barrier** (a per-chunk PRF-keyed 48-bit permutation over three snakes, with a per-chunk mask space of ≈ 2^70.20 balanced partitions). 8-Seed isolation ensures compromise of any one domain provides zero information about the others.

**Ambiguity-Based Security.** The number of observation-consistent *configurations* grows with data size — a property orthogonal to Shannon's key-entropy bound (distinct from Shannon's perfect-secrecy relationship on plaintext entropy; not a violation of it). The Interlocked Barrier converts known-plaintext cryptanalysis from a computational-hardness problem into an instance-formulation one under the PRF assumption: a known-plaintext crib does not fix any bit-position-to-lane mapping for a solver to anchor on.

**[Quick Start](#quick-start)**

**[How the barrier works — accessible explanation](ITB.md)**

**[Empirical Red-Team validation](REDTEAM.md)** — the shipping registry's PRF-grade primitives plus lab-only accidentally-weak controls exercised across an attacker-realistic distinguisher matrix (body-byte statistics indistinguishable from CSPRNG at 1σ over the tested plaintext-size × barrier-fill envelope), a dual-nonce related-nonce differential decomposition (three scenarios × six Δ patterns × two plaintext kinds), Crib / Full / Partial KPA under the always-on 48-bit Interlocked Barrier (anchor protection empirically confirmed on below-spec primitives, PRF-conditional throughout), a nonce-reuse decomposition (simultaneous collision requires a CSPRNG hardware fault; single-slot collision closes on the un-collided axis a fortiori), a COBS-alignment probe across the full Barrier Fill range, a direct pathological-input recovery probe (0 per-byte recoveries across the tested decoder family at 10⁶+ trial-position pairs), and structural / FFT / Markov statistical surfaces. The ChainHash construction empirically absorbs multiple trapdoor mechanism classes (structural partition, chosen-constants collision, round-reduced, accidentally-weak) via two absorption mechanisms — feedforward-depth and input-XOR keying. **SAT-based lockSeed recovery is structurally unmeasurable at attacker-realism.** All closures are instance-formulation-bounded and sample-bounded; where they invoke primitive strength, PRF-conditional.

**[Why KPA and advanced attacks are addressed by the barrier](SCIENCE.md)**

**[Scientific paper (Preprint)](https://doi.org/10.5281/zenodo.19229395)** — A. Kuvshinov, "A Symmetric Cipher Construction with Ambiguity-Based Security"

**[Discord](https://discord.gg/wRYF8shHpd)** — invite to chat with developer.

## Status

The Core API and the Go C ABI are consolidated around the `triple/` facade and the Cfg-only Low-Level surface. The 48-bit always-on barrier is engaged unconditionally on every call and its adversarial re-verification is documented in [REDTEAM.md](REDTEAM.md).

### Library

| Native | Status | Features | Tests | Packages |
|---|---|---|---|---|
| Go Native | Shipped | `triple/` facade + Cfg-only Low-Level | Passing on Intel Rocket Lake reference host | TBD |
| C ABI (`cmd/cshared`) | Shipped | `ITB_Triple_*` exports + Cfg-aware capi header | Passing on Intel Rocket Lake reference host | TBD |

<!-- preserved-verbatim: cross-platform verification block; do not paraphrase; re-runs after bindings rework produce fresh numbers -->

**Cross-platform verified.** Encrypt / Decrypt round-trip validated between x86_64 (Intel / AMD) and AArch64 (Graviton 4).

**Cross-binding interop verified.** All 34 implementations (Go Core + 33 bindings) produce byte-identical wire format and decrypt every other implementation's output.

Full matrix:
- 34 × 34 (Go Core + 33 bindings) = 1156 pairs
- 9 shipped profiles (4 Single Message, 4 Streaming, 1 blob-only)
- 1 sample file (`tools/eitb/in-file.txt`, 4 KiB, deterministic)
- **9248 cells PASS** (8 cipher-carrying profiles × 34 × 34); 1156 cells N/A (blob-only profile intentionally exposes no cipher surface)

**All features fully implemented.** Every binding is a thin proxy over the same `ITB_Triple_*` FFI surface and exposes both shapes uniformly — Single Message and Streaming, AEAD and Non-AEAD — with the stream pump adapted to each language's native IO idiom (`io.Reader` / `io.Writer` in Go, the equivalent stream abstraction per language).

**Maintenance path.** Subsequent open-source work covers bug fixes, documentation, and additional bindings only. Custom closed encryption constructions and downstream software stacks are available on commercial request.

<!-- /preserved-verbatim -->

## Why ITB

Traditional symmetric ciphers (AES, ChaCha20) place all security burden on the mathematical strength of their core primitive. The keystream is XOR'd directly with plaintext — any weakness in the primitive that surfaces on its output is immediately observable, because the attacker sees the primitive's output directly.

ITB inverts this approach. The construction interposes a **random container** (generated from `crypto/rand`) between the hash output and the observer, then re-maps each 48-bit chunk of the interleaved payload through a per-chunk PRF-keyed permutation drawn from a space of roughly 2^70.20 balanced partitions. The hash output is consumed by modifying random bytes that the attacker never sees; the mapping from plaintext bit to observed lane is itself a per-chunk secret. Two structural facts follow, both conditional on the PRF assumption and fresh per-message nonces:

- **A known-plaintext crib does not fix any bit-position-to-lane mapping for a solver to anchor on.**
- **Because the mask of each chunk is keyed independently of every other chunk, additional crib chunks multiply the attacker's enumeration rather than contributing constraints that couple chunks — the known-plaintext instance stays under-determined regardless of how much plaintext the attacker holds.** This turns known-plaintext cryptanalysis from a computational-hardness problem into an instance-formulation one: under the PRF assumption there is no unique solution for a faster solver to discover.

**Why the math is simple.** The construction uses only elementary operations: XOR, bitwise AND, modulo, bit shifts, and the per-chunk rank-unrank pair that produces the mask triple. There are no Galois fields, no S-boxes, no polynomial multiplication. The security comes from the **architecture**, not from the complexity of the math. Each architectural layer addresses a specific attack vector:

- **Random container** — hash output unobservable under passive observation (COA, KPA).
- **Per-bit XOR (1:1)** — 56 independent mask bits per pixel; every observation consistent with any plaintext.
- **Interlocked Barrier** — always-on; per-chunk PRF-keyed 48-bit permutation over three snakes; ≈ 2^70.20 mask space per chunk.
- **8-seed isolation** — noiseSeed, lockSeed, dataSeed1..3, startSeed1..3 drawn as independent CSPRNG components and keyed into separate channels, so a structural shortcut against one primitive channel cannot leak into another's derivation.
- **Noise bit embedding** — no bit position is deterministically data from the public format.

**Why the barrier and the PRF are complementary.** The PRF closes the candidate-verification step; the barrier and the surrounding architectural layers deny the point of application. Neither is sufficient alone: the architectural layers cannot resist total inversion of the primitive, and without the barrier the attacker would observe the keystream directly.

**The two-step reduction and the gcd anti-collapse trap.** The two-step reduction that draws each mask triple reaches the full partition space; the rejected same-rank alternative would have confined the draw to 1 / 66861 of that space, so full-space coverage is a deliberate property of the construction, not an accident. The reduction is deterministic and constant-time, carrying a fixed, publicly-known per-chunk deviation of about 2^-57.8 that accumulates to about 2^-34.4 over a maximum-size message; distinguishing this granularity would require on the order of 2^115.6 chunk samples, well beyond any attainable budget.

**Triple Ouroboros 3-snake split.** The plaintext is split across three interleaved snakes with independent per-snake offsets and configurations, so a single known crib maps onto three unknown-offset streams whose per-snake boundaries are not recoverable from the interleaved container. This is a distinct, composable barrier from the per-chunk mask space: the split raises the enumeration dimension while the mask space raises the per-chunk floor.

**Empirical footing.** Across a broad primitive spectrum spanning deliberately broken lab controls through paper-grade PRFs, the underlying pixel construction produced ciphertext with no distinguishable signal at the tested sample sizes on every statistical surface measured — evidence for the barrier's absorption of primitive weakness on the shared pixel construction, not a proof that no distinguisher exists.

**Threat model boundary.** The closure of the known-plaintext and chosen-plaintext families is conditional on the configured primitive behaving as a secure PRF and on fresh per-message nonces; total inversion of the primitive, or a reused nonce, is outside what the barrier is designed to close. The security properties described here are architectural arguments and self-audit evidence, not independent cryptanalysis: ITB has had no external review or formal certification, and the strong claims are stated conditionally for that reason. See [PROOFS.md](PROOFS.md), [SCIENCE.md](SCIENCE.md), and [SECURITY.md](SECURITY.md) for the full treatment.

> **Important.** ITB is an experimental construction without peer review or independent cryptanalysis. The information-theoretic barrier is a **software-level property**, reinforced by the noise absorption channel, the always-on Interlocked Barrier, and the encoding-ambiguity channel; the CCA leak surface is bounded to the noise-position channel under MAC + Reveal (see [Proof 6](PROOFS.md)). It provides no guarantees against hardware-level attacks. All security claims have not been independently verified.

## Installation

```bash
go get github.com/everanium/itb@latest
```

## Building

ITB ships two pixel-processing backends selected automatically at compile time, plus a fallback build tag for hosts that lack the assembly kernels' baseline features:

| Mode | Command | Pixel Processing | Requirements |
|---|---|---|---|
| **CGO (default)** | <code>-buildmode=c-shared</code> | C with runtime-dispatched SIMD tiers | C compiler (GCC/Clang); no minimum SIMD requirement — Tier A (AVX-512F + AVX-512BW + AVX-512VL + GFNI + AVX-512VBMI, 8-pixel batch), Tier A′ (AVX-512F + AVX-512BW + AVX-512VL without GFNI / VBMI, 8-pixel batch — Cascade Lake class), Tier B (AVX2 + GFNI, 4-pixel batch), and Tier B′ (AVX2 only, 4-pixel batch — Zen 3 / Haswell class) are selected via `__builtin_cpu_supports` at first call; hosts below all four SIMD tiers fall through to the portable scalar C path (Tier C). Leftover 4–7-pixel batches at the end of a Tier A / A′ loop route through the applicable Tier B / B′ / C helper, so a Cascade Lake host completes end-to-end as A′ + B′ + C |
| **No ITB ASM** (CGO) | <code>-buildmode=c-shared&nbsp;-tags=noitbasm</code> | C with SIMD auto-vectorization; ITB chain-absorb / Interlocked Barrier / Areion permutation ASM disabled; upstream stdlib ASM (`zeebo/blake3`, `golang.org/x/crypto`, `jedisct1/go-aes`) stays engaged | C compiler (GCC/Clang) |
| **Pure Go** | `CGO_ENABLED=0 ...` | Portable Go pipeline (`process_generic.go`) | None (any GOOS / GOARCH the Go compiler supports) |

### CPU baseline for the shipped assembly kernels

The shipped `_amd64.s` kernels target a modern x86_64 baseline. The exact CPU feature each kernel needs is detected once at package init via `golang.org/x/sys/cpu` and dispatched from there:

| Kernel | Required CPU feature | Runtime capability flag |
|---|---|---|
| Interlocked Barrier — scalar apply | BMI2 (PEXTQ / PDEPQ) | `interlock.HasBMI2` |
| Interlocked Barrier — AVX-512F rank-unrank | AVX-512F (VPERMT2Q, VPCMPUQ, VPTESTMQ, mask-merged VPSUBQ / VPORQ, VPTERNLOGQ / VPSLLQ / VPSRLQ constant synthesis on ZMM) | `interlock.HasAVX512RankMask` |
| Interlocked Barrier — AVX2 rank-unrank | AVX2 + BMI2 (VPERMD, VPCMPEQQ, VPCMPGTQ predicated ops on YMM; scalar PDEPQ remap tail) | `interlock.HasAVX2RankMask` |
| Areion-SoEM — top-tier batched permute + fused chain | VAES + AVX-512 | `areionasm.HasVAESAVX512` |
| Areion-SoEM — mid-tier per-half permute | VAES + AVX2 | `areionasm.HasVAESAVX2NoAVX512` |
| Areion-SoEM — mid-tier YMM 2-lane batched chain-absorb (`Areion*ChainAbsorb*x4VaesAvx2`) | VAES + AVX2 (no AVX-512F) | `areionasm.HasVAESAVX2Batched` |
| Areion-SoEM — AES-NI XMM 4-lane batched chain-absorb | AES-NI (AESENC / AESENCLAST on XMM) | `areionasm.HasAESNIBatched` |
| BLAKE2b — AVX-512 4-lane YMM chain-absorb + fused chain | AVX-512F | `blake2basm.HasAVX512Fused` |
| BLAKE2b — AVX2 4-lane YMM chain-absorb (synthesised rotates) | AVX2 (no AVX-512F) | `blake2basm.HasAVX2Fused` |
| BLAKE2s — AVX-512 4-lane XMM chain-absorb + fused chain | AVX-512F | `blake2sasm.HasAVX512Fused` |
| BLAKE2s — AVX2 4-lane XMM chain-absorb (synthesised rotates) | AVX2 (no AVX-512F) | `blake2sasm.HasAVX2Fused` |
| BLAKE3 — AVX-512 4-lane XMM chain-absorb + fused chain | AVX-512F | `blake3asm.HasAVX512Fused` |
| BLAKE3 — AVX2 4-lane XMM chain-absorb (synthesised rotates) | AVX2 (no AVX-512F) | `blake3asm.HasAVX2Fused` |
| AES-CMAC — batched CBC-MAC / fused chain | VAES + AVX-512 | `aescmacasm.HasVAESAVX512` |
| AES-CMAC — AES-NI XMM 4-lane batched chain-absorb | AES-NI (AESENC / AESENCLAST on XMM) | `aescmacasm.HasAESNIBatched` |
| SipHash-2-4 — AVX-512 4-lane YMM chain-absorb + fused chain | AVX-512F | `siphashasm.HasAVX512Fused` |
| SipHash-2-4 — AVX2 4-lane YMM chain-absorb | AVX2 (no AVX-512F) | `siphashasm.HasAVX2Fused` |
| ChaCha20 — AVX-512 4-lane XMM chain-absorb + fused chain (68-byte chain fuses two compressions per YMM register) | AVX-512F | `chacha20asm.HasAVX512Fused` |
| ChaCha20 — AVX2 4-lane XMM chain-absorb (synthesised rotates; 68-byte AVX2 chain also fuses two compressions per YMM) | AVX2 (no AVX-512F) | `chacha20asm.HasAVX2Fused` |

Every chain-absorb family additionally ships a 13-byte-shape kernel (`*ChainAbsorb13x4`) at each tier that batches the Interlocked Barrier per-group PRF fill derivation — four sequential group indices per call — under the family's capability flag for that tier.

Cross-referenced to shipping x86 microarchitectures:

- **Intel** — top-tier fused ZMM chain kernels are exercised end-to-end from **Rocket Lake (11th-gen, e.g. i7-11700K)** onward. Ice Lake mobile parts carry the required flags but are not the reference host. **Cascade Lake / Cooper Lake and other AVX-512-without-VAES / VBMI SKUs** engage the AVX-512F ARX chain kernels for the BLAKE / ChaCha20 / SipHash family plus the XMM AES-NI 4-lane batched kernels for Areion-SoEM and AES-CMAC, and select pixel-encoder Tier A′ (AVX-512F+BW+VL without GFNI/VBMI). **Haswell through Comet Lake** engage the AVX2 4-lane chain kernels, the AVX2 4-lane interlock rank-mask kernel, the XMM AES-NI 4-lane batched kernels, and pixel-encoder Tier B′ (AVX2 no GFNI).
- **AMD** — top-tier fused ZMM chain kernels engage from **Zen 4 onward** (server-class Zen 4 / Zen 5); pixel encoder runs Tier A (GFNI present). **Zen 3** engages the mid-tier VAES-on-YMM per-half Areion permute, the XMM AES-NI 4-lane batched chain-absorb kernels for AES-CMAC (and Areion-SoEM in tandem with the VAES YMM permute), the AVX2 4-lane BLAKE / ChaCha20 / SipHash chain kernels, the AVX2 4-lane interlock rank-mask kernel, and pixel-encoder Tier B′. **Zen 1 / Zen 2** carry AES-NI but `PEXT` / `PDEP` are microcode-emulated with data-dependent latency, so those hosts skip the Interlocked Barrier BMI2 apply kernels and take the `softPEXT48` / `softPDEP48` Go fallback there; the AVX2 chain-absorb and AES-NI batched kernels still engage.
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

`ITB_NONCE_BITS=512` sets the default on-wire nonce width in bits at process init (accepted values: `128` / `256` / `512`). Per-Pipeline overrides live in `triple.Opts.NonceBits` on the facade side and in the `*itb.Config.NonceBits` field on the Low-Level side; the env value is the compile-in default when neither override is supplied.

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

Throughput scales with data size due to goroutine parallelism across CPU cores. CGO mode uses the C pixel kernel on top of AVX-512 / AVX2 batched chain-absorb hash kernels for every PRF-grade primitive (`hashes/internal/<primitive>asm` plus `internal/areionasm` for Areion-SoEM); `CGO_ENABLED=0` swaps only the C pixel kernel for the portable Go pipeline, while the batched hash ASM stays engaged via Go assembly. Decrypt does not require `crypto/rand` and scales further on high-core-count CPUs.

### Concurrency

A single `triple.Pipeline` is safe for concurrent `EncryptStream` / `DecryptStream` / `EncryptMessage` / `DecryptMessage` calls: post-`Init` and post-`Open`, all Pipeline state relevant to encryption is read-only, and per-call state (readers, writers, per-chunk scratch inside the itb IO entry) lives on the caller's stack. `Rekey` mutates Pipeline state and must be serialised against concurrent cipher calls by the caller (see [`triple/rekey.go`](triple/rekey.go)); `Close` wipes secret material atomically and subsequent method calls return `triple.ErrClosed`.

The Low-Level free functions (`itb.Encrypt3x{128,256,512}Cfg`, `itb.EncryptAuth3x{128,256,512}Cfg`, `itb.EncryptStream3x{128,256,512}Cfg`, `itb.EncryptStreamAuth3xCfg`, and the `Decrypt` counterparts) take read-only seed pointers and a `*itb.Config` and allocate output per call — they are thread-safe under concurrent invocation on the same seeds. Concurrent mutation of the shared `*itb.Config` by other goroutines must be serialised by the caller.

## Quick Start

Six worked examples cover the surface. Four use the `triple/` facade (the shipped user-facing entry point); two use the Low-Level `*Cfg` free functions directly. Every example runs against one of the shipped profiles listed in [`triple/profile.go`](triple/profile.go):

Single-primitive profiles (one inner hash across every seed slot):

- `singlemsg-triple-mac-v1` — Single Message Triple with MAC.
- `singlemsg-triple-nomac-v1` — Single Message Triple No MAC.
- `streaming-aead-triple-mac-v1` — Streaming AEAD Triple with MAC.
- `streaming-noaead-triple-v1` — Streaming Non-AEAD Triple.
- `blob-triple-mac-v1` — MAC-authenticated blob-only bundle (no cipher surface; used by `Init` / `Rekey` to bundle session state).

Mixed-primitive profiles (per-slot primitive constellation, uniform width per profile):

- `singlemsg-triple-mac-mixed-v1` — Single Message Triple with MAC, width 128 (alternates aescmac / siphash24).
- `singlemsg-triple-nomac-mixed-v1` — Single Message Triple No MAC, width 512 (alternates areion512 / blake2b512).
- `streaming-aead-triple-mac-mixed-v1` — Streaming AEAD Triple with MAC, width 256 (spread across every shipped width-256 primitive).
- `streaming-noaead-triple-mixed-v1` — Streaming Non-AEAD Triple, width 256 (different balance from the AEAD mixed profile so paired mixed streams stay slot-distinguishable).

All shipped profiles default to **parallax on (Pre-inner ciphers) + wrapper (Outer cipher) on**; both toggles are opt-out via `triple.Opts`. Every seed component, PRF key, MAC key, and wrapper master is drawn from `crypto/rand` at `Init` time.

**The user's story.** Call `triple.Init(profile, opts)` to receive a `*triple.Pipeline` plus a `blob` byte slice. **The blob is the full session bundle** — profile identifier, both masters, and the inner Blob{N} carrying the 8-seed components + per-slot PRF keys + optional MAC material. Ship the blob to the receiver out-of-band; the receiver calls `triple.Open(profile, blob, opts)` and reconstructs the same Pipeline. Both sides then encrypt / decrypt against their Pipeline.

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

    "github.com/everanium/itb"
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

    "github.com/everanium/itb"
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

### Rekey — Rotating Parallax + Wrapper Masters

`Rekey` rotates the parallax and wrapper master keys mid-session
without touching the 8 inner seeds (which stay fixed for a
session's lifetime by construction). Only meaningful when
`opts.ParallaxOn` or `opts.WrapperOn` is set (the shipped
profiles enable both by default). Pass explicit 32-byte masters or
`nil` for CSPRNG generation; the receiver picks up the new masters
through a fresh `Pipeline.Blob()` handshake.

```go
package main

import (
    "crypto/rand"

    "github.com/everanium/itb"
    "github.com/everanium/itb/triple"
)

func main() {
    // Runtime tuning — process-global, one-shot at startup.
    itb.SetMemoryLimit(512 << 20)
    itb.SetGCPercent(20)

    enc, blob, err := triple.Init(triple.ProfileSingleMsgTripleMACV1, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer enc.Close()

    // ... some traffic through enc ...

    // Rotate masters. Pass nil for CSPRNG-generated masters, or
    // supply 32-byte slices from application key management.
    newPerm := make([]byte, 32)
    newWrap := make([]byte, 32)
    if _, err := rand.Read(newPerm); err != nil {
        panic(err)
    }
    if _, err := rand.Read(newWrap); err != nil {
        panic(err)
    }
    if err := enc.Rekey(newPerm, newWrap); err != nil {
        panic(err)
    }

    // Receiver reconstructs against the refreshed session blob.
    refreshed := enc.Blob()
    dec, err := triple.Open(triple.ProfileSingleMsgTripleMACV1, refreshed, triple.Opts{MaxWorkers: 4, NonceBits: 512})
    if err != nil {
        panic(err)
    }
    defer dec.Close()

    _ = blob // discard the pre-rekey blob; the refreshed one supersedes it
}
```

Serialise `Rekey` against concurrent cipher calls on the same
`Pipeline` — the 8 inner seeds are read-only, but the parallax
and wrapper master slots are mutated.

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
    OuterCipher:  "aescmac",     // "aescmac" = AES-128-CTR outer cipher (legacy shared-alphabet string; see wrapper/README.md)
})
```

`WithParallax` and `WithWrapper` are `*bool` so a nil pointer defers to the profile default while a non-nil pointer forces the chosen setting. Every other field takes its zero value to mean "inherit the profile default".

### Full Opts override — every knob in one block

The 4 examples above pass `triple.Opts{}` (all profile defaults). Every `triple.Opts` field can be set explicitly on a single `Init` (mirrored on `Open`); this one block collects the whole override surface in one place so the full knob set is visible from a single reference:

```go
enc, blob, err := triple.Init(triple.ProfileStreamingAEADTripleMACV1, triple.Opts{
    // Externally-supplied masters (e.g. ML-KEM decapsulation output);
    // nil = auto-generate via crypto/rand.
    PermMaster: permKeyFromKEM, // 32+ bytes
    WrapMaster: wrapKeyFromKEM, // 32+ bytes

    // Per-Pipeline Config overrides:
    NonceBits:   512,          // 128 / 256 / 512
    BarrierFill: 8,            // profile default varies
    MaxWorkers:  4,            // cap goroutines for this instance

    // Cryptographic knob overrides:
    MacName:      "hmac-blake3",
    InnerHash:    "areion512",
    KeyBits:      1024,        // integer multiple of the primitive's native hash width
    OuterCipher:  "chacha20",

    // Parallax knob overrides:
    ParallaxPalette:     []string{"aescmac", "areion512", "blake3"},
    ParallaxSegmentSize: 4093,

    // Layer toggles (three-state; nil = profile default, non-nil = force):
    WithParallax: nil, // stay with profile default (on)
    WithWrapper:  nil, // stay with profile default (on)

    // Streaming knob:
    ChunkSize: 1 << 20,        // 1 MiB (default 16 MiB per profile)
})
```

Any field left at its zero value defers to the resolved profile's default; a nil `*bool` toggle defers to the profile default while a non-nil pointer forces the chosen setting. `Open` accepts the same `Opts` shape — on the receiver side the non-toggle structural overrides (`InnerHash`, `KeyBits`, `ParallaxPalette`, etc.) are informational only, because the inner Blob{N} carries the seed material and per-instance `*itb.Config` snapshot; the two layer toggles remain effective.

### Accepted values per Opts field

| Field | Accepted value | Notes |
|---|---|---|
| `PermMaster` | `[]byte`, ≥ 32 bytes (or nil) | Externally-supplied parallax master (e.g. ML-KEM output); nil = crypto/rand auto-generate. |
| `WrapMaster` | `[]byte`, ≥ 32 bytes (or nil) | Externally-supplied wrapper master; nil = crypto/rand auto-generate. |
| `WithParallax` | `*bool` (nil / &false / &true) | Three-state override; nil = profile default (on for every shipped profile). |
| `WithWrapper` | `*bool` (nil / &false / &true) | Three-state override; nil = profile default. |
| `MaxWorkers` | `int` (0 or 1 .. `runtime.NumCPU`) | 0 = runtime.NumCPU fallback; positive = per-Pipeline goroutine cap. |
| `NonceBits` | `128` / `256` / `512` (or 0 = default) | On-wire nonce width. Default per profile. |
| `BarrierFill` | `int > 0` (or 0 = default) | CSPRNG barrier fill margin; profile default varies. |
| `ChunkSize` | `int > 0` bytes (or 0 = default) | Streaming chunk-size budget; default `itb.DefaultChunkSize` = 16 MiB. |
| `MacName` | `"kmac256"` \| `"hmac-sha256"` \| `"hmac-blake3"` | The shipped MACs (see `macs/registry.go`). Empty = profile default. Non-MAC profiles ignore. |
| `InnerHash` | one of the shipped primitive names below | Empty = profile default. |
| `MixedHashes` | `[8]string`, all slots one of the shipped primitive names below | Zero-value array (all slots empty) = profile default. When any slot is non-empty, all 8 must be non-empty, every entry's primitive width must equal the effective width, and the override wins over `InnerHash` (both dispatch paths are mutually exclusive). Slot ordering: `[0]noise [1]lock [2]data1 [3]data2 [4]data3 [5]start1 [6]start2 [7]start3`. |
| `KeyBits` | `512` / `1024` / `2048` (or 0 = default) | Integer multiple of the primitive's native hash width (128 / 256 / 512). |
| `OuterCipher` | one of the shipped primitive names below | Empty = profile default. Wrapper-off profiles ignore. |
| `ParallaxPalette` | slice of primitive names from the set below | Empty = profile default palette. Order matters — parallax dispatches per-segment by slot. |
| `ParallaxSegmentSize` | `int` in `[1, 65535]`, coprime to `504` (not divisible by 2, 3, or 7); or `0` = default | Default `4093` (prime). Sensible values: primes like `4093` / `4099` / `4111` / `4127`; any composite is fine iff coprime to 504. Parallax segment size. |

**Shipped primitive names.** The single canonical registry (see `hashes/registry.go` + `wrapper/wrapper.go` `CipherNames`) uses the same string alphabet for `InnerHash`, `OuterCipher`, and each `ParallaxPalette` entry:

```
areion256  areion512  blake2b256  blake2b512  blake2s  blake3  aescmac  siphash24  chacha20
```

**Name reuse — legacy.** The string `"aescmac"` names two different primitives depending on which field it appears in:

- `InnerHash: "aescmac"` → **AES-CMAC** (the MAC-family primitive, `hashes/registry.go`).
- `OuterCipher: "aescmac"` → **AES-128-CTR** (the stream cipher).
- `ParallaxPalette: []string{"aescmac", ... }` → **AES-128-CTR** (the stream cipher).

Every other name in the registry maps 1:1 across fields (a `blake3` `InnerHash` and a `blake3` `OuterCipher` denote the same construction — a BLAKE3 keystream). Users who reach for AES on the outer cipher path get AES-128-CTR whether they type `"aescmac"` or use the `wrapper.CipherAES128CTR` constant.

**Profile-name constants.** The shipped profiles live in [`triple/profile.go`](triple/profile.go) as string constants; call sites should use the constants rather than raw strings:

| Constant | String value | Notes |
|---|---|---|
| `triple.ProfileSingleMsgTripleMACV1` | `"singlemsg-triple-mac-v1"` | Single-primitive, width 512 |
| `triple.ProfileSingleMsgTripleNoMACV1` | `"singlemsg-triple-nomac-v1"` | Single-primitive, width 512 |
| `triple.ProfileStreamingAEADTripleMACV1` | `"streaming-aead-triple-mac-v1"` | Single-primitive, width 512 |
| `triple.ProfileStreamingNoAEADTripleV1` | `"streaming-noaead-triple-v1"` | Single-primitive, width 512 |
| `triple.ProfileBlobTripleMACV1` | `"blob-triple-mac-v1"` | Single-primitive, width 512, blob-only |
| `triple.ProfileSingleMsgTripleMACMixedV1` | `"singlemsg-triple-mac-mixed-v1"` | Mixed-primitive, width 128 |
| `triple.ProfileSingleMsgTripleNoMACMixedV1` | `"singlemsg-triple-nomac-mixed-v1"` | Mixed-primitive, width 512 |
| `triple.ProfileStreamingAEADTripleMACMixedV1` | `"streaming-aead-triple-mac-mixed-v1"` | Mixed-primitive, width 256 |
| `triple.ProfileStreamingNoAEADTripleMixedV1` | `"streaming-noaead-triple-mixed-v1"` | Mixed-primitive, width 256 |

The shipped profiles are populated at package init. Callers who need a configuration outside the shipped set install a user-defined `triple.Profile` at process init via `triple.RegisterProfile(name, p)` and reference the registered name from `triple.Init` / `triple.Open` like any shipped profile. The registered name is a wire contract with the receiver, so a profile bound to a name cannot be silently rebound — evolving a profile's shape picks a new name (typically appending `-v2`, `-v3`, …).

Name rules for `RegisterProfile`:

- Matches `^[a-z][a-z0-9-]{2,63}$` — lowercase ASCII letter start; 2–63 further ASCII lowercase letters, digits, or hyphens.
- Must not start with one of the reserved shipped-catalogue prefixes: `singlemsg-`, `streaming-`, `blob-`. User profiles pick a distinct prefix (organisation tag, application name).
- Must not already be registered; re-registration returns `triple.ErrProfileExists`.

Every `triple.Profile` field is validated fail-fast before the registration lands: `Mode` in the shipped set (`singlemsg-mac` / `singlemsg-nomac` / `streaming-aead` / `streaming-noaead` / `blob-only`); `Width` in {128, 256, 512}; `InnerHash` resolves via `hashes.Find` to a Spec whose width matches `Width` (single-primitive dispatch), OR `MixedHashes` populates all 8 slots with primitives whose width matches `Width` and `InnerHash` is empty (mixed-primitive dispatch — the two paths are mutually exclusive); `KeyBits` a positive multiple of `Width`; `MacName` (when non-empty) in `macs.Registry`; `OuterCipher` in `wrapper.CipherNames` when `WrapperOn` is true; every `ParallaxPalette` entry in `wrapper.CipherNames` and the palette size in [`parallax.MinPaletteSize`, `parallax.MaxPaletteSize`] when `ParallaxOn` is true; `ChunkSize` / `ParallaxSegmentSize` non-negative (zero defers to the compile-in default). `RegisterProfile` is safe under concurrent invocation with itself, `Init`, and `Open`.

Worked example — installing a 256-bit BLAKE3 Streaming AEAD variant and using it identically to a shipped profile:

```go
package main

import (
    "github.com/everanium/itb"
    "github.com/everanium/itb/parallax"
    "github.com/everanium/itb/triple"
)

func init() {
    // Register once at process init — a profile name is a wire
    // contract with the receiver, so both sides register the same
    // (name, Profile) pair before any Init / Open call fires.
    if err := triple.RegisterProfile("acme-triple-b3-256-v1", triple.Profile{
        Mode:                "streaming-aead",
        Width:               256,
        InnerHash:           "blake3",
        KeyBits:             1024,
        MacName:             "hmac-blake3",
        OuterCipher:         "chacha20",
        ParallaxPalette:     []string{"aescmac", "chacha20", "blake3"},
        ParallaxSegmentSize: parallax.DefaultSegmentSize,
        ChunkSize:           itb.DefaultChunkSize,
        ParallaxOn:          true,
        WrapperOn:           true,
    }); err != nil {
        panic(err)
    }
}

func main() {
    enc, blob, err := triple.Init("acme-triple-b3-256-v1", triple.Opts{})
    if err != nil {
        panic(err)
    }
    defer enc.Close()
    _ = blob // ship the blob out-of-band; receiver calls triple.Open on the same name.
}
```

Worked example — installing a mixed-primitive width-256 Streaming AEAD variant. Same shape as the single-primitive example above, with the single `InnerHash` field replaced by the 8-slot `MixedHashes` array (leaving `InnerHash` empty — the two dispatch paths are mutually exclusive). Slot ordering matches the 8-seed constellation: `[0]noise [1]lock [2]data1 [3]data2 [4]data3 [5]start1 [6]start2 [7]start3`.

```go
package main

import (
    "github.com/everanium/itb"
    "github.com/everanium/itb/parallax"
    "github.com/everanium/itb/triple"
)

func init() {
    // Register once at process init — the profile name is a wire
    // contract with the receiver, so both sides register the same
    // (name, Profile) pair before any Init / Open call fires. The
    // mixed constellation is a per-slot primitive assignment that
    // spreads dispatch across several width-256 primitives on one
    // Pipeline; every slot's primitive width must equal Profile.Width
    // (fail-fast at RegisterProfile via validateMixedHashes).
    if err := triple.RegisterProfile("acme-triple-mixed-256-v1", triple.Profile{
        Mode:                "streaming-aead",
        Width:               256,
        // InnerHash left empty — mixed dispatch reads MixedHashes.
        KeyBits:             1024,
        MacName:             "hmac-blake3",
        OuterCipher:         "chacha20",
        ParallaxPalette:     []string{"aescmac", "chacha20", "blake3"},
        ParallaxSegmentSize: parallax.DefaultSegmentSize,
        ChunkSize:           itb.DefaultChunkSize,
        ParallaxOn:          true,
        WrapperOn:           true,
        MixedHashes: [8]string{
            "areion256", "blake3", "blake2b256", "blake2s",   // noise, lock, data1, data2
            "chacha20", "areion256", "blake3", "blake2b256",  // data3, start1, start2, start3
        },
    }); err != nil {
        panic(err)
    }
}

func main() {
    enc, blob, err := triple.Init("acme-triple-mixed-256-v1", triple.Opts{})
    if err != nil {
        panic(err)
    }
    defer enc.Close()
    _ = blob // ship the blob out-of-band; receiver calls triple.Open on the same name.
}
```

The same mixed constellation can also be applied per-call against any single-primitive or mixed base profile without registering a new name — pass an 8-slot array as `Opts.MixedHashes` to `triple.Init` / `triple.Open`, and both sides use it in place of the base profile's default:

```go
// ProfileStreamingAEADTripleMACV1 is width 512; override slots must
// all resolve to width-512 primitives (validated fail-fast at Init).
override := [8]string{
    "areion512", "blake2b512", "areion512", "blake2b512",
    "areion512", "blake2b512", "areion512", "blake2b512",
}
enc, blob, err := triple.Init(triple.ProfileStreamingAEADTripleMACV1, triple.Opts{
    MixedHashes: override, // switch to mixed for this Pipeline only
})
// ... receiver on the other side calls triple.Open with the same MixedHashes.
```

Every mixed-hash slot is validated fail-fast at registration: each name must resolve via `hashes.Find`, each primitive's width must equal the profile's `Width`, and every one of the 8 slots must be populated (partial fills are refused rather than defaulted per slot). A typo in a primitive name or a width mismatch surfaces at process init with a descriptive error naming the offending slot, so a misconfigured mixed profile never reaches the encrypt path.

`triple.Opts` also carries a per-call `MixedHashes [8]string` override — the same field name and semantics as `Profile.MixedHashes`, but supplied at `Init` / `Open` time instead of at registration. A zero-value array defers to the profile default; a fully-populated array switches this Pipeline to the given constellation without a separate `RegisterProfile` call. The four shipped mixed profiles above are referenced by their constants exactly like the shipped single-primitive profiles, no separate wiring is required; the `Opts.MixedHashes` override is the escape hatch for callers who want a mixed shape only for one Pipeline instance rather than as a stable named profile.

Every per-call slot goes through the same `hashes.Find` / width-match fail-fast validation the profile-registration path uses (via `allocEightSeedsMixed` at `Init` / `importInnerBlobMixed` at `Open`), so a typo'd primitive name or a width mismatch surfaces at `Init` time with an error naming the offending slot. When both `Opts.InnerHash` and `Opts.MixedHashes` are set, `MixedHashes` wins and `InnerHash` is ignored — same mutual-exclusion rule the `Profile` fields obey. `Open` must be called with the same override the sender used at `Init`, so both sides reconstruct the identical effective shape.

C-ABI callers install a persistent profile via `ITB_Triple_RegisterProfile(name, opts)` — `opts` is a URL-query-encoded profile-shape string with the same keys the shipped opts parser accepts, plus profile-only fields (`mode`, `width`, `parallaxOn`, `wrapperOn`). The mixed-primitive dispatch is selected by supplying `innerHashes=<comma-separated 8-entry list>` in place of `innerHash=<name>` (the two are mutually exclusive, mirroring the Go-side `MixedHashes` / `InnerHash` split); slot ordering matches the Go-side array. The duplicate-name path maps to `ITB_ERR_PROFILE_EXISTS`; every other validation failure maps to `ITB_ERR_BAD_INPUT`. The same `innerHashes=<list>` key is also accepted by the per-call opts string passed to `ITB_Triple_Init(name, opts)` / `ITB_Triple_Open(name, opts)`, giving bindings the per-call `Opts.MixedHashes` override at the FFI boundary without any binding-side code change — every existing raw-key escape hatch (`itb_opts_set` / `withRaw` / `with_raw` / equivalent) already carries the new key end-to-end.

## Advanced — Low-Level `*Cfg` surface

The `triple/` facade is the recommended entry point. Callers who need the raw 8-seed handoff — for custom key management, unusual PRF combinations, or in-process integration with existing seed material — consume the Low-Level `*Cfg` free functions directly. Every Low-Level entry takes an explicit `*itb.Config` (`nil` accepts all compile-in defaults); the process-wide setter surface has been retired.

### Low-Level 1 — Single Message with MAC

Message-shape variant using `itb.EncryptAuth3x256Cfg` / `itb.DecryptAuth3x256Cfg`. The pattern mirrors the 256-bit-width variant; substitute `128Cfg` or `512Cfg` when the primitive width changes. 8 typed seeds map to the canonical slot order (noise, lock, data1..3, start1..3); pairwise distinctness (byte-level `Components` comparison plus pointer identity) is enforced at the call site.

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

    // 8 independent CSPRNG-keyed Areion-SoEM-256 paired closures.
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

    wire, err := itb.EncryptAuth3x256Cfg(
        cfg,
        ns, ls, ds1, ds2, ds3, ss1, ss2, ss3,
        plaintext, macFunc,
    )
    if err != nil {
        panic(err)
    }

    plain, err := itb.DecryptAuth3x256Cfg(
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

### Low-Level 2 — Streaming AEAD (MAC Authenticated, IO-Driven)

Stream-shape variant using the `any`-seed IO-Driven entry `itb.EncryptStreamAuth3xCfg` / `itb.DecryptStreamAuth3xCfg`. The 8 seeds pass in as `any` handles — the entry point dispatches on width internally, so `*itb.Seed128`, `*itb.Seed256`, and `*itb.Seed512` seeds all flow through the same IO surface.

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

**User-Driven Loop counterpart.** Callers who prefer to drive the read / write loop from their own code (external control over chunk granularity, back-pressure, or interleaved work between chunks) use the typed User-Driven Loop entries `itb.EncryptStreamAuth3x{128,256,512}Cfg(cfg, 8 seeds, data, chunkSize, mac, emit func([]byte) error)`, `itb.EncryptStream3x{128,256,512}Cfg(cfg, 8 seeds, data, chunkSize, emit func([]byte) error)` and their `Decrypt` counterparts. The `emit` callback receives each wire chunk as it lands; the caller is responsible for framing, back-pressure, and disposition. The IO-Driven and User-Driven Loop variants produce identical on-wire bytes.

### Custom user-supplied primitives

A user primitive is pluggable at the Low-Level surface in two shapes.

- **Closure-directly-passed.** Construct `itb.HashFunc{N}` (single-call) and `itb.BatchHashFunc{N}` (batched-arm) closures per seed slot and pass them directly to the `*Cfg` Low-Level entry point. The primitive is responsible for its own keying and pooling; ITB's per-pixel dispatcher wires both arms through the seed's `Hash` and `BatchHash` fields. The primitive stays local to the constructing call site — `hashes.Find` does not resolve it.
- **Registered by name via `hashes.Register(spec hashes.Spec) error`.** The custom primitive gains a canonical name that the `hashes.Find` / `hashes.Make{N}` / `hashes.Make{N}Pair` dispatchers resolve alongside shipped entries. The Spec carries `Name` (lowercase letters, digits, underscores; capped at `hashes.MaxNameLen = 12` characters — the cap matches `parallax.MaxCipherNameLen` so the registered primitive fits `"<name>:<index>"` inside a 16-byte 128-bit-PRF input block if the caller later wires it into a parallax palette entry), `Width` (`W128` / `W256` / `W512`), and exactly one `Make{N}Pair` factory field matching the width. Registration is process-wide, appended after the shipped Registry in `hashes.AllPrimitives`, and immutable — a second `Register` for the same name returns `hashes.ErrHashExists`. The shipped `hashes.Registry` itself is untouched, so the FFI iteration surface (`ITB_HashName` / `ITB_HashWidth`) is unaffected. `hashes.Register` is a Go-native API only; bindings are triple-only and do not expose custom-primitive plug.

The registered path composes with the `triple.Pipeline` facade: `triple.Init(profile, opts)` selects primitives by name via `hashes.Find`, so a registered name is reachable through the same facade the shipped primitives use. Closure-directly-passed primitives are reachable only through the Low-Level `*Cfg` entry points.

```go
import (
    "crypto/sha256"

    "github.com/everanium/itb"
    "github.com/everanium/itb/hashes"
)

func init() {
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
```

### Runtime tuning (memory / GC)

Go-native callers reach the Go runtime memory / GC pacing knobs through `itb.SetMemoryLimit(N)` and `itb.SetGCPercent(P)`. Both are **process-global** — they call directly into `runtime/debug.SetMemoryLimit` and `runtime/debug.SetGCPercent` and therefore affect the entire Go runtime, including every concurrently-running `triple.Pipeline` (or Low-Level `*Cfg` call) in the same process. They are orthogonal to any per-Pipeline configuration on `*itb.Config` / `triple.Opts`; the Pipeline knobs govern per-instance encryption behaviour, not the runtime's heap-size or GC-trigger pacing. Pass `-1` to either setter to query the current value without changing it.

Bindings drive the same knobs over the C ABI via `ITB_SetMemoryLimit` and `ITB_SetGCPercent` (see `cmd/cshared/main.go`). Both mirror the Go signatures — `int64` limit in bytes, `int` percent — and negative arguments query without mutating.

Both knobs are additionally readable from the environment at libitb load time via `ITB_GOMEMLIMIT` and `ITB_GOGC` (see [Memory](#memory)); any subsequent programmatic setter call from Go-native code or a binding overrides the env-set value.

**Per-Pipeline memory / GC control is not available.** The Go runtime does not expose per-goroutine or per-object memory-limit / GC-percent scopes, so the setters cannot be scoped to one `Pipeline` while another Pipeline in the same process observes a different setting. Applications that need distinct heap regimes for distinct workloads run them in separate processes.

The `triple/` package does not re-export these setters; Go-native users who wire a `triple.Pipeline` and want the runtime tuners in the same call site `import "github.com/everanium/itb"` alongside `import "github.com/everanium/itb/triple"` to reach `itb.SetMemoryLimit` / `itb.SetGCPercent` directly.

## Hash primitives (`hashes/`)

The `hashes/` subpackage ships **paired** cached factories for every PRF-grade primitive on the FFI surface. Each `<Primitive>Pair()` factory pre-keys its primitive once at construction and returns a `(single, batched, key)` triple. The batched arm wires the AVX-512 batched chain-absorb dispatch through `Seed.BatchHash` automatically; a `sync.Pool` amortises per-call scratch allocation. A `<Primitive>PairWithKey` counterpart takes the fixed key as a single non-variadic argument for explicit-key call sites.

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

See [hashes/CONSTRUCTIONS.md](hashes/CONSTRUCTIONS.md) for per-primitive construction descriptions (how each registry name wraps its underlying RFC / NIST primitive, where the wrappers diverge from the canonical specification, and why).

## MACs (`macs/`)

The `macs/` subpackage ships three MAC primitives with a fixed 32-byte tag and FFI-stable index order. All three pre-key the primitive once at construction and are safe to call concurrently. Each MAC also carries an incremental multi-slice arm (`MACIncrementalFunc`, name-keyed via `macs.MakeIncremental`) that the authenticated entry points use to absorb the MAC input parts directly instead of concatenating them into a scratch buffer first — wired automatically by `triple.Init` / `triple.Open`, worth roughly +7.5% end-to-end decrypt throughput on the hmac-blake3 default profile at 16 MB.

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

**What ChainHash does and does not include.** ChainHash returns the full native-width block. The narrowing is not part of ChainHash: the per-pixel encoder consumes only the low word (`hLo` / `h[0]`) and discards the rest, while the Interlocked Barrier's per-chunk mask draw consumes the full 128-bit `HashFunc128` output pair `(lo, hi)` as the rank input to `rankToMaskTriple48` — both words are load-bearing. So the output narrowing at 128 / 256 / 512-bit is an encoder-layer and barrier-layer choice layered on top of ChainHash, not a property of ChainHash itself. Under the PRF assumption any consistent subset of a PRF's output is itself a PRF on those bits; the discarded portion carries no information the encoder or the barrier's mask-triple unrank needs.

## How it works

ITB encrypts data into raw RGBWYOPA pixel containers (8 channels per pixel: Red, Green, Blue, White, Yellow, Orange, Purple, Alpha — mnemonic labels for an 8-byte unit; the format is not tied to image processing) generated from `crypto/rand`. Each 8-bit channel carries 7 data bits and 1 noise bit, yielding 56 data bits per pixel at 1.14× overhead. Each pixel's bit-plane selection and per-channel XOR masks are derived from a ChainHash of the seed and a per-message nonce.

The data is embedded starting at a seed-dependent pixel offset with wrap-around — the physical layout in the container is completely non-sequential. The interleaved payload is then routed through the Interlocked Barrier: every 48-bit (6-byte) chunk of the payload is re-mapped into three 16-of-48 lanes by a per-chunk mask triple drawn from the ≈ 2^70.20 balanced-partition space, keyed by the lockSeed and the nonce. An observer sees uniformly random pixel values with no way to determine which pixels carry data, in what order, what bit-plane is used, or which bits of a given chunk feed which snake.

## Hash width variants

The library provides three parallel API sets for different hash output widths. All share the same pixel format, framing, and security properties — the difference is in ChainHash intermediate state width.

| API | Seeds | Hash Type | State | Effective Max Key |
|---|---|---|---|---|
| `EncryptAuth3x256Cfg` / `DecryptAuth3x256Cfg` | 8 | `HashFunc256` (256-bit) | 256-bit | 1024 bits |
| `EncryptAuth3x512Cfg` / `DecryptAuth3x512Cfg` | 8 | `HashFunc512` (512-bit) | 512-bit | 2048 bits |
| `EncryptAuth3x128Cfg` / `DecryptAuth3x128Cfg` | 8 | `HashFunc128` (128-bit) | 128-bit | 1024 bits |

Streaming counterparts follow the same shape with a `Stream` prefix; the width-agnostic `EncryptStreamAuth3x{128,256,512}Cfg` / `DecryptStreamAuth3x{128,256,512}Cfg` and `EncryptStream3x{128,256,512}Cfg` / `DecryptStream3x{128,256,512}Cfg` accept `any`-typed seeds and dispatch on width internally.

## Wire format

```
Offset  Size     Content
0       N        Main nonce (crypto/rand, public; N = 16/32/64 bytes for 128/256/512-bit nonce)
N       N        Interlock nonce (crypto/rand, public; drawn independently; symmetric in width with the main nonce)
2N      2        Width (uint16 big-endian)
2N+2    2        Height (uint16 big-endian)
2N+4    W×H×8    Raw RGBWYOPA pixel data with embedded encrypted payload,
                 routed through the Interlocked Barrier
```

Default nonce size is 512 bits (64 bytes) — chosen so the birthday-bound on collision is beyond any realistic deployment volume without the caller having to override. Configurable down to 128 or 256 bits via `triple.Opts.NonceBits` or `*itb.Config.NonceBits`; the process-wide default lives in `itb.DefaultNonceBits` (compile-in) and is optionally overridden at process init by `ITB_NONCE_BITS`. The wire format is identical across all three hash width variants and across Single Message vs Streaming shapes at the byte level — a single-chunk stream is byte-shape-identical to a Single Message wire.

## Minimum container size

The unified CCA-resistant envelope floor `MinPixels := MinPixelsAuth` applies across both the authenticated and non-authenticated surfaces: the minimum container is `ceil(keyBits / log₂(7))` pixels, so the 7^P encoding-ambiguity floor exceeds the key space at the smallest container size, and envelope length does not distinguish the authenticated from the non-authenticated surface at the floor.

| Key size | Min pixels → container | Noise barrier |
|---|---|---|
| 512 bits  | 183 → 196 (14×14) | 2^1568 ≥ 2^512 |
| 1024 bits | 365 → 400 (20×20) | 2^3200 ≥ 2^1024 |
| 2048 bits | 730 → 784 (28×28) | 2^6272 ≥ 2^2048 |

## Integrity (MAC-Inside-Encrypt)

The core construction provides confidentiality only. For integrity protection against bit-flipping attacks, use the MAC-Inside-Encrypt pattern — the MAC is encrypted inside the container, preserving oracle-free deniability. On the `triple/` facade this is opt-in by profile selection (`singlemsg-triple-mac-v1` or `streaming-aead-triple-mac-v1`); on the Low-Level surface it is opt-in by choosing the `EncryptAuth*` entry over the plain `Encrypt*` one.

**Important.** Never place a MAC outside the encrypted container in cleartext — this creates a verification oracle that breaks deniability.

## 8-Seed isolation

The 8 mandatory seeds are drawn as independent CSPRNG components; the API surface enforces pairwise distinctness across all 8 slots by byte-level `Components` comparison in addition to pointer identity, so both the same seed handle passed twice and two byte-identical seed handles (reachable through blob import or the Low-Level constructors) are rejected on the same gate at call entry. The 8-seed layout is what lets the security argument treat each channel's entropy source as disjoint: mutual information between independently-drawn seeds is zero, so a structural shortcut against one primitive channel cannot leak into another's derivation.

## Security summary

| Property | ITB |
|---|---|
| Key space | Up to 2^2048 |
| Grover resistance | √P × 2^keyBits (Core / MAC + Silent Drop) to √P × 2^(keyBits/2) (MAC + Reveal) |
| Plausible deniability | Every mode (wrong seed → garbage indistinguishable from valid plaintext) |
| Encoding ambiguity | Every mode (7^P unverifiable rotation combinations, surviving CCA; CSPRNG residue adds independent ambiguity in data positions) |
| Interlocked Barrier | Always on; per-chunk 48-bit keyed permutation over three snakes; per-chunk mask space ≈ 2^70.20 balanced partitions |
| 8-seed isolation | Every mode (noiseSeed, lockSeed, dataSeed1..3, startSeed1..3 independent) |
| Oracle-free deniability | Core ITB / MAC + Silent Drop; MAC + Reveal has a CCA oracle bounded to the noise-position channel (Proof 6) |
| Known-plaintext resistance (Crib / Full / Partial KPA) | Under the PRF assumption and fresh nonces, closed at the instance-formulation layer by the barrier's per-chunk ≈ 2^70.20 mask space + per-chunk PRF independence + 3-snake enumeration dimension + 8-seed isolation (architectural claim) |
| Chosen-plaintext resistance | Under the PRF assumption and fresh nonces, the always-on keyed permutation plus fresh per-message draws leave ciphertext at the statistical floor (architectural claim) |
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
- **Simulation-based** proof with an ideal functionality that always returns random bytes: the noise-absorption layer's output is information-theoretically indistinguishable from random under passive observation (Theorem 1), and computationally indistinguishable from a CSPRNG-generated cover under the PRF and CSPRNG assumptions.
- **Quantitative information flow**: the per-byte noise-absorption barrier leaks 0 bits about the hash output per observation under COA / KPA (Theorem 1 marginal uniformity + Theorem 2 candidate equiprobability); under CCA the noise position leaks 3 bits per pixel from noiseSeed (Theorem 6), bounded to that channel — dataSeed, lockSeed, and startSeed channels remain unaffected.

All three approaches use standard mathematics. The formal relationship between ITB's Ambiguity-Based Security and Shannon's framework remains an open research question (see [SCIENCE.md](SCIENCE.md)).

## Bindings

The binding surface is the **`ITB_Triple_*` capi shim** (see `cmd/cshared/main.go`) — ten entries today: the lifecycle quad `ITB_Triple_Init` / `ITB_Triple_Open` / `ITB_Triple_Rekey` / `ITB_Triple_Close`, the handle-helper `ITB_Triple_Free`, the four cipher entry points `ITB_Triple_EncryptMessage` / `ITB_Triple_DecryptMessage` / `ITB_Triple_EncryptStream` / `ITB_Triple_DecryptStream`, and the profile-registry entry `ITB_Triple_RegisterProfile` that installs a user-defined profile shape via a URL-query opts string. Every binding is a thin proxy over that surface: an FFI-stable handle table on top of the lifecycle entries, an error-code mapping over `ITB_LastError`, and an optional URL-query-style opts-string parser for the per-Pipeline overrides. The Cfg-suffixed Low-Level Go surface does **not** ship in any binding — it remains Go-native for callers who need the raw 8-seed handoff.

### Fleet plan (33 bindings)

The binding fleet landed in two logical bands. Every band is a thin proxy over the same `ITB_Triple_*` shim surface; the differentiation is only in transport (in-process CGO vs a small out-of-process relay).

- **Tier 1 Thin (14 bindings)** — direct in-process consumers of the C shared library. C, C++, Fortran, Ada, D, Rust, C#, Python, Node.js plus four small companion facades and the primary BEAM binding (Erlang). Each binding is a thin proxy: a language-idiomatic handle-lifetime wrapper + Opts URL-query builder + FFI shims for the `ITB_Triple_*` exports + status-code table + language-native `io.Reader` / `io.Writer` adapters for the stream-pump surface. Zero ITB construction logic; every hash-name / MAC-name / cipher-name / profile-name is an opaque string passed through to Go for validation.
- **Tier 2 Relay (19 bindings)** — a small out-of-process relay speaks the `ITB_Triple_*` shim over one of four backends (C / Java / C# / BEAM) and hands it to a language runtime that cannot embed the C shared library directly. Every relay is a thin proxy of a thin proxy; ITB's construction logic never lives outside the shipped Go core.

Docs describe the fleet at the architectural level while the per-binding rework lands. Every binding's public surface will read as "call Init to receive a `Pipeline` handle plus a blob byte slice, ship the blob to the receiver, both sides encrypt / decrypt" — the same user-story the Go `triple/` facade tells. Per-binding examples ship in each binding's own directory once the rework lands.

### Fleet listing

The complete per-language fleet listing — 34 rows with directory paths, tiers, target package registries, and future install commands — lives in [`bindings/README.md#fleet-listing`](bindings/README.md#fleet-listing) to keep the root README compact.

## See also

- [FAQ.md](FAQ.md) — Plain-language analytical walkthrough of the most-asked cryptanalytic scenarios (jokeHash, CRC128, FNV-1a) under the shipped barrier.
- [ITB.md](ITB.md) — How the barrier works (accessible explanation) and shipped feature reference.
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
