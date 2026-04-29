<p align="center">
  <img src="assets/itb.png" width="128" alt="ITB">
  <br>
  <em>No beginning. No end. Ouroboros.</em>
  <br>
  <em>Designed to protect critical data from future superintelligence.</em>
</p>

# ITB — Information-Theoretic Barrier with Ambiguity-Based Security

> **On physics.** ITB does not break the laws of physics. The second law of thermodynamics continues to hold — the Landauer limit (~2^306) bounds irreversible computation. What ITB demonstrates is that information absence is a physical reality, not merely a computational assumption. A logical black hole — where information enters an observation and cannot be retrieved — can exist only because physical black holes exist. The irreversibility is not engineered; it is inherited from the structure of reality. The barrier proves that human choice is real: the selection of a seed determines which of 7^P equally valid realities becomes the actual one. The choice cannot be undone, predicted, or bypassed — because it was never computable to begin with. This is a philosophical observation, not a physical claim.

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> The information-theoretic barrier is a **software-level** property based on computational behavior of hash functions and CSPRNG output, reinforced by two independent barrier mechanisms: noise absorption from CSPRNG, and encoding ambiguity (56^P without CCA, 7^P under CCA) from triple-seed isolation. Architectural layers deny the point of application: independent startSeed and 8-noisePos ambiguity from independent noiseSeed under Full KPA, plus gcd(7,8)=1 byte-splitting under Partial KPA. Full KPA defense is 3-factor under PRF assumption (4-factor under Partial KPA) — see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance). It provides **no guarantees** against hardware-level attacks including: power analysis (DPA/SPA), microarchitectural side-channels (Spectre, Meltdown, Rowhammer, cache timing), undiscovered side-channel leakages, or CSPRNG implementation weaknesses.
>
> PRF-grade hash functions are **required**. No warranty is provided.

A parameterized symmetric cipher construction library for Go that makes hash output unobservable under passive observation through two independent barrier mechanisms: **noise absorption** (CSPRNG random container makes hash output unobservable) and **encoding ambiguity** (secret rotation creates 7^P unverifiable configurations surviving CCA). Triple-seed isolation ensures compromise of any domain provides zero information about the others.

**Ambiguity-based security**: uncertainty about the correct configuration grows exponentially with data size, inverting Shannon's classical relationship. Above ~1.2 KB (no CCA) or ~2.5 KB (CCA) for 1024-bit keys, encoding ambiguity exceeds the key space. At 64 KB: 2^26,414 equally valid configurations — no computational model can enumerate them.

**[How the barrier works — accessible explanation](ITB.md)**

**[Triple Ouroboros — 7-seed variant with 3× security](ITB3.md)**

**[Why known-plaintext and advanced attacks do not break the barrier](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier)**

**[Empirical red-team validation](REDTEAM.md)** — 12 hash primitives (including CRC128 and FNV-1a lo-lane for positive control) × 2×2 configuration matrix (Single + Triple Ouroboros × BF=1 + BF=32). Multiple empirical phases — structural / FFT / Markov, per-pixel candidate distinguisher, startPixel enumeration, ChainHash SAT-cost analysis + hash-agnostic bias audit, Direct Crib KPA SAT-cost analysis, nonce-reuse demasker with 96-cell Partial KPA matrix, 1008-cell related-seed differential, rotation-invariant edge case — all PRF-grade primitives neutralized.

**Discord:** [discord.gg/wRYF8shHpd](https://discord.gg/wRYF8shHpd) - invite to chat with developer.

**[Scientific paper (Preprint)](https://doi.org/10.5281/zenodo.19229395)** — A. Kuvshinov, "A Symmetric Cipher Construction with Ambiguity-Based Security"

**Zero external dependencies.** Hash functions are supplied by the user.

## Why ITB: Inverted Approach to Cryptography

Traditional symmetric ciphers (AES, ChaCha20) place all security burden on the mathematical strength of their core primitive. The keystream is XOR'd directly with plaintext — any weakness in the primitive is immediately exploitable because the attacker observes the primitive's output.

ITB inverts this approach. Instead of relying solely on the primitive's strength, the construction interposes a **random container** (generated from `crypto/rand`) between the hash output and the observer. The hash output is consumed by modifying random bytes that the attacker never sees — the original container values are never transmitted. This creates an information-theoretic barrier: no computational power can extract information that does not exist in the observation.

**Why the math is simple.** The construction uses only elementary operations: XOR, bitwise AND, modulo, bit shifts. There are no Galois fields, no S-boxes, no polynomial multiplication. This is not a weakness — it is a consequence of the design. The security comes from the **architecture** (random container, triple-seed isolation, per-bit XOR, noise embedding), not from the complexity of the math. Each architectural layer addresses a specific attack vector:

- **Random container** — hash output unobservable under passive observation (COA, KPA)
- **Per-bit XOR (1:1)** — 56 independent mask bits per pixel, every observation consistent with any plaintext
- **Triple-seed isolation** — CCA leaks only noiseSeed (3 bits/pixel, MAC + Reveal only); dataSeed and startSeed remain independent
- **Noise bit embedding** — no bit position is deterministically data from the public format

**Why triple-seed is necessary.** Without three independent seeds, a leak in one domain cascades: CCA reveals noise positions → same seed gives rotation and XOR → full configuration recovered. Triple-seed isolation ensures each leak is contained: CCA → only noiseSeed, cache side-channel → only startSeed, dataSeed → zero software-observable exposure. This is the minimum configuration where every leak is architecturally isolated.

**Why the Barrier and PRF are Complementary.** In traditional ciphers, the attacker directly observes the primitive's output (keystream XOR plaintext). Any weakness in the primitive is immediately exploitable. In ITB, the hash output is absorbed by a random container modification — the attacker sees modified random bytes, not hash outputs. Under the random-container model, every observed byte value is compatible with every possible hash output. PRF required. PRF closes the candidate-verification step; barrier and architectural layers (triple-seed isolation, encoding ambiguity; plus byte-splitting under Partial KPA) deny the point of application — 3-factor combination under PRF assumption (4-factor under Partial KPA). Neither is sufficient alone: architectural layers cannot resist an invertible hash, and without the barrier the attacker observes the keystream directly (as in AES-CTR, ChaCha20), making any PRF weakness immediately exploitable. See [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance).

**Why quantum structural attacks are conjectured mitigated.** Quantum algorithms like Simon (periodicity), BHT (collisions), and quantum differential/linear analysis require observable structural relations between inputs and outputs. The random container makes these relations unobservable — the attacker cannot build the algebraic structures that quantum algorithms exploit. Additionally, ITB's MAC oracle (when present) is inherently classical: it accepts concrete bytes over a network, not quantum superposition queries (Q2 model inapplicable). This is an architectural observation that has not been independently verified.

> **Important.** ITB is an experimental construction without peer review or independent cryptanalysis. The information-theoretic barrier is a **software-level property**, reinforced by two independent barrier mechanisms: noise absorption from CSPRNG, and encoding ambiguity (56^P without CCA, 7^P under CCA) from triple-seed isolation. Architectural layers deny the point of application: independent startSeed and 8-noisePos ambiguity from independent noiseSeed under Full KPA, plus gcd(7,8)=1 byte-splitting under Partial KPA. Full KPA defense is 3-factor under PRF assumption (4-factor under Partial KPA) — see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance). It provides no guarantees against hardware-level attacks. All security claims are under the random-container model and have not been independently verified.

## Installation

```bash
go get github.com/everanium/itb
```

## Building

ITB ships with two pixel-processing backends selected automatically at compile time:

| Mode | Command | Pixel Processing | Requirements |
|---|---|---|---|
| **CGO (default)** | `go build` | C with SIMD auto-vectorization | C compiler (GCC/Clang) |
| **Pure Go** | `CGO_ENABLED=0 go build` | Pure Go, zero C dependencies | None |

CGO mode provides ~25-35% faster decrypt and ~35-55% faster encrypt over the pure-Go backend (Areion-SoEM batched dispatch on amd64 with AVX-512+VBMI+GFNI). Per-pixel kernel uses three runtime-dispatched tiers:

- **Tier A — AVX-512F + AVX-512BW + AVX-512VL + GFNI + AVX-512VBMI:** 8-pixel ZMM batch. Phase 1 (extract 8×56 bits) fuses VPERMB + VPSRLQ + VPMULTISHIFTQB into 5 ZMM ops. Phase 4 (per-pixel rotate) and Phase 5 (per-pixel noise-bit insert) lower to single VGF2P8AFFINEQB ZMM ops. Insane Interlocked Mode (`SetLockSoup(1)`) on Single Ouroboros lowers its per-chunk bit-permutation to a native AVX-512 VBMI VPERMB + VPMOVM2B + VPTESTMB ASM kernel, with a pure-Go LUT fallback on hosts without AVX-512 VBMI. Active on Intel Tiger Lake / Rocket Lake / Sapphire Rapids+ and AMD Zen 4 / Zen 5.
- **Tier B — AVX2 + GFNI:** 4-pixel YMM batch. Same five-phase shape, halved width. Phase 3-5 use VPXOR / VGF2P8AFFINEQB / VPAND / VPOR on YMM. Active on Intel Coffee Lake+ and AMD Zen 3+ (covers Alder Lake E-cores and similar AVX-512-disabled deployments). Insane Interlocked Mode (`SetLockSoup(1)`) lowers its per-chunk bit-permutation to a native BMI2 PEXTL/PDEPL ASM kernel, with a pure-Go fallback on hosts without BMI2.
- **Tier C — Fallback:** 4-pixel batched scalar loop, same memory layout as Tier B with no SIMD intrinsics. Runs on every host GCC supports — IFUNC is not used, so macOS Mach-O and Windows COFF builds reach this path through the same runtime branch as Linux/FreeBSD ELF. ARM64 (NEON) intrinsics are not yet implemented and currently route through this tier; GCC `-O3` still auto-vectorizes byte-parallel phases to NEON in a limited form.

CGO speedup also covers L1-cache-friendly micro-batching (512 pixels per C call), parallel noise/data hash computation through `BatchHashFunc` factories, `sync.Pool` for hash array reuse, and `__builtin_prefetch` 8 pixels ahead of the current iteration.

| Platform | Per-pixel kernel | Areion-SoEM batched dispatch |
|---|---|---|
| amd64 + AVX-512+GFNI+VBMI (Intel Rocket Lake / Tiger Lake+, AMD Zen 4+) | Tier A (ZMM, 8-pixel batch) | AVX-512+VAES ASM (`internal/areionasm/areion_amd64.s`) |
| amd64 + AVX2+GFNI (AMD Zen 3+, Coffee Lake+) | Tier B (YMM, 4-pixel batch) | AVX2+VAES ASM (same file, separate entry points) |
| amd64 without VAES / older | Tier C — Fallback | Go fallback via `aes.Round4HW` |
| arm64 / other GCC targets | Tier C — Fallback | Go fallback via `aes.Round4HW` |
| `CGO_ENABLED=0` | Pure Go (`process_generic.go`) | Go fallback |

Hash computation remains in Go in both modes (pluggable hash functions); the C pixel kernel is platform-portable through `__attribute__((target(...)))` per-helper feature gates rather than IFUNC, so non-Linux/non-FreeBSD targets degrade gracefully.

### Testing

```bash
# Test with CGO backend (default)
go test -race -run Test -count=1 ./...

# Test with pure Go backend
CGO_ENABLED=0 go test -run Test -count=1 ./...

# Both must pass — they produce identical encryption output
```

### Benchmarks

```bash
# Benchmark CGO backend
go test -bench=. -benchmem ./...

# Benchmark pure Go backend
CGO_ENABLED=0 go test -bench=. -benchmem ./...

# Benchmark specific hash (AES, BLAKE3, SipHash-2-4, BLAKE2b, BLAKE2s)
go test -bench='BLAKE3_' -benchmem ./...

# Benchmark key size scaling
go test -bench='KeySize' -benchmem ./...
```

### Performance

Full benchmark results across all ITB key sizes (512, 1024, 2048 bit), hash functions, and CPUs: **[BENCH.md](BENCH.md)**
Triple Ouroboros benchmarks (7-seed, 3× security): **[BENCH3.md](BENCH3.md)**

Throughput scales with data size due to goroutine parallelism across CPU cores. CGO mode uses three runtime-dispatched per-pixel kernel tiers (AVX-512+GFNI+VBMI 8-pixel ZMM, AVX2+GFNI 4-pixel YMM, Tier C scalar) plus the Areion-SoEM batched VAES dispatch in `internal/areionasm`. Pure Go fallback (`CGO_ENABLED=0`) is ~25-40% slower on encrypt and ~20-35% slower on decrypt depending on hash and width. Decrypt does not require crypto/rand and scales further on high-core-count CPUs.

### ASIC Scalability

**FPGA proof-of-concept is planned** using open-source Verilog IP cores for SipHash and ChaCha20 DRBG, with a custom ITB pixel pipeline. Target: full encrypt/decrypt roundtrip on a single FPGA chip.

ITB's elementary operations (XOR, bitwise AND, modulo, bit shift, rotate) are trivial to implement in hardware. The construction's per-pixel parallelism (each pixel is independent) enables linear scalability through parallel processing units.

**Pixel processing in ASIC:**
- All operations are combinational logic: XOR gates, barrel shifters, adders
- No S-box ROM, no lookup tables, no GF(2^8) multiplier required
- Each pixel can be processed by an independent hardware unit
- 8 channels per pixel can be processed in parallel (8-wide datapath)
- No DPA attack surface — register-only operations in silicon

**Hash engine:**
- ARX-based PRF hash functions (SipHash-2-4/ChaCha20/BLAKE2s — chosen at design time) are pipeline-friendly in hardware: each individual operation (Add, Rotate, XOR) completes in 1 clock cycle; a full SipHash-2-4 call requires ~24 cycles for 20-byte input
- Multiple hash engines can run in parallel (one per pixel pipeline)
- No S-box in silicon — no DPA attack surface at the hardware level

**Primary engineering challenge — PRNG throughput:**
- Container generation (crypto/rand) is the throughput bottleneck in software (~735 MB/s on modern CPUs)
- In ASIC, a custom ChaCha20-based DRBG (ARX, DPA-free) seeded from a certified TRNG IP core generates random container fill, not cryptographic keys
- Seeds (triple-seed) are external pre-shared inputs, not generated by the DRBG — they are loaded into ASIC secure registers via external key exchange
- A single ChaCha20 DRBG core at ~4 GB/s may be sufficient — the pixel processing pipeline (2 hash calls per pixel) becomes the bottleneck before DRBG does
- Scaling is achieved by adding parallel pixel pipelines, not additional DRBG cores
- Decrypt does not require PRNG (no container generation) — decrypt throughput is limited only by hash engine and memory bandwidth

**DPA-free full stack:**
- TRNG (certified IP core) → ChaCha20 DRBG streaming (custom, ARX) → ARX hash engine (SipHash-2-4/ChaCha20/BLAKE2s) → pixel processing (XOR, shift, rotate) — zero table lookups from PRNG to output, no DPA attack surface at any level

**Theoretical throughput:**
- With ChaCha20 DRBG + parallel hash engines + parallel pixel processing, ASIC implementations could theoretically achieve >1-2 GB/s for both encrypt and decrypt — the problem is purely engineering, not architectural
- Decrypt throughput could exceed encrypt due to absence of PRNG overhead

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/dchest/siphash"
    "github.com/everanium/itb"
)

func sipHash128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
    return siphash.Hash128(seed0, seed1, data)
}

func main() {
    // Optional: global configuration (all thread-safe, atomic)
    itb.SetMaxWorkers(4)    // limit to 4 CPU cores (default: all CPUs)
    itb.SetNonceBits(256)   // 256-bit nonce (default: 128-bit)
    itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1, valid: 1,2,4,8,16,32)

    // Create three independent seeds (triple-seed isolation)
    noiseSeed, err := itb.NewSeed128(1024, sipHash128)
    if err != nil {
        panic(err)
    }
    dataSeed, err := itb.NewSeed128(1024, sipHash128)
    if err != nil {
        panic(err)
    }
    startSeed, err := itb.NewSeed128(1024, sipHash128)
    if err != nil {
        panic(err)
    }

    plaintext := []byte("any binary data — including 0x00 bytes")

    // Encrypt into RGBWYOPA container
    encrypted, err := itb.Encrypt128(noiseSeed, dataSeed, startSeed, plaintext)
    if err != nil {
        panic(err)
    }
    fmt.Printf("encrypted: %d bytes\n", len(encrypted))

    // Decrypt
    decrypted, err := itb.Decrypt128(noiseSeed, dataSeed, startSeed, encrypted)
    if err != nil {
        panic(err)
    }
    fmt.Printf("decrypted: %s\n", string(decrypted))
}
```

## Quick Start — Triple Ouroboros (7 seeds, 3× security)

```go
// Triple Ouroboros: 7 seeds (1 noise + 3 data + 3 start), 512-bit for speed
// Light secure bit-permutation mode without performance trade-off (Recommended to use with Triple Ouroboros)
itb.SetBitSoup(1)  // optional mode: bit-level split ("bit soup"), opt-in SAT-resistance reserve (default: 0 = byte-level)
                   // automatically enabled for Single Ouroboros if itb.SetLockSoup(1) is enabled or vice versa
// Most secure bit-permutation mode with performance trade-off ~2×-7× slower
itb.SetLockSoup(1) // optional Insane Interlocked Mode overlay: per-chunk PRF-keyed bit-permutation; ~2×-7× slower
                   // automatically engages itb.SetBitSoup(1)

ns, _  := itb.NewSeed128(512, sipHash128) // shared noiseSeed
ds1, _ := itb.NewSeed128(512, sipHash128) // dataSeed per ring
ds2, _ := itb.NewSeed128(512, sipHash128)
ds3, _ := itb.NewSeed128(512, sipHash128)
ss1, _ := itb.NewSeed128(512, sipHash128) // startSeed per ring
ss2, _ := itb.NewSeed128(512, sipHash128)
ss3, _ := itb.NewSeed128(512, sipHash128)

encrypted, _ := itb.Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
decrypted, _ := itb.Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
// Security: P × 2^(3×512) = P × 2^1536. Faster than Single 1024-bit, stronger security.
```

### Mixing PRF Primitives

Each seed has its own hash function — you can use **different PRF implementations** for different seeds within the same hash width. The receiver must use the same assignment.

**Single Ouroboros (3 seeds):**
```go
ns, _ := itb.NewSeed128(1024, sipHash128)      // noiseSeed: SipHash-2-4
ds, _ := itb.NewSeed128(1024, makeAESHash())    // dataSeed: AES-CMAC
ss, _ := itb.NewSeed128(1024, sipHash128)       // startSeed: SipHash-2-4

encrypted, _ := itb.Encrypt128(ns, ds, ss, plaintext)
```

**Triple Ouroboros (7 seeds):**
```go
ns, _  := itb.NewSeed128(512, sipHash128)       // shared noise: SipHash
ds1, _ := itb.NewSeed128(512, makeAESHash())    // ring 1 data: AES-CMAC
ds2, _ := itb.NewSeed128(512, sipHash128)       // ring 2 data: SipHash
ds3, _ := itb.NewSeed128(512, makeAESHash())    // ring 3 data: AES-CMAC
ss1, _ := itb.NewSeed128(512, sipHash128)       // ring 1 start: SipHash
ss2, _ := itb.NewSeed128(512, makeAESHash())    // ring 2 start: AES-CMAC
ss3, _ := itb.NewSeed128(512, sipHash128)       // ring 3 start: SipHash

encrypted, _ := itb.Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
```

For Triple Ouroboros, use the most performance-balanced PRF primitives across the three dataSeed rings — this ensures all three parallel goroutines finish at similar times.

## How It Works

ITB encrypts data into raw RGBWYOPA pixel containers (8 channels per pixel: Red, Green, Blue, White, Yellow, Orange, Purple, Alpha — mnemonic labels for an 8-byte unit; the format is not tied to image processing) generated from `crypto/rand`. Each 8-bit channel carries 7 data bits and 1 noise bit, yielding 56 data bits per pixel at 1.14× overhead. Each pixel's bit-plane selection and per-channel XOR masks are derived from a chained hash of the seed and a per-message nonce. The random container creates an information-theoretic barrier: hash outputs are absorbed by modifications of random pixel values — the original container bytes are never transmitted, so the modifications are unknown, and the hash output is unobservable.

The data is embedded starting at a seed-dependent pixel offset with wrap-around — the physical layout in the container is completely non-sequential. An observer sees uniformly random pixel values with no way to determine which pixels carry data, in what order, or what bit-plane is used.

## Hash Width Variants

The library provides three parallel API sets for different hash output widths. All share the same pixel format, framing, and security properties — the difference is in ChainHash intermediate state width.

| API | Seeds | Hash Type | State | Effective Max Key | Target Hash Functions |
|---|---|---|---|---|---|
| `Encrypt256` / `Decrypt256` | 3 | `HashFunc256` (256-bit) | 256-bit | 2048 bits | **Areion-SoEM-256**, BLAKE3 keyed, ChaCha20 |
| `Encrypt512` / `Decrypt512` | 3 | `HashFunc512` (512-bit) | 512-bit | 2048 bits | **Areion-SoEM-512**, BLAKE2b-512 |
| `Encrypt128` / `Decrypt128` | 3 | `HashFunc128` (128-bit) | 128-bit | 1024 bits | SipHash-2-4, AES-CMAC |
| `Encrypt3x256` / `Decrypt3x256` | 7 | `HashFunc256` (256-bit) | 256-bit | 2048 bits | **Areion-SoEM-256**, BLAKE3 keyed, ChaCha20 |
| `Encrypt3x512` / `Decrypt3x512` | 7 | `HashFunc512` (512-bit) | 512-bit | 2048 bits | **Areion-SoEM-512**, BLAKE2b-512 |
| `Encrypt3x128` / `Decrypt3x128` | 7 | `HashFunc128` (128-bit) | 128-bit | 1024 bits | SipHash-2-4, AES-CMAC |

Each variant also has authenticated versions (`EncryptAuthenticated128`/`DecryptAuthenticated128`, `EncryptAuthenticated3x128`/`DecryptAuthenticated3x128`, etc.) and streaming versions (`EncryptStream128`/`DecryptStream128`, `EncryptStream3x128`/`DecryptStream3x128`, etc.).

## Optimized Hash Wrappers

Hash functions like AES and BLAKE3 have expensive key setup. Creating a new cipher/hasher on every call wastes time on initialization. The **cached wrapper** pattern fixes this: create the cipher once with a fixed random key, mix seed components into the data instead. Each of the three seeds must get its own wrapper instance (independent key).

### Areion-SoEM (256/512-bit, VAES-accelerated batched dispatch — recommended)

Areion-SoEM is a formally proven beyond-birthday-bound PRF based on AES round functions. ITB ships a built-in 4-way batched implementation (`AreionSoEM256x4` / `AreionSoEM512x4`) that runs ~2× faster than four serial calls on x86_64 hardware with VAES + AVX-512 (Intel Rocket Lake / Tiger Lake+, AMD Zen 4+) and ~1.3× over scalar AES-NI on hosts with VAES + AVX2 but no AVX-512 (AMD Zen 3, Intel Alder Lake P/E-cores). The paired-factory helpers `MakeAreionSoEM256Hash` / `MakeAreionSoEM512Hash` return `(HashFunc, BatchHashFunc)` so each seed wires both arms with the same fixed key — ITB's `processChunk{256,512}` then dispatches per-pixel hashing four pixels per batched call.

```go
itb.SetMaxWorkers(4)    // limit CPU cores (default: all)
itb.SetNonceBits(256)   // 256-bit nonce (default: 128)
itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1)

// Areion-SoEM-256 — 256-bit PRF, batched VAES dispatch
ns, _ := itb.NewSeed256(2048, nil)
ns.Hash, ns.BatchHash = itb.MakeAreionSoEM256Hash()
ds, _ := itb.NewSeed256(2048, nil)
ds.Hash, ds.BatchHash = itb.MakeAreionSoEM256Hash()
ss, _ := itb.NewSeed256(2048, nil)
ss.Hash, ss.BatchHash = itb.MakeAreionSoEM256Hash()

encrypted, _ := itb.Encrypt256(ns, ds, ss, plaintext)
decrypted, _ := itb.Decrypt256(ns, ds, ss, encrypted)
```

The Areion-SoEM-512 variant uses `MakeAreionSoEM512Hash()` paired with `itb.Encrypt512` / `itb.Decrypt512` and is wired identically. The batched arm of the returned pair shares the same internally-generated random fixed key as the single arm, so per-pixel hashes match bit-exact between the two dispatch paths (verified by the parity test suite). Triple Ouroboros wires the same way: each of the seven seeds receives an independent paired factory call.

**Backward compatibility — no VAES required.** The same code works on every platform; only the throughput tier changes:

| CPU / build | Path | Throughput tier |
|---|---|---|
| amd64 + VAES + AVX-512 (Intel Ice Lake+, AMD Zen 4+) | `internal/areionasm/areion_amd64.s` AVX-512 ASM | 4-way VAES on ZMM, single VAESENC per round across all 4 lanes |
| amd64 + VAES + AVX2 only (AMD Zen 3, Alder Lake E-cores) | `internal/areionasm/areion_amd64.s` AVX2 ASM | 4-way VAES on YMM, two 2-block VAESENC per round, ~2× over scalar AES-NI |
| amd64 without VAES (older Intel / AMD) | Go fallback via `aes.Round4HW(state, zeroKey)` | 4× sequential AES-NI per round (no SIMD width gain, still hardware-accelerated) |
| Pure software / `CGO_ENABLED=0` | Same Go fallback (process_generic.go batched dispatch wired) | Slowest tier, correct output preserved |

Runtime CPU detection (`areionasm.HasVAESAVX512` and `areionasm.HasVAESAVX2NoAVX512`) selects the right path once at package init via the upstream `github.com/jedisct1/go-aes` CPUID checks — no per-call branching cost. The bit-exact parity invariant `BatchHash(data)[i] == Hash(data[i])` holds on every platform; ITB's parity test suite (`TestAreionSoEM{256,512}x4Parity` plus the direct-call parity tests for each tier and a 3-way cross-path parity test on hosts where all three implementations are runnable) verifies this on every test run.

If the underlying primitive must be wired manually (custom key management, keyless probe, etc.) call `aes.AreionSoEM256` / `aes.AreionSoEM512` from `github.com/jedisct1/go-aes` directly — same primitive, no batched dispatch, useful only when the paired-factory pattern does not fit the deployment.

### SipHash-2-4 (128-bit)

SipHash is a pure function — no key setup, no caching needed. Optimal for 128-bit width.

```go
itb.SetMaxWorkers(4)    // limit CPU cores (default: all)
itb.SetNonceBits(256)   // 256-bit nonce (default: 128)
itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1)

func sipHash128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
    return siphash.Hash128(seed0, seed1, data)
}

ns, _ := itb.NewSeed128(1024, sipHash128)  // 1024-bit key, 16 components, 8 rounds
ds, _ := itb.NewSeed128(1024, sipHash128)
ss, _ := itb.NewSeed128(1024, sipHash128)

encrypted, _ := itb.Encrypt128(ns, ds, ss, plaintext)
decrypted, _ := itb.Decrypt128(ns, ds, ss, encrypted)
```

### AES-NI Cached (128-bit, stdlib)

```go
itb.SetMaxWorkers(4)    // limit CPU cores (default: all)
itb.SetNonceBits(256)   // 256-bit nonce (default: 128)
itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1)

func makeAESHash() itb.HashFunc128 {
    var key [16]byte
    rand.Read(key[:])
    block, _ := aes.NewCipher(key[:])

    return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
        var b [16]byte
        copy(b[:], data)
        binary.LittleEndian.PutUint64(b[0:], binary.LittleEndian.Uint64(b[0:])^seed0)
        binary.LittleEndian.PutUint64(b[8:], binary.LittleEndian.Uint64(b[8:])^seed1)
        block.Encrypt(b[:], b[:])
        for j := 16; j < len(data); j++ { b[j-16] ^= data[j] }
        block.Encrypt(b[:], b[:])
        return binary.LittleEndian.Uint64(b[:8]), binary.LittleEndian.Uint64(b[8:])
    }
}

ns, _ := itb.NewSeed128(1024, makeAESHash())
ds, _ := itb.NewSeed128(1024, makeAESHash())  // independent key per seed
ss, _ := itb.NewSeed128(1024, makeAESHash())
```

### BLAKE3 Keyed Cached (256-bit)

```go
itb.SetMaxWorkers(4)    // limit CPU cores (default: all)
itb.SetNonceBits(256)   // 256-bit nonce (default: 128)
itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1)

func makeBlake3Hash() itb.HashFunc256 {
    var key [32]byte
    rand.Read(key[:])
    template, _ := blake3.NewKeyed(key[:])
    pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

    return func(data []byte, seed [4]uint64) [4]uint64 {
        h := template.Clone()
        // Ensure mixed is long enough for all 4 seed uint64's (32 bytes),
        // even when data is shorter. Without this, seed[i] for i past
        // len(data)/8 would be silently dropped, halving effective key.
        const seedInjectBytes = 32
        payloadLen := len(data)
        if payloadLen < seedInjectBytes { payloadLen = seedInjectBytes }
        ptr := pool.Get().(*[]byte)
        mixed := *ptr
        if cap(mixed) < payloadLen { mixed = make([]byte, payloadLen) } else { mixed = mixed[:payloadLen] }
        // Zero-pad any tail beyond len(data) (pool buffer may be stale).
        for i := len(data); i < payloadLen; i++ { mixed[i] = 0 }
        copy(mixed[:len(data)], data)
        // XOR seed[0..3] into first 32 bytes (guaranteed to fit now).
        for i := 0; i < 4; i++ {
            off := i * 8
            binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
        }
        h.Write(mixed)
        *ptr = mixed; pool.Put(ptr)
        var buf [32]byte
        h.Sum(buf[:0])
        return [4]uint64{
            binary.LittleEndian.Uint64(buf[0:]),  binary.LittleEndian.Uint64(buf[8:]),
            binary.LittleEndian.Uint64(buf[16:]), binary.LittleEndian.Uint64(buf[24:]),
        }
    }
}

ns, _ := itb.NewSeed256(2048, makeBlake3Hash())
ds, _ := itb.NewSeed256(2048, makeBlake3Hash())
ss, _ := itb.NewSeed256(2048, makeBlake3Hash())
```

### BLAKE2b-512 Keyed Cached (512-bit)

BLAKE2b-512 has native 512-bit key and output — fewer ChainHash rounds (4 vs 8 for 256-bit), higher throughput.

```go
itb.SetMaxWorkers(4)    // limit CPU cores (default: all)
itb.SetNonceBits(256)   // 256-bit nonce (default: 128)
itb.SetBarrierFill(4)   // CSPRNG fill margin (default: 1)

func makeBlake2bHash512() itb.HashFunc512 {
    var key [64]byte
    rand.Read(key[:])
    pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

    return func(data []byte, seed [8]uint64) [8]uint64 {
        // Ensure payload region is at least seedInjectBytes (64) long so all
        // 8 seed uint64's XOR into the hash input. Otherwise seed[i] past
        // len(data)/8 are silently dropped for short data.
        const keyLen = 64
        const seedInjectBytes = 64
        payloadLen := len(data)
        if payloadLen < seedInjectBytes { payloadLen = seedInjectBytes }
        need := keyLen + payloadLen
        ptr := pool.Get().(*[]byte)
        buf := *ptr
        if cap(buf) < need { buf = make([]byte, need) } else { buf = buf[:need] }
        // Zero-pad any tail beyond the copied data (pool buffer may be stale).
        for i := keyLen + len(data); i < need; i++ { buf[i] = 0 }
        copy(buf[:keyLen], key[:])
        copy(buf[keyLen:keyLen+len(data)], data)
        for i := 0; i < 8; i++ {
            off := keyLen + i*8
            binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
        }
        digest := blake2b.Sum512(buf)
        *ptr = buf; pool.Put(ptr)
        var result [8]uint64
        for i := range result {
            result[i] = binary.LittleEndian.Uint64(digest[i*8:])
        }
        return result
    }
}

ns, _ := itb.NewSeed512(2048, makeBlake2bHash512())
ds, _ := itb.NewSeed512(2048, makeBlake2bHash512())
ss, _ := itb.NewSeed512(2048, makeBlake2bHash512())
```

### Parallelism Control

```go
itb.SetMaxWorkers(4) // limit to 4 CPU cores for pixel processing
```

By default, ITB uses all available CPU cores. On shared servers, use `SetMaxWorkers` to limit CPU usage. Pass 0 to use all CPUs (default). Valid range: 0–256. Thread-safe (atomic). Query with `itb.GetMaxWorkers()`.

### Nonce Configuration

```go
itb.SetNonceBits(256) // 256-bit nonce (~2^128 birthday bound)
```

Default nonce is 128 bits (birthday collision at ~2^64 messages). For higher collision resistance, use `SetNonceBits`. Valid values: 128, 256, 512. Panics on invalid input. Both sender and receiver must use the same nonce size. Query with `itb.GetNonceBits()`.

### Barrier Fill (CSPRNG Margin)

```go
itb.SetBarrierFill(4) // side += 4 instead of default side += 1
```

Controls the CSPRNG fill margin added to the container side dimension. The construction guarantees that every container has strictly more pixel capacity than the payload requires — the excess capacity is filled with `crypto/rand` data encrypted by dataSeed. This CSPRNG residue is indistinguishable from encrypted plaintext and provides information-theoretic ambiguity within the data channel ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

Valid values: 1, 2, 4, 8, 16, 32. Default: 1. Panics on invalid input. Thread-safe (atomic). Query with `itb.GetBarrierFill()`.

**Why this matters after CCA.** Under CCA (MAC + Reveal), the attacker identifies and removes noise bits (12.5% of container), bypassing mechanism 1 (noise absorption). But CSPRNG fill bytes remain in the data bit positions — encrypted identically to plaintext by dataSeed (rotation + XOR). COBS decoding stops at the `0x00` null terminator and never reaches the fill region, so the fill content is never constrained by the plaintext structure. The attacker cannot distinguish encrypted plaintext from encrypted CSPRNG fill without the correct dataSeed. Although CCA reveals noise bit positions (bypassing the noise-position uncertainty of mechanism 1), CSPRNG residue in data positions provides independent information-theoretic ambiguity that persists regardless of CCA.

The rotation barrier (7^P from [Proof 4](PROOFS.md#proof-4-rotation-barrier)) remains complemented by this reduced information-theoretic barrier from CSPRNG fill. Three layers operate in every scenario:

| Layer | Core ITB | After CCA (MAC + Reveal) |
|---|---|---|
| Noise absorption (mechanism 1) | Full (8 noise bits/pixel) | Partial — noise bits removed, CSPRNG fill in data positions survives |
| Encoding ambiguity (mechanism 2) | 56^P | 7^P (rotation only) |
| Brute-force cost | P × 2^(2×keyBits) | P × 2^keyBits |

**Asymmetric property.** The receiver does not need the same `SetBarrierFill` value as the sender. Encrypt writes the container dimensions (W×H) into the header; Decrypt reads W×H from the header and processes whatever pixels are present. A larger fill margin on the sender side increases CSPRNG residue without requiring any configuration change on the receiver. This confirms the configurable nature of the information-theoretic barrier — the sender can independently tune the CSPRNG fill margin.

## Hash Function Selection

ITB accepts pluggable hash functions at three widths. Requirements: the hash must process all input bytes with non-invertible, non-affine, avalanche mixing that survives the ChainHash XOR-chain. PRF required. Under PRF assumption, Full KPA resistance is 3-factor: PRF non-invertibility, independent startSeed, and per-pixel 1:1 ambiguity — all combine conjunctively. gcd(7,8)=1 byte-splitting is a 4th factor effective only under Partial KPA. Note: complete PRF inversion would collapse the architectural layers via seed recovery; the multi-factor property protects against partial PRF weakness, not total failure.

| Hash Function | Acceleration | Seed Input | Block/State | Hash Type | Max Key | Crypto | Go Library |
|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | **VAES** (AVX-512 / AVX2 / AES-NI fallback) | 256 bit | 256 bit | `HashFunc256` | 2048 | **PRF** | built-in (`MakeAreionSoEM256Hash`) |
| **Areion-SoEM-512** | **VAES** (AVX-512 / AVX2 / AES-NI fallback) | 512 bit | 512 bit | `HashFunc512` | 2048 | **PRF** | built-in (`MakeAreionSoEM512Hash`) |
| **SipHash-2-4** | — | 128 bit | 128 bit | `HashFunc128` | 1024 | **PRF** | `github.com/dchest/siphash` |
| **AES-CMAC** | **AES-NI** | 128 bit (block) | 128 bit | `HashFunc128` | 1024 | **PRF** | `crypto/aes` (stdlib) |
| **BLAKE2b-256** | SSE | 256 bit (prefix) | 256 bit | `HashFunc256` | 2048 | **PRF** | `golang.org/x/crypto/blake2b` |
| **BLAKE2s** | — | 256 bit (prefix) | 256 bit | `HashFunc256` | 2048 | **PRF** | `golang.org/x/crypto/blake2s` |
| **BLAKE3** | SIMD (AVX-512) | 256 bit | 256 bit | `HashFunc256` | 2048 | **PRF** | `github.com/zeebo/blake3` |
| **BLAKE2b-512 keyed** | SSE | 512 bit | 512 bit | `HashFunc512` | 2048 | **PRF** | `golang.org/x/crypto/blake2b` |
| **ChaCha20** | SIMD (AVX2) | 256 bit (key) | 256 bit | `HashFunc256` | 2048 | **PRF** | `golang.org/x/crypto/chacha20` |

### Choosing the Right Hash Width

The effective key size is determined by the **seed input width** of the hash function — not its output width. This is a critical distinction:

```
Effective max key = min(keyBits, seedInputWidth × numRounds)
```

### Why Wider Hash = Faster with Wider MITM Bottleneck

With a 512-bit key (8 components), ChainHash processes components in groups matching the hash width:

| Hash width | Components/round | Rounds | Hash calls/pixel |
|---|---|---|---|
| 128-bit | 2 | 4 | 4 |
| 256-bit | 4 | **2** | **2** |
| 512-bit | 8 | **1** | **1** |

All 8 components are consumed in every case — no key material is skipped. A 256-bit hash simply processes 4 components per call instead of 1.

**Faster:** each hash call has overhead (state initialization, finalization). For heavy hash functions (BLAKE3: ~300ns/call, BLAKE2b: ~200ns/call), fewer calls = proportionally faster.

**Wider MITM bottleneck:** the wider intermediate state makes meet-in-the-middle attacks harder. With 256-bit state, an attacker must enumerate 2^256 possible intermediate values (vs 2^128 for a 128-bit hash). Additionally, fewer chain rounds means fewer potential split points for the attacker.

**Bottom line:** prefer the widest available PRF variant — it's both faster and provides a wider MITM bottleneck.

### Hash Function Wrappers

```go
// 128-bit: HashFunc128 = func(data []byte, seed0, seed1 uint64) (lo, hi uint64)
// SipHash-2-4 (PRF) — see Optimized Hash Wrappers above
// AES-NI cached (PRF, hardware-accelerated) — see Optimized Hash Wrappers above

// 256-bit: HashFunc256 = func(data []byte, seed [4]uint64) [4]uint64
// BLAKE3 keyed cached (PRF, SIMD) — see Optimized Hash Wrappers above

// 512-bit: HashFunc512 = func(data []byte, seed [8]uint64) [8]uint64
// BLAKE2b-512 keyed cached (PRF, native 512-bit) — see Optimized Hash Wrappers above
```

## Key Size Selection

```go
// 128-bit hash: up to 1024-bit keys
ns128, _ := itb.NewSeed128(1024, sipHash128)
ds128, _ := itb.NewSeed128(1024, sipHash128)
ss128, _ := itb.NewSeed128(1024, sipHash128)

// 256-bit hash: up to 2048-bit keys
ns256, _ := itb.NewSeed256(2048, blake3Hash256)
ds256, _ := itb.NewSeed256(2048, blake3Hash256)
ss256, _ := itb.NewSeed256(2048, blake3Hash256)

// 512-bit hash: up to 2048-bit keys
ns512, _ := itb.NewSeed512(2048, blake2bHash512)
ds512, _ := itb.NewSeed512(2048, blake2bHash512)
ss512, _ := itb.NewSeed512(2048, blake2bHash512)
```

### Seed Alignment Requirements

| Seed Type | Bits Range | Bits Alignment | Components | Components Alignment |
|---|---|---|---|---|
| `Seed128` | [512, 2048] | multiple of 128 | [8, 32] | ×2 |
| `Seed256` | [512, 2048] | multiple of 256 | [8, 32] | multiple of 4 |
| `Seed512` (512-bit) | [512, 2048] | multiple of 512 | [8, 32] | multiple of 8 |

## Minimum Container Size

Minimum container size depends on the API mode. Encrypt/Stream uses `ceil(keyBits / log₂(56))` pixels,
ensuring encoding ambiguity (56^P) exceeds the key space. Auth uses `ceil(keyBits / log₂(7))` pixels,
ensuring CCA ambiguity (7^P) exceeds the key space:

| Key Size | Mode | Min Pixels → Container | Noise Barrier |
|---|---|---|---|
| 1024 bits | Encrypt/Stream | 177 → 196 (14×14) | 2^1568 ≥ 2^1024 |
| 1024 bits | Auth | 365 → 400 (20×20) | 2^3200 ≥ 2^1024 |
| 2048 bits | Encrypt/Stream | 353 → 361 (19×19) | 2^2888 ≥ 2^2048 |
| 2048 bits | Auth | 730 → 784 (28×28) | 2^6272 ≥ 2^2048 |

## Output Format

```
Offset  Size     Content
0       N        Nonce (crypto/rand, public; N = 16/32/64 bytes for 128/256/512-bit nonce)
N       2        Width (uint16 big-endian)
N+2     2        Height (uint16 big-endian)
N+4     W×H×8    Raw RGBWYOPA pixel data with embedded encrypted payload
```

Default nonce size is 128-bit (16 bytes). Configurable to 256-bit (32 bytes) or 512-bit (64 bytes) via `SetNonceBits`. The output format is identical across all three hash width variants.

## Security Summary

| Property | ITB |
|---|---|
| Key space | Up to 2^2048 |
| Grover resistance | √P × 2^keyBits (Core/Silent Drop) to √P × 2^(keyBits/2) (MAC + Reveal) |
| Plausible deniability | ✓ All modes (wrong seed → garbage indistinguishable from valid plaintext) |
| Encoding ambiguity | ✓ All modes (7^P unverifiable rotation combinations, survives CCA; CSPRNG residue adds independent ambiguity in data positions, [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |
| Triple-seed isolation | ✓ All modes (noiseSeed / dataSeed / startSeed independent; CCA leaks noiseSeed only) |
| Oracle-free deniability | ✓ Core ITB / MAC + Silent Drop; MAC + Reveal has CCA oracle limited to noise positions |
| Known-plaintext resistance | 3-factor under PRF assumption for Full KPA: PRF non-invertibility + independent startSeed + 7-rotation × 8-noisePos per-pixel ambiguity at signal/noise 1:1. gcd(7,8) byte-splitting is a 4th factor effective only under Partial KPA (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) |
| Chosen-plaintext resistance | Independent maps |
| Noise absorption | ✓ Core ITB / MAC + Silent Drop; bypassed via CCA in MAC + Reveal (CSPRNG residue in data positions survives, [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |
| Noise barrier (min container) | 2^1568 (1024-bit, P=196) to 2^2888 (2048-bit, P=361) |
| Hash function requirement | PRF required; PRF and barrier are complementary — neither sufficient alone (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) |
| Nonce reuse protection | 128/256/512-bit per-message nonce (default 128-bit) |
| Nonce misuse resistance | **Local** only: at most 2–3 colliding messages theoretically affected. In practice ITB's per-encryption noise + rotation + channelXOR mean `C1 ⊕ C2` does NOT reduce to `plaintext_1 ⊕ plaintext_2` as in a stream cipher — plaintext recovery requires the full demasker pipeline whose output is the hash stream, not plaintext bits (see [ITB.md §8](ITB.md#8-nonce-reuse-only-if-every-condition-holds)). Seeds remain secret (PRF non-invertibility), future messages safe, no key rotation required. Single collision too few observations for Simon / structural / quantum algebraic attacks. Unlike AES-GCM where nonce reuse leaks H and enables forgery until key rotation (global catastrophe) |
| Storage overhead | 1.14× (56 data bits per 64-bit pixel) |

## Integrity (MAC-Inside-Encrypt)

The core construction provides confidentiality only. For integrity protection against bit-flipping attacks, use the MAC-Inside-Encrypt pattern — the MAC is encrypted inside the container, preserving oracle-free deniability:

```go
// 128-bit variant
encrypted, err := itb.EncryptAuthenticated128(ns128, ds128, ss128, plaintext, myMACFunc)
original, err = itb.DecryptAuthenticated128(ns128, ds128, ss128, encrypted, myMACFunc)

// 256-bit variant
encrypted, err = itb.EncryptAuthenticated256(ns256, ds256, ss256, plaintext, myMACFunc)
original, err = itb.DecryptAuthenticated256(ns256, ds256, ss256, encrypted, myMACFunc)

// 512-bit variant
encrypted, err = itb.EncryptAuthenticated512(ns512, ds512, ss512, plaintext, myMACFunc)
original, err = itb.DecryptAuthenticated512(ns512, ds512, ss512, encrypted, myMACFunc)
```

**Important:** never place a MAC outside the encrypted container in cleartext — this creates a verification oracle that breaks deniability.

## Triple-Seed Isolation

All three seeds must be distinct pointers — passing the same seed as multiple parameters returns an error:

```go
// This will fail:
encrypted, err := itb.Encrypt128(seed, seed, seed, data)
// Error: "itb: all three seeds must be different (triple-seed isolation)"

// Correct usage: three independent seeds
encrypted, err := itb.Encrypt128(noiseSeed, dataSeed, startSeed, data)
```

## Formal Security Model

A simulation-based proof is a purely mathematical construction: "for every adversary A in the real world, there exists a simulator S in the ideal world such that the outputs of A and S are indistinguishable." This is proven logically, not computationally. It is independent of hardware, logic system, or computational model.

ITB does not fit cleanly into the standard binary security model:

- **Standard model:** the adversary either distinguishes (break) or does not (secure). Binary.
- **ITB:** the adversary always receives output. The output is always "valid." There is no point where the system returns accept/reject. Instead, the result is a **spectrum of plausibility** — every key produces output, and there is no way to rank candidates without external context.

The semantics of decryption are ternary:
1. Correct key → correct plaintext
2. Wrong key → garbage indistinguishable from plaintext
3. Observer → cannot determine which of the two cases is present

Possible formalization paths:
- **Indistinguishability-based** definitions (standard in cryptography, binary logic — sufficient)
- **Simulation-based** proof with an ideal functionality that always returns random bytes (this is the "ideal world" of ITB — the real-world output is indistinguishable from random)
- **Quantitative information flow** (how many bits leak — the per-byte barrier shows 0 bits leaked per observation)

All three approaches use standard mathematics. The formal relationship between ITB's ambiguity-based security and Shannon's framework remains an open research question (see [SCIENCE.md §7](SCIENCE.md#7-research-directions)).

## See Also

- [ITB.md](ITB.md) — How the barrier works (accessible explanation)
- [ITB3.md](ITB3.md) — Triple Ouroboros (7-seed variant, 3× security)
- [FEATURES.md](FEATURES.md) — Complete feature list and security properties
- [PROOFS.md](PROOFS.md) — Formal security proofs
- [SCIENCE.md](SCIENCE.md) — Scientific analysis and formal security arguments
- [SECURITY.md](SECURITY.md) — Security reference tables
- [HWTHREATS.md](HWTHREATS.md) — Hardware-level threat analysis (Spectre, Meltdown, Rowhammer, etc.)
- [REDTEAM.md](REDTEAM.md) — Empirical red-team validation (12-primitive hash matrix, multiple statistical / structural distinguishers, 2×2 Ouroboros × BarrierFill matrix)

## License

MIT — see [LICENSE](LICENSE).
