# ITB — Information-Theoretic Barrier

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> The information-theoretic barrier is a **software-level** property based on computational behavior of hash functions and CSPRNG output, reinforced by two independent barrier mechanisms: noise absorption (CSPRNG) and encoding ambiguity (rotation from triple-seed isolation). It provides **no guarantees** against hardware-level attacks including: power analysis (DPA/SPA), microarchitectural side-channels (Spectre, Meltdown, Rowhammer, cache timing), undiscovered side-channel leakages, or CSPRNG implementation weaknesses.
>
> PRF-grade hash functions are **required**. No warranty is provided.

A parameterized symmetric cipher construction library for Go that achieves known-plaintext resistance under passive observation through an information-theoretic barrier.

**The barrier works strictly by information theory. No computational power can extract what does not exist in the observation.** The information-theoretic barrier absorbs the output of a cryptographic PRF hash function, making hash output unobservable to a passive observer. The construction creates an ocean of ambiguity: every observation is equally consistent with exponentially many configurations, none distinguishable from the real one.

**[How the barrier works — accessible explanation](ITB.md)**

**[Why known-plaintext and advanced attacks do not break the barrier](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier)**

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

**Why the barrier hardens PRF.** In traditional ciphers, the attacker directly observes the primitive's output (keystream XOR plaintext). Any weakness in the primitive is immediately exploitable. In ITB, the hash output is absorbed by a random container modification — the attacker sees modified random bytes, not hash outputs. Under the random-container model, every observed byte value is compatible with every possible hash output. PRF-grade hash functions are required — the barrier provides an additional architectural layer that makes hash output unobservable, a property no other symmetric cipher construction provides.

**Why quantum structural attacks are conjectured mitigated.** Quantum algorithms like Simon (periodicity), BHT (collisions), and quantum differential/linear analysis require observable structural relations between inputs and outputs. The random container makes these relations unobservable — the attacker cannot build the algebraic structures that quantum algorithms exploit. Additionally, ITB's MAC oracle (when present) is inherently classical: it accepts concrete bytes over a network, not quantum superposition queries (Q2 model inapplicable). This is an architectural observation that has not been independently verified.

> **Important.** ITB is an experimental construction without peer review or independent cryptanalysis. The information-theoretic barrier is a **software-level property**, reinforced by two independent mechanisms: noise absorption (CSPRNG) and encoding ambiguity (rotation from triple-seed isolation). It provides no guarantees against hardware-level attacks. All security claims are under the random-container model and have not been independently verified.

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

CGO mode provides ~15-22% faster decrypt and ~6-17% faster encrypt through:
- GCC `-O3` auto-vectorization of XOR/rotate/insert phases
- L1-cache-friendly micro-batching (512 pixels per C call)
- Parallel noise/data hash computation
- `sync.Pool` for hash array reuse

The C pixel processing code is portable — no platform-specific intrinsics. GCC `-O3` auto-vectorizes using the best available SIMD for each platform:

| Platform | SIMD | CGO Flag |
|---|---|---|
| x86-64 (Intel/AMD) | AVX2 (256-bit) | `-mavx2` (automatic) |
| ARM64 (Apple Silicon, AWS Graviton) | NEON (128-bit) | enabled by default |
| Other | Scalar `-O3` | — |

Hash computation remains in Go in both modes (pluggable hash functions).

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

### Performance (i7-11700K, VMware, CGO mode, 1024-2048 bit)

**Encrypt (MB/s):**

| Hash | Width | Crypto | ITB Key | 1 MB | 16 MB | 64 MB |
|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | PRF | 1024 | 138 | 146 | 135 |
| **BLAKE2b-512** | 512 | PRF | 2048 | 110 | 126 | 119 |
| **AES-CMAC** | 128 | PRF | 1024 | 114 | 143 | 132 |
| **BLAKE2s** | 256 | PRF | 2048 | 89 | 98 | 97 |
| **BLAKE2b-256** | 256 | PRF | 2048 | 75 | 92 | 92 |
| **BLAKE3** | 256 | PRF | 2048 | 64 | 68 | 63 |

**Decrypt (MB/s):**

| Hash | Width | Crypto | ITB Key | 1 MB | 16 MB | 64 MB |
|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | PRF | 1024 | 165 | 197 | 200 |
| **BLAKE2b-512** | 512 | PRF | 2048 | 151 | 173 | 171 |
| **AES-CMAC** | 128 | PRF | 1024 | 152 | 187 | 168 |
| **BLAKE2s** | 256 | PRF | 2048 | 106 | 121 | 107 |
| **BLAKE2b-256** | 256 | PRF | 2048 | 98 | 114 | 110 |
| **BLAKE3** | 256 | PRF | 2048 | 72 | 75 | 72 |

Throughput scales with data size due to goroutine parallelism across CPU cores. CGO mode uses C pixel processing with GCC `-O3 -mavx2` auto-vectorization + L1-cache micro-batching. Pure Go fallback (`CGO_ENABLED=0`) is ~10-20% slower on decrypt.

**BLAKE2b-512 highlight:** With 512-bit ChainHash (1 round for 512-bit key), BLAKE2b-512 is ~30% faster than BLAKE2b-256 (2 rounds) while providing wider MITM bottleneck (2^512 vs 2^256). PRF-level encryption at 110-173 MB/s.

### Server-class CPU (AMD EPYC 9655P, 96-Core, Bare metal, CGO mode, 1024-2048 bit)

ITB scales linearly with core count. Per-pixel parallelism across goroutines utilizes all available cores.

| Hash | Width | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 255 | 327 | 362 | 452 | 579 | 709 |
| **BLAKE2b-512** | 512 | 229 | 297 | 331 | 357 | 484 | 601 |
| **ChaCha20** | 256 | 199 | 257 | 309 | 302 | 408 | 536 |

ChainHash is not the bottleneck on high-core-count CPUs — crypto/rand container generation (~813 MB/s on this CPU) becomes the limiting factor for encrypt. Decrypt does not require crypto/rand and scales further.

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

## How It Works

ITB encrypts data into raw RGBWYOPA pixel containers (8 channels per pixel: Red, Green, Blue, White, Yellow, Orange, Purple, Alpha — mnemonic labels for an 8-byte unit; the format is not tied to image processing) generated from `crypto/rand`. Each 8-bit channel carries 7 data bits and 1 noise bit, yielding 56 data bits per pixel at 1.14× overhead. Each pixel's bit-plane selection and per-channel XOR masks are derived from a chained hash of the seed and a per-message nonce. The random container creates an information-theoretic barrier: hash outputs are absorbed by modifications of random pixel values — the original container bytes are never transmitted, so the modifications are unknown, and the hash output is unrecoverable from observation.

The data is embedded starting at a seed-dependent pixel offset with wrap-around — the physical layout in the container is completely non-sequential. An observer sees uniformly random pixel values with no way to determine which pixels carry data, in what order, or what bit-plane is used.

## Hash Width Variants

The library provides three parallel API sets for different hash output widths. All share the same pixel format, framing, and security properties — the difference is in ChainHash intermediate state width.

| API | Hash Type | State | Effective Max Key | Target Hash Functions |
|---|---|---|---|---|
| `Encrypt128` / `Decrypt128` | `HashFunc128` (128-bit) | 128-bit | 1024 bits | SipHash-2-4, AES-CMAC |
| `Encrypt256` / `Decrypt256` | `HashFunc256` (256-bit) | 256-bit | 2048 bits | BLAKE3 keyed |
| `Encrypt512` / `Decrypt512` | `HashFunc512` (512-bit) | 512-bit | 2048 bits | BLAKE2b-512 |

Each variant also has authenticated versions (`EncryptAuthenticated128`/`DecryptAuthenticated128`, `EncryptAuthenticated256`/`DecryptAuthenticated256`, `EncryptAuthenticated512`/`DecryptAuthenticated512`) and streaming versions (`EncryptStream128`/`DecryptStream128`, `EncryptStream256`/`DecryptStream256`, `EncryptStream512`/`DecryptStream512`).

## Optimized Hash Wrappers

Hash functions like AES and BLAKE3 have expensive key setup. Creating a new cipher/hasher on every call wastes time on initialization. The **cached wrapper** pattern fixes this: create the cipher once with a fixed random key, mix seed components into the data instead. Each of the three seeds must get its own wrapper instance (independent key).

### SipHash-2-4 (128-bit)

SipHash is a pure function — no key setup, no caching needed. Optimal for 128-bit width.

```go
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
func makeBlake3Hash() itb.HashFunc256 {
    var key [32]byte
    rand.Read(key[:])
    template, _ := blake3.NewKeyed(key[:])

    return func(data []byte, seed [4]uint64) [4]uint64 {
        h := template.Clone()  // Clone is thread-safe, Reset is not
        var mixed [32]byte
        copy(mixed[:], data)
        for i := 0; i < 4; i++ {
            off := i * 8
            binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
        }
        h.Write(mixed[:len(data)])
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
func makeBlake2bHash512() itb.HashFunc512 {
    var key [64]byte
    rand.Read(key[:])

    return func(data []byte, seed [8]uint64) [8]uint64 {
        var buf [84]byte // 64-byte key + 20-byte max data
        copy(buf[:64], key[:])
        copy(buf[64:], data)
        for i := 0; i < 8; i++ {
            off := 64 + i*8
            if off+8 <= len(buf) {
                v := binary.LittleEndian.Uint64(buf[off:])
                binary.LittleEndian.PutUint64(buf[off:], v^seed[i])
            }
        }
        digest := blake2b.Sum512(buf[:64+len(data)])
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

### Performance: Encrypt (i7-11700K, 16 threads)

| Hash | Width | Encrypt 1 MB | Encrypt 64 MB |
|---|---|---|---|
| SipHash-2-4 | 128-bit | ~80 MB/s | ~148 MB/s |
| AES-NI | 128-bit | ~24 MB/s | ~112 MB/s |
| BLAKE2b-512 | 512-bit | ~20 MB/s | ~122 MB/s |
| BLAKE3 | 256-bit | ~7 MB/s | ~58 MB/s |

### Parallelism Control

```go
itb.SetMaxWorkers(4) // limit to 4 CPU cores for pixel processing
```

By default, ITB uses all available CPU cores. On shared servers, use `SetMaxWorkers` to limit CPU usage. Valid range: 1–256. Thread-safe (atomic). Query with `itb.GetMaxWorkers()`.

## Hash Function Selection

ITB accepts pluggable hash functions at three widths. Requirements: the hash must process all input bytes with non-invertible, non-affine, avalanche mixing that survives the ChainHash XOR-chain. PRF required; the barrier hardens PRF by making hash output unobservable.

| Hash Function | Acceleration | Seed Input | Block/State | Hash Type | Max Key | Crypto | Go Library |
|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | — | 128 bit | 128 bit | `HashFunc128` | 1024 | **PRF** | `github.com/dchest/siphash` |
| **AES-CMAC** | **AES-NI** | 128 bit (block) | 128 bit | `HashFunc128` | 1024 | **PRF** | `crypto/aes` (stdlib) |
| **BLAKE2b keyed** | SSE | 256 bit (prefix) | 256 bit | `HashFunc256` | 2048 | **PRF** | `golang.org/x/crypto/blake2b` |
| **BLAKE2s keyed** | — | 256 bit (prefix) | 256 bit | `HashFunc256` | 2048 | **PRF** | `golang.org/x/crypto/blake2s` |
| **BLAKE3 keyed** | SIMD (AVX-512) | 256 bit | 256 bit | `HashFunc256` | 2048 | **PRF** | `github.com/zeebo/blake3` |
| **BLAKE2b-512 keyed** | SSE | 512 bit | 512 bit | `HashFunc512` | 2048 | **PRF** | `golang.org/x/crypto/blake2b` |

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

Information-theoretic security under the random-container model requires `ceil(keyBits / 7)` pixels,
ensuring the noise barrier (2^(8P)) strictly exceeds the key space:

| Key Size | Min Pixels → Container | Noise Barrier |
|---|---|---|
| 1024 bits | 147 → 169 (13×13) | 2^1352 ≥ 2^1024 |
| 2048 bits | 293 → 324 (18×18) | 2^2592 ≥ 2^2048 |

## Output Format

```
Offset  Size     Content
0       16       Nonce (crypto/rand, public)
16      2        Width (uint16 big-endian)
18      2        Height (uint16 big-endian)
20      W×H×8    Raw RGBWYOPA pixel data with embedded encrypted payload
```

The output format is identical across all three hash width variants.

## Security Summary

| Property | ITB |
|---|---|
| Key space | Up to 2^2048 |
| Grover resistance | √P × 2^keyBits (Core/Silent Drop) to √P × 2^(keyBits/2) (MAC + Reveal) |
| Oracle-free deniability | Yes |
| Hash function requirement | PRF required; barrier hardens PRF |
| Known-plaintext resistance | Under passive observation |
| Chosen-plaintext resistance | Independent maps |
| Nonce reuse protection | 128-bit per-message nonce |
| Noise barrier (min container) | 2^1352 (1024-bit) to 2^2592 (2048-bit) |
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

## See Also

- [ITB.md](ITB.md) — How the barrier works (accessible explanation)
- [FEATURES.md](FEATURES.md) — Complete feature list and security properties
- [PROOFS.md](PROOFS.md) — Formal security proofs
- [SCIENCE.md](SCIENCE.md) — Scientific analysis and formal security arguments
- [SECURITY.md](SECURITY.md) — Security reference tables
- [HWTHREATS.md](HWTHREATS.md) — Hardware-level threat analysis (Spectre, Meltdown, Rowhammer, etc.)

## License

MIT — see [LICENSE](LICENSE).
