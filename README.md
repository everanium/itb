# ITB — Information-Theoretic Barrier

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> The information-theoretic barrier is a **software-level** property based on computational behavior of hash functions and CSPRNG output. It provides **no guarantees** against hardware-level attacks including: power analysis (DPA/SPA), microarchitectural side-channels (Spectre, Meltdown, Rowhammer, cache timing), undiscovered side-channel leakages, or CSPRNG implementation weaknesses.
>
> The ability to use non-cryptographic hash functions is a theoretical property that has **not been independently verified** and provides **no security guarantees**. For any serious application — government, military, financial, medical, critical infrastructure, or production systems — use only PRF-grade hash functions (SipHash-2-4, AES-CMAC, BLAKE2b, BLAKE2s, BLAKE3). Use of non-cryptographic hash functions (XXH3, HighwayHash) is intended **solely for research and educational purposes** and is **potentially dangerous** in any real-world application. The authors provide no warranty of any kind. Use at your own risk.

A parameterized symmetric cipher construction library for Go that achieves known-plaintext resistance under passive observation through an information-theoretic barrier.

**Zero external dependencies.** Hash functions are supplied by the user.

**Central design idea:** The random container creates an information-theoretic barrier. PRF-grade hash functions are strongly recommended for production use, but the construction's architecture theoretically permits hash functions satisfying only five weaker requirements (full input sensitivity, chain survival, non-affine mixing, avalanche, non-invertibility) for research and educational purposes.

## Why ITB: Inverted Approach to Cryptography

Traditional symmetric ciphers (AES, ChaCha20) place all security burden on the mathematical strength of their core primitive. The keystream is XOR'd directly with plaintext — any weakness in the primitive is immediately exploitable because the attacker observes the primitive's output.

ITB inverts this approach. Instead of relying solely on the primitive's strength, the construction interposes a **random container** (generated from `crypto/rand`) between the hash output and the observer. The hash output is consumed by modifying random bytes that the attacker never sees — the original container values are never transmitted. This creates an information-theoretic barrier: no computational power can extract information that does not exist in the observation.

**Why the math is simple.** The construction uses only elementary operations: XOR, bitwise AND, modulo, bit shifts. There are no Galois fields, no S-boxes, no polynomial multiplication. This is not a weakness — it is a consequence of the design. The security comes from the **architecture** (random container, triple-seed isolation, per-bit XOR, noise embedding), not from the complexity of the math. Each architectural layer addresses a specific attack vector:

- **Random container** — hash output unobservable under passive observation (COA, KPA)
- **Per-bit XOR (1:1)** — 56 independent mask bits per pixel, every observation consistent with any plaintext
- **Triple-seed isolation** — CCA leaks only noiseSeed (3 bits/pixel); dataSeed and startSeed remain independent
- **Noise bit embedding** — no bit position is deterministically data from the public format

**Why triple-seed is necessary.** Without three independent seeds, a leak in one domain cascades: CCA reveals noise positions → same seed gives rotation and XOR → full configuration recovered. Triple-seed isolation ensures each leak is contained: CCA → only noiseSeed, cache side-channel → only startSeed, dataSeed → zero software-observable exposure. This is the minimum configuration where every leak is architecturally isolated.

**Why PRF requirements are relaxed.** In traditional ciphers, the attacker directly observes the primitive's output (keystream XOR plaintext). Any bias, invertibility, or algebraic structure is exploitable. In ITB, the hash output is absorbed by a random container modification — the attacker sees modified random bytes, not hash outputs. Under the random-container model, every observed byte value is compatible with every possible hash output. PRF-grade hash functions are strictly recommended for production use, but the construction's architecture theoretically permits weaker hash functions for research purposes. Using non-cryptographic hash functions in any real-world application is potentially dangerous.

**Why quantum structural attacks are conjectured mitigated.** Quantum algorithms like Simon (periodicity), BHT (collisions), and quantum differential/linear analysis require observable structural relations between inputs and outputs. The random container makes these relations unobservable — the attacker cannot build the algebraic structures that quantum algorithms exploit. Additionally, ITB's MAC oracle (when present) is inherently classical: it accepts concrete bytes over a network, not quantum superposition queries (Q2 model inapplicable). This is an architectural observation that has not been independently verified.

> **Important.** ITB is an experimental construction without peer review or independent cryptanalysis. The information-theoretic barrier is a ***software-level property*** — it provides no guarantees against hardware-level attacks. All security claims are under the random-container model and have not been independently verified.

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

# Benchmark specific hash (XXH3, AES, BLAKE3, HW256, SipHash-2-4, BLAKE2b, BLAKE2s)
go test -bench='XXH3_' -benchmem ./...
go test -bench='BLAKE3_' -benchmem ./...

# Benchmark key size scaling
go test -bench='KeySize' -benchmem ./...
```

### Performance (i7-11700K, CGO mode, 512-bit key)

**Encrypt (MB/s):**

| Hash | Width | Crypto | ITB Key | 1 MB | 16 MB | 64 MB |
|---|---|---|---|---|---|---|
| **XXH3×2** | 128 | — | 1024 | 186 | 201 | 195 |
| **XXH3** | 64 | — | 512 | 176 | 210 | 183 |
| **XXH3×4** | 256 | — | 2048 | 176 | 206 | 189 |
| **XXH3×8** | 512 | — | 2048 | 170 | 213 | 187 |
| **SipHash-2-4** | 128 | PRF | 1024 | 138 | 146 | 135 |
| **BLAKE2b-512** | 512 | **PRF** | 2048 | **110** | **126** | **119** |
| **AES-CMAC** | 128 | PRF | 1024 | 114 | 143 | 132 |
| **HW-256** | 256 | — | 2048 | 106 | 117 | 114 |
| **BLAKE2s** | 256 | PRF | 2048 | 89 | 98 | 97 |
| **HW-128** | 128 | — | 1024 | 88 | 96 | 95 |
| **BLAKE2b-256** | 256 | PRF | 2048 | 75 | 92 | 92 |
| **BLAKE3** | 256 | PRF | 2048 | 64 | 68 | 63 |
| **HW-64** | 64 | — | 512 | 63 | 66 | 64 |

**Decrypt (MB/s):**

| Hash | Width | Crypto | ITB Key | 1 MB | 16 MB | 64 MB |
|---|---|---|---|---|---|---|
| **XXH3×2** | 128 | — | 1024 | 285 | 322 | 302 |
| **XXH3×8** | 512 | — | 2048 | 282 | 319 | 297 |
| **XXH3×4** | 256 | — | 2048 | 275 | 307 | 283 |
| **XXH3** | 64 | — | 512 | 268 | 313 | 296 |
| **SipHash-2-4** | 128 | PRF | 1024 | 165 | 197 | 200 |
| **BLAKE2b-512** | 512 | **PRF** | 2048 | **151** | **173** | **171** |
| **AES-CMAC** | 128 | PRF | 1024 | 152 | 187 | 168 |
| **HW-256** | 256 | — | 2048 | 116 | 136 | 144 |
| **HW-128** | 128 | — | 1024 | 103 | 121 | 118 |
| **BLAKE2s** | 256 | PRF | 2048 | 106 | 121 | 107 |
| **BLAKE2b-256** | 256 | PRF | 2048 | 98 | 114 | 110 |
| **BLAKE3** | 256 | PRF | 2048 | 72 | 75 | 72 |
| **HW-64** | 64 | — | 512 | 67 | 79 | 77 |

Throughput scales with data size due to goroutine parallelism across CPU cores. CGO mode uses C pixel processing with GCC `-O3 -mavx2` auto-vectorization + L1-cache micro-batching. Pure Go fallback (`CGO_ENABLED=0`) is ~10-20% slower on decrypt.

**BLAKE2b-512 highlight:** With 512-bit ChainHash (1 round for 512-bit key), BLAKE2b-512 is ~30% faster than BLAKE2b-256 (2 rounds) while providing wider MITM bottleneck (2^512 vs 2^256). PRF-level encryption at 110-173 MB/s.

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/everanium/itb"
    "github.com/zeebo/xxh3"
)

func main() {
    // Create three independent seeds (triple-seed isolation)
    noiseSeed, err := itb.NewSeed(512, xxh3.HashSeed)
    if err != nil {
        panic(err)
    }
    dataSeed, err := itb.NewSeed(512, xxh3.HashSeed)
    if err != nil {
        panic(err)
    }
    startSeed, err := itb.NewSeed(512, xxh3.HashSeed)
    if err != nil {
        panic(err)
    }

    plaintext := []byte("any binary data — including 0x00 bytes")

    // Encrypt into RGBWYOPA container
    encrypted, err := itb.Encrypt(noiseSeed, dataSeed, startSeed, plaintext)
    if err != nil {
        panic(err)
    }
    fmt.Printf("encrypted: %d bytes\n", len(encrypted))

    // Decrypt
    decrypted, err := itb.Decrypt(noiseSeed, dataSeed, startSeed, encrypted)
    if err != nil {
        panic(err)
    }
    fmt.Printf("decrypted: %s\n", string(decrypted))
}
```

## How It Works

ITB encrypts data into raw RGBWYOPA pixel containers (8 channels per pixel: Red, Green, Blue, White, Yellow, Orange, Purple, Alpha) generated from `crypto/rand`. Each 8-bit channel carries 7 data bits and 1 noise bit, yielding 56 data bits per pixel at 1.14× overhead. Each pixel's bit-plane selection and per-channel XOR masks are derived from a chained hash of the seed and a per-message nonce. The random container creates an information-theoretic barrier: hash outputs are consumed by modifications of random pixel values and are not reconstructible from observations.

The data is embedded starting at a seed-dependent pixel offset with wrap-around — the physical layout in the container is completely non-sequential. An observer sees uniformly random pixel values with no way to determine which pixels carry data, in what order, or what bit-plane is used.

## Hash Width Variants

The library provides four parallel API sets for different hash output widths. All share the same pixel format, framing, and security properties — the difference is in ChainHash intermediate state width.

| API | Hash Type | State | Effective Max Key | Target Hash Functions |
|---|---|---|---|---|
| `Encrypt` / `Decrypt` | `HashFunc` (64-bit) | 64-bit | 512 bits | XXH3, XXH64 |
| `Encrypt128` / `Decrypt128` | `HashFunc128` (128-bit) | 128-bit | 1024 bits | SipHash-2-4, AES-CMAC |
| `Encrypt256` / `Decrypt256` | `HashFunc256` (256-bit) | 256-bit | 2048 bits | BLAKE3 keyed |
| `Encrypt512` / `Decrypt512` | `HashFunc512` (512-bit) | 512-bit | 2048 bits | BLAKE2b-512 |

Each variant also has authenticated versions (`EncryptAuthenticated`/`DecryptAuthenticated`, `EncryptAuthenticated128`/`DecryptAuthenticated128`, `EncryptAuthenticated256`/`DecryptAuthenticated256`, `EncryptAuthenticated512`/`DecryptAuthenticated512`) and streaming versions (`EncryptStream`/`DecryptStream`, `EncryptStream128`/`DecryptStream128`, `EncryptStream256`/`DecryptStream256`, `EncryptStream512`/`DecryptStream512`).

### 128-bit Example (SipHash-2-4)

```go
// HashFunc128: func(data []byte, seed0, seed1 uint64) (lo, hi uint64)
func sipHash128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
    return siphash.Hash128(seed0, seed1, data)
}

ns, _ := itb.NewSeed128(1024, sipHash128)  // 1024-bit key, 16 components, 8 rounds
ds, _ := itb.NewSeed128(1024, sipHash128)
ss, _ := itb.NewSeed128(1024, sipHash128)

encrypted, _ := itb.Encrypt128(ns, ds, ss, plaintext)
decrypted, _ := itb.Decrypt128(ns, ds, ss, encrypted)
```

### 256-bit Example (BLAKE3)

```go
// HashFunc256: func(data []byte, seed [4]uint64) [4]uint64
func blake3Hash256(data []byte, seed [4]uint64) [4]uint64 {
    var key [32]byte
    binary.LittleEndian.PutUint64(key[0:], seed[0])
    binary.LittleEndian.PutUint64(key[8:], seed[1])
    binary.LittleEndian.PutUint64(key[16:], seed[2])
    binary.LittleEndian.PutUint64(key[24:], seed[3])
    h, _ := blake3.NewKeyed(key[:])
    h.Write(data)
    var out [32]byte
    h.Sum(out[:0])
    var result [4]uint64
    for i := range result {
        result[i] = binary.LittleEndian.Uint64(out[i*8:])
    }
    return result
}
// Note: creates a new hasher per call. See "Optimized Hash Wrappers" below for production use.

ns, _ := itb.NewSeed256(2048, blake3Hash256)  // 2048-bit key, 32 components, 8 rounds
ds, _ := itb.NewSeed256(2048, blake3Hash256)
ss, _ := itb.NewSeed256(2048, blake3Hash256)

encrypted, _ := itb.Encrypt256(ns, ds, ss, plaintext)
decrypted, _ := itb.Decrypt256(ns, ds, ss, encrypted)
```

## Hash Function Selection

ITB accepts pluggable hash functions at four widths. Requirements: the hash must process all input bytes with non-invertible, non-affine, avalanche mixing that survives the ChainHash XOR-chain. PRF/PRP/PRG relaxed under the random-container model (PRF recommended).

| Hash Function | Acceleration | Seed Input | Block/State | Hash Type | Max Key | Crypto | Go Library |
|---|---|---|---|---|---|---|---|
| **XXH3** | SIMD (AVX2) | 64 bit | 64 bit | `HashFunc` | 512 | — | `github.com/zeebo/xxh3` |
| **HighwayHash-64** | SIMD (AVX2) | 64 bit (cached) | 256 bit | `HashFunc` | 512 | — | `github.com/minio/highwayhash` |
| **XXH3×2** | SIMD (AVX2) | 2×64 bit | 2×64 bit | `HashFunc128` | 1024 | — | `github.com/zeebo/xxh3` |
| **SipHash-2-4** | — | 128 bit | 128 bit | `HashFunc128` | 1024 | **PRF** | `github.com/dchest/siphash` |
| **HighwayHash-128** | SIMD (AVX2) | 128 bit (cached) | 256 bit | `HashFunc128` | 1024 | — | `github.com/minio/highwayhash` |
| **AES-CMAC** | **AES-NI** | 128 bit (block) | 128 bit | `HashFunc128` | 1024 | **PRF** | `crypto/aes` (stdlib) |
| **XXH3×4** | SIMD (AVX2) | 4×64 bit | 4×64 bit | `HashFunc256` | 2048 | — | `github.com/zeebo/xxh3` |
| **HighwayHash-256** | SIMD (AVX2) | 256 bit | 256 bit | `HashFunc256` | 2048 | — | `github.com/minio/highwayhash` |
| **BLAKE2b keyed** | SSE | 256 bit (prefix) | 256 bit | `HashFunc256` | 2048 | **PRF** | `golang.org/x/crypto/blake2b` |
| **BLAKE2s keyed** | — | 256 bit (prefix) | 256 bit | `HashFunc256` | 2048 | **PRF** | `golang.org/x/crypto/blake2s` |
| **BLAKE3 keyed** | SIMD (AVX-512) | 256 bit | 256 bit | `HashFunc256` | 2048 | **PRF** | `github.com/zeebo/blake3` |
| **XXH3×8** | SIMD (AVX2) | 8×64 bit | 8×64 bit | `HashFunc512` | 2048 | — | `github.com/zeebo/xxh3` |
| **BLAKE2b-512 keyed** | SSE | 512 bit | 512 bit | `HashFunc512` | 2048 | **PRF** | `golang.org/x/crypto/blake2b` |

### Choosing the Right Hash Width

The effective key size is determined by the **seed input width** of the hash function — not its output width. This is a critical distinction:

```
Effective max key = min(keyBits, seedInputWidth × numRounds)
```

**Common pitfall: XXH3-128 native.** XXH3-128 produces 128-bit output but accepts only a single 64-bit seed. Using it as `HashFunc128` would create a 64-bit bottleneck in ChainHash128, limiting effective security to 512 bits despite the 128-bit output. The correct approach for 128-bit ITB with XXH3 is **XXH3×2** — two independent `xxh3.HashSeed` calls, each with its own seed component:

```go
// WRONG: XXH3-128 native — 64-bit seed bottleneck, effective max = 512 bits
func bad128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
    h := xxh3.Hash128Seed(data, seed0 ^ seed1)  // seeds merged into 64 bits!
    return h.Lo, h.Hi
}

// CORRECT: XXH3×2 — two independent 64-bit calls = 128-bit state
func xxh3x2(data []byte, seed0, seed1 uint64) (uint64, uint64) {
    return xxh3.HashSeed(data, seed0), xxh3.HashSeed(data, seed1)
}
```

The same principle applies at 256-bit: use **XXH3×4** (four independent calls), not a single hash with wide output but narrow seed.

For hash functions with natively wide seed input (AES: 128-bit key, BLAKE3: 256-bit key, HighwayHash: 256-bit key), this is not an issue — seed width matches output width. See the "Optimized Hash Wrappers" section for recommended implementations.

### Why Wider Hash = Faster AND More Secure

With a 512-bit key (8 components), ChainHash processes components in groups matching the hash width:

| Hash width | Components/round | Rounds | Hash calls/pixel |
|---|---|---|---|
| 64-bit | 1 | 8 | 8 |
| 128-bit | 2 | 4 | 4 |
| 256-bit | 4 | **2** | **2** |
| 512-bit | 8 | **1** | **1** |

All 8 components are consumed in every case — no key material is skipped. A 256-bit hash simply processes 4 components per call instead of 1.

**Faster:** each hash call has overhead (state initialization, finalization). For heavy hash functions like HighwayHash (~200ns/call) or BLAKE3 (~300ns/call), fewer calls = proportionally faster. HighwayHash-256 at 97 MB/s vs HighwayHash-64 at 57 MB/s — same key, same algorithm, 1.7× faster.

**More secure:** the wider intermediate state makes meet-in-the-middle attacks harder. With 256-bit state, an attacker must enumerate 2^256 possible intermediate values (vs 2^64 for a 64-bit hash). Additionally, fewer chain rounds means fewer potential split points for the attacker.

This effect is negligible for lightweight hashes (XXH3: ~5ns/call) where per-call overhead is tiny.

**Bottom line:** when using heavy hash functions (HighwayHash, AES, BLAKE3), prefer the widest available variant — it's both faster and more secure.

### Hash Function Wrappers

```go
// 64-bit: HashFunc = func(data []byte, seed uint64) uint64
func xxh3Hash(data []byte, seed uint64) uint64 {
    return xxh3.HashSeed(data, seed)
}

// 128-bit: HashFunc128 = func(data []byte, seed0, seed1 uint64) (lo, hi uint64)
// Option A: XXH3×2 (non-crypto, fastest)
func xxh3x2(data []byte, seed0, seed1 uint64) (uint64, uint64) {
    return xxh3.HashSeed(data, seed0), xxh3.HashSeed(data, seed1)
}

// Option B: AES-NI cached (PRF, hardware-accelerated) — see Optimized Hash Wrappers

// 256-bit: HashFunc256 = func(data []byte, seed [4]uint64) [4]uint64
// Option A: XXH3×4 (non-crypto, fastest)
func xxh3x4(data []byte, seed [4]uint64) [4]uint64 {
    return [4]uint64{
        xxh3.HashSeed(data, seed[0]),
        xxh3.HashSeed(data, seed[1]),
        xxh3.HashSeed(data, seed[2]),
        xxh3.HashSeed(data, seed[3]),
    }
}

// Option B: BLAKE3 keyed cached (PRF, SIMD) — see Optimized Hash Wrappers
```

## Optimized Hash Wrappers

Hash functions like AES and BLAKE3 have expensive key setup. Creating a new cipher/hasher on every call (naive approach) wastes ~90% of time on initialization. The **cached wrapper** pattern fixes this: create the cipher once with a fixed random key, mix seed components into the data instead.

Each of the three seeds must get its own wrapper instance (independent key).

### AES-NI Cached (128-bit, stdlib)

```go
func makeAESHash() itb.HashFunc128 {
    var key [16]byte
    rand.Read(key[:])
    block, _ := aes.NewCipher(key[:])

    return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
        var b [16]byte
        // XOR seed into first 16 bytes of data
        copy(b[:], data)
        binary.LittleEndian.PutUint64(b[0:], binary.LittleEndian.Uint64(b[0:])^seed0)
        binary.LittleEndian.PutUint64(b[8:], binary.LittleEndian.Uint64(b[8:])^seed1)
        block.Encrypt(b[:], b[:])
        // Process remaining bytes (data is 20 bytes: 4 counter + 16 nonce)
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

### Performance: Naive vs Cached (1MB, i7-11700K)

| Hash | Naive | Cached | Speedup |
|---|---|---|---|
| AES-NI 128-bit | ~8 MB/s | ~122 MB/s | 15× |
| BLAKE3 256-bit | ~2 MB/s | ~55 MB/s | 27× |

## Key Size Selection

```go
// 64-bit hash: 512-bit keys (practical maximum)
ns, _ := itb.NewSeed(512, xxh3Hash)
ds, _ := itb.NewSeed(512, xxh3Hash)
ss, _ := itb.NewSeed(512, xxh3Hash)

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
| `Seed` (64-bit) | [512, 2048] | multiple of 64 | [8, 32] | any |
| `Seed128` | [512, 2048] | multiple of 128 | [8, 32] | even |
| `Seed256` | [512, 2048] | multiple of 256 | [8, 32] | multiple of 4 |
| `Seed512` (512-bit) | [512, 2048] | multiple of 512 | [8, 32] | multiple of 8 |

## Minimum Container Size

Information-theoretic security under the random-container model requires `ceil(keyBits / 7)` pixels,
ensuring the noise barrier (2^(8P)) strictly exceeds the key space:

| Key Size | Min Pixels → Container | Noise Barrier |
|---|---|---|
| 512 bits | 74 → 81 (9×9) | 2^648 ≥ 2^512 |
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

The output format is identical across all four hash width variants.

## Security Summary

| Property | ITB |
|---|---|
| Key space | Up to 2^2048 |
| Grover resistance | 2^(keyBits/2) |
| Oracle-free deniability | Yes |
| Hash function requirement | Requirements 1-5 (PRF recommended; weaker permitted for research) |
| Known-plaintext resistance | Under passive observation |
| Chosen-plaintext resistance | Independent maps |
| Nonce reuse protection | 128-bit per-message nonce |
| Noise barrier (min container) | 2^648 (512-bit) to 2^2592 (2048-bit) |
| Storage overhead | 1.14× (56 data bits per 64-bit pixel) |

## Integrity (MAC-inside-Encrypt)

The core construction provides confidentiality only. For integrity protection against bit-flipping attacks, use the MAC-inside-encrypt pattern — the MAC is encrypted inside the container, preserving oracle-free deniability:

```go
// Using EncryptAuthenticated / DecryptAuthenticated (available for all widths)
encrypted, err := itb.EncryptAuthenticated(noiseSeed, dataSeed, startSeed, plaintext, myMACFunc)
original, err := itb.DecryptAuthenticated(noiseSeed, dataSeed, startSeed, encrypted, myMACFunc)

// 128-bit variant
encrypted, err = itb.EncryptAuthenticated128(ns128, ds128, ss128, plaintext, myMACFunc)
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
encrypted, err := itb.Encrypt(seed, seed, seed, data)
// Error: "itb: all three seeds must be different (triple-seed isolation)"

// Correct usage: three independent seeds
encrypted, err := itb.Encrypt(noiseSeed, dataSeed, startSeed, data)
```

## See Also

- [FEATURES.md](FEATURES.md) — Complete feature list and security properties
- [PROOFS.md](PROOFS.md) — Formal security proofs
- [SCIENCE.md](SCIENCE.md) — Scientific analysis and formal security arguments
- [SECURITY.md](SECURITY.md) — Security reference tables
- [HWTHREATS.md](HWTHREATS.md) — Hardware-level threat analysis (Spectre, Meltdown, Rowhammer, etc.)

## License

MIT — see [LICENSE](LICENSE).
