# ITB Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of the outer keystream ciphers, one per PRF-grade ITB registry primitive: Areion-SoEM-256/512, BLAKE2b-256/512, BLAKE2s, BLAKE3, AES-128-CTR, SipHash-2-4 in CTR mode, ChaCha20 (RFC 8439). The keystream construction is delegated to the [`ctr`](../ctr/) package; AES-128-CTR and ChaCha20 use their native modes, the others run in PRF-counter mode. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (no output-buffer allocation); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Single Message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's `io.Reader` / `io.Writer` API or a User-Driven Loop emitting framed chunks through the wrapped writer.

The blob `Wrap` / `Unwrap` paths split the keystream XOR across up to 32 worker goroutines (the effective count is `min(32, GOMAXPROCS, chunks)`), each seeking its own keystream to its chunk's byte offset via `ctr.NewAt`. One logical CTR stream is therefore evaluated in disjoint ranges concurrently, byte-identical to a serial pass. With this, the slowest outer cipher keystream in the wrapper only round-trip (BLAKE2b-256, ~571 MB/s) stays ahead of ITB's combined per-direction throughput on this host (~200–350 MB/s), so no outer cipher is the wrapper-path bottleneck. AES-128-CTR with hardware AES-NI remains the fastest. The worker cap is fixed, not user-configurable: ITB's own per-pixel hashing already saturates every core, so the wrapper's secondary, partly memory-bound XOR must not over-subscribe by spawning a goroutine per core a second time.

Reproduction:

```sh
go test -run='^$' -bench='.' -benchtime=5s -count=1 ./wrapper/
```

Filter examples:

```sh
go test -run='^$' -bench='BenchmarkWrapperOnlyInPlace' -benchtime=5s -count=1 ./wrapper/
go test -run='^$' -bench='BenchmarkMessageTriple/lowlevel-nomac' -benchtime=5s -count=1 ./wrapper/
go test -run='^$' -bench='BenchmarkStreamingTriple/.*/aescmac' -benchtime=5s -count=1 ./wrapper/
```

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### Configuration

* Outer cipher path: all PRF-grade registry primitives (Areion-SoEM-256/512, BLAKE2b-256/512, BLAKE2s, BLAKE3, AES-128-CTR, SipHash-2-4, ChaCha20 (RFC 8439)), keystream built by the `ctr` package; blob XOR parallelised across up to 32 workers.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1` (minimum config so the outer cipher delta is not masked by per-pixel feature cost). The 48-bit Interlocked Barrier is always engaged and non-disableable by construction.
* `MaxWorkers=0` on the shared `*itb.Config` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single Message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via `copy()`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware (~3-5 ms per 16 MiB memcpy vs ~60-90 ms per 16 MiB Facade / Low-Level Decrypt).

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level (`*Cfg` entry points), **Loop** = User-Driven Loop, **IO** = IO-Driven, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1602 | 1923 |
| **Areion-SoEM-512** | 1611 | 1971 |
| **BLAKE2b-256** | 571 | 622 |
| **BLAKE2b-512** | 947 | 1014 |
| **BLAKE2s** | 617 | 672 |
| **BLAKE3** | 1123 | 1343 |
| **AES-128-CTR** | 2921 | 10110 |
| **SipHash-2-4** | 1893 | 2946 |
| **ChaCha20** | 1924 | 2725 |

`WrapInPlace` mutates the caller's blob and returns the per-stream nonce; no output buffer is allocated. A fresh nonce (~16 bytes) is allocated per call on the encrypt side, and the parallel XOR path additionally allocates per-worker keystream state for buffers at or above the 256 KiB threshold. `Wrap` returns a fresh wire = `nonce || keystream-XOR(blob)` and allocates `len(nonce) + len(blob)` bytes per call. The AES-128-CTR delta is dominated by the heap-page-fault cost of the 16 MiB output buffer; the PRF-counter ciphers are more compute-bound and the allocation savings are a smaller fraction of the total.

### Historical baseline — old ITB Triple Ouroboros

The tables in this section were measured on the old ITB Triple Ouroboros construction — before the 48-bit Interlocked Barrier became a non-disableable core of every Triple encrypt / decrypt call and before the lockSeed slot became mandatory. Numbers are retained as an orientation-scale reference for the outer cipher cost added on top of ITB. Shipped Interlocked Barrier bench numbers will supersede these tables when the outer cipher re-run lands.

Columns measure the wrapper composed with the Low-Level `*Cfg` entry points, which survive from the old ITB construction to the current line.

#### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | LL No MAC Enc | LL No MAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 276 | 322 | 243 | 295 |
| **Areion-SoEM-512** | 277 | 322 | 246 | 299 |
| **BLAKE2b-256** | 232 | 268 | 213 | 247 |
| **BLAKE2b-512** | 258 | 301 | 232 | 279 |
| **BLAKE2s** | 242 | 274 | 217 | 255 |
| **BLAKE3** | 267 | 305 | 238 | 288 |
| **AES-128-CTR** | 291 | 350 | 259 | 315 |
| **SipHash-2-4** | 274 | 329 | 248 | 310 |
| **ChaCha20** | 281 | 330 | 250 | 305 |

#### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk) — AEAD

| Cipher | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|
| **Areion-SoEM-256** | 231 | 280 |
| **Areion-SoEM-512** | 184 | 245 |
| **BLAKE2b-256** | 205 | 234 |
| **BLAKE2b-512** | 212 | 257 |
| **BLAKE2s** | 202 | 237 |
| **BLAKE3** | 219 | 259 |
| **AES-128-CTR** | 238 | 296 |
| **SipHash-2-4** | 234 | 284 |
| **ChaCha20** | 231 | 275 |

#### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk) — Non-AEAD

| Cipher | LL IO Enc | LL IO Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 240 | 280 | 237 | 244 |
| **Areion-SoEM-512** | 265 | 299 | 276 | 298 |
| **BLAKE2b-256** | 233 | 253 | 234 | 253 |
| **BLAKE2b-512** | 249 | 276 | 246 | 270 |
| **BLAKE2s** | 226 | 242 | 224 | 248 |
| **BLAKE3** | 251 | 277 | 254 | 278 |
| **AES-128-CTR** | 278 | 319 | 282 | 314 |
| **SipHash-2-4** | 277 | 310 | 278 | 303 |
| **ChaCha20** | 264 | 291 | 267 | 293 |

Decrypt outperforms Encrypt by 20-50% because the encrypt path runs additional per-pixel work that decrypt does not (nonce derivation + barrier prefill). Within the full ITB + wrapper tables the AES-NI and PRF-counter outer ciphers land close together: ITB's per-pixel hashing dominates the combined cost, so the outer cipher choice moves the totals only at the margin.

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
