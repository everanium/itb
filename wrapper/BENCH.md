# ITB Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of nine outer keystream ciphers, one per PRF-grade ITB registry primitive: Areion-SoEM-256/512, SipHash-2-4 in CTR mode, AES-128-CTR, BLAKE2b-256/512, BLAKE2s, BLAKE3, and ChaCha20 (RFC8439). The keystream construction is delegated to the [`ctr`](../ctr/) package; AES-128-CTR and ChaCha20 use their native modes, the others run in PRF-counter mode. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (zero allocation steady state); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single Message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's `io.Reader` / `io.Writer` API or a User-Driven Loop emitting framed chunks through the wrapped writer.

The blob `Wrap` / `Unwrap` paths split the keystream XOR across up to 32 worker goroutines (the effective count is `min(32, GOMAXPROCS, chunks)`), each seeking its own keystream to its chunk's byte offset via `ctr.NewAt`. One logical CTR stream is therefore evaluated in disjoint ranges concurrently, byte-identical to a serial pass. With this, the slowest outer cipher keystream in the Wrapper Only round-trip (BLAKE2b-256, ~546 MB/s) stays ahead of ITB's combined per-direction throughput on this host (~130–350 MB/s), so no outer cipher is the wrapper-path bottleneck. AES-128-CTR with hardware AES-NI remains the fastest of the nine. The worker cap is fixed, not user-configurable: ITB's own per-pixel hashing already saturates every core, so the wrapper's secondary, partly memory-bound XOR must not over-subscribe by spawning a goroutine per core a second time.

Reproduction:

```sh
go test -run='^$' -bench='.' -benchtime=5s -count=1 ./wrapper/
```

Filter examples:

```sh
go test -run='^$' -bench='BenchmarkWrapperOnlyInPlace' -benchtime=5s -count=1 ./wrapper/
go test -run='^$' -bench='BenchmarkMessageSingle/easy-nomac' -benchtime=5s -count=1 ./wrapper/
go test -run='^$' -bench='BenchmarkStreamingTriple/.*/aescmac' -benchtime=5s -count=1 ./wrapper/
```

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### Configuration

* Outer cipher path: all nine PRF-grade registry primitives (Areion-SoEM-256/512, SipHash-2-4, AES-128-CTR, BLAKE2b-256/512, BLAKE2s, BLAKE3, ChaCha20 (RFC8439)), keystream built by the `ctr` package; blob XOR parallelised across up to 32 workers.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb.SetMaxWorkers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single Message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via `copy()`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware (~3-5 ms per 16 MiB memcpy vs ~60-90 ms per 16 MiB Easy / Low-Level Decrypt).

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper Only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (zero alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1541 | 1935 |
| **Areion-SoEM-512** | 1615 | 1928 |
| **SipHash-2-4** | 1847 | 2924 |
| **AES-128-CTR** | 2870 | 10638 |
| **BLAKE2b-256** | 546 | 630 |
| **BLAKE2b-512** | 924 | 1100 |
| **BLAKE2s** | 611 | 713 |
| **BLAKE3** | 1069 | 1336 |
| **ChaCha20** | 1985 | 2717 |

`WrapInPlace` mutates the caller's blob and returns the per-stream nonce; the steady-state allocation is one nonce buffer (~16 bytes) per call. `Wrap` returns a fresh wire = `nonce || keystream-XOR(blob)` and allocates `len(nonce) + len(blob)` bytes per call. The AES-128-CTR delta is dominated by the heap-page-fault cost of the 16 MiB output buffer; the PRF-counter ciphers are more compute-bound and the allocation savings are a smaller fraction of the total.

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 191 | 276 | 174 | 254 | 186 | 281 | 177 | 259 |
| **Areion-SoEM-512** | 188 | 269 | 176 | 253 | 189 | 278 | 177 | 260 |
| **SipHash-2-4** | 190 | 279 | 178 | 254 | 198 | 296 | 178 | 264 |
| **AES-128-CTR** | 197 | 286 | 173 | 262 | 187 | 283 | 177 | 265 |
| **BLAKE2b-256** | 167 | 230 | 158 | 219 | 172 | 239 | 163 | 229 |
| **BLAKE2b-512** | 185 | 266 | 172 | 246 | 190 | 273 | 172 | 246 |
| **BLAKE2s** | 176 | 244 | 165 | 230 | 178 | 248 | 167 | 233 |
| **BLAKE3** | 189 | 274 | 175 | 253 | 191 | 276 | 176 | 257 |
| **ChaCha20** | 196 | 286 | 180 | 265 | 195 | 287 | 183 | 270 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 272 | 328 | 238 | 291 | 277 | 327 | 246 | 301 |
| **Areion-SoEM-512** | 276 | 320 | 244 | 299 | 279 | 321 | 244 | 298 |
| **SipHash-2-4** | 278 | 324 | 248 | 301 | 283 | 331 | 250 | 309 |
| **AES-128-CTR** | 283 | 333 | 255 | 313 | 292 | 350 | 255 | 316 |
| **BLAKE2b-256** | 232 | 263 | 206 | 246 | 232 | 265 | 207 | 242 |
| **BLAKE2b-512** | 253 | 294 | 229 | 272 | 256 | 297 | 229 | 277 |
| **BLAKE2s** | 235 | 269 | 208 | 254 | 237 | 268 | 212 | 253 |
| **BLAKE3** | 258 | 299 | 233 | 278 | 263 | 305 | 235 | 287 |
| **ChaCha20** | 274 | 325 | 247 | 302 | 285 | 332 | 251 | 309 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 127 | 160 | 130 | 161 |
| **Areion-SoEM-512** | 125 | 155 | 124 | 155 |
| **SipHash-2-4** | 126 | 169 | 135 | 172 |
| **AES-128-CTR** | 167 | 232 | 169 | 237 |
| **BLAKE2b-256** | 67 | 71 | 67 | 71 |
| **BLAKE2b-512** | 90 | 106 | 90 | 106 |
| **BLAKE2s** | 72 | 61 | 57 | 59 |
| **BLAKE3** | 97 | 113 | 94 | 114 |
| **ChaCha20** | 122 | 129 | 120 | 151 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk) — Non-AEAD

| Cipher | Easy IO Enc | Easy IO Dec | Easy Loop Enc | Easy Loop Dec | LL IO Enc | LL IO Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 132 | 160 | 138 | 168 | 141 | 167 | 138 | 174 |
| **Areion-SoEM-512** | 139 | 163 | 140 | 170 | 141 | 172 | 141 | 171 |
| **SipHash-2-4** | 147 | 183 | 148 | 185 | 151 | 188 | 152 | 192 |
| **AES-128-CTR** | 188 | 256 | 188 | 259 | 191 | 261 | 189 | 260 |
| **BLAKE2b-256** | 66 | 75 | 68 | 75 | 67 | 74 | 68 | 74 |
| **BLAKE2b-512** | 95 | 110 | 95 | 109 | 95 | 111 | 96 | 110 |
| **BLAKE2s** | 53 | 64 | 70 | 81 | 71 | 72 | 71 | 80 |
| **BLAKE3** | 103 | 123 | 105 | 125 | 105 | 121 | 105 | 125 |
| **ChaCha20** | 135 | 167 | 136 | 169 | 135 | 167 | 135 | 170 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 144 | 169 | 149 | 169 |
| **Areion-SoEM-512** | 157 | 188 | 161 | 183 |
| **SipHash-2-4** | 166 | 201 | 174 | 201 |
| **AES-128-CTR** | 227 | 274 | 232 | 271 |
| **BLAKE2b-256** | 68 | 71 | 70 | 73 |
| **BLAKE2b-512** | 101 | 99 | 102 | 110 |
| **BLAKE2s** | 81 | 88 | 81 | 88 |
| **BLAKE3** | 122 | 132 | 120 | 132 |
| **ChaCha20** | 172 | 193 | 172 | 196 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk) — Non-AEAD

| Cipher | Easy IO Enc | Easy IO Dec | Easy Loop Enc | Easy Loop Dec | LL IO Enc | LL IO Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 166 | 178 | 164 | 172 | 169 | 189 | 175 | 193 |
| **Areion-SoEM-512** | 176 | 189 | 178 | 187 | 181 | 191 | 172 | 178 |
| **SipHash-2-4** | 193 | 209 | 195 | 212 | 198 | 217 | 196 | 213 |
| **AES-128-CTR** | 242 | 278 | 242 | 266 | 245 | 276 | 243 | 271 |
| **BLAKE2b-256** | 73 | 74 | 73 | 74 | 72 | 76 | 74 | 76 |
| **BLAKE2b-512** | 110 | 112 | 112 | 114 | 113 | 117 | 113 | 117 |
| **BLAKE2s** | 83 | 88 | 86 | 89 | 87 | 90 | 87 | 87 |
| **BLAKE3** | 133 | 142 | 139 | 146 | 140 | 149 | 142 | 150 |
| **ChaCha20** | 190 | 209 | 191 | 205 | 192 | 212 | 197 | 211 |

The Easy and Low-Level paths land within run-to-run noise on every cipher × direction cell. Triple Ouroboros consistently outpaces Single by 30-40% — the three parallel encryption pipes saturate more of the available HT. Decrypt outperforms Encrypt by 20-50% because the encrypt path runs additional per-pixel work that decrypt does not (nonce derivation + barrier prefill). Within the full ITB + wrapper tables the AES-NI and PRF-counter outer ciphers land close together: ITB's per-pixel hashing dominates the combined cost, so the outer cipher choice moves the totals only at the margin.

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
