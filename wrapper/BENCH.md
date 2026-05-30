# ITB Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive: Areion-SoEM-256/512, BLAKE2b-256/512, BLAKE2s, BLAKE3, AES-128-CTR, SipHash-2-4 in CTR mode, ChaCha20 (RFC 8439). The keystream construction is delegated to the [`ctr`](../ctr/) package; AES-128-CTR and ChaCha20 use their native modes, the others run in PRF-counter mode. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (no output-buffer allocation); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single Message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's `io.Reader` / `io.Writer` API or a User-Driven Loop emitting framed chunks through the wrapped writer.

The blob `Wrap` / `Unwrap` paths split the keystream XOR across up to 32 worker goroutines (the effective count is `min(32, GOMAXPROCS, chunks)`), each seeking its own keystream to its chunk's byte offset via `ctr.NewAt`. One logical CTR stream is therefore evaluated in disjoint ranges concurrently, byte-identical to a serial pass. With this, the slowest outer cipher keystream in the Wrapper Only round-trip (BLAKE2b-256, ~546 MB/s) stays ahead of ITB's combined per-direction throughput on this host (~130–350 MB/s), so no outer cipher is the wrapper-path bottleneck. AES-128-CTR with hardware AES-NI remains the fastest. The worker cap is fixed, not user-configurable: ITB's own per-pixel hashing already saturates every core, so the wrapper's secondary, partly memory-bound XOR must not over-subscribe by spawning a goroutine per core a second time.

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

* Outer cipher path: all PRF-grade registry primitives (Areion-SoEM-256/512, BLAKE2b-256/512, BLAKE2s, BLAKE3, AES-128-CTR, SipHash-2-4, ChaCha20 (RFC 8439)), keystream built by the `ctr` package; blob XOR parallelised across up to 32 workers.
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

| Cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1541 | 1935 |
| **Areion-SoEM-512** | 1615 | 1928 |
| **BLAKE2b-256** | 546 | 630 |
| **BLAKE2b-512** | 924 | 1100 |
| **BLAKE2s** | 611 | 713 |
| **BLAKE3** | 1069 | 1336 |
| **AES-128-CTR** | 2870 | 10638 |
| **SipHash-2-4** | 1847 | 2924 |
| **ChaCha20** | 1985 | 2717 |

`WrapInPlace` mutates the caller's blob and returns the per-stream nonce; no output buffer is allocated. A fresh nonce (~16 bytes) is allocated per call on the encrypt side, and the parallel XOR path additionally allocates per-worker keystream state for buffers at or above the 256 KiB threshold. `Wrap` returns a fresh wire = `nonce || keystream-XOR(blob)` and allocates `len(nonce) + len(blob)` bytes per call. The AES-128-CTR delta is dominated by the heap-page-fault cost of the 16 MiB output buffer; the PRF-counter ciphers are more compute-bound and the allocation savings are a smaller fraction of the total.

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 194 | 285 | 172 | 255 | 194 | 276 | 177 | 256 |
| **Areion-SoEM-512** | 192 | 272 | 178 | 255 | 193 | 295 | 177 | 257 |
| **BLAKE2b-256** | 169 | 235 | 162 | 224 | 173 | 241 | 162 | 225 |
| **BLAKE2b-512** | 184 | 263 | 173 | 246 | 185 | 264 | 171 | 245 |
| **BLAKE2s** | 172 | 238 | 164 | 236 | 176 | 254 | 163 | 232 |
| **BLAKE3** | 187 | 269 | 175 | 248 | 185 | 265 | 175 | 252 |
| **AES-128-CTR** | 199 | 288 | 182 | 265 | 201 | 298 | 183 | 267 |
| **SipHash-2-4** | 194 | 281 | 179 | 254 | 193 | 284 | 178 | 261 |
| **ChaCha20** | 194 | 284 | 180 | 262 | 192 | 262 | 166 | 257 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 271 | 330 | 237 | 298 | 276 | 322 | 243 | 295 |
| **Areion-SoEM-512** | 274 | 321 | 245 | 300 | 277 | 322 | 246 | 299 |
| **BLAKE2b-256** | 236 | 266 | 212 | 252 | 232 | 268 | 213 | 247 |
| **BLAKE2b-512** | 253 | 285 | 217 | 265 | 258 | 301 | 232 | 279 |
| **BLAKE2s** | 240 | 268 | 214 | 256 | 242 | 274 | 217 | 255 |
| **BLAKE3** | 261 | 308 | 237 | 286 | 267 | 305 | 238 | 288 |
| **AES-128-CTR** | 287 | 343 | 253 | 318 | 291 | 350 | 259 | 315 |
| **SipHash-2-4** | 281 | 325 | 246 | 286 | 274 | 329 | 248 | 310 |
| **ChaCha20** | 280 | 328 | 248 | 306 | 281 | 330 | 250 | 305 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 163 | 224 | 168 | 223 |
| **Areion-SoEM-512** | 165 | 219 | 168 | 229 |
| **BLAKE2b-256** | 148 | 202 | 151 | 202 |
| **BLAKE2b-512** | 159 | 214 | 162 | 216 |
| **BLAKE2s** | 149 | 203 | 156 | 193 |
| **BLAKE3** | 165 | 224 | 166 | 227 |
| **AES-128-CTR** | 173 | 242 | 171 | 244 |
| **SipHash-2-4** | 171 | 233 | 170 | 234 |
| **ChaCha20** | 170 | 232 | 171 | 236 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk) — Non-AEAD

| Cipher | Easy IO Enc | Easy IO Dec | Easy Loop Enc | Easy Loop Dec | LL IO Enc | LL IO Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 190 | 259 | 190 | 258 | 191 | 250 | 190 | 258 |
| **Areion-SoEM-512** | 188 | 258 | 188 | 253 | 188 | 261 | 190 | 257 |
| **BLAKE2b-256** | 168 | 217 | 172 | 215 | 172 | 216 | 169 | 215 |
| **BLAKE2b-512** | 179 | 239 | 180 | 231 | 180 | 232 | 175 | 234 |
| **BLAKE2s** | 168 | 229 | 172 | 221 | 175 | 227 | 174 | 224 |
| **BLAKE3** | 186 | 252 | 185 | 250 | 188 | 247 | 188 | 251 |
| **AES-128-CTR** | 195 | 272 | 193 | 268 | 196 | 272 | 197 | 269 |
| **SipHash-2-4** | 191 | 263 | 191 | 262 | 195 | 269 | 194 | 265 |
| **ChaCha20** | 195 | 267 | 192 | 264 | 190 | 266 | 196 | 265 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 223 | 280 | 231 | 280 |
| **Areion-SoEM-512** | 206 | 223 | 184 | 245 |
| **BLAKE2b-256** | 203 | 234 | 205 | 234 |
| **BLAKE2b-512** | 210 | 240 | 212 | 257 |
| **BLAKE2s** | 196 | 231 | 202 | 237 |
| **BLAKE3** | 214 | 257 | 219 | 259 |
| **AES-128-CTR** | 237 | 298 | 238 | 296 |
| **SipHash-2-4** | 223 | 288 | 234 | 284 |
| **ChaCha20** | 224 | 272 | 231 | 275 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk) — Non-AEAD

| Cipher | Easy IO Enc | Easy IO Dec | Easy Loop Enc | Easy Loop Dec | LL IO Enc | LL IO Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 265 | 286 | 244 | 261 | 240 | 280 | 237 | 244 |
| **Areion-SoEM-512** | 240 | 291 | 264 | 292 | 265 | 299 | 276 | 298 |
| **BLAKE2b-256** | 229 | 248 | 232 | 251 | 233 | 253 | 234 | 253 |
| **BLAKE2b-512** | 244 | 268 | 246 | 267 | 249 | 276 | 246 | 270 |
| **BLAKE2s** | 226 | 249 | 224 | 232 | 226 | 242 | 224 | 248 |
| **BLAKE3** | 246 | 266 | 250 | 271 | 251 | 277 | 254 | 278 |
| **AES-128-CTR** | 277 | 316 | 274 | 311 | 278 | 319 | 282 | 314 |
| **SipHash-2-4** | 272 | 301 | 275 | 300 | 277 | 310 | 278 | 303 |
| **ChaCha20** | 263 | 293 | 265 | 295 | 264 | 291 | 267 | 293 |

The Easy and Low-Level paths land within run-to-run noise on every cipher × direction cell. Triple Ouroboros consistently outpaces Single by 30-40% — the three parallel encryption pipes saturate more of the available HT. Decrypt outperforms Encrypt by 20-50% because the encrypt path runs additional per-pixel work that decrypt does not (nonce derivation + barrier prefill). Within the full ITB + wrapper tables the AES-NI and PRF-counter outer ciphers land close together: ITB's per-pixel hashing dominates the combined cost, so the outer cipher choice moves the totals only at the margin.

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
