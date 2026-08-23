# ITB Rust Binding — Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive in CTR mode. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `wrap_in_place` row mutates the caller's `Vec<u8>` (no output-buffer allocation); the `wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's streaming AEAD entry points or a User-Driven Loop emitting framed chunks through the wrapped writer.

The wrapper bench covers all outer ciphers — each in CTR mode.

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `wrap_in_place` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

The Rust binding adds the per-call libloading-FFI crossing and a `Vec<u8>` materialisation on the helper return path. The wrapper only row therefore reads slightly under the matching Go-native row at 16 MiB; the gap closes on the full ITB + wrapper rows, where the ITB encrypt / decrypt time dominates over the keystream XOR + FFI overhead.

## Binding asymmetry note

The Rust binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level.

## Reproduction

```sh
# Build libitb.so:
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared

# Run the full 306-case sub-bench matrix:
cd bindings/rust
cargo bench --bench bench_wrapper
```

Filter examples:

```sh
ITB_BENCH_FILTER=bench_wrapper_only \
    cargo bench --bench bench_wrapper

ITB_BENCH_FILTER=bench_msg_single_easy_nomac \
    cargo bench --bench bench_wrapper

ITB_BENCH_FILTER=bench_stream_triple \
    cargo bench --bench bench_wrapper
```

## Configuration

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `nonce_bits=128`, `barrier_fill=1`, `bit_soup=0`, `lock_soup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb::set_max_workers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine clone each iteration via `Vec::clone()`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1401 | 1474 |
| **Areion-SoEM-512** | 1712 | 1512 |
| **BLAKE2b-256** | 618 | 581 |
| **BLAKE2b-512** | 1045 | 950 |
| **BLAKE2s** | 604 | 593 |
| **BLAKE3** | 1105 | 1081 |
| **AES-128-CTR** | 2986 | 3059 |
| **SipHash-2-4** | 2330 | 1972 |
| **ChaCha20** | 2181 | 1878 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 169 | 267 | 180 | 258 | 198 | 283 | 185 | 261 |
| **Areion-SoEM-512** | 197 | 280 | 180 | 258 | 193 | 281 | 183 | 262 |
| **BLAKE2b-256** | 175 | 233 | 166 | 223 | 181 | 240 | 167 | 219 |
| **BLAKE2b-512** | 189 | 256 | 168 | 233 | 187 | 263 | 176 | 246 |
| **BLAKE2s** | 179 | 234 | 165 | 227 | 183 | 242 | 166 | 227 |
| **BLAKE3** | 191 | 271 | 177 | 246 | 193 | 270 | 177 | 255 |
| **AES-128-CTR** | 202 | 294 | 188 | 269 | 208 | 297 | 189 | 273 |
| **SipHash-2-4** | 199 | 287 | 184 | 262 | 196 | 291 | 187 | 265 |
| **ChaCha20** | 199 | 286 | 184 | 257 | 200 | 292 | 186 | 265 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 265 | 308 | 237 | 285 | 272 | 308 | 239 | 292 |
| **Areion-SoEM-512** | 268 | 309 | 238 | 288 | 270 | 308 | 243 | 294 |
| **BLAKE2b-256** | 227 | 258 | 206 | 245 | 231 | 261 | 210 | 243 |
| **BLAKE2b-512** | 251 | 288 | 226 | 268 | 250 | 289 | 226 | 270 |
| **BLAKE2s** | 228 | 262 | 209 | 246 | 235 | 265 | 214 | 241 |
| **BLAKE3** | 245 | 284 | 225 | 270 | 248 | 298 | 230 | 280 |
| **AES-128-CTR** | 281 | 328 | 249 | 306 | 285 | 331 | 254 | 310 |
| **SipHash-2-4** | 273 | 319 | 244 | 298 | 278 | 320 | 247 | 299 |
| **ChaCha20** | 271 | 316 | 242 | 292 | 279 | 322 | 247 | 301 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 133 | 201 | 129 | 185 |
| **Areion-SoEM-512** | 134 | 200 | 131 | 184 |
| **BLAKE2b-256** | 124 | 179 | 123 | 168 |
| **BLAKE2b-512** | 128 | 189 | 122 | 169 |
| **BLAKE2s** | 125 | 180 | 120 | 165 |
| **BLAKE3** | 131 | 193 | 128 | 180 |
| **AES-128-CTR** | 135 | 202 | 131 | 187 |
| **SipHash-2-4** | 133 | 196 | 130 | 184 |
| **ChaCha20** | 133 | 196 | 129 | 181 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 173 | 244 | 176 | 250 |
| **Areion-SoEM-512** | 174 | 243 | 175 | 249 |
| **BLAKE2b-256** | 160 | 214 | 151 | 209 |
| **BLAKE2b-512** | 162 | 221 | 165 | 235 |
| **BLAKE2s** | 160 | 213 | 159 | 214 |
| **BLAKE3** | 167 | 232 | 172 | 236 |
| **AES-128-CTR** | 175 | 252 | 174 | 256 |
| **SipHash-2-4** | 167 | 244 | 175 | 246 |
| **ChaCha20** | 170 | 238 | 171 | 247 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 165 | 225 | 159 | 208 |
| **Areion-SoEM-512** | 163 | 225 | 160 | 210 |
| **BLAKE2b-256** | 146 | 200 | 147 | 187 |
| **BLAKE2b-512** | 153 | 213 | 155 | 202 |
| **BLAKE2s** | 152 | 196 | 148 | 190 |
| **BLAKE3** | 161 | 222 | 159 | 203 |
| **AES-128-CTR** | 168 | 237 | 166 | 219 |
| **SipHash-2-4** | 164 | 231 | 163 | 211 |
| **ChaCha20** | 166 | 225 | 161 | 212 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 222 | 261 | 225 | 266 |
| **Areion-SoEM-512** | 225 | 267 | 226 | 269 |
| **BLAKE2b-256** | 197 | 214 | 198 | 231 |
| **BLAKE2b-512** | 213 | 253 | 212 | 252 |
| **BLAKE2s** | 199 | 234 | 204 | 239 |
| **BLAKE3** | 218 | 253 | 221 | 262 |
| **AES-128-CTR** | 234 | 284 | 235 | 279 |
| **SipHash-2-4** | 221 | 273 | 228 | 279 |
| **ChaCha20** | 225 | 270 | 231 | 278 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
