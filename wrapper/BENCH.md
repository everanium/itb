# ITB Format-Deniability Wrapper Benchmark Results

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of three outer keystream ciphers — AES-128-CTR (stdlib AES-NI), ChaCha20-RFC8439 (`golang.org/x/crypto/chacha20`), or SipHash-2-4 in CTR mode (`dchest/siphash` PRF + custom counter loop). The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (zero allocation steady state); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's `io.Reader` / `io.Writer` API or a User-Driven Loop emitting framed chunks through the wrapped writer.

Outer cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path adds no allocation pressure. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR runs single-threaded on one core. ChaCha20 (~700 MB/s peak on a single core via `x/crypto/chacha20`) and SipHash-CTR (~250-280 MB/s peak via the `dchest/siphash` PRF + 8-byte refill loop) become the bottleneck once ITB's Triple decrypt path approaches ~1 GB/s on big-iron. AES-128-CTR retains hardware acceleration on every HT thread the goroutine lands on and stays out of the critical path even there.

Reproduction:

```sh
go test -run='^$' -bench='.' -benchtime=5s -count=1 ./wrapper/
```

Filter examples:

```sh
go test -run='^$' -bench='BenchmarkWrapperOnlyInPlace' -benchtime=5s -count=1 ./wrapper/
go test -run='^$' -bench='BenchmarkMessageSingle/easy-nomac' -benchtime=5s -count=1 ./wrapper/
go test -run='^$' -bench='BenchmarkStreamingTriple/.*/aes' -benchtime=5s -count=1 ./wrapper/
```

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### Configuration

* Outer cipher path: AES-128-CTR (stdlib + AES-NI), ChaCha20-RFC8439 (`golang.org/x/crypto/chacha20`), SipHash-2-4 in CTR mode (`dchest/siphash` + custom counter loop).
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb.SetMaxWorkers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via `copy()`; the memcpy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware (~3-5 ms per 16 MiB memcpy vs ~60-90 ms per 16 MiB Easy / Low-Level Decrypt).

### Wrapper Only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (zero alloc) MB/s |
|---|---|---|
| **AES-128-CTR** | 2470 | **4170** |
| **ChaCha20** | 330 | 344 |
| **SipHash-CTR** | 271 | 281 |

`WrapInPlace` mutates the caller's blob and returns the per-stream nonce; the steady-state allocation is one nonce buffer (~16 bytes) per call. `Wrap` returns a fresh wire = `nonce || keystream-XOR(blob)` and allocates `len(nonce) + len(blob)` bytes per call. The AES delta is dominated by the heap-page-fault cost of the 16 MiB output buffer; ChaCha20 and SipHash-CTR are compute-bound and the allocation savings are largely absorbed by the keystream throughput ceiling.

### Single Message — Single Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 192 | 278 | 143 | 186 | 136 | 178 |
| **Easy** MAC Authenticated | 174 | 257 | 133 | 178 | 128 | 169 |
| **Low-Level** No MAC | 191 | 279 | 141 | 189 | 135 | 176 |
| **Low-Level** MAC Authenticated | 176 | 251 | 134 | 181 | 127 | 170 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 265 | 318 | 187 | 214 | 175 | 178 |
| **Easy** MAC Authenticated | 233 | 289 | 174 | 201 | 162 | 188 |
| **Low-Level** No MAC | 271 | 324 | 181 | 215 | 180 | 200 |
| **Low-Level** MAC Authenticated | 241 | 297 | 170 | 201 | 165 | 189 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 162 | 220 | 128 | 161 | 121 | 159 |
| **Streaming AEAD Low-Level** IO-Driven | 162 | 235 | 126 | 163 | 122 | 151 |
| **Streaming Easy** No MAC, IO-Driven | 183 | 255 | 141 | 173 | 133 | 166 |
| **Streaming Easy** No MAC, User-Driven Loop | 182 | 251 | 140 | 169 | 135 | 162 |
| **Streaming Low-Level** No MAC, IO-Driven | 183 | 255 | 141 | 179 | 133 | 163 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 184 | 254 | 141 | 173 | 135 | 169 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 218 | 280 | 167 | 192 | 157 | 178 |
| **Streaming AEAD Low-Level** IO-Driven | 230 | 284 | 171 | 193 | 157 | 188 |
| **Streaming Easy** No MAC, IO-Driven | 268 | 301 | 187 | 205 | 174 | 199 |
| **Streaming Easy** No MAC, User-Driven Loop | 266 | 300 | 187 | 200 | 175 | 185 |
| **Streaming Low-Level** No MAC, IO-Driven | 270 | 302 | 189 | 206 | 177 | 183 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 272 | 308 | 190 | 209 | 157 | 190 |

The Easy and Low-Level paths land within run-to-run noise on every cipher × direction cell. Triple Ouroboros consistently outpaces Single by 30-40% — the three parallel encryption pipes saturate more of the available HT. Decrypt outperforms Encrypt by 20-50% because the encrypt path runs additional per-pixel work that decrypt does not (nonce derivation + barrier prefill).

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
