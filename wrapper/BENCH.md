# ITB Format-Deniability Wrapper Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of the outer keystream ciphers — one per PRF-grade ITB registry primitive. The keystream construction is delegated to the [`ctr`](../ctr/) package; AES-128-CTR and ChaCha20 (RFC 8439) use their native modes, the others run in PRF-counter mode. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (no output-buffer allocation); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Single Message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's `io.Reader` / `io.Writer` API or a User-Driven Loop emitting framed chunks through the wrapped writer.

The blob `Wrap` / `Unwrap` paths split the keystream XOR across up to 32 worker goroutines (the effective count is `min(32, GOMAXPROCS, chunks)`), each seeking its own keystream to its chunk's byte offset via `ctr.NewAt`. One logical CTR stream is therefore evaluated in disjoint ranges concurrently, byte-identical to a serial pass. With this, the slowest outer cipher keystream in the wrapper only round-trip (BLAKE2b-256, ~598 MB/s) stays ahead of ITB's combined per-direction throughput on this host (~200–350 MB/s), so no outer cipher is the wrapper-path bottleneck. AES-128-CTR with hardware AES-NI remains the fastest. The worker cap is fixed, not user-configurable: ITB's own per-pixel hashing already saturates every core, so the wrapper's secondary, partly memory-bound XOR must not over-subscribe by spawning a goroutine per core a second time.

Reproduction:

```sh
go test -run='^$' -bench='.' -benchtime=5s -count=1 ./wrapper/
```

Filter examples:

```sh
go test -run='^$' -bench='BenchmarkWrapperOnlyInPlace' -benchtime=5s -count=1 ./wrapper/
go test -run='^$' -bench='BenchmarkMessageTriple/nomac' -benchtime=5s -count=1 ./wrapper/
go test -run='^$' -bench='BenchmarkStreamingTriple/.*/aescmac' -benchtime=5s -count=1 ./wrapper/
```

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### Configuration

* Outer cipher path: every PRF-grade registry primitive, keystream built by the `ctr` package; blob XOR parallelised across up to 32 workers.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1` (minimum config so the outer cipher delta is not masked by per-pixel feature cost). The 48-bit Interlocked Barrier is always engaged and non-disableable by construction.
* `MaxWorkers=0` on the shared `*itb.Config` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single Message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Full ITB + wrapper benches route through `triple.Pipeline` — a single `triple.Init` before the timed loop, then `Pipeline.EncryptMessage` / `DecryptMessage` / `EncryptStream` / `DecryptStream` per iteration; the pipeline owns the buffer pool across iterations.

Column abbreviations in the Full ITB + wrapper tables: **IO** = IO-Driven (`io.Reader` / `io.Writer` streaming), **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 1635 | 2157 |
| **Areion-SoEM-512** | 1724 | 2126 |
| **BLAKE2b-256** | 610 | 642 |
| **BLAKE2b-512** | 1027 | 1222 |
| **BLAKE2s** | 657 | 760 |
| **BLAKE3** | 1155 | 1408 |
| **AES-128-CTR** | 3082 | 12688 |
| **SipHash-2-4** | 1914 | 3202 |
| **ChaCha20** | 2156 | 2959 |

`WrapInPlace` mutates the caller's blob and returns the per-stream nonce; no output buffer is allocated. A fresh nonce (~16 bytes) is allocated per call on the encrypt side, and the parallel XOR path additionally allocates per-worker keystream state for buffers at or above the 256 KiB threshold. `Wrap` returns a fresh wire = `nonce || keystream-XOR(blob)` and allocates `len(nonce) + len(blob)` bytes per call. The AES-128-CTR delta is dominated by the heap-page-fault cost of the 16 MiB output buffer; the PRF-counter ciphers are more compute-bound and the allocation savings are a smaller fraction of the total.

### Full ITB + wrapper

Numbers below route through `triple.Pipeline` (Single Message via `EncryptMessage` / `DecryptMessage`, streaming via `EncryptStream` / `DecryptStream` on `io.Reader` / `io.Writer`). Pipeline owns the buffer lifecycle across iterations, so timing reflects steady-state composition cost rather than per-call heap allocation. Encrypt and decrypt directions are timed separately in each row.

#### Single Message (16 MiB plaintext)

| Cipher | No MAC Enc | No MAC Dec | MAC Enc | MAC Dec |
|---|---:|---:|---:|---:|
| **Areion-SoEM-256** | 461 | 488 | 409 | 439 |
| **Areion-SoEM-512** | 464 | 492 | 387 | 448 |
| **BLAKE2b-256** | 364 | 389 | 335 | 361 |
| **BLAKE2b-512** | 421 | 460 | 387 | 407 |
| **BLAKE2s** | 375 | 405 | 342 | 360 |
| **BLAKE3** | 437 | 463 | 387 | 412 |
| **AES-128-CTR** | 470 | 542 | 433 | 466 |
| **SipHash-2-4** | 486 | 492 | 423 | 466 |
| **ChaCha20** | 480 | 487 | 412 | 453 |

#### Streaming AEAD (64 MiB plaintext, 16 MiB chunk)

| Cipher | AEAD IO Enc | AEAD IO Dec |
|---|---:|---:|
| **Areion-SoEM-256** | 390 | 446 |
| **Areion-SoEM-512** | 395 | 426 |
| **BLAKE2b-256** | 325 | 356 |
| **BLAKE2b-512** | 363 | 403 |
| **BLAKE2s** | 323 | 357 |
| **BLAKE3** | 375 | 419 |
| **AES-128-CTR** | 416 | 480 |
| **SipHash-2-4** | 408 | 449 |
| **ChaCha20** | 409 | 463 |

#### Streaming Non-AEAD (64 MiB plaintext, 16 MiB chunk)

| Cipher | IO Enc | IO Dec |
|---|---:|---:|
| **Areion-SoEM-256** | 469 | 503 |
| **Areion-SoEM-512** | 461 | 486 |
| **BLAKE2b-256** | 370 | 383 |
| **BLAKE2b-512** | 424 | 443 |
| **BLAKE2s** | 369 | 385 |
| **BLAKE3** | 441 | 464 |
| **AES-128-CTR** | 491 | 534 |
| **SipHash-2-4** | 477 | 514 |
| **ChaCha20** | 489 | 522 |

Decrypt runs 5–15 % faster than encrypt across ciphers (the encrypt path additionally derives per-pixel nonce material and the interlock barrier fill state). ITB's per-pixel hashing dominates the combined cost, so the outer cipher choice moves the totals only at the margin: AES-NI and PRF-counter ciphers span ~20 % top to bottom, with the smaller-state BLAKE variants at the low end and the AES / SipHash / ChaCha families at the high end.

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
