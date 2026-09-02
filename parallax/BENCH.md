# ITB Parallax Horizontal-Multiplexing Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB and parallax are configured with, not conferred by either construction itself.

The parallax layer splits a plaintext into fixed-size segments and XORs each segment under one counter-mode keystream chosen from a user-configured palette by a per-message keyed schedule. The keystream construction for every palette slot is delegated to the [`ctr`](../ctr/) package; per-slot subkeys are derived through the anchor `palette[0]` under [`kdf`](../kdf/). The wire formats are:

- **Single-message wire** — `nonce(16) ‖ ciphertext_body`. Body length matches plaintext length exactly.
- **Streaming wire** — concatenation of per-chunk frames `u32_LE(body_len) ‖ nonce(16) ‖ encrypted_body(body_len)`, one frame per chunk. The chunk size is fixed for the stream's lifetime at construction time.

parallax is **Non-AEAD** by design. The streaming length prefix is unauthenticated; a single-bit modification to any prefix desynchronises every subsequent frame on the stream. Callers compose parallax under ITB's authenticated transport (Easy Mode or Streaming AEAD) when wire integrity is required.

The body XOR is dispatched across up to `min(GOMAXPROCS, 32)` worker goroutines, each owning its slice of the segment list. A serial fast path runs in the caller's goroutine for payloads below the per-package `parallelThreshold` to avoid amortising per-worker keystream-setup cost over too few segments.

## Platform

- CPU: 11th Gen Intel Core i7-11700K @ 3.60 GHz (Rocket Lake, AES-NI, AVX-512, VPCLMULQDQ, GFNI)
- 8 physical cores / 16 logical CPUs
- OS / arch: Linux 7.0.9-arch1-1, `linux/amd64`
- Toolchain: `go1.27.0-X:nodwarf5`
- `GOMAXPROCS=16` (default)

## How to reproduce

```sh
go test -run='^$' -bench='.' -benchtime=1s -count=1 ./parallax/
```

Filter examples:

```sh
go test -run='^$' -bench='BenchmarkParallaxPerPrimitiveHomogeneous/aescmac' -benchtime=1s -count=1 ./parallax/
go test -run='^$' -bench='BenchmarkParallaxChunkedStream/aescmac'           -benchtime=1s -count=1 ./parallax/
go test -run='^$' -bench='BenchmarkParallaxStream/aescmac'                  -benchtime=1s -count=1 ./parallax/
go test -run='^$' -bench='BenchmarkParallaxWorkerScaling'                   -benchtime=1s -count=1 ./parallax/
```

Bench-side tuning is available through `PARALLAX_*` environment variables consumed by `parallax/testmain_test.go`: `PARALLAX_S`, `PARALLAX_SIZE`, `PARALLAX_CHUNK_SIZE`, `PARALLAX_N`, `PARALLAX_PRIMITIVE`, `PARALLAX_PALETTE`, `PARALLAX_PALETTE_LABEL`. These knobs adjust segment size, plaintext size, streaming chunk size, palette width, single-primitive focus, and explicit heterogeneous palette composition respectively.

## Per-primitive throughput across segment size (Single Message, 4 MiB, N=9, Encrypt)

Each row uses a homogeneous palette of N=9 copies of the named primitive across a Single Message Encrypt at the listed segment widths. Source: `BenchmarkParallaxPerPrimitiveHomogeneous`. Throughput in MB/s; per-row maximum bolded.

| Primitive | S=17 | S=251 | S=1031 | S=4093 | S=16381 | S=65521 |
|---|---:|---:|---:|---:|---:|---:|
| Areion-SoEM-256 | 355 | 1574 | 1965 | **2062** | 2004 | 1940 |
| Areion-SoEM-512 | 177 | 1152 | 1819 | **2000** | 1992 | 1986 |
| BLAKE2b-256 | 388 | 758 | 916 | 902 | **959** | 629 |
| BLAKE2b-512 | 380 | 1065 | 1353 | **1367** | 1266 | 1058 |
| BLAKE2s | 400 | 861 | 996 | 949 | **1011** | 740 |
| BLAKE3 | 732 | 1459 | 1557 | 1526 | **1581** | 1362 |
| AES-CMAC | 163 | 1483 | 2520 | 3508 | 3442 | **3827** |
| SipHash-2-4 | 1437 | 2284 | **2632** | 2595 | 2536 | 2397 |
| ChaCha20 | 275 | 1446 | 2184 | 2202 | **2355** | 2308 |

Throughput amortises sharply between S=17 and S=251 (2–9×) and a further 1.5–3× through S=4093 for most primitives, then plateaus. SipHash-2-4 is essentially flat above S=251 — its per-segment fixed cost is already negligible at small widths. BLAKE2b-256 drops at S=65521 (629 MB/s, down from ~930 at S=4093–16381) and BLAKE2s shows the same effect at smaller magnitude — the smaller-state BLAKE2 entries lose L1 locality once a segment exceeds the cache-fit boundary; the wider-state BLAKE2b-512 and BLAKE3 do not exhibit the dip.

EncryptInPlace tracks Encrypt closely across the matrix — mean signed delta ≈ −3 %, p90 |delta| ≈ 17 % — reflecting that the in-place wire build plus the slice-copy-back accounts for the same byte movement as the allocate-and-return path. The in-place variant retains caller-owned buffer lifetime without trading away throughput.

## Plaintext-size sweep (Single Message, S=4093, N=9, Encrypt)

How throughput scales as the plaintext grows. Sub-bench: `BenchmarkParallaxPerPrimitiveHomogeneous` with `PARALLAX_SIZE` override.

| Primitive | 1 KiB | 64 KiB | 1 MiB | 4 MiB | 16 MiB |
|---|---:|---:|---:|---:|---:|
| Areion-SoEM-256 | 194 | 444 | 1017 | 2062 | **2540** |
| Areion-SoEM-512 | 163 | 432 | 994 | 2000 | **2507** |
| BLAKE2b-256 | 87 | 170 | 588 | 902 | **1069** |
| BLAKE2b-512 | 129 | 264 | 786 | 1367 | **1689** |
| BLAKE2s | 105 | 198 | 729 | 949 | **1109** |
| BLAKE3 | 42 | 293 | 617 | 1526 | **1919** |
| AES-CMAC | 219 | 909 | 1964 | 3508 | **4314** |
| SipHash-2-4 | 490 | 586 | 1509 | 2595 | **3159** |
| ChaCha20 | 314 | 549 | 1242 | 2202 | **2980** |

The 1 KiB row sits below the parallel threshold — per-segment dispatch and worker setup dominate. The 64 KiB row crosses the threshold but lacks the payload to amortise the parallel-path startup cost. From 1 MiB onward each primitive walks toward its steady-state ceiling; the 16 MiB column is the cleanest read on each primitive's intrinsic per-byte cost. SipHash-2-4 dominates the small-plaintext regime — at S=4093 / 1 KiB its per-segment hash-state cost amortises better than any other entry under the serial fast path.

## Streaming throughput across chunk size (N=3 homogeneous, plaintext = chunk × 4, EncryptWriter)

Streaming emits one frame per chunk; each frame is one `EncryptInPlace` call's output. Throughput tracks the per-chunk cost amortised by per-stream framing overhead. The plaintext is pinned at chunkSize × 4 so each sub-bench encrypts four chunks per iteration regardless of chunk width. Source: `BenchmarkParallaxChunkedStream` (default 1/4/16/64 MiB sweep) plus `BenchmarkParallaxStream` driven by `PARALLAX_CHUNK_SIZE` for the 64 KiB / 256 KiB columns.

| Primitive | 64 KiB | 256 KiB | 1 MiB | 4 MiB | 16 MiB | 64 MiB |
|---|---:|---:|---:|---:|---:|---:|
| Areion-SoEM-256 | 449 | 963 | 1329 | 2007 | 2177 | **2249** |
| Areion-SoEM-512 | 442 | 911 | 1340 | 1973 | 2016 | **2138** |
| BLAKE2b-256 | 170 | 464 | 751 | 938 | 948 | **994** |
| BLAKE2b-512 | 264 | 610 | 964 | 1364 | 1494 | **1560** |
| BLAKE2s | 197 | 511 | 770 | 952 | 1054 | **1102** |
| BLAKE3 | 325 | 688 | 1049 | 1570 | 1646 | **1802** |
| AES-CMAC | 892 | 1620 | 2608 | 2936 | **2955** | 2896 |
| SipHash-2-4 | 553 | 1071 | 1781 | 2333 | 2522 | **2704** |
| ChaCha20 | 511 | 1024 | 1611 | 2262 | 2364 | **2585** |

Per-chunk framing dominates below ~1 MiB. At chunkSize = 64 KiB every primitive sits 2–4× below its 4 MiB rate; the inflection sits at 256 KiB, and amortisation is largely complete by 1 MiB. AES-CMAC retains the highest absolute number across the small-chunk band because its per-block cost is already dwarfed by per-chunk `EncryptInPlace` setup; BLAKE2b-256 collapses to 170 MB/s at 64 KiB because the smallest hash output and lowest per-chunk throughput pair poorly with the framing tax. Above 1 MiB chunks the streaming row approaches the Single Message rate at the matching primitive.

## Stream-shape comparison (4 MiB plaintext, chunk 16 MiB)

A 4 MiB plaintext at the default 16 MiB chunkSize emits exactly one frame per encrypt — the no-fragmentation baseline against which the chunked rows above can be read. The same homogeneous N=3 palette underlies every row. Source: `BenchmarkParallaxStream`.

| Primitive | EncryptWriter | EncryptReader | DecryptWriter | DecryptReader | OneShotEncrypt |
|---|---:|---:|---:|---:|---:|
| Areion-SoEM-256 | 1510 | 1693 | **2335** | 1721 | 1971 |
| Areion-SoEM-512 | 1391 | 1613 | **2287** | 1720 | 1794 |
| BLAKE2b-256 | 766 | 873 | **912** | 834 | 812 |
| BLAKE2b-512 | 1141 | 1232 | **1498** | 1218 | 1335 |
| BLAKE2s | 856 | 867 | **1062** | 918 | 908 |
| BLAKE3 | 1239 | 1342 | **1675** | 1444 | 1472 |
| AES-CMAC | 1884 | 2407 | **4829** | 3167 | 3478 |
| SipHash-2-4 | 1689 | 1941 | **2790** | 2063 | 2499 |
| ChaCha20 | 1599 | 1826 | **2579** | 2010 | 1928 |

DecryptWriter is the consistently fastest streaming shape — 1.5–2.6× over EncryptWriter for every primitive — because the in-place decrypt path avoids the wire-buffer accumulation the encrypt writer performs. EncryptReader runs within ~10 % of EncryptWriter on most primitives. OneShotEncrypt always edges past EncryptWriter (no per-chunk envelope), and the gap converges within a few percent for the Areion family and ChaCha20 once the chunk grows past 16 MiB.

## Palette-size sweep (Single Message, S=4093, 4 MiB, Encrypt)

Palette width versus throughput, holding everything else at the package default. Source: `BenchmarkParallaxPaletteSize`.

| N | Composition shape | MB/s | Allocs/op |
|---|---|---:|---:|
| 3 | seeded draws from the registry | 1173 | 817 |
| 9 — shuffle A | registry permutation (seed 42) | 1583 | 1489 |
| 9 — shuffle B | registry permutation (seed 1337) | 1541 | 1484 |
| 24 | seeded draws | 1332 | 2696 |
| 36 | seeded draws | 1723 | 3530 |
| 254 | seeded draws near MaxPaletteSize | 1031 | 20221 |

The two N=9 shuffles land within a few percent of each other — multiset identity dominates ordering for full-registry shuffles at this segment width. N=254 loses ~33 % vs N=9 because per-slot setup (20 k allocs/op vs 1.5 k) stops amortising against a 4 MiB workload; the allocation budget scales roughly linearly with N. For a long-lived `Cipherset` the per-slot KDF derivation runs once at construction and disappears from per-message accounting; the N=254 row is the single-`NewCipherset` worst case.

## Heterogeneous palette compositions (N=5, S=4093, 4 MiB, EncryptWriter)

Throughput depends much more on which primitives populate the slots than on the palette width. Source: `BenchmarkParallaxPaletteStreaming` driven by `PARALLAX_PALETTE`.

| Label | Composition | MB/s |
|---|---|---:|
| fast-mix | `aescmac, siphash24, chacha20, blake3, aescmac` | **1687** |
| balanced | `aescmac, chacha20, blake3, blake2s, siphash24` | 1360 |
| slow-mix | `blake2b256, blake2b512, blake2s, areion256, areion512` | 1065 |

fast-mix beats slow-mix by ~54 % at fixed N=5. The choice of which primitives populate the palette is the load-bearing knob, not the count.

## Anchor-primitive effect (same multiset, different `palette[0]`)

The anchor primitive drives the per-slot KDF derivation and the schedule-seed expansion. Both costs are one-time per `NewCipherset` call; the anchor effect therefore surfaces only when steady-state segment work is itself large. Multiset: `{aescmac, chacha20, blake3, siphash24, blake2s}`.

| Anchor | MB/s @ 4 MiB | MB/s @ 16 MiB |
|---|---:|---:|
| AES-CMAC | 1351 | 1732 |
| ChaCha20 | 1303 | **1744** |
| BLAKE3 | **1398** | 1722 |

At 4 MiB the three rows spread within ~7 % of each other; at 16 MiB they converge to within ~1 % — the schedule-seed work is fully amortised once steady-state per-segment work dominates the total.

## GOMAXPROCS scaling (default mixed N=3 palette, S=4093, 4 MiB, Encrypt)

Source: `BenchmarkParallaxWorkerScaling`. Default mixed palette `{aescmac, chacha20, blake3}`.

| GOMAXPROCS | MB/s | speed-up vs P=1 |
|---:|---:|---:|
| 1 | 555 | 1.00× |
| 2 | 991 | 1.79× |
| 4 | 1584 | 2.85× |
| 8 | 2173 | 3.91× |
| 16 | **2183** | 3.93× |

Near-linear from P=1 → P=2 (the serial fast path is slower than the parallel path even at P=2 due to per-worker keystream amortisation), then diminishing returns. The bandwidth ceiling lands around 2 GB/s at P=8 on this Rocket Lake target; the SMT step P=8 → P=16 yields a marginal lift only. Larger segments lift the ceiling: the same workload at S=16381 reaches 4 GB/s at P=4 (`aescmac`-homogeneous), while S=251 caps near 2.1× scaling because per-segment overhead dominates.

## Per-segment dispatch

Each per-worker keystream is built once at offset 0 and the per-segment hot loop reseats its counter to the segment's absolute byte offset via [`ctr.ResettableKeystream.ResetCounter`](../ctr/) before XOR. The dispatch is uniform across every palette slot and every branch (parallel or serial) — there is no per-primitive policy table and no exported tuning knob. Cross-decryptability is therefore trivial: the wire is a function of `(masterKey, palette, nonce, plaintext)` only.

## Notes

- The serial fast path runs when the plaintext is below `parallelThreshold = 8 KiB`. Below this threshold the per-worker keystream-setup cost cannot be amortised; serial dispatch in the caller's goroutine wins.
- The streaming chunk size (`SetChunkSize`, default 16 MiB) controls the wire-frame body width on the chunked streaming surface only. The Single Message API does not consume the chunk size; segment width is the only S-axis knob for `Encrypt` / `Decrypt` / `EncryptInPlace` / `DecryptInPlace`.
- The default segment size 4093 lands within ~10 % of the per-primitive optimum for the entire registry: AES-CMAC and BLAKE2b-256 trail their peaks at the highest S by less than ~15 %, and the remaining primitives peak at or adjacent to S=4093. The default is a stable choice across mixed palettes where no single primitive dominates the schedule.
- Worker-scaling shape is per-primitive, not per-package. The bandwidth-limited primitives (AES-CMAC) plateau early; the compute-bound primitives (BLAKE2b-512) keep climbing through P=16 because the parallel path lifts the per-core compute bottleneck before the bandwidth ceiling becomes the constraint.
