## ITB Parallax Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](../README.md) for jurisdictional certification details.

Throughput benchmarks for the `parallax` horizontal-multiplexing layer (fixed-size segment XOR under a per-message keyed schedule over [`ctr`](../ctr/) keystreams derived via [`kdf`](../kdf/), dispatched across up to `min(GOMAXPROCS, 32)` workers above `parallelThreshold`; see [README.md](./README.md) for the wire formats, threat model, and API).

## Platform

- CPU: 11th Gen Intel Core i7-11700K @ 3.60 GHz (Rocket Lake, AES-NI, AVX-512, VPCLMULQDQ, GFNI)
- 8 physical cores / 16 logical CPUs
- OS / arch: Linux 7.1.11-arch1-1, `linux/amd64`
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

Bench-side tuning is available through `PARALLAX_*` environment variables consumed by `parallax/bench_test.go`'s `TestMain`: `PARALLAX_S`, `PARALLAX_SIZE`, `PARALLAX_CHUNK_SIZE`, `PARALLAX_N`, `PARALLAX_PRIMITIVE`, `PARALLAX_PALETTE`, `PARALLAX_PALETTE_LABEL`. These knobs adjust segment size, plaintext size, streaming chunk size, palette width, single-primitive focus, and explicit heterogeneous palette composition respectively.

## Per-primitive throughput across segment size (Single Message, 4 MiB, N=9, Encrypt)

Each row uses a homogeneous palette of N=9 copies of the named primitive across a Single Message Encrypt at the listed segment widths. Source: `BenchmarkParallaxPerPrimitiveHomogeneous`. Throughput in MB/s; per-row maximum bolded.

| Primitive | S=17 | S=251 | S=1031 | S=4093 | S=16381 | S=65521 |
|---|---:|---:|---:|---:|---:|---:|
| Areion-SoEM-256 | 1035 | 2200 | 2214 | 2465 | **2492** | 2346 |
| Areion-SoEM-512 | 847 | 1984 | 2283 | 2396 | **2443** | 2424 |
| BLAKE2b-256 | 609 | 1745 | 1813 | 2117 | **2233** | 2030 |
| BLAKE2b-512 | 568 | 1646 | 2039 | 2230 | 2494 | **2656** |
| BLAKE2s | 664 | 1667 | 1989 | 2602 | 2610 | **2683** |
| BLAKE3 | 774 | 1870 | 2311 | 2732 | 2843 | **2915** |
| AES-128-CTR | 1513 | 2525 | 2570 | 2809 | 2738 | **3080** |
| SipHash-2-4 | 1186 | 2419 | 2528 | 2706 | 2747 | **2803** |
| ChaCha20 | 1002 | 2108 | 2688 | 2810 | 2901 | **3016** |

Throughput amortises sharply between S=17 and S=251 (1.7–2.9×) and a further 1.1–1.6× through S=4093 for most primitives, then plateaus. SipHash-2-4 is essentially flat above S=251 — its per-segment fixed cost is already negligible at small widths. Areion-SoEM-256, Areion-SoEM-512, and BLAKE2b-256 peak at S=16381 and sit slightly lower at S=65521 (−1 % to −9 %), whereas the remaining six primitives continue climbing to their row maxima at S=65521.

`EncryptInPlace` tracks `Encrypt` closely across the matrix — mean signed delta ≈ −3 %, p90 |delta| ≈ 17 % — reflecting that the in-place wire build plus the slice-copy-back accounts for the same byte movement as the allocate-and-return path. The in-place variant retains caller-owned buffer lifetime without trading away throughput.

## Plaintext-size sweep (Single Message, S=4093, N=9, Encrypt)

How throughput scales as the plaintext grows. Sub-bench: `BenchmarkParallaxPerPrimitiveHomogeneous` with `PARALLAX_SIZE` override.

| Primitive | 1 KiB | 64 KiB | 1 MiB | 4 MiB | 16 MiB |
|---|---:|---:|---:|---:|---:|
| Areion-SoEM-256 | 101 | 576 | 1191 | 2465 | **3671** |
| Areion-SoEM-512 | 84 | 555 | 1082 | 2396 | **3613** |
| BLAKE2b-256 | 144 | 525 | 1127 | 2117 | **3066** |
| BLAKE2b-512 | 164 | 619 | 1168 | 2230 | **3635** |
| BLAKE2s | 168 | 646 | 1188 | 2602 | **3633** |
| BLAKE3 | 217 | 729 | 1470 | 2732 | **3868** |
| AES-128-CTR | 160 | 839 | 1268 | 2809 | **3815** |
| SipHash-2-4 | 587 | 877 | 1572 | 2706 | **3859** |
| ChaCha20 | 592 | 832 | 1556 | 2810 | **3840** |

The 1 KiB row sits below the parallel threshold — per-segment dispatch and worker setup dominate. The 64 KiB row crosses the threshold but lacks the payload to amortise the parallel-path startup cost. From 1 MiB onward each primitive walks toward its steady-state ceiling; the 16 MiB column is the cleanest read on each primitive's intrinsic per-byte cost. ChaCha20 and SipHash-2-4 dominate the small-plaintext regime — at S=4093 / 1 KiB their per-segment state cost amortises better than any other entry under the serial fast path.

## Streaming throughput across chunk size (N=3 homogeneous, plaintext = chunk × 4, EncryptWriter)

Streaming emits one frame per chunk; each frame is one `EncryptInto` call's output. Throughput tracks the per-chunk cost amortised by per-stream framing overhead. The plaintext is pinned at chunkSize × 4 so each sub-bench encrypts four chunks per iteration regardless of chunk width. Source: `BenchmarkParallaxChunkedStream` (default 1/4/16/64 MiB sweep) plus `BenchmarkParallaxStream` driven by `PARALLAX_CHUNK_SIZE` for the 64 KiB / 256 KiB columns.

| Primitive | 64 KiB | 256 KiB | 1 MiB | 4 MiB | 16 MiB | 64 MiB |
|---|---:|---:|---:|---:|---:|---:|
| Areion-SoEM-256 | 2168 | 2464 | 2348 | **2930** | 2584 | 2906 |
| Areion-SoEM-512 | 2319 | 2324 | 2114 | **2978** | 2463 | 2736 |
| BLAKE2b-256 | 1899 | 1994 | 1841 | 2108 | 2593 | **2801** |
| BLAKE2b-512 | 2206 | 2159 | 2344 | 2812 | 2691 | **2913** |
| BLAKE2s | 2218 | 2147 | 2330 | 2576 | **2805** | 2719 |
| BLAKE3 | 2161 | 2315 | 2434 | **3109** | 2812 | 2957 |
| AES-128-CTR | 2307 | 2338 | **3177** | 3106 | 2823 | 2951 |
| SipHash-2-4 | 2135 | 2464 | 2715 | **3081** | 2846 | 2931 |
| ChaCha20 | 2456 | 2453 | 2800 | **2922** | 2737 | 2847 |

Per-chunk framing overhead is modest even at small chunk widths. At chunkSize = 64 KiB every primitive already reaches 1899–2456 MB/s (within ~11–37 % of its 4 MiB rate), climbing to 1994–2464 MB/s at 256 KiB, and amortisation is largely complete by 1 MiB. ChaCha20 (2456 MB/s) and AES-128-CTR (2307 MB/s) retain the highest absolute numbers across the small-chunk band because their per-block cost is dwarfed by per-chunk `EncryptInto` setup; BLAKE2b-256 sits at the low end (1899 MB/s at 64 KiB) where the smallest hash output and lowest per-chunk throughput pair with the framing tax. Above 1 MiB chunks the streaming row approaches the Single Message rate at the matching primitive.

## Stream-shape comparison (4 MiB plaintext, chunk 16 MiB)

A 4 MiB plaintext at the default 16 MiB chunkSize emits exactly one frame per encrypt — the no-fragmentation baseline against which the chunked rows above can be read. The same homogeneous N=3 palette underlies every row. Source: `BenchmarkParallaxStream`.

| Primitive | EncryptWriter | EncryptReader | DecryptWriter | DecryptReader | `OneShotEncrypt` |
|---|---:|---:|---:|---:|---:|
| Areion-SoEM-256 | 2500 | 2591 | **2719** | 2139 | 2702 |
| Areion-SoEM-512 | 2434 | **2716** | 2682 | 2079 | 2303 |
| BLAKE2b-256 | 1793 | 2047 | **2285** | 1705 | 2093 |
| BLAKE2b-512 | 1896 | 1987 | **2615** | 1864 | 2124 |
| BLAKE2s | 1970 | 2322 | 2628 | 1973 | **2665** |
| BLAKE3 | 2160 | 2540 | 2720 | 1999 | **3001** |
| AES-128-CTR | 2392 | 3037 | **3138** | 2343 | 3116 |
| SipHash-2-4 | 2102 | 2746 | 2946 | 2179 | **2999** |
| ChaCha20 | 2398 | 2654 | 2564 | 2271 | **3028** |

DecryptWriter, EncryptReader, and `OneShotEncrypt` are the fastest shapes across the matrix: DecryptWriter leads four primitives (1.07–1.40× over EncryptWriter across all rows), EncryptReader leads Areion-SoEM-512 (2716 vs 2682), and `OneShotEncrypt` leads BLAKE2s (2665), BLAKE3 (3001), SipHash-2-4 (2999), and ChaCha20 (3028). Among incremental streaming shapes, DecryptWriter leads seven primitives while EncryptReader edges past DecryptWriter on Areion-SoEM-512 (2716 vs 2682) and ChaCha20 (2654 vs 2564). The in-place decrypt path avoids the wire-buffer accumulation the encrypt writer performs. `OneShotEncrypt` typically edges past EncryptWriter (no per-chunk envelope); Areion-SoEM-512 is the exception where EncryptWriter narrowly leads (2434 vs 2303). The gap converges within a few percent for the Areion family and ChaCha20 once the chunk grows past 16 MiB.

## Palette-size sweep (Single Message, S=4093, 4 MiB, Encrypt)

Palette width versus throughput, holding everything else at the package default. Source: `BenchmarkParallaxPaletteSize`.

| N | Composition shape | MB/s | Allocs/op |
|---|---|---:|---:|
| 3 | seeded draws from the registry | 2629 | 102 |
| 9 — shuffle A | registry permutation (seed 42) | 2342 | 342 |
| 9 — shuffle B | registry permutation (seed 1337) | 2418 | 342 |
| 24 | seeded draws | 2258 | 822 |
| 36 | seeded draws | 2312 | 1064 |
| 254 | seeded draws near MaxPaletteSize | 1459 | 8271 |

The two N=9 shuffles land within a few percent of each other — multiset identity dominates ordering for full-registry shuffles at this segment width. N=254 loses ~39 % vs N=9 because per-slot setup (8.3 k allocs/op vs 342) stops amortising against a 4 MiB workload; the allocation budget scales roughly linearly with N. For a long-lived `Cipherset` the per-slot KDF derivation runs once at construction and disappears from per-message accounting; the N=254 row is the single-`NewCipherset` worst case.

## Heterogeneous palette compositions (N=5, S=4093, 4 MiB, EncryptWriter)

Throughput depends much more on which primitives populate the slots than on the palette width. Source: `BenchmarkParallaxPaletteStreaming` driven by `PARALLAX_PALETTE`.

| Label | Composition | MB/s |
|---|---|---:|
| fast-mix | `aescmac, siphash24, chacha20, blake3, aescmac` | **2386** |
| balanced | `aescmac, chacha20, blake3, blake2s, siphash24` | 2204 |
| slow-mix | `blake2b256, blake2b512, blake2s, areion256, areion512` | 2210 |

fast-mix beats slow-mix by ~8 % at fixed N=5. The choice of which primitives populate the palette is the load-bearing knob, not the count.

## Anchor-primitive effect (same multiset, different `palette[0]`)

The anchor primitive drives the per-slot KDF derivation and the schedule-seed expansion. Both costs are one-time per `NewCipherset` call; the anchor effect therefore surfaces only when steady-state segment work is itself large. Multiset: `{aescmac, chacha20, blake3, siphash24, blake2s}`.

| Anchor | MB/s @ 4 MiB | MB/s @ 16 MiB |
|---|---:|---:|
| BLAKE3 | 2148 | 2278 |
| AES-128-CTR | 2346 | 2378 |
| ChaCha20 | **2406** | **2381** |

At 4 MiB the three rows spread within ~12 % of each other; at 16 MiB they converge to within ~4 % — the schedule-seed work is fully amortised once steady-state per-segment work dominates the total.

## GOMAXPROCS scaling (default mixed N=3 palette, S=4093, 4 MiB, Encrypt)

Source: `BenchmarkParallaxWorkerScaling`. Default mixed palette `{aescmac, chacha20, blake3}`.

| GOMAXPROCS | MB/s | speed-up vs P=1 |
|---:|---:|---:|
| 1 | 1936 | 1.00× |
| 2 | 2591 | 1.34× |
| 4 | **2852** | **1.47×** |
| 8 | 2763 | 1.43× |
| 16 | 2763 | 1.43× |

Throughput steps up 1.34× from P=1 → P=2 (the serial fast path is slower than the parallel path even at P=2 due to per-worker keystream amortisation) and reaches its ~2.85 GB/s bandwidth ceiling at P=4 (1.47×) on this Rocket Lake target; the steps to P=8 and P=16 (2763 MB/s, 1.43×) land within measurement noise. Larger segments lift the ceiling: the same workload at S=16381 reaches 4 GB/s at P=4 (`aescmac`-homogeneous), while S=251 caps near 2.1× scaling because per-segment overhead dominates.

## Per-segment dispatch

Each per-worker keystream is built once at offset 0 and the per-segment hot loop reseats its counter to the segment's absolute byte offset via [`ctr.ResettableKeystream.ResetCounter`](../ctr/) before XOR. The dispatch is uniform across every palette slot and every branch (parallel or serial) — there is no per-primitive policy table and no exported tuning knob. Cross-decryptability is therefore trivial: the wire is a function of `(masterKey, palette, nonce, plaintext)` only.

## Notes

- The serial fast path runs when the plaintext is below `parallelThreshold = 8 KiB`. Below this threshold the per-worker keystream-setup cost cannot be amortised; serial dispatch in the caller's goroutine wins.
