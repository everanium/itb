## ITB Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](README.md) for jurisdictional certification details.

Results below were collected at `ITB_NONCE_BITS=512` with `ITB_GOMEMLIMIT=4GiB` + `ITB_GOGC=100` capping the Go runtime heap. ARX-based PRF-grade primitives dispatch through hand-written AVX-512 / AVX2 chain-absorb ASM kernels (each primitive family at its natural active register width); AES-family primitives (AES-ITB-128, Areion-SoEM-256, Areion-SoEM-512, AES-CMAC) dispatch through VAES / AES-NI kernels: the pixel-pipeline fused cascade and the batch-16 Interlocked Barrier fill cascade both auto-select the widest VAES tier the host offers (ZMM on VAES + AVX-512F, YMM on VAES + AVX2 without AVX-512F, VEX / non-VEX SSE XMM on the remaining AES-NI hosts). The fused cascade tier is overridable via `ITB_FORCE_HASH_TIER`; the batch-16 fill cascade tier is separately overridable via `ITB_FORCE_INTERLOCK_PRF_FILL_TIER`.

Reproduction:

```sh
ITB_NONCE_BITS=512 ITB_GOMEMLIMIT=4GiB ITB_GOGC=100 \
  go test -bench='BenchmarkExtTriple.*_(1MB|16MB|64MB)$' -run='^$' -benchtime=5s -count=1
```

## Intel Core i7-11700K 8C/16HT

The AES-ITB-128 rows appear here, in the AMD EPYC 9655P section further down, and in the ARM64 Graviton 4 section.

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 512 | NPRF | 621 | 737 | 910 | 656 | 784 | 1006 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 412 | 474 | 511 | 430 | 504 | 551 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 423 | 489 | 540 | 422 | 517 | 579 |
| **BLAKE2b-256** | 256 | 512 | PRF | 272 | 307 | 328 | 279 | 314 | 334 |
| **BLAKE2b-512** | 512 | 512 | PRF | 299 | 341 | 360 | 314 | 357 | 377 |
| **BLAKE2s** | 256 | 512 | PRF | 250 | 279 | 283 | 254 | 293 | 291 |
| **BLAKE3** | 256 | 512 | PRF | 299 | 354 | 360 | 319 | 365 | 369 |
| **AES-CMAC** | 128 | 512 | PRF | 483 | 546 | 645 | 489 | 589 | 685 |
| **SipHash-2-4** | 128 | 512 | PRF | 358 | 409 | 438 | 378 | 427 | 467 |
| **ChaCha20** | 256 | 512 | PRF | 157 | 174 | 171 | 159 | 180 | 177 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 571 | 680 | 859 | 599 | 737 | 913 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 305 | 345 | 344 | 295 | 355 | 380 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 329 | 379 | 398 | 342 | 389 | 420 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 178 | 195 | 199 | 179 | 199 | 205 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 207 | 224 | 232 | 212 | 232 | 239 |
| **BLAKE2s** | 256 | 1024 | PRF | 161 | 174 | 176 | 166 | 179 | 181 |
| **BLAKE3** | 256 | 1024 | PRF | 212 | 236 | 239 | 217 | 243 | 243 |
| **AES-CMAC** | 128 | 1024 | PRF | 385 | 447 | 487 | 402 | 462 | 511 |
| **SipHash-2-4** | 128 | 1024 | PRF | 258 | 283 | 298 | 265 | 297 | 309 |
| **ChaCha20** | 256 | 1024 | PRF | 95 | 102 | 99 | 96 | 104 | 100 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 503 | 638 | 746 | 550 | 673 | 818 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 198 | 219 | 220 | 201 | 226 | 232 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 225 | 251 | 258 | 232 | 260 | 269 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 104 | 112 | 113 | 104 | 112 | 116 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 123 | 130 | 133 | 124 | 133 | 137 |
| **BLAKE2s** | 256 | 2048 | PRF | 96 | 102 | 103 | 96 | 102 | 102 |
| **BLAKE3** | 256 | 2048 | PRF | 133 | 145 | 143 | 133 | 145 | 144 |
| **AES-CMAC** | 128 | 2048 | PRF | 273 | 310 | 327 | 288 | 323 | 345 |
| **SipHash-2-4** | 128 | 2048 | PRF | 159 | 172 | 176 | 163 | 176 | 181 |
| **ChaCha20** | 256 | 2048 | PRF | 52 | 56 | 54 | 53 | 57 | 55 |

## AMD EPYC 9655P 96C/192HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 512 | NPRF | 1033 | 1704 | 2222 | 1264 | 2418 | 2835 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 867 | 1433 | 1757 | 1036 | 2000 | 2306 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 819 | 1525 | 1811 | 1052 | 2002 | 2318 |
| **BLAKE2b-256** | 256 | 512 | PRF | 668 | 1244 | 1425 | 836 | 1609 | 1685 |
| **BLAKE2b-512** | 512 | 512 | PRF | 718 | 1268 | 1475 | 863 | 1662 | 1774 |
| **BLAKE2s** | 256 | 512 | PRF | 659 | 1154 | 1248 | 748 | 1376 | 1482 |
| **BLAKE3** | 256 | 512 | PRF | 709 | 1305 | 1531 | 825 | 1678 | 1883 |
| **AES-CMAC** | 128 | 512 | PRF | 886 | 1630 | 1943 | 1040 | 2118 | 2462 |
| **SipHash-2-4** | 128 | 512 | PRF | 808 | 1440 | 1680 | 950 | 1980 | 2161 |
| **ChaCha20** | 256 | 512 | PRF | 495 | 807 | 854 | 583 | 940 | 1030 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 1004 | 1726 | 2092 | 1213 | 2394 | 2782 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 754 | 1422 | 1527 | 913 | 1784 | 1952 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 768 | 1334 | 1700 | 976 | 1840 | 2029 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 598 | 990 | 1073 | 654 | 1185 | 1218 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 627 | 1108 | 1125 | 688 | 1265 | 1379 |
| **BLAKE2s** | 256 | 1024 | PRF | 519 | 826 | 958 | 594 | 970 | 1084 |
| **BLAKE3** | 256 | 1024 | PRF | 586 | 1071 | 1197 | 672 | 1251 | 1369 |
| **AES-CMAC** | 128 | 1024 | PRF | 768 | 1537 | 1631 | 890 | 1946 | 2026 |
| **SipHash-2-4** | 128 | 1024 | PRF | 705 | 1228 | 1357 | 808 | 1577 | 1664 |
| **ChaCha20** | 256 | 1024 | PRF | 372 | 532 | 633 | 421 | 616 | 702 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 960 | 1572 | 1959 | 1119 | 2241 | 2644 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 621 | 1190 | 1273 | 732 | 1408 | 1494 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 678 | 1258 | 1412 | 833 | 1543 | 1673 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 428 | 621 | 757 | 493 | 765 | 833 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 485 | 743 | 877 | 547 | 859 | 986 |
| **BLAKE2s** | 256 | 2048 | PRF | 379 | 567 | 633 | 431 | 650 | 700 |
| **BLAKE3** | 256 | 2048 | PRF | 460 | 697 | 820 | 525 | 826 | 909 |
| **AES-CMAC** | 128 | 2048 | PRF | 652 | 1215 | 1324 | 760 | 1502 | 1578 |
| **SipHash-2-4** | 128 | 2048 | PRF | 547 | 987 | 1008 | 660 | 1090 | 1151 |
| **ChaCha20** | 256 | 2048 | PRF | 251 | 329 | 396 | 283 | 369 | 445 |

## ARM64 Graviton 4 16C/16HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 512 | NPRF | 427 | 443 | 429 | 452 | 484 | 458 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 213 | 215 | 211 | 219 | 225 | 224 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 256 | 254 | 256 | 265 | 274 | 271 |
| **BLAKE2b-256** | 256 | 512 | PRF | 96 | 96 | 96 | 97 | 97 | 99 |
| **BLAKE2b-512** | 512 | 512 | PRF | 113 | 113 | 114 | 115 | 116 | 115 |
| **BLAKE2s** | 256 | 512 | PRF | 127 | 127 | 126 | 129 | 128 | 130 |
| **BLAKE3** | 256 | 512 | PRF | 165 | 163 | 165 | 169 | 171 | 170 |
| **AES-CMAC** | 128 | 512 | PRF | 342 | 355 | 346 | 351 | 373 | 362 |
| **SipHash-2-4** | 128 | 512 | PRF | 180 | 182 | 179 | 184 | 187 | 187 |
| **ChaCha20** | 256 | 512 | PRF | 77 | 77 | 77 | 77 | 78 | 79 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 385 | 399 | 386 | 407 | 425 | 416 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 140 | 140 | 140 | 142 | 144 | 143 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 184 | 181 | 181 | 188 | 189 | 188 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 55 | 55 | 56 | 55 | 56 | 56 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 66 | 66 | 67 | 66 | 66 | 68 |
| **BLAKE2s** | 256 | 1024 | PRF | 76 | 75 | 76 | 77 | 76 | 77 |
| **BLAKE3** | 256 | 1024 | PRF | 104 | 104 | 105 | 105 | 106 | 107 |
| **AES-CMAC** | 128 | 1024 | PRF | 267 | 271 | 272 | 277 | 289 | 286 |
| **SipHash-2-4** | 128 | 1024 | PRF | 114 | 113 | 113 | 115 | 115 | 117 |
| **ChaCha20** | 256 | 1024 | PRF | 41 | 43 | 43 | 42 | 43 | 44 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 325 | 329 | 322 | 336 | 350 | 344 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 83 | 83 | 83 | 84 | 84 | 85 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 117 | 116 | 117 | 119 | 119 | 120 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 29 | 30 | 31 | 29 | 31 | 31 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 36 | 37 | 37 | 36 | 37 | 37 |
| **BLAKE2s** | 256 | 2048 | PRF | 40 | 42 | 42 | 40 | 42 | 43 |
| **BLAKE3** | 256 | 2048 | PRF | 59 | 60 | 61 | 59 | 61 | 61 |
| **AES-CMAC** | 128 | 2048 | PRF | 187 | 188 | 189 | 192 | 197 | 199 |
| **SipHash-2-4** | 128 | 2048 | PRF | 64 | 64 | 66 | 65 | 65 | 66 |
| **ChaCha20** | 256 | 2048 | PRF | 21 | 23 | 23 | 22 | 23 | 23 |

## DRBG ITB Container Fill (Benchmark)

DRBG Standalone Benchmark Fill and Low-Level Triple Ouroboros Encrypt with AES-ITB-128 seeds at 1024-bit key width and 16 MB of plaintext, `ITB_NONCE_BITS=512`, no parallax or wrapper layer, Intel Core i7-11700K, median of three 5 s runs. The DRBG columns measure the fill alone, without ITB: 18 MB split into three 6 MB thirds filled by three goroutines, aggregate MB/s, median of three 2 s runs.

| DRBG | ITB Encrypt 16 MB | DRBG Rocket Lake | DRBG Zen 5 | DRBG Graviton 4 |
|---|---|---|---|---|
| `""` (auto) | 708 | 16702 | 25934 | 18685 |
| `aesitb128` | 704 | 27155 | 106958 | 60037 |
| `csprng` | 595 | 2265 | 2497 | 934 |
| `areion256` | 549 | 1635 | 5299 | 1322 |
| `areion512` | 552 | 1673 | 6552 | 1082 |
| `blake2b256` | 245 | 357 | 269 | 238 |
| `blake2b512` | 383 | 662 | 529 | 448 |
| `blake2s` | 275 | 425 | 312 | 271 |
| `blake3` | 441 | 941 | 875 | 602 |
| `aescmac` | 695 | 19928 | 36178 | 23002 |
| `siphash24` | 595 | 2224 | 3127 | 1879 |
| `chacha20` | 594 | 2071 | 2853 | 3671 |

Reproduction:

```sh
ITB_NONCE_BITS=512 ITB_GOMEMLIMIT=4GiB ITB_GOGC=100 \
  go test -bench='BenchmarkExtTripleAESITB128DRBG' -run='^$' -benchtime=5s -count=3
  go test -bench='BenchmarkArmsParallel3/.*/18MB' -run='^$' -benchtime=2s -count=3 ./internal/drbg/
```
