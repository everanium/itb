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
| **AES-ITB-128** | 128 | 512 | NPRF | 1051 | 1747 | 2155 | 1338 | 2431 | 2819 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 868 | 1463 | 1792 | 1073 | 1958 | 2226 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 876 | 1428 | 1868 | 1106 | 1989 | 2260 |
| **BLAKE2b-256** | 256 | 512 | PRF | 768 | 1269 | 1468 | 823 | 1586 | 1688 |
| **BLAKE2b-512** | 512 | 512 | PRF | 741 | 1313 | 1499 | 885 | 1647 | 1739 |
| **BLAKE2s** | 256 | 512 | PRF | 661 | 1192 | 1263 | 738 | 1372 | 1490 |
| **BLAKE3** | 256 | 512 | PRF | 759 | 1301 | 1532 | 853 | 1640 | 1789 |
| **AES-CMAC** | 128 | 512 | PRF | 871 | 1601 | 1957 | 1066 | 2157 | 2440 |
| **SipHash-2-4** | 128 | 512 | PRF | 829 | 1442 | 1734 | 974 | 1953 | 2130 |
| **ChaCha20** | 256 | 512 | PRF | 529 | 848 | 962 | 589 | 935 | 1043 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 991 | 1626 | 2184 | 1262 | 2423 | 2780 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 768 | 1338 | 1539 | 925 | 1724 | 1893 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 853 | 1312 | 1632 | 984 | 1786 | 2035 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 587 | 1016 | 1087 | 678 | 1181 | 1212 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 626 | 1068 | 1131 | 730 | 1247 | 1282 |
| **BLAKE2s** | 256 | 1024 | PRF | 524 | 874 | 916 | 593 | 987 | 1050 |
| **BLAKE3** | 256 | 1024 | PRF | 598 | 1119 | 1177 | 684 | 1242 | 1336 |
| **AES-CMAC** | 128 | 1024 | PRF | 787 | 1459 | 1743 | 939 | 1916 | 1999 |
| **SipHash-2-4** | 128 | 1024 | PRF | 686 | 1293 | 1377 | 835 | 1550 | 1647 |
| **ChaCha20** | 256 | 1024 | PRF | 392 | 558 | 645 | 422 | 595 | 708 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 970 | 1651 | 2027 | 1182 | 2240 | 2623 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 652 | 1081 | 1260 | 767 | 1360 | 1456 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 741 | 1233 | 1408 | 848 | 1524 | 1651 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 462 | 700 | 747 | 501 | 761 | 821 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 477 | 761 | 852 | 561 | 850 | 949 |
| **BLAKE2s** | 256 | 2048 | PRF | 399 | 583 | 642 | 419 | 613 | 689 |
| **BLAKE3** | 256 | 2048 | PRF | 476 | 758 | 811 | 522 | 820 | 915 |
| **AES-CMAC** | 128 | 2048 | PRF | 691 | 1297 | 1315 | 767 | 1479 | 1572 |
| **SipHash-2-4** | 128 | 2048 | PRF | 563 | 980 | 980 | 642 | 1088 | 1159 |
| **ChaCha20** | 256 | 2048 | PRF | 266 | 331 | 400 | 280 | 363 | 423 |

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
| `""` (auto) | 708 | 16702 | 26708 | 18685 |
| `aesitb128` | 704 | 27155 | 108871 | 60037 |
| `csprng` | 595 | 2265 | 2500 | 934 |
| `areion256` | 549 | 1635 | 2238 | 1322 |
| `areion512` | 552 | 1673 | 2329 | 1082 |
| `blake2b256` | 245 | 357 | 259 | 238 |
| `blake2b512` | 383 | 662 | 503 | 448 |
| `blake2s` | 275 | 425 | 301 | 271 |
| `blake3` | 441 | 941 | 794 | 602 |
| `aescmac` | 695 | 19928 | 36268 | 23002 |
| `siphash24` | 595 | 2224 | 2922 | 1879 |
| `chacha20` | 594 | 2071 | 3060 | 3671 |

Reproduction:

```sh
ITB_NONCE_BITS=512 ITB_GOMEMLIMIT=4GiB ITB_GOGC=100 \
  go test -bench='BenchmarkExtTripleAESITB128DRBG' -run='^$' -benchtime=5s -count=3
  go test -bench='BenchmarkArmsParallel3/.*/18MB' -run='^$' -benchtime=2s -count=3 ./internal/drbg/
```
