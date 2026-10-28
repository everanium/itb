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
| **AES-ITB-128** | 128 | 512 | NPRF | 476 | 625 | 757 | 511 | 666 | 807 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 320 | 383 | 432 | 323 | 403 | 436 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 313 | 401 | 424 | 324 | 413 | 415 |
| **BLAKE2b-256** | 256 | 512 | PRF | 225 | 259 | 284 | 223 | 263 | 289 |
| **BLAKE2b-512** | 512 | 512 | PRF | 250 | 297 | 301 | 247 | 295 | 333 |
| **BLAKE2s** | 256 | 512 | PRF | 195 | 230 | 243 | 200 | 228 | 262 |
| **BLAKE3** | 256 | 512 | PRF | 256 | 297 | 302 | 260 | 313 | 325 |
| **AES-CMAC** | 128 | 512 | PRF | 364 | 482 | 538 | 404 | 458 | 566 |
| **SipHash-2-4** | 128 | 512 | PRF | 299 | 329 | 393 | 305 | 362 | 398 |
| **ChaCha20** | 256 | 512 | PRF | 124 | 157 | 155 | 127 | 153 | 157 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 454 | 582 | 674 | 429 | 629 | 751 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 224 | 268 | 284 | 223 | 283 | 303 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 245 | 307 | 328 | 246 | 313 | 325 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 141 | 170 | 185 | 141 | 177 | 180 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 160 | 184 | 196 | 161 | 195 | 211 |
| **BLAKE2s** | 256 | 1024 | PRF | 127 | 153 | 157 | 126 | 163 | 157 |
| **BLAKE3** | 256 | 1024 | PRF | 154 | 200 | 215 | 165 | 214 | 202 |
| **AES-CMAC** | 128 | 1024 | PRF | 310 | 380 | 395 | 330 | 390 | 450 |
| **SipHash-2-4** | 128 | 1024 | PRF | 211 | 249 | 266 | 220 | 247 | 281 |
| **ChaCha20** | 256 | 1024 | PRF | 74 | 94 | 91 | 75 | 95 | 92 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 426 | 518 | 603 | 446 | 552 | 648 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 146 | 179 | 192 | 149 | 181 | 190 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 164 | 204 | 212 | 168 | 209 | 214 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 83 | 98 | 104 | 84 | 105 | 108 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 97 | 120 | 121 | 89 | 120 | 124 |
| **BLAKE2s** | 256 | 2048 | PRF | 82 | 94 | 94 | 79 | 94 | 94 |
| **BLAKE3** | 256 | 2048 | PRF | 103 | 127 | 124 | 109 | 128 | 131 |
| **AES-CMAC** | 128 | 2048 | PRF | 221 | 271 | 302 | 236 | 286 | 313 |
| **SipHash-2-4** | 128 | 2048 | PRF | 121 | 156 | 163 | 132 | 157 | 172 |
| **ChaCha20** | 256 | 2048 | PRF | 45 | 51 | 50 | 46 | 50 | 51 |

## AMD EPYC 9655P 96C/192HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 512 | NPRF | 1025 | 1716 | 2406 | 1325 | 2485 | 2845 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 888 | 1411 | 1995 | 1089 | 2010 | 2294 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 935 | 1491 | 2012 | 1113 | 2027 | 2330 |
| **BLAKE2b-256** | 256 | 512 | PRF | 733 | 1299 | 1490 | 840 | 1587 | 1680 |
| **BLAKE2b-512** | 512 | 512 | PRF | 742 | 1375 | 1595 | 897 | 1687 | 1812 |
| **BLAKE2s** | 256 | 512 | PRF | 681 | 1207 | 1345 | 760 | 1374 | 1511 |
| **BLAKE3** | 256 | 512 | PRF | 747 | 1358 | 1621 | 858 | 1655 | 1805 |
| **AES-CMAC** | 128 | 512 | PRF | 913 | 1607 | 2117 | 1088 | 2184 | 2458 |
| **SipHash-2-4** | 128 | 512 | PRF | 858 | 1477 | 1863 | 1017 | 1950 | 2150 |
| **ChaCha20** | 256 | 512 | PRF | 548 | 860 | 946 | 597 | 966 | 1081 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 1048 | 1782 | 2367 | 1273 | 2417 | 2823 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 792 | 1397 | 1698 | 945 | 1774 | 1948 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 881 | 1410 | 1807 | 1007 | 1800 | 2076 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 598 | 1026 | 1084 | 676 | 1163 | 1201 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 665 | 1104 | 1168 | 724 | 1255 | 1315 |
| **BLAKE2s** | 256 | 1024 | PRF | 544 | 866 | 933 | 602 | 960 | 1037 |
| **BLAKE3** | 256 | 1024 | PRF | 606 | 1108 | 1215 | 688 | 1250 | 1337 |
| **AES-CMAC** | 128 | 1024 | PRF | 795 | 1574 | 1783 | 944 | 1932 | 2021 |
| **SipHash-2-4** | 128 | 1024 | PRF | 731 | 1351 | 1483 | 830 | 1556 | 1655 |
| **ChaCha20** | 256 | 1024 | PRF | 398 | 574 | 663 | 424 | 587 | 694 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 974 | 1675 | 2278 | 1176 | 2319 | 2665 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 675 | 1209 | 1371 | 766 | 1405 | 1525 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 712 | 1253 | 1541 | 824 | 1545 | 1694 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 472 | 676 | 773 | 511 | 753 | 822 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 512 | 774 | 895 | 560 | 829 | 958 |
| **BLAKE2s** | 256 | 2048 | PRF | 395 | 557 | 638 | 426 | 603 | 690 |
| **BLAKE3** | 256 | 2048 | PRF | 497 | 739 | 844 | 534 | 815 | 910 |
| **AES-CMAC** | 128 | 2048 | PRF | 694 | 1307 | 1408 | 788 | 1464 | 1532 |
| **SipHash-2-4** | 128 | 2048 | PRF | 596 | 976 | 1026 | 649 | 1081 | 1147 |
| **ChaCha20** | 256 | 2048 | PRF | 267 | 333 | 409 | 285 | 363 | 423 |

## ARM64 Graviton 4 16C/16HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 512 | NPRF | 424 | 453 | 434 | 446 | 477 | 453 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 264 | 269 | 265 | 272 | 277 | 275 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 285 | 288 | 283 | 290 | 301 | 294 |
| **BLAKE2b-256** | 256 | 512 | PRF | 95 | 95 | 96 | 96 | 97 | 98 |
| **BLAKE2b-512** | 512 | 512 | PRF | 113 | 113 | 113 | 114 | 114 | 116 |
| **BLAKE2s** | 256 | 512 | PRF | 126 | 126 | 127 | 128 | 129 | 129 |
| **BLAKE3** | 256 | 512 | PRF | 166 | 167 | 165 | 169 | 169 | 170 |
| **AES-CMAC** | 128 | 512 | PRF | 344 | 360 | 347 | 353 | 370 | 360 |
| **SipHash-2-4** | 128 | 512 | PRF | 180 | 181 | 180 | 182 | 187 | 186 |
| **ChaCha20** | 256 | 512 | PRF | 77 | 77 | 78 | 78 | 78 | 79 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 383 | 404 | 391 | 401 | 423 | 406 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 191 | 191 | 189 | 193 | 194 | 194 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 212 | 213 | 211 | 216 | 221 | 218 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 55 | 55 | 56 | 55 | 56 | 56 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 66 | 66 | 67 | 66 | 67 | 68 |
| **BLAKE2s** | 256 | 1024 | PRF | 76 | 75 | 76 | 76 | 76 | 77 |
| **BLAKE3** | 256 | 1024 | PRF | 104 | 104 | 104 | 106 | 106 | 106 |
| **AES-CMAC** | 128 | 1024 | PRF | 269 | 277 | 272 | 276 | 291 | 282 |
| **SipHash-2-4** | 128 | 1024 | PRF | 113 | 113 | 114 | 115 | 112 | 115 |
| **ChaCha20** | 256 | 1024 | PRF | 41 | 43 | 43 | 41 | 43 | 44 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 325 | 334 | 329 | 333 | 345 | 339 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 120 | 120 | 121 | 122 | 121 | 122 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 143 | 141 | 143 | 144 | 145 | 144 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 29 | 30 | 31 | 30 | 30 | 31 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 35 | 36 | 37 | 35 | 36 | 37 |
| **BLAKE2s** | 256 | 2048 | PRF | 40 | 42 | 42 | 40 | 42 | 43 |
| **BLAKE3** | 256 | 2048 | PRF | 59 | 59 | 61 | 59 | 60 | 61 |
| **AES-CMAC** | 128 | 2048 | PRF | 190 | 191 | 190 | 193 | 196 | 194 |
| **SipHash-2-4** | 128 | 2048 | PRF | 64 | 65 | 65 | 65 | 66 | 66 |
| **ChaCha20** | 256 | 2048 | PRF | 21 | 23 | 23 | 22 | 23 | 23 |

## DRBG ITB Container Fill (Benchmark)

DRBG Standalone Benchmark Fill and Low-Level Triple Ouroboros Encrypt with AES-ITB-128 seeds at 1024-bit key width and 16 MB of plaintext, `ITB_NONCE_BITS=512`, no parallax or wrapper layer, Intel Core i7-11700K, median of three 5 s runs. The DRBG columns measure the fill alone, without ITB: 18 MB split into three 6 MB thirds filled by three goroutines, aggregate MB/s, median of three 2 s runs.

| DRBG | ITB Encrypt 16 MB | DRBG Rocket Lake | DRBG Zen 5 | DRBG Graviton 4 |
|---|---|---|---|---|
| `""` (auto) | 555 | 10861 | 26381 | 17701 |
| `aesitb128` | 620 | 13029 | 115520 | 58772 |
| `csprng` | 534 | 2174 | 2497 | 933 |
| `areion256` | 551 | 4837 | 6994 | 4366 |
| `areion512` | 552 | 5017 | 10436 | 3983 |
| `blake2b256` | 530 | 2812 | 2769 | 697 |
| `blake2b512` | 541 | 5367 | 5461 | 1381 |
| `blake2s` | 546 | 5998 | 6314 | 1692 |
| `blake3` | 543 | 7976 | 8912 | 2406 |
| `aescmac` | 582 | 11212 | 36382 | 20905 |
| `siphash24` | 558 | 8721 | 12786 | 2999 |
| `chacha20` | 595 | 9923 | 12879 | 3655 |

Reproduction:

```sh
ITB_NONCE_BITS=512 ITB_GOMEMLIMIT=4GiB ITB_GOGC=100 \
  go test -bench='BenchmarkExtTripleAESITB128DRBG' -run='^$' -benchtime=5s -count=3
  go test -bench='BenchmarkArmsParallel3/.*/18MB' -run='^$' -benchtime=2s -count=3 ./internal/drbg/
```
