# ITB Triple Ouroboros Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Results below were collected at `ITB_NONCE_BITS=512` with `ITB_GOMEMLIMIT=4GiB` + `ITB_GOGC=100` capping the Go runtime heap. Every PRF-grade primitive in the shipped hash registry dispatches through hand-written AVX-512 / AVX2 chain-absorb ASM kernels (each primitive family at its natural active register width); AES-ITB-128 dispatches through the AES-NI-family kernels: the pixel-pipeline fused cascade and the batch-16 Interlocked Barrier fill cascade both auto-select the widest VAES tier the host offers (ZMM on VAES + AVX-512F, YMM on VAES + AVX2 without AVX-512F, VEX / legacy-SSE XMM on the remaining AES-NI hosts). The fused cascade tier is overridable via `ITB_FORCE_HASH_TIER`; the batch-16 fill cascade tier is separately overridable via `ITB_FORCE_INTERLOCK_PRF_FILL_TIER`.

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
| **AES-ITB-128** | 128 | 512 | NPRF | 653 | 767 | 1002 | 722 | 863 | 1136 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 422 | 484 | 530 | 450 | 516 | 586 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 448 | 466 | 557 | 461 | 538 | 598 |
| **BLAKE2b-256** | 256 | 512 | PRF | 271 | 299 | 319 | 275 | 307 | 330 |
| **BLAKE2b-512** | 512 | 512 | PRF | 296 | 331 | 352 | 302 | 346 | 369 |
| **BLAKE2s** | 256 | 512 | PRF | 246 | 274 | 281 | 253 | 288 | 296 |
| **BLAKE3** | 256 | 512 | PRF | 299 | 343 | 343 | 309 | 356 | 371 |
| **AES-CMAC** | 128 | 512 | PRF | 509 | 580 | 665 | 501 | 635 | 758 |
| **SipHash-2-4** | 128 | 512 | PRF | 375 | 419 | 457 | 385 | 442 | 481 |
| **ChaCha20** | 256 | 512 | PRF | 271 | 304 | 307 | 275 | 316 | 326 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 612 | 717 | 910 | 664 | 793 | 1048 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 305 | 348 | 367 | 312 | 356 | 383 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 333 | 373 | 398 | 346 | 393 | 424 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 170 | 183 | 191 | 171 | 189 | 197 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 193 | 211 | 218 | 191 | 215 | 224 |
| **BLAKE2s** | 256 | 1024 | PRF | 155 | 174 | 171 | 160 | 176 | 175 |
| **BLAKE3** | 256 | 1024 | PRF | 201 | 225 | 227 | 205 | 233 | 231 |
| **AES-CMAC** | 128 | 1024 | PRF | 402 | 459 | 505 | 413 | 472 | 549 |
| **SipHash-2-4** | 128 | 1024 | PRF | 254 | 280 | 296 | 257 | 290 | 307 |
| **ChaCha20** | 256 | 1024 | PRF | 174 | 192 | 195 | 175 | 199 | 198 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 543 | 628 | 758 | 581 | 689 | 837 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 196 | 215 | 228 | 206 | 226 | 233 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 226 | 250 | 262 | 229 | 256 | 272 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 97 | 104 | 106 | 98 | 104 | 108 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 112 | 123 | 125 | 116 | 124 | 126 |
| **BLAKE2s** | 256 | 2048 | PRF | 90 | 99 | 97 | 91 | 98 | 98 |
| **BLAKE3** | 256 | 2048 | PRF | 121 | 134 | 132 | 122 | 136 | 134 |
| **AES-CMAC** | 128 | 2048 | PRF | 280 | 304 | 337 | 280 | 324 | 345 |
| **SipHash-2-4** | 128 | 2048 | PRF | 154 | 167 | 173 | 156 | 169 | 176 |
| **ChaCha20** | 256 | 2048 | PRF | 102 | 112 | 111 | 102 | 112 | 113 |

## AMD EPYC 9655P 96C/192HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 512 | NPRF | 1158 | 1904 | 2464 | 1437 | 2602 | 3025 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 960 | 1582 | 2037 | 1118 | 2059 | 2423 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 1017 | 1609 | 1989 | 1173 | 2083 | 2475 |
| **BLAKE2b-256** | 256 | 512 | PRF | 770 | 1312 | 1513 | 851 | 1623 | 1745 |
| **BLAKE2b-512** | 512 | 512 | PRF | 805 | 1380 | 1582 | 892 | 1686 | 1811 |
| **BLAKE2s** | 256 | 512 | PRF | 701 | 1254 | 1321 | 778 | 1438 | 1527 |
| **BLAKE3** | 256 | 512 | PRF | 767 | 1348 | 1536 | 861 | 1649 | 1818 |
| **AES-CMAC** | 128 | 512 | PRF | 985 | 1754 | 2174 | 1141 | 2283 | 2609 |
| **SipHash-2-4** | 128 | 512 | PRF | 869 | 1575 | 1852 | 1024 | 2008 | 2246 |
| **ChaCha20** | 256 | 512 | PRF | 737 | 1327 | 1453 | 820 | 1517 | 1625 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 1115 | 1894 | 2388 | 1317 | 2493 | 2924 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 853 | 1408 | 1720 | 973 | 1787 | 2000 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 929 | 1474 | 1800 | 1060 | 1865 | 2166 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 638 | 1045 | 1089 | 683 | 1177 | 1271 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 674 | 1120 | 1163 | 742 | 1271 | 1326 |
| **BLAKE2s** | 256 | 1024 | PRF | 558 | 888 | 970 | 604 | 989 | 1101 |
| **BLAKE3** | 256 | 1024 | PRF | 615 | 1064 | 1142 | 702 | 1210 | 1275 |
| **AES-CMAC** | 128 | 1024 | PRF | 852 | 1578 | 1829 | 980 | 2017 | 2145 |
| **SipHash-2-4** | 128 | 1024 | PRF | 754 | 1405 | 1492 | 843 | 1616 | 1787 |
| **ChaCha20** | 256 | 1024 | PRF | 589 | 976 | 1032 | 635 | 1081 | 1154 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 1038 | 1777 | 2277 | 1207 | 2352 | 2733 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 686 | 1234 | 1320 | 794 | 1419 | 1528 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 787 | 1296 | 1546 | 906 | 1593 | 1757 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 474 | 710 | 759 | 504 | 768 | 821 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 513 | 765 | 894 | 553 | 825 | 953 |
| **BLAKE2s** | 256 | 2048 | PRF | 401 | 571 | 651 | 421 | 607 | 709 |
| **BLAKE3** | 256 | 2048 | PRF | 477 | 726 | 798 | 519 | 802 | 878 |
| **AES-CMAC** | 128 | 2048 | PRF | 704 | 1336 | 1440 | 804 | 1553 | 1627 |
| **SipHash-2-4** | 128 | 2048 | PRF | 611 | 1001 | 1035 | 665 | 1103 | 1165 |
| **ChaCha20** | 256 | 2048 | PRF | 439 | 656 | 726 | 472 | 683 | 778 |

## ARM64 Graviton 4 16C/16HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 512 | NPRF | 430 | 454 | 432 | 445 | 483 | 464 |
| **Areion-SoEM-256** | 256 | 512 | PRF | 178 | 178 | 177 | 181 | 183 | 182 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 224 | 227 | 221 | 229 | 231 | 233 |
| **BLAKE2b-256** | 256 | 512 | PRF | 92 | 90 | 92 | 93 | 94 | 94 |
| **BLAKE2b-512** | 512 | 512 | PRF | 107 | 107 | 107 | 107 | 107 | 109 |
| **BLAKE2s** | 256 | 512 | PRF | 124 | 123 | 124 | 125 | 126 | 128 |
| **BLAKE3** | 256 | 512 | PRF | 158 | 158 | 158 | 159 | 159 | 161 |
| **AES-CMAC** | 128 | 512 | PRF | 346 | 358 | 352 | 359 | 380 | 374 |
| **SipHash-2-4** | 128 | 512 | PRF | 181 | 180 | 180 | 184 | 190 | 186 |
| **ChaCha20** | 256 | 512 | PRF | 141 | 141 | 140 | 142 | 142 | 144 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 1024 | NPRF | 390 | 411 | 389 | 408 | 434 | 414 |
| **Areion-SoEM-256** | 256 | 1024 | PRF | 111 | 110 | 111 | 112 | 113 | 113 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 151 | 151 | 150 | 152 | 156 | 154 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 52 | 53 | 54 | 53 | 54 | 54 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 62 | 62 | 63 | 62 | 63 | 64 |
| **BLAKE2s** | 256 | 1024 | PRF | 73 | 73 | 74 | 74 | 74 | 75 |
| **BLAKE3** | 256 | 1024 | PRF | 99 | 99 | 99 | 100 | 101 | 101 |
| **AES-CMAC** | 128 | 1024 | PRF | 271 | 278 | 271 | 280 | 294 | 287 |
| **SipHash-2-4** | 128 | 1024 | PRF | 114 | 112 | 114 | 112 | 115 | 116 |
| **ChaCha20** | 256 | 1024 | PRF | 84 | 85 | 85 | 86 | 86 | 87 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **AES-ITB-128** | 128 | 2048 | NPRF | 326 | 330 | 324 | 340 | 353 | 346 |
| **Areion-SoEM-256** | 256 | 2048 | PRF | 61 | 63 | 64 | 61 | 63 | 64 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 91 | 91 | 91 | 90 | 92 | 93 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 28 | 29 | 29 | 28 | 29 | 29 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 32 | 34 | 34 | 33 | 35 | 35 |
| **BLAKE2s** | 256 | 2048 | PRF | 39 | 41 | 41 | 39 | 41 | 42 |
| **BLAKE3** | 256 | 2048 | PRF | 55 | 55 | 57 | 55 | 56 | 57 |
| **AES-CMAC** | 128 | 2048 | PRF | 189 | 191 | 191 | 194 | 199 | 196 |
| **SipHash-2-4** | 128 | 2048 | PRF | 65 | 65 | 65 | 66 | 65 | 67 |
| **ChaCha20** | 256 | 2048 | PRF | 46 | 48 | 48 | 45 | 48 | 48 |

## Intel Core i7-11700K 8C/16HT — New 48-bit Interlocked ITB vs Old ITB (Lock Soup + Lock Batch mode) — Delta

Interlocked ITB with the nonce widens from 128 bits to 512 bits (secure default), and the overlay moves from an opt-in 24-bit Lock Soup + Lock Batch mask (roughly 2^33 mask space per chunk group) to an always-on 48-bit Interlocked Barrier (~ 2^70 mask space per chunk group). Previous "Lock Soup + Lock Batch" mode on the same i7-11700K host is the fair comparison point — both sides carry an overlay derivation cost per chunk, and the ratio isolates the ~ 2^37 mask-space widening plus the 4× nonce widening.

Encrypt at 64 MB (MB/s per primitive per width; new / old ; **►** marks ratios ≥ 100%):

| Primitive          | 512-bit E 64 MB     | 1024-bit E 64 MB    | 2048-bit E 64 MB    |
|--------------------|:-------------------:|:-------------------:|:-------------------:|
| **Areion-SoEM-256** | 530 / 198 (268%) ►  | 367 / 179 (205%) ►  | 228 / 141 (162%) ►  |
| **Areion-SoEM-512** | 557 / 226 (246%) ►  | 398 / 198 (201%) ►  | 262 / 162 (162%) ►  |
| **BLAKE2b-256**     | 319 / 118 (270%) ►  | 191 / 84 (227%) ►   | 106 / 54 (196%) ►   |
| **BLAKE2b-512**     | 352 / 174 (202%) ►  | 218 / 134 (163%) ►  | 125 / 88 (142%) ►   |
| **BLAKE2s**         | 281 / 130 (216%) ►  | 171 / 91 (188%) ►   | 97 / 59 (164%) ►    |
| **BLAKE3**          | 343 / 130 (264%) ►  | 227 / 101 (225%) ►  | 132 / 69 (191%) ►   |
| **AES-CMAC**        | 665 / 165 (403%) ►  | 505 / 153 (330%) ►  | 337 / 120 (281%) ►  |
| **SipHash-2-4**     | 457 / 158 (289%) ►  | 296 / 126 (235%) ►  | 173 / 90 (192%) ►   |
| **ChaCha20**        | 307 / 110 (279%) ►  | 195 / 86 (227%) ►   | 111 / 58 (191%) ►   |

Decrypt at 64 MB (MB/s per primitive per width; new / old ; **►** marks ratios ≥ 100%):

| Primitive          | 512-bit D 64 MB     | 1024-bit D 64 MB    | 2048-bit D 64 MB    |
|--------------------|:-------------------:|:-------------------:|:-------------------:|
| **Areion-SoEM-256** | 586 / 248 (236%) ►  | 383 / 215 (178%) ►  | 233 / 165 (141%) ►  |
| **Areion-SoEM-512** | 598 / 280 (214%) ►  | 424 / 240 (177%) ►  | 272 / 187 (145%) ►  |
| **BLAKE2b-256**     | 330 / 135 (244%) ►  | 197 / 93 (212%) ►   | 108 / 56 (193%) ►   |
| **BLAKE2b-512**     | 369 / 211 (175%) ►  | 224 / 152 (147%) ►  | 126 / 96 (131%) ►   |
| **BLAKE2s**         | 296 / 144 (206%) ►  | 175 / 100 (175%) ►  | 98 / 62 (158%) ►    |
| **BLAKE3**          | 371 / 148 (251%) ►  | 231 / 110 (210%) ►  | 134 / 74 (181%) ►   |
| **AES-CMAC**        | 758 / 211 (359%) ►  | 549 / 177 (310%) ►  | 345 / 137 (252%) ►  |
| **SipHash-2-4**     | 481 / 187 (257%) ►  | 307 / 143 (215%) ►  | 176 / 98 (180%) ►   |
| **ChaCha20**        | 326 / 133 (245%) ►  | 198 / 98 (202%) ►   | 113 / 64 (177%) ►   |

**Every shipped primitive now sits well above the old ITB line at every width on both Encrypt and Decrypt.** Ratios span from **131%** (BLAKE2b-512 at 2048-bit Decrypt, the tightest cell) to **403%** (AES-CMAC at 512-bit Encrypt, the widest). The cumulative uplift covers the fused ChainHash cascade kernels landed across every PRF-grade primitive, DRBG bulk-fill CSPRNG on the encrypt hot path, bound-based sizing plus classical pipeline overlap in `buildTripleWire3`, and bridge-free ZMM Interlocked Barrier kernels — sustained through a 4× nonce widening (128 → 512 bit) and a ~2^37 mask-space widening (24-bit Lock Soup + Lock Batch → 48-bit Interlocked Barrier).

**AES-CMAC leads the fleet** at 403% / 330% / 281% Encrypt and 359% / 310% / 252% Decrypt across the 512 / 1024 / 2048 bit widths — VAES + AVX-512 fused kernels amortise cleanly across the widened overlay. **BLAKE2b-256, BLAKE3, ChaCha20, SipHash-2-4, Areion-SoEM-256/512** cluster in the 200-270% band at 512-bit and stay ≥140% through the 2048-bit line. **BLAKE2b-512** and **BLAKE2s** carry the tightest cells (131-175% at 2048-bit Decrypt) — the wider container's higher per-chunk overhead relative to the per-byte hash cost still leaves every cell comfortably above the old ITB baseline.

**Further rows** for other µarchs are scheduled — this table is a first-pass baseline pending maintainer-assisted runs on additional hardware.
