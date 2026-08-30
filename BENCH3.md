# ITB Triple Ouroboros Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Results below were collected at `ITB_NONCE_BITS=512` with `ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` capping the Go runtime heap. Every PRF-grade primitive in the shipped hash registry dispatches through hand-written AVX-512 / AVX2 chain-absorb ASM kernels (each primitive family at its natural active register width).

Reproduction:

```sh
ITB_NONCE_BITS=512 ITB_GOMEMLIMIT=512MiB ITB_GOGC=20 \
  go test -bench='BenchmarkExtTriple.*_(1MB|16MB|64MB)$' -run='^$' -benchtime=5s -count=1
```

## Intel Core i7-11700K 8C/16HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 130 | 224 | 279 | 292 | 329 | 400 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 134 | 237 | 293 | 304 | 356 | 442 |
| **BLAKE2b-256** | 256 | 512 | PRF | 104 | 162 | 184 | 197 | 210 | 235 |
| **BLAKE2b-512** | 512 | 512 | PRF | 106 | 164 | 189 | 193 | 212 | 246 |
| **BLAKE2s** | 256 | 512 | PRF | 89 | 128 | 144 | 142 | 159 | 173 |
| **BLAKE3** | 256 | 512 | PRF | 100 | 151 | 166 | 175 | 172 | 211 |
| **AES-CMAC** | 128 | 512 | PRF | 132 | 217 | 265 | 280 | 305 | 380 |
| **SipHash-2-4** | 128 | 512 | PRF | 116 | 184 | 213 | 226 | 244 | 284 |
| **ChaCha20** | 256 | 512 | PRF | 115 | 171 | 198 | 208 | 223 | 254 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 114 | 180 | 207 | 214 | 235 | 269 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 119 | 199 | 235 | 243 | 272 | 319 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 83 | 116 | 126 | 126 | 134 | 145 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 84 | 118 | 130 | 131 | 142 | 150 |
| **BLAKE2s** | 256 | 1024 | PRF | 64 | 85 | 90 | 90 | 96 | 100 |
| **BLAKE3** | 256 | 1024 | PRF | 74 | 103 | 111 | 112 | 122 | 128 |
| **AES-CMAC** | 128 | 1024 | PRF | 108 | 171 | 192 | 203 | 224 | 252 |
| **SipHash-2-4** | 128 | 1024 | PRF | 90 | 132 | 149 | 144 | 161 | 176 |
| **ChaCha20** | 256 | 1024 | PRF | 91 | 125 | 134 | 133 | 144 | 158 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 92 | 126 | 138 | 145 | 153 | 164 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 104 | 149 | 167 | 179 | 184 | 204 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 57 | 70 | 75 | 76 | 80 | 82 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 58 | 75 | 78 | 79 | 84 | 85 |
| **BLAKE2s** | 256 | 2048 | PRF | 43 | 50 | 52 | 51 | 54 | 54 |
| **BLAKE3** | 256 | 2048 | PRF | 51 | 63 | 66 | 65 | 69 | 72 |
| **AES-CMAC** | 128 | 2048 | PRF | 83 | 119 | 131 | 130 | 140 | 152 |
| **SipHash-2-4** | 128 | 2048 | PRF | 67 | 85 | 91 | 91 | 96 | 101 |
| **ChaCha20** | 256 | 2048 | PRF | 58 | 81 | 81 | 85 | 90 | 92 |

## AMD EPYC 9655P 96C/192HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 397 | 469 | 513 | 679 | 888 | 1078 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 393 | 488 | 519 | 765 | 908 | 1095 |
| **BLAKE2b-256** | 256 | 512 | PRF | 349 | 402 | 475 | 532 | 770 | 878 |
| **BLAKE2b-512** | 512 | 512 | PRF | 370 | 412 | 472 | 566 | 800 | 919 |
| **BLAKE2s** | 256 | 512 | PRF | 338 | 373 | 442 | 476 | 654 | 787 |
| **BLAKE3** | 256 | 512 | PRF | 358 | 382 | 472 | 518 | 746 | 865 |
| **AES-CMAC** | 128 | 512 | PRF | 378 | 454 | 503 | 673 | 912 | 1031 |
| **SipHash-2-4** | 128 | 512 | PRF | 381 | 427 | 497 | 629 | 842 | 964 |
| **ChaCha20** | 256 | 512 | PRF | 367 | 405 | 491 | 567 | 807 | 892 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 364 | 411 | 483 | 576 | 808 | 913 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 378 | 429 | 488 | 660 | 772 | 916 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 312 | 333 | 414 | 429 | 573 | 723 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 316 | 353 | 423 | 459 | 611 | 764 |
| **BLAKE2s** | 256 | 1024 | PRF | 273 | 300 | 355 | 363 | 468 | 593 |
| **BLAKE3** | 256 | 1024 | PRF | 303 | 328 | 399 | 414 | 555 | 662 |
| **AES-CMAC** | 128 | 1024 | PRF | 372 | 418 | 469 | 571 | 765 | 900 |
| **SipHash-2-4** | 128 | 1024 | PRF | 336 | 371 | 433 | 506 | 658 | 803 |
| **ChaCha20** | 256 | 1024 | PRF | 326 | 361 | 415 | 454 | 620 | 764 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 320 | 358 | 425 | 467 | 619 | 727 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 347 | 351 | 397 | 525 | 695 | 822 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 248 | 272 | 338 | 319 | 432 | 502 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 250 | 277 | 334 | 338 | 445 | 525 |
| **BLAKE2s** | 256 | 2048 | PRF | 203 | 226 | 269 | 258 | 326 | 383 |
| **BLAKE3** | 256 | 2048 | PRF | 235 | 259 | 303 | 303 | 386 | 476 |
| **AES-CMAC** | 128 | 2048 | PRF | 299 | 331 | 400 | 450 | 563 | 678 |
| **SipHash-2-4** | 128 | 2048 | PRF | 275 | 298 | 365 | 388 | 480 | 584 |
| **ChaCha20** | 256 | 2048 | PRF | 260 | 293 | 347 | 344 | 449 | 559 |

##ARM Graviton 4 16C/16HT

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 43 | 49 | 51 | 46 | 54 | 57 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 50 | 57 | 59 | 56 | 63 | 66 |
| **BLAKE2b-256** | 256 | 512 | PRF | 41 | 44 | 46 | 42 | 49 | 50 |
| **BLAKE2b-512** | 512 | 512 | PRF | 42 | 47 | 48 | 44 | 52 | 53 |
| **BLAKE2s** | 256 | 512 | PRF | 33 | 36 | 37 | 34 | 39 | 40 |
| **BLAKE3** | 256 | 512 | PRF | 20 | 23 | 23 | 19 | 21 | 25 |
| **AES-CMAC** | 128 | 512 | PRF | 53 | 60 | 61 | 57 | 67 | 69 |
| **SipHash-2-4** | 128 | 512 | PRF | 58 | 66 | 68 | 76 | 75 | 78 |
| **ChaCha20** | 256 | 512 | PRF | 6 | 22 | 31 | 7 | 20 | 32 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 32 | 36 | 36 | 34 | 38 | 39 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 39 | 44 | 45 | 45 | 48 | 49 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 27 | 32 | 31 | 28 | 34 | 34 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 29 | 33 | 33 | 31 | 36 | 36 |
| **BLAKE2s** | 256 | 1024 | PRF | 20 | 24 | 24 | 23 | 25 | 26 |
| **BLAKE3** | 256 | 1024 | PRF | 11 | 14 | 12 | 14 | 13 | 15 |
| **AES-CMAC** | 128 | 1024 | PRF | 41 | 45 | 46 | 43 | 50 | 51 |
| **SipHash-2-4** | 128 | 1024 | PRF | 48 | 53 | 54 | 54 | 59 | 61 |
| **ChaCha20** | 256 | 1024 | PRF | 4 | 13 | 20 | 4 | 11 | 20 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 20 | 23 | 23 | 23 | 24 | 24 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 26 | 30 | 30 | 28 | 32 | 32 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 18 | 20 | 20 | 19 | 21 | 21 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 19 | 21 | 21 | 21 | 22 | 22 |
| **BLAKE2s** | 256 | 2048 | PRF | 13 | 14 | 14 | 14 | 15 | 15 |
| **BLAKE3** | 256 | 2048 | PRF | 7 | 8 | 8 | 8 | 8 | 8 |
| **AES-CMAC** | 128 | 2048 | PRF | 27 | 31 | 31 | 28 | 33 | 33 |
| **SipHash-2-4** | 128 | 2048 | PRF | 35 | 39 | 39 | 39 | 42 | 43 |
| **ChaCha20** | 256 | 2048 | PRF | 2 | 7 | 11 | 2 | 6 | 11 |

## Intel Core i7-11700K 8C/16HT — New 48-bit Interlocked ITB vs Old ITB (Lock Soup + Lock Batch mode) — Delta

Interlocked ITB with the nonce widens from 128 bits to 512 bits (secure default), and the overlay moves from an opt-in 24-bit Lock Soup + Lock Batch mask (roughly 2^33 mask space per chunk group) to an always-on 48-bit Interlocked Barrier (~ 2^70 mask space per chunk group). Previous "Lock Soup + Lock Batch" mode on the same i7-11700K host is the fair comparison point — both sides carry an overlay derivation cost per chunk, and the ratio isolates the ~ 2^37 mask-space widening plus the 4× nonce widening.

Encrypt at 64 MB (MB/s per primitive per width; new / old ; **►** marks ratios ≥ 100%):

| Primitive          | 512-bit E 64 MB    | 1024-bit E 64 MB   | 2048-bit E 64 MB   |
|--------------------|:------------------:|:------------------:|:------------------:|
| **Areion-SoEM-256** | 279 / 198 (141%) ► | 207 / 179 (116%) ► | 138 / 141 (98%)    |
| **Areion-SoEM-512** | 293 / 226 (130%) ► | 235 / 198 (119%) ► | 167 / 162 (103%) ► |
| **BLAKE2b-256**     | 184 / 118 (156%) ► | 126 / 84 (150%) ►  | 75 / 54 (139%) ►   |
| **BLAKE2b-512**     | 189 / 174 (109%) ► | 130 / 134 (97%)    | 78 / 88 (89%)      |
| **BLAKE2s**         | 144 / 130 (111%) ► | 90 / 91 (99%)      | 52 / 59 (88%)      |
| **BLAKE3**          | 166 / 130 (128%) ► | 111 / 101 (110%) ► | 66 / 69 (96%)      |
| **AES-CMAC**        | 265 / 165 (161%) ► | 192 / 153 (125%) ► | 131 / 120 (109%) ► |
| **SipHash-2-4**     | 213 / 158 (135%) ► | 149 / 126 (118%) ► | 91 / 90 (101%) ►   |
| **ChaCha20**        | 198 / 110 (180%) ► | 134 / 86 (156%) ►  | 81 / 58 (140%) ►   |

Decrypt at 64 MB (MB/s per primitive per width; new / old ; **►** marks ratios ≥ 100%):

| Primitive          | 512-bit D 64 MB    | 1024-bit D 64 MB   | 2048-bit D 64 MB   |
|--------------------|:------------------:|:------------------:|:------------------:|
| **Areion-SoEM-256** | 400 / 248 (161%) ► | 269 / 215 (125%) ► | 164 / 165 (99%)    |
| **Areion-SoEM-512** | 442 / 280 (158%) ► | 319 / 240 (133%) ► | 204 / 187 (109%) ► |
| **BLAKE2b-256**     | 235 / 135 (174%) ► | 145 / 93 (156%) ►  | 82 / 56 (146%) ►   |
| **BLAKE2b-512**     | 246 / 211 (117%) ► | 150 / 152 (99%)    | 85 / 96 (89%)      |
| **BLAKE2s**         | 173 / 144 (120%) ► | 100 / 100 (100%) ► | 54 / 62 (87%)      |
| **BLAKE3**          | 211 / 148 (143%) ► | 128 / 110 (116%) ► | 72 / 74 (97%)      |
| **AES-CMAC**        | 380 / 211 (180%) ► | 252 / 177 (142%) ► | 152 / 137 (111%) ► |
| **SipHash-2-4**     | 284 / 187 (152%) ► | 176 / 143 (123%) ► | 101 / 98 (103%) ►  |
| **ChaCha20**        | 254 / 133 (191%) ► | 158 / 98 (161%) ►  | 92 / 64 (144%) ►   |

**Every shipped primitive now sits at or above the old ITB line at 512-bit width on both Encrypt and Decrypt**, and every shipped primitive on the 1024-bit line except BLAKE2b-512 stays at or above baseline (BLAKE2b-512 lands at 97-99%, essentially at baseline; BLAKE2s 1024-bit E sits at 99% and D at exactly baseline). The full ASM optimisation cycle (pack56 batched inversion + chain-kernel narrowing per family + ChaCha20 fused68 + interlock fill batching per family + bridge-free ZMM interlock kernel rewrite) delivers a fleet-wide throughput uplift that fully amortises the widened nonce envelope + always-on 48-bit interlock mask.

**ChaCha20 gains largest** (+80% at 512-bit E / +91% at 512-bit D / +56% at 1024-bit E / +61% at 1024-bit D) — the fused68 dual-compression kernel plus interlock fill batching remove the two dominant bottlenecks the pre-v0.3.0 line paid on this primitive; the interlock kernel rewrite compounds the win on the decrypt lane. **AES-CMAC** climbs to +61% at 512-bit E / +80% at 512-bit D and +25% / +42% at 1024-bit E/D — the AVX-512 VAES chain kernels amortise cleanly across the widened overlay + nonce cost. **BLAKE family** climbs from residual (65-90% pre-refresh) to above baseline at all 512-bit widths on all four variants, with BLAKE2b-256 sitting at +39-74% across all three widths thanks to combined narrowing + fill batching. **Areion-SoEM family** collects +30-58% on 512-bit Decrypt from the interlock kernel rewrite compounding on top of the pack56 batched inversion and the VAES-YMM 4-lane ChainAbsorb landings.

**2048-bit residual** is now split: **AES-CMAC**, **BLAKE2b-256**, **ChaCha20**, and **Areion-SoEM-512** all sit at or above baseline at 2048-bit width (+3-46% D); **SipHash-2-4** matches baseline (101-103%); **Areion-SoEM-256** and **BLAKE3** land at 96-99% (essentially at baseline); **BLAKE2b-512** and **BLAKE2s** are the sole cells 11-13% below baseline at that width. The 2048-bit line reflects the wider container's higher per-chunk overhead relative to the per-byte hash cost — the pattern is comfortably absorbed by the wider security envelope, and the mid-tier residual is confined to two primitives rather than fleet-wide.

**Further rows** for other µarchs (Zen 3+, ARM64 Graviton 4, etc.) are scheduled — this table is a first-pass baseline pending maintainer-assisted runs on additional hardware.
