# ITB Triple Ouroboros Benchmark Results

Results below were collected at `ITB_NONCE_SIZE=128` on hosts with AVX-512 SIMD support. All nine PRF-grade hash primitives in the registry — Areion-SoEM-256, Areion-SoEM-512, SipHash-2-4, AES-CMAC, BLAKE2b-512, BLAKE2b-256, BLAKE2s, BLAKE3, ChaCha20 — dispatch through hand-written ZMM AVX-512 (and VAES + AVX-512 where applicable) chain-absorb ASM kernels at the per-pixel hash hot path; the C ABI and Python FFI stacks populate the batched arm automatically.

Lock Soup derives a fresh PRF-keyed bit-permutation mask per chunk, so per-byte primitive call rate is ~10× higher than the plain / Bit-Soup-only paths and the hash hot path becomes throughput-bound. AMD EPYC 9655P closes this gap on every primitive — Zen 5's 192 HT + full-width 512-bit ALU + absent AVX-512 frequency throttle absorb the higher call rate better than Rocket Lake's narrower issue width.

Reproduction:

```sh
ITB_NONCE_SIZE=128 go test -bench='BenchmarkExtTriple*' -benchtime=2s -count=1
ITB_NONCE_SIZE=128 ITB_BITSOUP=1 go test -bench='BenchmarkExtTriple*' -benchtime=2s -count=1
ITB_NONCE_SIZE=128 ITB_LOCKSOUP=1 go test -bench='BenchmarkExtTriple*' -benchtime=2s -count=1
```

Pre-ZMM-optimisation reference numbers: [OLDBENCH3.md](https://github.com/everanium/itb/blob/main/archive/OLDBENCH3.md) — old benchmark results without full ASM AVX-512 ZMM kernel optimisations.

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 328 | 375 | 377 | 400 | 489 | 495 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 325 | 381 | 381 | 396 | 484 | 489 |
| **SipHash-2-4** | 128 | 512 | PRF | 259 | 285 | 299 | 314 | 354 | 356 |
| **AES-CMAC** | 128 | 512 | PRF | 309 | 352 | 356 | 384 | 460 | 455 |
| **BLAKE2b-512** | 512 | 512 | PRF | 242 | 270 | 270 | 281 | 320 | 325 |
| **BLAKE2b-256** | 256 | 512 | PRF | 177 | 194 | 197 | 199 | 220 | 221 |
| **BLAKE2s** | 256 | 512 | PRF | 189 | 202 | 205 | 215 | 233 | 236 |
| **BLAKE3** | 256 | 512 | PRF | 224 | 242 | 246 | 258 | 286 | 286 |
| **ChaCha20** | 256 | 512 | PRF | 204 | 219 | 221 | 232 | 251 | 256 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 267 | 308 | 301 | 309 | 370 | 375 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 272 | 312 | 251 | 319 | 377 | 385 |
| **SipHash-2-4** | 128 | 1024 | PRF | 193 | 206 | 206 | 211 | 230 | 234 |
| **AES-CMAC** | 128 | 1024 | PRF | 247 | 275 | 276 | 293 | 322 | 312 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 168 | 180 | 182 | 184 | 202 | 204 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 112 | 117 | 120 | 118 | 124 | 127 |
| **BLAKE2s** | 256 | 1024 | PRF | 121 | 127 | 129 | 129 | 137 | 139 |
| **BLAKE3** | 256 | 1024 | PRF | 148 | 157 | 158 | 163 | 167 | 177 |
| **ChaCha20** | 256 | 1024 | PRF | 131 | 138 | 139 | 140 | 149 | 151 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 197 | 216 | 217 | 221 | 248 | 251 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 207 | 227 | 232 | 234 | 260 | 266 |
| **SipHash-2-4** | 128 | 2048 | PRF | 120 | 126 | 127 | 129 | 135 | 138 |
| **AES-CMAC** | 128 | 2048 | PRF | 161 | 178 | 181 | 190 | 208 | 210 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 103 | 108 | 110 | 110 | 116 | 116 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 63 | 66 | 66 | 65 | 68 | 69 |
| **BLAKE2s** | 256 | 2048 | PRF | 69 | 72 | 72 | 72 | 75 | 75 |
| **BLAKE3** | 256 | 2048 | PRF | 89 | 92 | 94 | 93 | 97 | 98 |
| **ChaCha20** | 256 | 2048 | PRF | 75 | 79 | 80 | 79 | 82 | 83 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 514 | 447 | 588 | 601 | 782 | 981 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 498 | 438 | 539 | 583 | 764 | 940 |
| **SipHash-2-4** | 128 | 512 | PRF | 449 | 454 | 540 | 549 | 743 | 871 |
| **AES-CMAC** | 128 | 512 | PRF | 471 | 485 | 576 | 579 | 818 | 975 |
| **BLAKE2b-512** | 512 | 512 | PRF | 419 | 397 | 544 | 541 | 684 | 946 |
| **BLAKE2b-256** | 256 | 512 | PRF | 339 | 422 | 497 | 483 | 661 | 865 |
| **BLAKE2s** | 256 | 512 | PRF | 356 | 406 | 526 | 506 | 658 | 854 |
| **BLAKE3** | 256 | 512 | PRF | 399 | 410 | 557 | 522 | 698 | 877 |
| **ChaCha20** | 256 | 512 | PRF | 357 | 444 | 503 | 519 | 673 | 921 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 431 | 443 | 561 | 554 | 686 | 861 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 461 | 408 | 539 | 546 | 662 | 856 |
| **SipHash-2-4** | 128 | 1024 | PRF | 365 | 394 | 485 | 490 | 641 | 825 |
| **AES-CMAC** | 128 | 1024 | PRF | 413 | 454 | 530 | 480 | 705 | 881 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 339 | 365 | 471 | 483 | 602 | 825 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 285 | 326 | 445 | 391 | 484 | 671 |
| **BLAKE2s** | 256 | 1024 | PRF | 294 | 345 | 448 | 411 | 530 | 699 |
| **BLAKE3** | 256 | 1024 | PRF | 328 | 378 | 473 | 451 | 578 | 768 |
| **ChaCha20** | 256 | 1024 | PRF | 318 | 362 | 466 | 426 | 558 | 722 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 340 | 376 | 491 | 490 | 633 | 839 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 355 | 359 | 504 | 512 | 617 | 738 |
| **SipHash-2-4** | 128 | 2048 | PRF | 306 | 348 | 452 | 401 | 495 | 667 |
| **AES-CMAC** | 128 | 2048 | PRF | 345 | 389 | 488 | 451 | 625 | 762 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 269 | 328 | 422 | 378 | 497 | 650 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 218 | 287 | 360 | 293 | 371 | 484 |
| **BLAKE2s** | 256 | 2048 | PRF | 225 | 286 | 374 | 312 | 420 | 529 |
| **BLAKE3** | 256 | 2048 | PRF | 257 | 319 | 413 | 350 | 434 | 599 |
| **ChaCha20** | 256 | 2048 | PRF | 241 | 316 | 399 | 332 | 413 | 582 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 294 | 344 | 347 | 380 | 473 | 469 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 301 | 337 | 354 | 373 | 469 | 474 |
| **SipHash-2-4** | 128 | 512 | PRF | 243 | 290 | 284 | 295 | 347 | 334 |
| **AES-CMAC** | 128 | 512 | PRF | 281 | 336 | 346 | 355 | 446 | 450 |
| **BLAKE2b-512** | 512 | 512 | PRF | 227 | 256 | 264 | 267 | 315 | 319 |
| **BLAKE2b-256** | 256 | 512 | PRF | 167 | 191 | 191 | 194 | 215 | 217 |
| **BLAKE2s** | 256 | 512 | PRF | 180 | 201 | 200 | 204 | 228 | 233 |
| **BLAKE3** | 256 | 512 | PRF | 212 | 232 | 235 | 243 | 281 | 275 |
| **ChaCha20** | 256 | 512 | PRF | 192 | 199 | 202 | 208 | 237 | 246 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 248 | 297 | 289 | 301 | 353 | 360 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 257 | 299 | 292 | 313 | 362 | 364 |
| **SipHash-2-4** | 128 | 1024 | PRF | 172 | 180 | 183 | 199 | 223 | 224 |
| **AES-CMAC** | 128 | 1024 | PRF | 229 | 254 | 264 | 276 | 318 | 324 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 160 | 174 | 177 | 180 | 199 | 200 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 108 | 115 | 117 | 115 | 125 | 126 |
| **BLAKE2s** | 256 | 1024 | PRF | 117 | 121 | 124 | 124 | 134 | 136 |
| **BLAKE3** | 256 | 1024 | PRF | 141 | 151 | 154 | 154 | 168 | 173 |
| **ChaCha20** | 256 | 1024 | PRF | 122 | 130 | 129 | 134 | 146 | 147 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 190 | 206 | 213 | 214 | 242 | 245 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 202 | 218 | 220 | 229 | 247 | 254 |
| **SipHash-2-4** | 128 | 2048 | PRF | 112 | 124 | 121 | 123 | 131 | 134 |
| **AES-CMAC** | 128 | 2048 | PRF | 167 | 179 | 185 | 186 | 209 | 207 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 100 | 103 | 108 | 107 | 113 | 116 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 61 | 64 | 65 | 64 | 67 | 68 |
| **BLAKE2s** | 256 | 2048 | PRF | 68 | 70 | 72 | 71 | 74 | 75 |
| **BLAKE3** | 256 | 2048 | PRF | 85 | 88 | 92 | 89 | 95 | 97 |
| **ChaCha20** | 256 | 2048 | PRF | 74 | 78 | 78 | 77 | 80 | 82 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 483 | 482 | 552 | 848 | 953 | 1045 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 459 | 459 | 518 | 845 | 951 | 1056 |
| **SipHash-2-4** | 128 | 512 | PRF | 450 | 439 | 532 | 756 | 886 | 1039 |
| **AES-CMAC** | 128 | 512 | PRF | 455 | 451 | 525 | 773 | 993 | 1112 |
| **BLAKE2b-512** | 512 | 512 | PRF | 444 | 424 | 489 | 698 | 806 | 995 |
| **BLAKE2b-256** | 256 | 512 | PRF | 374 | 377 | 465 | 591 | 775 | 1005 |
| **BLAKE2s** | 256 | 512 | PRF | 389 | 405 | 482 | 625 | 782 | 956 |
| **BLAKE3** | 256 | 512 | PRF | 412 | 428 | 518 | 722 | 810 | 1011 |
| **ChaCha20** | 256 | 512 | PRF | 418 | 401 | 491 | 668 | 817 | 1004 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 441 | 418 | 519 | 746 | 803 | 1033 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 439 | 407 | 521 | 764 | 830 | 1035 |
| **SipHash-2-4** | 128 | 1024 | PRF | 404 | 379 | 445 | 623 | 771 | 890 |
| **AES-CMAC** | 128 | 1024 | PRF | 424 | 398 | 517 | 673 | 834 | 1057 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 391 | 372 | 454 | 569 | 734 | 885 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 324 | 329 | 405 | 457 | 587 | 796 |
| **BLAKE2s** | 256 | 1024 | PRF | 345 | 326 | 420 | 484 | 629 | 816 |
| **BLAKE3** | 256 | 1024 | PRF | 375 | 357 | 442 | 532 | 678 | 846 |
| **ChaCha20** | 256 | 1024 | PRF | 361 | 338 | 425 | 514 | 656 | 810 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 387 | 383 | 455 | 589 | 741 | 931 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 424 | 356 | 464 | 634 | 752 | 887 |
| **SipHash-2-4** | 128 | 2048 | PRF | 328 | 317 | 402 | 472 | 552 | 773 |
| **AES-CMAC** | 128 | 2048 | PRF | 367 | 349 | 420 | 561 | 679 | 840 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 314 | 309 | 403 | 434 | 534 | 751 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 256 | 277 | 328 | 329 | 436 | 550 |
| **BLAKE2s** | 256 | 2048 | PRF | 267 | 299 | 356 | 342 | 421 | 585 |
| **BLAKE3** | 256 | 2048 | PRF | 295 | 297 | 393 | 401 | 476 | 688 |
| **ChaCha20** | 256 | 2048 | PRF | 273 | 298 | 358 | 377 | 487 | 625 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup + Lock Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 65 | 69 | 73 | 71 | 76 | 76 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 57 | 59 | 60 | 59 | 63 | 63 |
| **SipHash-2-4** | 128 | 512 | PRF | 77 | 81 | 86 | 86 | 88 | 92 |
| **AES-CMAC** | 128 | 512 | PRF | 83 | 88 | 90 | 88 | 95 | 98 |
| **BLAKE2b-512** | 512 | 512 | PRF | 54 | 56 | 57 | 56 | 59 | 60 |
| **BLAKE2b-256** | 256 | 512 | PRF | 52 | 55 | 56 | 56 | 59 | 60 |
| **BLAKE2s** | 256 | 512 | PRF | 52 | 55 | 56 | 56 | 57 | 60 |
| **BLAKE3** | 256 | 512 | PRF | 44 | 47 | 48 | 45 | 49 | 50 |
| **ChaCha20** | 256 | 512 | PRF | 32 | 55 | 59 | 37 | 59 | 63 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 64 | 69 | 70 | 68 | 73 | 73 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 56 | 58 | 60 | 57 | 61 | 61 |
| **SipHash-2-4** | 128 | 1024 | PRF | 69 | 74 | 77 | 74 | 79 | 82 |
| **AES-CMAC** | 128 | 1024 | PRF | 78 | 83 | 86 | 85 | 91 | 92 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 50 | 51 | 51 | 51 | 53 | 53 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 45 | 47 | 47 | 47 | 48 | 50 |
| **BLAKE2s** | 256 | 1024 | PRF | 44 | 48 | 47 | 42 | 49 | 49 |
| **BLAKE3** | 256 | 1024 | PRF | 40 | 42 | 42 | 39 | 44 | 44 |
| **ChaCha20** | 256 | 1024 | PRF | 30 | 48 | 51 | 33 | 53 | 54 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 60 | 62 | 63 | 62 | 66 | 67 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 53 | 55 | 56 | 55 | 57 | 58 |
| **SipHash-2-4** | 128 | 2048 | PRF | 58 | 61 | 62 | 62 | 65 | 63 |
| **AES-CMAC** | 128 | 2048 | PRF | 67 | 73 | 75 | 75 | 76 | 79 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 41 | 43 | 43 | 43 | 43 | 44 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 34 | 35 | 35 | 34 | 37 | 35 |
| **BLAKE2s** | 256 | 2048 | PRF | 34 | 36 | 36 | 32 | 36 | 37 |
| **BLAKE3** | 256 | 2048 | PRF | 34 | 37 | 37 | 37 | 39 | 40 |
| **ChaCha20** | 256 | 2048 | PRF | 26 | 38 | 40 | 29 | 41 | 41 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Bit Soup + Lock Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 208 | 303 | 329 | 320 | 392 | 503 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 184 | 224 | 302 | 247 | 332 | 405 |
| **SipHash-2-4** | 128 | 512 | PRF | 224 | 260 | 371 | 333 | 456 | 557 |
| **AES-CMAC** | 128 | 512 | PRF | 201 | 322 | 348 | 347 | 478 | 566 |
| **BLAKE2b-512** | 512 | 512 | PRF | 157 | 229 | 248 | 223 | 306 | 391 |
| **BLAKE2b-256** | 256 | 512 | PRF | 170 | 215 | 254 | 219 | 314 | 394 |
| **BLAKE2s** | 256 | 512 | PRF | 167 | 202 | 241 | 230 | 315 | 388 |
| **BLAKE3** | 256 | 512 | PRF | 157 | 204 | 232 | 222 | 293 | 311 |
| **ChaCha20** | 256 | 512 | PRF | 37 | 87 | 121 | 42 | 104 | 160 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 186 | 237 | 328 | 286 | 376 | 465 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 167 | 244 | 276 | 246 | 358 | 396 |
| **SipHash-2-4** | 128 | 1024 | PRF | 211 | 270 | 333 | 307 | 396 | 518 |
| **AES-CMAC** | 128 | 1024 | PRF | 215 | 279 | 327 | 320 | 453 | 537 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 164 | 197 | 216 | 235 | 306 | 363 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 164 | 200 | 224 | 214 | 263 | 309 |
| **BLAKE2s** | 256 | 1024 | PRF | 170 | 199 | 232 | 223 | 290 | 340 |
| **BLAKE3** | 256 | 1024 | PRF | 143 | 179 | 198 | 198 | 227 | 297 |
| **ChaCha20** | 256 | 1024 | PRF | 37 | 85 | 118 | 41 | 99 | 155 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 189 | 252 | 299 | 278 | 390 | 434 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 157 | 213 | 287 | 239 | 322 | 410 |
| **SipHash-2-4** | 128 | 2048 | PRF | 201 | 255 | 308 | 290 | 392 | 444 |
| **AES-CMAC** | 128 | 2048 | PRF | 207 | 279 | 329 | 308 | 429 | 487 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 160 | 176 | 201 | 212 | 266 | 312 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 149 | 182 | 210 | 186 | 223 | 278 |
| **BLAKE2s** | 256 | 2048 | PRF | 156 | 205 | 214 | 204 | 268 | 299 |
| **BLAKE3** | 256 | 2048 | PRF | 135 | 192 | 195 | 183 | 250 | 278 |
| **ChaCha20** | 256 | 2048 | PRF | 35 | 80 | 112 | 38 | 96 | 133 |
