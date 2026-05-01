# ITB Single Ouroboros Benchmark Results

Results below were collected at `ITB_NONCE_SIZE=128` on hosts with AVX-512 SIMD support. All nine PRF-grade hash primitives in the registry — Areion-SoEM-256, Areion-SoEM-512, SipHash-2-4, AES-CMAC, BLAKE2b-512, BLAKE2b-256, BLAKE2s, BLAKE3, ChaCha20 — dispatch through hand-written ZMM AVX-512 (and VAES + AVX-512 where applicable) chain-absorb ASM kernels at the per-pixel hash hot path; the C ABI and Python FFI stacks populate the batched arm automatically.

Reproduction:

```sh
ITB_NONCE_SIZE=128 go test -bench='BenchmarkExtSingle*' -benchtime=2s -count=1
ITB_NONCE_SIZE=128 ITB_LOCKSOUP=1 go test -bench='BenchmarkExtSingle*' -benchtime=2s -count=1
```

Pre-ZMM-optimisation reference numbers: [OLDBENCH.md](https://github.com/everanium/itb/blob/main/archive/OLDBENCH.md) — old benchmark results without full ASM AVX-512 ZMM kernel optimisations.

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 238 | 209 | 224 | 373 | 412 | 418 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 239 | 256 | 216 | 374 | 415 | 415 |
| **SipHash-2-4** | 128 | 512 | PRF | 199 | 215 | 176 | 291 | 317 | 323 |
| **AES-CMAC** | 128 | 512 | PRF | 227 | 198 | 210 | 350 | 391 | 392 |
| **BLAKE2b-512** | 512 | 512 | PRF | 190 | 197 | 168 | 267 | 279 | 212 |
| **BLAKE2b-256** | 256 | 512 | PRF | 151 | 155 | 156 | 191 | 197 | 200 |
| **BLAKE2s** | 256 | 512 | PRF | 132 | 149 | 117 | 205 | 217 | 217 |
| **BLAKE3** | 256 | 512 | PRF | 145 | 157 | 158 | 244 | 260 | 263 |
| **ChaCha20** | 256 | 512 | PRF | 168 | 175 | 115 | 224 | 231 | 233 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 207 | 220 | 219 | 299 | 321 | 324 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 201 | 215 | 224 | 313 | 338 | 340 |
| **SipHash-2-4** | 128 | 1024 | PRF | 158 | 166 | 166 | 211 | 215 | 217 |
| **AES-CMAC** | 128 | 1024 | PRF | 187 | 201 | 153 | 277 | 296 | 297 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 141 | 118 | 102 | 179 | 186 | 187 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 97 | 96 | 100 | 113 | 119 | 107 |
| **BLAKE2s** | 256 | 1024 | PRF | 109 | 111 | 93 | 129 | 132 | 131 |
| **BLAKE3** | 256 | 1024 | PRF | 129 | 134 | 127 | 161 | 163 | 164 |
| **ChaCha20** | 256 | 1024 | PRF | 117 | 120 | 121 | 137 | 143 | 141 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 165 | 169 | 173 | 221 | 228 | 228 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 172 | 182 | 182 | 235 | 245 | 243 |
| **SipHash-2-4** | 128 | 2048 | PRF | 111 | 111 | 112 | 129 | 129 | 134 |
| **AES-CMAC** | 128 | 2048 | PRF | 148 | 154 | 154 | 191 | 195 | 200 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 95 | 96 | 66 | 109 | 111 | 102 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 58 | 61 | 62 | 63 | 66 | 65 |
| **BLAKE2s** | 256 | 2048 | PRF | 66 | 66 | 67 | 72 | 74 | 75 |
| **BLAKE3** | 256 | 2048 | PRF | 82 | 84 | 85 | 92 | 95 | 95 |
| **ChaCha20** | 256 | 2048 | PRF | 71 | 74 | 73 | 80 | 81 | 82 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 300 | 310 | 333 | 586 | 708 | 771 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 293 | 302 | 318 | 619 | 688 | 760 |
| **SipHash-2-4** | 128 | 512 | PRF | 276 | 289 | 304 | 583 | 648 | 735 |
| **AES-CMAC** | 128 | 512 | PRF | 284 | 305 | 316 | 605 | 676 | 754 |
| **BLAKE2b-512** | 512 | 512 | PRF | 267 | 292 | 304 | 558 | 642 | 726 |
| **BLAKE2b-256** | 256 | 512 | PRF | 245 | 286 | 298 | 480 | 575 | 680 |
| **BLAKE2s** | 256 | 512 | PRF | 246 | 277 | 285 | 482 | 584 | 649 |
| **BLAKE3** | 256 | 512 | PRF | 257 | 283 | 297 | 520 | 609 | 673 |
| **ChaCha20** | 256 | 512 | PRF | 256 | 279 | 288 | 496 | 600 | 667 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 262 | 284 | 317 | 557 | 627 | 687 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 282 | 296 | 310 | 578 | 631 | 655 |
| **SipHash-2-4** | 128 | 1024 | PRF | 245 | 268 | 279 | 472 | 561 | 629 |
| **AES-CMAC** | 128 | 1024 | PRF | 258 | 285 | 285 | 516 | 622 | 683 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 239 | 272 | 282 | 466 | 529 | 634 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 215 | 240 | 267 | 380 | 445 | 545 |
| **BLAKE2s** | 256 | 1024 | PRF | 216 | 236 | 267 | 400 | 454 | 584 |
| **BLAKE3** | 256 | 1024 | PRF | 227 | 246 | 276 | 428 | 489 | 621 |
| **ChaCha20** | 256 | 1024 | PRF | 223 | 251 | 271 | 404 | 494 | 603 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 232 | 260 | 285 | 478 | 533 | 649 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 250 | 261 | 288 | 512 | 536 | 599 |
| **SipHash-2-4** | 128 | 2048 | PRF | 213 | 222 | 264 | 388 | 440 | 554 |
| **AES-CMAC** | 128 | 2048 | PRF | 221 | 253 | 278 | 427 | 487 | 603 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 204 | 229 | 258 | 371 | 411 | 532 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 175 | 204 | 232 | 284 | 352 | 427 |
| **BLAKE2s** | 256 | 2048 | PRF | 181 | 199 | 238 | 294 | 339 | 439 |
| **BLAKE3** | 256 | 2048 | PRF | 193 | 218 | 251 | 329 | 374 | 501 |
| **ChaCha20** | 256 | 2048 | PRF | 187 | 212 | 244 | 313 | 363 | 478 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup + Lock Soup mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 66 | 70 | 67 | 75 | 79 | 80 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 57 | 59 | 59 | 61 | 63 | 65 |
| **SipHash-2-4** | 128 | 512 | PRF | 78 | 82 | 70 | 90 | 93 | 96 |
| **AES-CMAC** | 128 | 512 | PRF | 82 | 84 | 86 | 97 | 100 | 104 |
| **BLAKE2b-512** | 512 | 512 | PRF | 50 | 55 | 54 | 58 | 60 | 60 |
| **BLAKE2b-256** | 256 | 512 | PRF | 53 | 53 | 53 | 56 | 60 | 62 |
| **BLAKE2s** | 256 | 512 | PRF | 52 | 55 | 55 | 58 | 59 | 61 |
| **BLAKE3** | 256 | 512 | PRF | 50 | 52 | 48 | 54 | 57 | 56 |
| **ChaCha20** | 256 | 512 | PRF | 30 | 48 | 55 | 36 | 58 | 61 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 63 | 63 | 65 | 69 | 75 | 77 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 56 | 57 | 58 | 60 | 63 | 64 |
| **SipHash-2-4** | 128 | 1024 | PRF | 70 | 73 | 73 | 81 | 81 | 85 |
| **AES-CMAC** | 128 | 1024 | PRF | 77 | 80 | 81 | 89 | 90 | 95 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 46 | 49 | 50 | 52 | 54 | 55 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 40 | 45 | 46 | 46 | 48 | 49 |
| **BLAKE2s** | 256 | 1024 | PRF | 46 | 46 | 47 | 50 | 52 | 52 |
| **BLAKE3** | 256 | 1024 | PRF | 43 | 45 | 48 | 49 | 49 | 50 |
| **ChaCha20** | 256 | 1024 | PRF | 28 | 45 | 48 | 33 | 50 | 53 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 59 | 61 | 60 | 65 | 67 | 69 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 51 | 55 | 54 | 56 | 59 | 59 |
| **SipHash-2-4** | 128 | 2048 | PRF | 58 | 59 | 59 | 65 | 65 | 68 |
| **AES-CMAC** | 128 | 2048 | PRF | 68 | 71 | 71 | 77 | 80 | 79 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 40 | 42 | 43 | 44 | 46 | 47 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 32 | 35 | 35 | 35 | 37 | 37 |
| **BLAKE2s** | 256 | 2048 | PRF | 34 | 36 | 37 | 38 | 39 | 39 |
| **BLAKE3** | 256 | 2048 | PRF | 36 | 39 | 39 | 39 | 42 | 42 |
| **ChaCha20** | 256 | 2048 | PRF | 25 | 37 | 39 | 28 | 40 | 41 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Bit Soup + Lock Soup mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 157 | 188 | 230 | 255 | 320 | 424 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 137 | 172 | 215 | 233 | 285 | 357 |
| **SipHash-2-4** | 128 | 512 | PRF | 172 | 197 | 233 | 285 | 379 | 417 |
| **AES-CMAC** | 128 | 512 | PRF | 153 | 200 | 237 | 288 | 385 | 451 |
| **BLAKE2b-512** | 512 | 512 | PRF | 141 | 167 | 192 | 218 | 282 | 256 |
| **BLAKE2b-256** | 256 | 512 | PRF | 136 | 178 | 181 | 220 | 277 | 311 |
| **BLAKE2s** | 256 | 512 | PRF | 145 | 161 | 183 | 228 | 281 | 328 |
| **BLAKE3** | 256 | 512 | PRF | 127 | 160 | 173 | 190 | 255 | 244 |
| **ChaCha20** | 256 | 512 | PRF | 34 | 73 | 99 | 40 | 96 | 146 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 155 | 176 | 224 | 254 | 315 | 383 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 149 | 175 | 208 | 231 | 284 | 342 |
| **SipHash-2-4** | 128 | 1024 | PRF | 168 | 192 | 218 | 269 | 324 | 419 |
| **AES-CMAC** | 128 | 1024 | PRF | 166 | 201 | 231 | 277 | 358 | 441 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 135 | 163 | 193 | 216 | 252 | 320 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 126 | 158 | 180 | 204 | 244 | 288 |
| **BLAKE2s** | 256 | 1024 | PRF | 137 | 154 | 173 | 215 | 238 | 324 |
| **BLAKE3** | 256 | 1024 | PRF | 121 | 151 | 171 | 180 | 227 | 269 |
| **ChaCha20** | 256 | 1024 | PRF | 34 | 71 | 99 | 39 | 92 | 146 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 147 | 174 | 212 | 237 | 288 | 352 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 142 | 166 | 209 | 230 | 270 | 325 |
| **SipHash-2-4** | 128 | 2048 | PRF | 154 | 164 | 220 | 244 | 282 | 368 |
| **AES-CMAC** | 128 | 2048 | PRF | 159 | 179 | 235 | 257 | 299 | 372 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 126 | 142 | 167 | 196 | 225 | 299 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 117 | 134 | 161 | 176 | 191 | 248 |
| **BLAKE2s** | 256 | 2048 | PRF | 120 | 140 | 177 | 186 | 235 | 269 |
| **BLAKE3** | 256 | 2048 | PRF | 116 | 132 | 157 | 167 | 210 | 251 |
| **ChaCha20** | 256 | 2048 | PRF | 33 | 67 | 94 | 38 | 88 | 134 |
