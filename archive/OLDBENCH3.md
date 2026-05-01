# ITB Triple Ouroboros Benchmark Results

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 194 | 210 | 199 | 219 | 237 | 239 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 190 | 202 | 195 | 211 | 228 | 227 |
| **SipHash-2-4** | 128 | 512 | PRF | 153 | 207 | 207 | 224 | 240 | 242 |
| **AES-CMAC** | 128 | 512 | PRF | 148 | 192 | 183 | 152 | 192 | 212 |
| **BLAKE2b-512** | 512 | 512 | PRF | 112 | 137 | 133 | 145 | 154 | 154 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 83 | 96 | 95 | 102 | 106 | 104 |
| **BLAKE3** | 256 | 512 | PRF | 54 | 63 | 62 | 62 | 64 | 63 |
| **ChaCha20** | 256 | 512 | PRF | 83 | 95 | 97 | 93 | 103 | 102 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 124 | 128 | 127 | 137 | 141 | 142 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 123 | 126 | 128 | 132 | 138 | 140 |
| **SipHash-2-4** | 128 | 1024 | PRF | 102 | 133 | 130 | 141 | 146 | 149 |
| **AES-CMAC** | 128 | 1024 | PRF | 91 | 111 | 109 | 112 | 121 | 120 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 71 | 80 | 82 | 76 | 82 | 83 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 51 | 54 | 54 | 55 | 56 | 56 |
| **BLAKE3** | 256 | 1024 | PRF | 31 | 32 | 32 | 33 | 34 | 33 |
| **ChaCha20** | 256 | 1024 | PRF | 52 | 54 | 54 | 54 | 57 | 57 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 75 | 77 | 74 | 79 | 81 | 81 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 73 | 75 | 75 | 76 | 80 | 80 |
| **SipHash-2-4** | 128 | 2048 | PRF | 66 | 77 | 76 | 75 | 81 | 81 |
| **AES-CMAC** | 128 | 2048 | PRF | 55 | 63 | 64 | 64 | 67 | 66 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 43 | 45 | 45 | 45 | 46 | 46 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 27 | 29 | 29 | 29 | 30 | 30 |
| **BLAKE3** | 256 | 2048 | PRF | 17 | 17 | 17 | 16 | 17 | 16 |
| **ChaCha20** | 256 | 2048 | PRF | 28 | 29 | 29 | 28 | 30 | 30 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 326 | 371 | 497 | 479 | 622 | 811 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 336 | 354 | 544 | 485 | 615 | 813 |
| **SipHash-2-4** | 128 | 512 | PRF | 326 | 446 | 525 | 477 | 674 | 848 |
| **AES-CMAC** | 128 | 512 | PRF | 276 | 397 | 482 | 430 | 583 | 736 |
| **BLAKE2b-512** | 512 | 512 | PRF | 227 | 371 | 423 | 326 | 483 | 609 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 180 | 296 | 358 | 290 | 359 | 468 |
| **BLAKE3** | 256 | 512 | PRF | 139 | 227 | 258 | 201 | 274 | 335 |
| **ChaCha20** | 256 | 512 | PRF | 222 | 337 | 434 | 334 | 460 | 610 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 268 | 325 | 390 | 378 | 486 | 624 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 266 | 323 | 401 | 385 | 492 | 628 |
| **SipHash-2-4** | 128 | 1024 | PRF | 265 | 429 | 476 | 405 | 588 | 741 |
| **AES-CMAC** | 128 | 1024 | PRF | 227 | 328 | 415 | 337 | 423 | 555 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 173 | 280 | 322 | 224 | 352 | 449 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 128 | 225 | 238 | 169 | 237 | 341 |
| **BLAKE3** | 256 | 1024 | PRF | 97 | 137 | 167 | 117 | 173 | 179 |
| **ChaCha20** | 256 | 1024 | PRF | 177 | 276 | 322 | 241 | 347 | 414 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 214 | 303 | 369 | 293 | 406 | 511 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 212 | 277 | 375 | 297 | 374 | 529 |
| **SipHash-2-4** | 128 | 2048 | PRF | 219 | 352 | 395 | 303 | 451 | 572 |
| **AES-CMAC** | 128 | 2048 | PRF | 175 | 251 | 300 | 232 | 334 | 409 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 118 | 208 | 209 | 162 | 226 | 213 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 97 | 141 | 160 | 118 | 164 | 175 |
| **BLAKE3** | 256 | 2048 | PRF | 59 | 81 | 91 | 72 | 105 | 112 |
| **ChaCha20** | 256 | 2048 | PRF | 134 | 200 | 223 | 160 | 213 | 261 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 186 | 193 | 196 | 206 | 237 | 231 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 173 | 184 | 184 | 199 | 223 | 229 |
| **SipHash-2-4** | 128 | 512 | PRF | 149 | 188 | 196 | 214 | 243 | 242 |
| **AES-CMAC** | 128 | 512 | PRF | 144 | 172 | 178 | 186 | 208 | 205 |
| **BLAKE2b-512** | 512 | 512 | PRF | 108 | 131 | 135 | 141 | 149 | 153 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 80 | 94 | 92 | 99 | 102 | 104 |
| **BLAKE3** | 256 | 512 | PRF | 53 | 65 | 66 | 61 | 64 | 66 |
| **ChaCha20** | 256 | 512 | PRF | 80 | 94 | 93 | 96 | 103 | 105 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 122 | 127 | 125 | 130 | 140 | 143 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 120 | 123 | 123 | 130 | 140 | 142 |
| **SipHash-2-4** | 128 | 1024 | PRF | 105 | 123 | 125 | 132 | 145 | 148 |
| **AES-CMAC** | 128 | 1024 | PRF | 91 | 108 | 110 | 111 | 117 | 120 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 69 | 79 | 80 | 84 | 88 | 88 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 49 | 54 | 54 | 52 | 57 | 59 |
| **BLAKE3** | 256 | 1024 | PRF | 29 | 33 | 33 | 32 | 33 | 34 |
| **ChaCha20** | 256 | 1024 | PRF | 48 | 54 | 55 | 54 | 57 | 57 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 70 | 73 | 74 | 75 | 80 | 81 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 70 | 75 | 75 | 75 | 79 | 78 |
| **SipHash-2-4** | 128 | 2048 | PRF | 66 | 75 | 75 | 75 | 82 | 83 |
| **AES-CMAC** | 128 | 2048 | PRF | 55 | 62 | 62 | 64 | 67 | 66 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 40 | 43 | 44 | 44 | 44 | 46 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 27 | 29 | 29 | 29 | 29 | 31 |
| **BLAKE3** | 256 | 2048 | PRF | 16 | 17 | 17 | 16 | 17 | 17 |
| **ChaCha20** | 256 | 2048 | PRF | 27 | 29 | 29 | 28 | 30 | 30 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 375 | 371 | 418 | 597 | 746 | 920 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 403 | 363 | 487 | 599 | 783 | 945 |
| **SipHash-2-4** | 128 | 512 | PRF | 312 | 441 | 540 | 534 | 841 | 1014 |
| **AES-CMAC** | 128 | 512 | PRF | 275 | 361 | 459 | 465 | 642 | 823 |
| **BLAKE2b-512** | 512 | 512 | PRF | 204 | 330 | 407 | 326 | 562 | 670 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 174 | 259 | 346 | 260 | 444 | 532 |
| **BLAKE3** | 256 | 512 | PRF | 133 | 201 | 250 | 216 | 289 | 301 |
| **ChaCha20** | 256 | 512 | PRF | 228 | 311 | 392 | 349 | 569 | 708 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 310 | 328 | 432 | 452 | 578 | 776 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 340 | 321 | 425 | 445 | 577 | 751 |
| **SipHash-2-4** | 128 | 1024 | PRF | 267 | 390 | 470 | 462 | 659 | 871 |
| **AES-CMAC** | 128 | 1024 | PRF | 224 | 313 | 385 | 380 | 502 | 613 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 161 | 270 | 307 | 296 | 362 | 434 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 131 | 210 | 233 | 181 | 259 | 262 |
| **BLAKE3** | 256 | 1024 | PRF | 95 | 135 | 162 | 119 | 160 | 176 |
| **ChaCha20** | 256 | 1024 | PRF | 182 | 264 | 304 | 250 | 394 | 458 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 251 | 261 | 344 | 327 | 411 | 566 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 256 | 269 | 365 | 331 | 403 | 581 |
| **SipHash-2-4** | 128 | 2048 | PRF | 222 | 323 | 367 | 343 | 486 | 629 |
| **AES-CMAC** | 128 | 2048 | PRF | 173 | 238 | 304 | 252 | 329 | 425 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 123 | 165 | 217 | 190 | 234 | 243 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 88 | 137 | 136 | 103 | 166 | 134 |
| **BLAKE3** | 256 | 2048 | PRF | 58 | 82 | 87 | 70 | 94 | 90 |
| **ChaCha20** | 256 | 2048 | PRF | 134 | 184 | 212 | 177 | 256 | 276 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup + Lock Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 51 | 57 | 58 | 53 | 60 | 59 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 46 | 50 | 50 | 46 | 53 | 51 |
| **SipHash-2-4** | 128 | 512 | PRF | 55 | 72 | 69 | 68 | 75 | 77 |
| **AES-CMAC** | 128 | 512 | PRF | 75 | 98 | 95 | 87 | 109 | 109 |
| **BLAKE2b-512** | 512 | 512 | PRF | 38 | 46 | 45 | 45 | 49 | 50 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 35 | 42 | 41 | 40 | 43 | 44 |
| **BLAKE3** | 256 | 512 | PRF | 27 | 31 | 31 | 30 | 32 | 32 |
| **ChaCha20** | 256 | 512 | PRF | 36 | 42 | 42 | 39 | 43 | 45 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 45 | 49 | 50 | 46 | 52 | 52 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 41 | 44 | 44 | 41 | 46 | 46 |
| **SipHash-2-4** | 128 | 1024 | PRF | 48 | 61 | 57 | 56 | 63 | 64 |
| **AES-CMAC** | 128 | 1024 | PRF | 58 | 69 | 71 | 69 | 74 | 83 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 32 | 37 | 38 | 35 | 39 | 40 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 27 | 31 | 31 | 30 | 33 | 32 |
| **BLAKE3** | 256 | 1024 | PRF | 19 | 21 | 21 | 21 | 22 | 22 |
| **ChaCha20** | 256 | 1024 | PRF | 28 | 32 | 32 | 30 | 33 | 33 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 36 | 39 | 39 | 37 | 40 | 41 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 33 | 36 | 35 | 34 | 37 | 39 |
| **SipHash-2-4** | 128 | 2048 | PRF | 37 | 44 | 42 | 42 | 48 | 47 |
| **AES-CMAC** | 128 | 2048 | PRF | 41 | 49 | 48 | 46 | 50 | 53 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 24 | 27 | 27 | 26 | 28 | 28 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 19 | 21 | 21 | 20 | 22 | 21 |
| **BLAKE3** | 256 | 2048 | PRF | 13 | 13 | 13 | 13 | 13 | 13 |
| **ChaCha20** | 256 | 2048 | PRF | 19 | 21 | 21 | 20 | 21 | 22 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Bit Soup + Lock Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 190 | 265 | 295 | 280 | 388 | 417 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 175 | 236 | 272 | 236 | 347 | 399 |
| **SipHash-2-4** | 128 | 512 | PRF | 166 | 307 | 334 | 325 | 433 | 517 |
| **AES-CMAC** | 128 | 512 | PRF | 188 | 296 | 342 | 346 | 514 | 600 |
| **BLAKE2b-512** | 512 | 512 | PRF | 101 | 186 | 219 | 207 | 255 | 264 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 87 | 177 | 192 | 194 | 209 | 239 |
| **BLAKE3** | 256 | 512 | PRF | 77 | 128 | 130 | 141 | 182 | 200 |
| **ChaCha20** | 256 | 512 | PRF | 132 | 214 | 257 | 225 | 335 | 359 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 186 | 227 | 291 | 246 | 310 | 419 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 169 | 208 | 276 | 220 | 284 | 366 |
| **SipHash-2-4** | 128 | 1024 | PRF | 155 | 277 | 306 | 286 | 411 | 468 |
| **AES-CMAC** | 128 | 1024 | PRF | 166 | 260 | 306 | 261 | 414 | 456 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 93 | 171 | 188 | 172 | 244 | 236 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 73 | 132 | 144 | 147 | 158 | 183 |
| **BLAKE3** | 256 | 1024 | PRF | 64 | 100 | 102 | 101 | 118 | 127 |
| **ChaCha20** | 256 | 1024 | PRF | 119 | 201 | 227 | 189 | 254 | 291 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 162 | 206 | 251 | 216 | 264 | 329 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 155 | 197 | 233 | 200 | 247 | 306 |
| **SipHash-2-4** | 128 | 2048 | PRF | 149 | 251 | 277 | 242 | 312 | 416 |
| **AES-CMAC** | 128 | 2048 | PRF | 136 | 203 | 256 | 208 | 287 | 372 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 71 | 135 | 133 | 135 | 150 | 178 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 63 | 98 | 103 | 93 | 105 | 140 |
| **BLAKE3** | 256 | 2048 | PRF | 48 | 66 | 79 | 61 | 79 | 90 |
| **ChaCha20** | 256 | 2048 | PRF | 95 | 147 | 169 | 134 | 192 | 202 |
