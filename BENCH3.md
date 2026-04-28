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
| **ChaCha20** | 256 | 512 | PRF | 83 | 95 | 97 | 93 | 103 | 102 |
| **BLAKE2s** | 256 | 512 | PRF | 83 | 96 | 95 | 102 | 106 | 104 |
| **BLAKE3** | 256 | 512 | PRF | 54 | 63 | 62 | 62 | 64 | 63 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 124 | 128 | 127 | 137 | 141 | 142 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 123 | 126 | 128 | 132 | 138 | 140 |
| **SipHash-2-4** | 128 | 1024 | PRF | 102 | 133 | 130 | 141 | 146 | 149 |
| **AES-CMAC** | 128 | 1024 | PRF | 91 | 111 | 109 | 112 | 121 | 120 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 71 | 80 | 82 | 76 | 82 | 83 |
| **ChaCha20** | 256 | 1024 | PRF | 52 | 54 | 54 | 54 | 57 | 57 |
| **BLAKE2s** | 256 | 1024 | PRF | 51 | 54 | 54 | 55 | 56 | 56 |
| **BLAKE3** | 256 | 1024 | PRF | 31 | 32 | 32 | 33 | 34 | 33 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 75 | 77 | 74 | 79 | 81 | 81 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 73 | 75 | 75 | 76 | 80 | 80 |
| **SipHash-2-4** | 128 | 2048 | PRF | 66 | 77 | 76 | 75 | 81 | 81 |
| **AES-CMAC** | 128 | 2048 | PRF | 55 | 63 | 64 | 64 | 67 | 66 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 43 | 45 | 45 | 45 | 46 | 46 |
| **ChaCha20** | 256 | 2048 | PRF | 28 | 29 | 29 | 28 | 30 | 30 |
| **BLAKE2s** | 256 | 2048 | PRF | 27 | 29 | 29 | 29 | 30 | 30 |
| **BLAKE3** | 256 | 2048 | PRF | 17 | 17 | 17 | 16 | 17 | 16 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 326 | 371 | 497 | 479 | 622 | 811 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 336 | 354 | 544 | 485 | 615 | 813 |
| **SipHash-2-4** | 128 | 512 | PRF | 326 | 446 | 525 | 477 | 674 | 848 |
| **AES-CMAC** | 128 | 512 | PRF | 276 | 397 | 482 | 430 | 583 | 736 |
| **BLAKE2b-512** | 512 | 512 | PRF | 227 | 371 | 423 | 326 | 483 | 609 |
| **ChaCha20** | 256 | 512 | PRF | 222 | 337 | 434 | 334 | 460 | 610 |
| **BLAKE2s** | 256 | 512 | PRF | 180 | 296 | 358 | 290 | 359 | 468 |
| **BLAKE3** | 256 | 512 | PRF | 139 | 227 | 258 | 201 | 274 | 335 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 268 | 325 | 390 | 378 | 486 | 624 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 266 | 323 | 401 | 385 | 492 | 628 |
| **SipHash-2-4** | 128 | 1024 | PRF | 265 | 429 | 476 | 405 | 588 | 741 |
| **AES-CMAC** | 128 | 1024 | PRF | 227 | 328 | 415 | 337 | 423 | 555 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 173 | 280 | 322 | 224 | 352 | 449 |
| **ChaCha20** | 256 | 1024 | PRF | 177 | 276 | 322 | 241 | 347 | 414 |
| **BLAKE2s** | 256 | 1024 | PRF | 128 | 225 | 238 | 169 | 237 | 341 |
| **BLAKE3** | 256 | 1024 | PRF | 97 | 137 | 167 | 117 | 173 | 179 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 214 | 303 | 369 | 293 | 406 | 511 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 212 | 277 | 375 | 297 | 374 | 529 |
| **SipHash-2-4** | 128 | 2048 | PRF | 219 | 352 | 395 | 303 | 451 | 572 |
| **AES-CMAC** | 128 | 2048 | PRF | 175 | 251 | 300 | 232 | 334 | 409 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 118 | 208 | 209 | 162 | 226 | 213 |
| **ChaCha20** | 256 | 2048 | PRF | 134 | 200 | 223 | 160 | 213 | 261 |
| **BLAKE2s** | 256 | 2048 | PRF | 97 | 141 | 160 | 118 | 164 | 175 |
| **BLAKE3** | 256 | 2048 | PRF | 59 | 81 | 91 | 72 | 105 | 112 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 186 | 193 | 196 | 206 | 237 | 231 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 173 | 184 | 184 | 199 | 223 | 229 |
| **SipHash-2-4** | 128 | 512 | PRF | 149 | 188 | 196 | 214 | 243 | 242 |
| **AES-CMAC** | 128 | 512 | PRF | 144 | 172 | 178 | 186 | 208 | 205 |
| **BLAKE2b-512** | 512 | 512 | PRF | 108 | 131 | 135 | 141 | 149 | 153 |
| **ChaCha20** | 256 | 512 | PRF | 80 | 94 | 93 | 96 | 103 | 105 |
| **BLAKE2s** | 256 | 512 | PRF | 80 | 94 | 92 | 99 | 102 | 104 |
| **BLAKE3** | 256 | 512 | PRF | 53 | 65 | 66 | 61 | 64 | 66 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 122 | 127 | 125 | 130 | 140 | 143 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 120 | 123 | 123 | 130 | 140 | 142 |
| **SipHash-2-4** | 128 | 1024 | PRF | 105 | 123 | 125 | 132 | 145 | 148 |
| **AES-CMAC** | 128 | 1024 | PRF | 91 | 108 | 110 | 111 | 117 | 120 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 69 | 79 | 80 | 84 | 88 | 88 |
| **ChaCha20** | 256 | 1024 | PRF | 48 | 54 | 55 | 54 | 57 | 57 |
| **BLAKE2s** | 256 | 1024 | PRF | 49 | 54 | 54 | 52 | 57 | 59 |
| **BLAKE3** | 256 | 1024 | PRF | 29 | 33 | 33 | 32 | 33 | 34 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 70 | 73 | 74 | 75 | 80 | 81 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 70 | 75 | 75 | 75 | 79 | 78 |
| **SipHash-2-4** | 128 | 2048 | PRF | 66 | 75 | 75 | 75 | 82 | 83 |
| **AES-CMAC** | 128 | 2048 | PRF | 55 | 62 | 62 | 64 | 67 | 66 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 40 | 43 | 44 | 44 | 44 | 46 |
| **ChaCha20** | 256 | 2048 | PRF | 27 | 29 | 29 | 28 | 30 | 30 |
| **BLAKE2s** | 256 | 2048 | PRF | 27 | 29 | 29 | 29 | 29 | 31 |
| **BLAKE3** | 256 | 2048 | PRF | 16 | 17 | 17 | 16 | 17 | 17 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 375 | 371 | 418 | 597 | 746 | 920 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 403 | 363 | 487 | 599 | 783 | 945 |
| **SipHash-2-4** | 128 | 512 | PRF | 312 | 441 | 540 | 534 | 841 | 1014 |
| **AES-CMAC** | 128 | 512 | PRF | 275 | 361 | 459 | 465 | 642 | 823 |
| **BLAKE2b-512** | 512 | 512 | PRF | 204 | 330 | 407 | 326 | 562 | 670 |
| **ChaCha20** | 256 | 512 | PRF | 228 | 311 | 392 | 349 | 569 | 708 |
| **BLAKE2s** | 256 | 512 | PRF | 174 | 259 | 346 | 260 | 444 | 532 |
| **BLAKE3** | 256 | 512 | PRF | 133 | 201 | 250 | 216 | 289 | 301 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 310 | 328 | 432 | 452 | 578 | 776 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 340 | 321 | 425 | 445 | 577 | 751 |
| **SipHash-2-4** | 128 | 1024 | PRF | 267 | 390 | 470 | 462 | 659 | 871 |
| **AES-CMAC** | 128 | 1024 | PRF | 224 | 313 | 385 | 380 | 502 | 613 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 161 | 270 | 307 | 296 | 362 | 434 |
| **ChaCha20** | 256 | 1024 | PRF | 182 | 264 | 304 | 250 | 394 | 458 |
| **BLAKE2s** | 256 | 1024 | PRF | 131 | 210 | 233 | 181 | 259 | 262 |
| **BLAKE3** | 256 | 1024 | PRF | 95 | 135 | 162 | 119 | 160 | 176 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 251 | 261 | 344 | 327 | 411 | 566 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 256 | 269 | 365 | 331 | 403 | 581 |
| **SipHash-2-4** | 128 | 2048 | PRF | 222 | 323 | 367 | 343 | 486 | 629 |
| **AES-CMAC** | 128 | 2048 | PRF | 173 | 238 | 304 | 252 | 329 | 425 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 123 | 165 | 217 | 190 | 234 | 243 |
| **ChaCha20** | 256 | 2048 | PRF | 134 | 184 | 212 | 177 | 256 | 276 |
| **BLAKE2s** | 256 | 2048 | PRF | 88 | 137 | 136 | 103 | 166 | 134 |
| **BLAKE3** | 256 | 2048 | PRF | 58 | 82 | 87 | 70 | 94 | 90 |
