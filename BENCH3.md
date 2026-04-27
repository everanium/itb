# ITB Triple Ouroboros Benchmark Results

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 153 | 201 | 197 | 222 | 235 | 240 |
| **AES-CMAC** | 128 | 512 | PRF | 138 | 179 | 176 | 191 | 211 | 209 |
| **BLAKE2b-512** | 512 | 512 | PRF | 112 | 136 | 132 | 142 | 155 | 157 |
| **AreionSoEM512** | 512 | 512 | PRF | 112 | 137 | 132 | 141 | 151 | 155 |
| **AreionSoEM256** | 256 | 512 | PRF | 104 | 129 | 131 | 137 | 146 | 149 |
| **BLAKE2s** | 256 | 512 | PRF | 82 | 96 | 95 | 101 | 106 | 107 |
| **ChaCha20** | 256 | 512 | PRF | 86 | 97 | 97 | 101 | 106 | 107 |
| **BLAKE3** | 256 | 512 | PRF | 48 | 55 | 54 | 54 | 56 | 57 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 105 | 129 | 132 | 138 | 148 | 147 |
| **AES-CMAC** | 128 | 1024 | PRF | 88 | 108 | 109 | 111 | 119 | 119 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 70 | 83 | 83 | 84 | 87 | 89 |
| **AreionSoEM512** | 512 | 1024 | PRF | 69 | 82 | 81 | 84 | 89 | 89 |
| **AreionSoEM256** | 256 | 1024 | PRF | 65 | 78 | 77 | 79 | 84 | 83 |
| **BLAKE2s** | 256 | 1024 | PRF | 51 | 55 | 56 | 55 | 59 | 58 |
| **ChaCha20** | 256 | 1024 | PRF | 51 | 57 | 56 | 56 | 59 | 60 |
| **BLAKE3** | 256 | 1024 | PRF | 29 | 30 | 29 | 29 | 30 | 30 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 64 | 78 | 77 | 79 | 82 | 83 |
| **AES-CMAC** | 128 | 2048 | PRF | 53 | 61 | 63 | 61 | 66 | 67 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 43 | 46 | 46 | 45 | 48 | 49 |
| **AreionSoEM512** | 512 | 2048 | PRF | 43 | 45 | 45 | 45 | 47 | 48 |
| **AreionSoEM256** | 256 | 2048 | PRF | 38 | 42 | 42 | 41 | 44 | 45 |
| **BLAKE2s** | 256 | 2048 | PRF | 27 | 30 | 30 | 29 | 31 | 32 |
| **ChaCha20** | 256 | 2048 | PRF | 28 | 31 | 30 | 29 | 31 | 31 |
| **BLAKE3** | 256 | 2048 | PRF | 15 | 16 | 15 | 15 | 15 | 15 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 322 | 443 | 566 | 464 | 681 | 864 |
| **AES-CMAC** | 128 | 512 | PRF | 279 | 394 | 480 | 425 | 579 | 749 |
| **AreionSoEM512** | 512 | 512 | PRF | 257 | 368 | 470 | 368 | 518 | 656 |
| **AreionSoEM256** | 256 | 512 | PRF | 247 | 347 | 444 | 373 | 516 | 684 |
| **BLAKE2b-512** | 512 | 512 | PRF | 226 | 371 | 423 | 332 | 475 | 606 |
| **ChaCha20** | 256 | 512 | PRF | 229 | 335 | 425 | 316 | 451 | 596 |
| **BLAKE2s** | 256 | 512 | PRF | 189 | 290 | 359 | 281 | 374 | 483 |
| **BLAKE3** | 256 | 512 | PRF | 145 | 214 | 241 | 190 | 268 | 325 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 272 | 392 | 465 | 385 | 584 | 714 |
| **AES-CMAC** | 128 | 1024 | PRF | 235 | 333 | 397 | 312 | 479 | 583 |
| **AreionSoEM512** | 512 | 1024 | PRF | 206 | 301 | 385 | 279 | 398 | 503 |
| **AreionSoEM256** | 256 | 1024 | PRF | 198 | 296 | 383 | 275 | 380 | 510 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 171 | 285 | 322 | 242 | 346 | 415 |
| **ChaCha20** | 256 | 1024 | PRF | 178 | 278 | 333 | 238 | 326 | 421 |
| **BLAKE2s** | 256 | 1024 | PRF | 139 | 219 | 240 | 192 | 224 | 229 |
| **BLAKE3** | 256 | 1024 | PRF | 107 | 147 | 151 | 129 | 157 | 195 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 224 | 373 | 377 | 314 | 469 | 535 |
| **AES-CMAC** | 128 | 2048 | PRF | 183 | 250 | 307 | 248 | 306 | 414 |
| **AreionSoEM512** | 512 | 2048 | PRF | 161 | 243 | 274 | 207 | 292 | 339 |
| **AreionSoEM256** | 256 | 2048 | PRF | 157 | 225 | 264 | 203 | 285 | 319 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 132 | 198 | 217 | 177 | 219 | 221 |
| **ChaCha20** | 256 | 2048 | PRF | 135 | 191 | 210 | 165 | 225 | 266 |
| **BLAKE2s** | 256 | 2048 | PRF | 92 | 145 | 153 | 128 | 162 | 182 |
| **BLAKE3** | 256 | 2048 | PRF | 61 | 86 | 101 | 76 | 96 | 112 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 155 | 190 | 201 | 213 | 244 | 248 |
| **AES-CMAC** | 128 | 512 | PRF | 135 | 167 | 166 | 182 | 203 | 206 |
| **BLAKE2b-512** | 512 | 512 | PRF | 107 | 130 | 132 | 144 | 153 | 157 |
| **AreionSoEM512** | 512 | 512 | PRF | 107 | 130 | 136 | 141 | 152 | 157 |
| **AreionSoEM256** | 256 | 512 | PRF | 102 | 120 | 125 | 132 | 145 | 148 |
| **BLAKE2s** | 256 | 512 | PRF | 80 | 95 | 96 | 100 | 106 | 107 |
| **ChaCha20** | 256 | 512 | PRF | 81 | 95 | 95 | 97 | 106 | 108 |
| **BLAKE3** | 256 | 512 | PRF | 47 | 54 | 54 | 54 | 56 | 58 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 101 | 121 | 125 | 132 | 147 | 149 |
| **AES-CMAC** | 128 | 1024 | PRF | 90 | 105 | 106 | 109 | 118 | 121 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 68 | 80 | 81 | 83 | 89 | 91 |
| **AreionSoEM512** | 512 | 1024 | PRF | 68 | 79 | 82 | 80 | 87 | 89 |
| **AreionSoEM256** | 256 | 1024 | PRF | 64 | 75 | 76 | 76 | 82 | 85 |
| **BLAKE2s** | 256 | 1024 | PRF | 48 | 54 | 55 | 52 | 58 | 61 |
| **ChaCha20** | 256 | 1024 | PRF | 50 | 55 | 56 | 53 | 59 | 60 |
| **BLAKE3** | 256 | 1024 | PRF | 27 | 29 | 29 | 29 | 30 | 30 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 64 | 75 | 76 | 76 | 83 | 86 |
| **AES-CMAC** | 128 | 2048 | PRF | 54 | 61 | 64 | 61 | 64 | 66 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 40 | 46 | 47 | 45 | 49 | 49 |
| **AreionSoEM512** | 512 | 2048 | PRF | 39 | 43 | 45 | 43 | 47 | 48 |
| **AreionSoEM256** | 256 | 2048 | PRF | 37 | 42 | 42 | 41 | 44 | 44 |
| **BLAKE2s** | 256 | 2048 | PRF | 27 | 30 | 30 | 30 | 31 | 32 |
| **ChaCha20** | 256 | 2048 | PRF | 27 | 29 | 30 | 28 | 31 | 31 |
| **BLAKE3** | 256 | 2048 | PRF | 14 | 15 | 16 | 16 | 16 | 16 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 307 | 431 | 524 | 518 | 819 | 1012 |
| **AES-CMAC** | 128 | 512 | PRF | 274 | 356 | 447 | 473 | 669 | 787 |
| **AreionSoEM512** | 512 | 512 | PRF | 254 | 353 | 421 | 398 | 595 | 798 |
| **AreionSoEM256** | 256 | 512 | PRF | 249 | 334 | 426 | 392 | 595 | 742 |
| **BLAKE2b-512** | 512 | 512 | PRF | 215 | 324 | 408 | 343 | 560 | 663 |
| **ChaCha20** | 256 | 512 | PRF | 232 | 332 | 401 | 346 | 559 | 694 |
| **BLAKE2s** | 256 | 512 | PRF | 174 | 274 | 323 | 272 | 402 | 481 |
| **BLAKE3** | 256 | 512 | PRF | 140 | 200 | 244 | 217 | 284 | 309 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 270 | 395 | 455 | 426 | 668 | 785 |
| **AES-CMAC** | 128 | 1024 | PRF | 218 | 324 | 390 | 355 | 492 | 657 |
| **AreionSoEM512** | 512 | 1024 | PRF | 208 | 282 | 362 | 308 | 435 | 581 |
| **AreionSoEM256** | 256 | 1024 | PRF | 201 | 277 | 343 | 291 | 412 | 558 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 167 | 253 | 294 | 246 | 397 | 414 |
| **ChaCha20** | 256 | 1024 | PRF | 185 | 245 | 309 | 254 | 391 | 455 |
| **BLAKE2s** | 256 | 1024 | PRF | 130 | 199 | 209 | 195 | 295 | 315 |
| **BLAKE3** | 256 | 1024 | PRF | 101 | 136 | 155 | 134 | 195 | 183 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 222 | 309 | 387 | 329 | 474 | 597 |
| **AES-CMAC** | 128 | 2048 | PRF | 177 | 239 | 298 | 253 | 372 | 421 |
| **AreionSoEM512** | 512 | 2048 | PRF | 158 | 212 | 271 | 218 | 325 | 374 |
| **AreionSoEM256** | 256 | 2048 | PRF | 155 | 220 | 262 | 222 | 312 | 341 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 126 | 185 | 208 | 172 | 242 | 255 |
| **ChaCha20** | 256 | 2048 | PRF | 133 | 192 | 228 | 171 | 242 | 284 |
| **BLAKE2s** | 256 | 2048 | PRF | 96 | 131 | 142 | 121 | 138 | 192 |
| **BLAKE3** | 256 | 2048 | PRF | 65 | 91 | 93 | 81 | 93 | 106 |
