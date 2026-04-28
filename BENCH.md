# ITB Single Ouroboros Benchmark Results

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 151 | 150 | 144 | 184 | 196 | 212 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 137 | 134 | 138 | 189 | 198 | 197 |
| **SipHash-2-4** | 128 | 512 | PRF | 131 | 166 | 159 | 195 | 220 | 213 |
| **AES-CMAC** | 128 | 512 | PRF | 125 | 153 | 140 | 167 | 191 | 186 |
| **BLAKE2b-512** | 512 | 512 | PRF | 97 | 116 | 113 | 120 | 139 | 131 |
| **ChaCha20** | 256 | 512 | PRF | 73 | 86 | 81 | 87 | 100 | 99 |
| **BLAKE2s** | 256 | 512 | PRF | 76 | 86 | 81 | 90 | 101 | 98 |
| **BLAKE3** | 256 | 512 | PRF | 54 | 60 | 58 | 59 | 66 | 62 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 104 | 108 | 106 | 120 | 128 | 129 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 100 | 104 | 102 | 123 | 130 | 134 |
| **SipHash-2-4** | 128 | 1024 | PRF | 94 | 113 | 106 | 122 | 139 | 127 |
| **AES-CMAC** | 128 | 1024 | PRF | 80 | 97 | 93 | 99 | 113 | 114 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 62 | 72 | 71 | 72 | 83 | 80 |
| **ChaCha20** | 256 | 1024 | PRF | 46 | 52 | 50 | 50 | 53 | 57 |
| **BLAKE2s** | 256 | 1024 | PRF | 43 | 49 | 50 | 49 | 56 | 54 |
| **BLAKE3** | 256 | 1024 | PRF | 29 | 31 | 31 | 30 | 32 | 35 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 68 | 69 | 71 | 74 | 79 | 80 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 67 | 69 | 69 | 72 | 78 | 77 |
| **SipHash-2-4** | 128 | 2048 | PRF | 61 | 73 | 67 | 75 | 80 | 80 |
| **AES-CMAC** | 128 | 2048 | PRF | 50 | 58 | 57 | 62 | 66 | 67 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 38 | 42 | 42 | 42 | 45 | 47 |
| **ChaCha20** | 256 | 2048 | PRF | 27 | 28 | 27 | 28 | 30 | 30 |
| **BLAKE2s** | 256 | 2048 | PRF | 24 | 28 | 27 | 28 | 30 | 30 |
| **BLAKE3** | 256 | 2048 | PRF | 15 | 17 | 17 | 17 | 18 | 17 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 251 | 273 | 297 | 469 | 524 | 635 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 250 | 257 | 309 | 489 | 556 | 649 |
| **SipHash-2-4** | 128 | 512 | PRF | 255 | 312 | 341 | 516 | 624 | 719 |
| **AES-CMAC** | 128 | 512 | PRF | 221 | 267 | 314 | 423 | 507 | 630 |
| **BLAKE2b-512** | 512 | 512 | PRF | 192 | 250 | 267 | 326 | 468 | 515 |
| **ChaCha20** | 256 | 512 | PRF | 196 | 234 | 288 | 333 | 414 | 527 |
| **BLAKE2s** | 256 | 512 | PRF | 166 | 213 | 219 | 268 | 329 | 433 |
| **BLAKE3** | 256 | 512 | PRF | 129 | 174 | 205 | 176 | 245 | 313 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 212 | 219 | 281 | 359 | 434 | 565 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 220 | 212 | 279 | 379 | 427 | 553 |
| **SipHash-2-4** | 128 | 1024 | PRF | 215 | 296 | 307 | 415 | 551 | 625 |
| **AES-CMAC** | 128 | 1024 | PRF | 182 | 237 | 270 | 326 | 422 | 503 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 157 | 199 | 228 | 244 | 307 | 394 |
| **ChaCha20** | 256 | 1024 | PRF | 154 | 216 | 232 | 245 | 316 | 386 |
| **BLAKE2s** | 256 | 1024 | PRF | 122 | 185 | 159 | 176 | 206 | 218 |
| **BLAKE3** | 256 | 1024 | PRF | 86 | 130 | 128 | 120 | 181 | 195 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 175 | 192 | 259 | 279 | 375 | 431 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 174 | 181 | 255 | 285 | 360 | 446 |
| **SipHash-2-4** | 128 | 2048 | PRF | 187 | 243 | 268 | 326 | 447 | 474 |
| **AES-CMAC** | 128 | 2048 | PRF | 153 | 195 | 228 | 244 | 327 | 353 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 114 | 166 | 159 | 165 | 227 | 199 |
| **ChaCha20** | 256 | 2048 | PRF | 117 | 163 | 171 | 167 | 224 | 241 |
| **BLAKE2s** | 256 | 2048 | PRF | 81 | 102 | 99 | 116 | 161 | 180 |
| **BLAKE3** | 256 | 2048 | PRF | 62 | 68 | 66 | 68 | 81 | 112 |
