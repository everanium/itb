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
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 76 | 86 | 81 | 90 | 101 | 98 |
| **BLAKE3** | 256 | 512 | PRF | 54 | 60 | 58 | 59 | 66 | 62 |
| **ChaCha20** | 256 | 512 | PRF | 73 | 86 | 81 | 87 | 100 | 99 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 104 | 108 | 106 | 120 | 128 | 129 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 100 | 104 | 102 | 123 | 130 | 134 |
| **SipHash-2-4** | 128 | 1024 | PRF | 94 | 113 | 106 | 122 | 139 | 127 |
| **AES-CMAC** | 128 | 1024 | PRF | 80 | 97 | 93 | 99 | 113 | 114 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 62 | 72 | 71 | 72 | 83 | 80 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 43 | 49 | 50 | 49 | 56 | 54 |
| **BLAKE3** | 256 | 1024 | PRF | 29 | 31 | 31 | 30 | 32 | 35 |
| **ChaCha20** | 256 | 1024 | PRF | 46 | 52 | 50 | 50 | 53 | 57 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 68 | 69 | 71 | 74 | 79 | 80 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 67 | 69 | 69 | 72 | 78 | 77 |
| **SipHash-2-4** | 128 | 2048 | PRF | 61 | 73 | 67 | 75 | 80 | 80 |
| **AES-CMAC** | 128 | 2048 | PRF | 50 | 58 | 57 | 62 | 66 | 67 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 38 | 42 | 42 | 42 | 45 | 47 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 24 | 28 | 27 | 28 | 30 | 30 |
| **BLAKE3** | 256 | 2048 | PRF | 15 | 17 | 17 | 17 | 18 | 17 |
| **ChaCha20** | 256 | 2048 | PRF | 27 | 28 | 27 | 28 | 30 | 30 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 251 | 273 | 297 | 469 | 524 | 635 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 250 | 257 | 309 | 489 | 556 | 649 |
| **SipHash-2-4** | 128 | 512 | PRF | 255 | 312 | 341 | 516 | 624 | 719 |
| **AES-CMAC** | 128 | 512 | PRF | 221 | 267 | 314 | 423 | 507 | 630 |
| **BLAKE2b-512** | 512 | 512 | PRF | 192 | 250 | 267 | 326 | 468 | 515 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 166 | 213 | 219 | 268 | 329 | 433 |
| **BLAKE3** | 256 | 512 | PRF | 129 | 174 | 205 | 176 | 245 | 313 |
| **ChaCha20** | 256 | 512 | PRF | 196 | 234 | 288 | 333 | 414 | 527 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 212 | 219 | 281 | 359 | 434 | 565 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 220 | 212 | 279 | 379 | 427 | 553 |
| **SipHash-2-4** | 128 | 1024 | PRF | 215 | 296 | 307 | 415 | 551 | 625 |
| **AES-CMAC** | 128 | 1024 | PRF | 182 | 237 | 270 | 326 | 422 | 503 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 157 | 199 | 228 | 244 | 307 | 394 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 122 | 185 | 159 | 176 | 206 | 218 |
| **BLAKE3** | 256 | 1024 | PRF | 86 | 130 | 128 | 120 | 181 | 195 |
| **ChaCha20** | 256 | 1024 | PRF | 154 | 216 | 232 | 245 | 316 | 386 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 175 | 192 | 259 | 279 | 375 | 431 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 174 | 181 | 255 | 285 | 360 | 446 |
| **SipHash-2-4** | 128 | 2048 | PRF | 187 | 243 | 268 | 326 | 447 | 474 |
| **AES-CMAC** | 128 | 2048 | PRF | 153 | 195 | 228 | 244 | 327 | 353 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 114 | 166 | 159 | 165 | 227 | 199 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 81 | 102 | 99 | 116 | 161 | 180 |
| **BLAKE3** | 256 | 2048 | PRF | 62 | 68 | 66 | 68 | 81 | 112 |
| **ChaCha20** | 256 | 2048 | PRF | 117 | 163 | 171 | 167 | 224 | 241 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup + Lock Soup mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 52 | 57 | 55 | 57 | 65 | 65 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 47 | 50 | 49 | 51 | 56 | 56 |
| **SipHash-2-4** | 128 | 512 | PRF | 56 | 69 | 64 | 69 | 81 | 82 |
| **AES-CMAC** | 128 | 512 | PRF | 67 | 83 | 73 | 89 | 109 | 107 |
| **BLAKE2b-512** | 512 | 512 | PRF | 38 | 46 | 46 | 43 | 53 | 53 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 35 | 40 | 41 | 41 | 46 | 46 |
| **BLAKE3** | 256 | 512 | PRF | 27 | 31 | 31 | 29 | 35 | 35 |
| **ChaCha20** | 256 | 512 | PRF | 35 | 40 | 41 | 39 | 45 | 48 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 45 | 50 | 48 | 52 | 57 | 58 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 40 | 45 | 45 | 45 | 50 | 51 |
| **SipHash-2-4** | 128 | 1024 | PRF | 44 | 57 | 56 | 56 | 67 | 66 |
| **AES-CMAC** | 128 | 1024 | PRF | 52 | 66 | 66 | 67 | 76 | 78 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 32 | 38 | 32 | 36 | 43 | 42 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 26 | 31 | 28 | 30 | 33 | 32 |
| **BLAKE3** | 256 | 1024 | PRF | 19 | 22 | 22 | 20 | 23 | 24 |
| **ChaCha20** | 256 | 1024 | PRF | 26 | 30 | 30 | 30 | 34 | 33 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 33 | 38 | 40 | 39 | 44 | 45 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 34 | 36 | 37 | 36 | 40 | 40 |
| **SipHash-2-4** | 128 | 2048 | PRF | 36 | 45 | 44 | 43 | 50 | 50 |
| **AES-CMAC** | 128 | 2048 | PRF | 39 | 48 | 48 | 46 | 53 | 53 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 24 | 26 | 24 | 26 | 29 | 29 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 19 | 21 | 20 | 21 | 21 | 22 |
| **BLAKE3** | 256 | 2048 | PRF | 13 | 14 | 14 | 13 | 14 | 14 |
| **ChaCha20** | 256 | 2048 | PRF | 19 | 22 | 21 | 21 | 23 | 23 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Bit Soup + Lock Soup mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 147 | 172 | 216 | 239 | 295 | 369 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 142 | 168 | 195 | 227 | 303 | 318 |
| **SipHash-2-4** | 128 | 512 | PRF | 133 | 200 | 232 | 244 | 373 | 417 |
| **AES-CMAC** | 128 | 512 | PRF | 152 | 192 | 227 | 260 | 371 | 444 |
| **BLAKE2b-512** | 512 | 512 | PRF | 79 | 137 | 163 | 132 | 191 | 254 |
| **BLAKE2b-256** | 256 | 512 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 512 | PRF | 74 | 117 | 138 | 126 | 197 | 192 |
| **BLAKE3** | 256 | 512 | PRF | 64 | 100 | 108 | 99 | 136 | 169 |
| **ChaCha20** | 256 | 512 | PRF | 99 | 134 | 153 | 168 | 245 | 268 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 138 | 173 | 197 | 219 | 288 | 342 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 134 | 154 | 193 | 207 | 242 | 296 |
| **SipHash-2-4** | 128 | 1024 | PRF | 129 | 190 | 225 | 223 | 324 | 412 |
| **AES-CMAC** | 128 | 1024 | PRF | 133 | 178 | 208 | 223 | 308 | 358 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 72 | 125 | 136 | 117 | 186 | 181 |
| **BLAKE2b-256** | 256 | 1024 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 1024 | PRF | 64 | 96 | 99 | 103 | 124 | 125 |
| **BLAKE3** | 256 | 1024 | PRF | 51 | 89 | 85 | 76 | 109 | 102 |
| **ChaCha20** | 256 | 1024 | PRF | 91 | 125 | 141 | 147 | 194 | 216 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 126 | 160 | 179 | 187 | 238 | 279 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 122 | 154 | 173 | 179 | 229 | 255 |
| **SipHash-2-4** | 128 | 2048 | PRF | 124 | 163 | 194 | 201 | 300 | 320 |
| **AES-CMAC** | 128 | 2048 | PRF | 111 | 148 | 184 | 181 | 237 | 285 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 59 | 102 | 104 | 100 | 141 | 118 |
| **BLAKE2b-256** | 256 | 2048 | PRF | — | — | — | — | — | — |
| **BLAKE2s** | 256 | 2048 | PRF | 49 | 69 | 88 | 72 | 80 | 98 |
| **BLAKE3** | 256 | 2048 | PRF | 39 | 58 | 66 | 50 | 66 | 76 |
| **ChaCha20** | 256 | 2048 | PRF | 83 | 105 | 113 | 123 | 162 | 183 |
