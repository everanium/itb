# ITB Single Ouroboros Benchmark Results

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### ITB 512-bit

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 128 | 157 | 161 | 178 | 212 | 218 |
| **AES-CMAC** | 128 | 512 | PRF | 117 | 142 | 146 | 151 | 185 | 190 |
| **BLAKE2b-512** | 512 | 512 | PRF | 99 | 115 | 124 | 131 | 149 | 149 |
| **AreionSoEM512** | 512 | 512 | PRF | 99 | 112 | 111 | 128 | 133 | 139 |
| **AreionSoEM256** | 256 | 512 | PRF | 113 | 109 | 108 | 124 | 129 | 129 |
| **BLAKE2s** | 256 | 512 | PRF | 75 | 87 | 88 | 84 | 100 | 104 |
| **ChaCha20** | 256 | 512 | PRF | 73 | 87 | 89 | 87 | 101 | 104 |
| **BLAKE3** | 256 | 512 | PRF | 48 | 56 | 57 | 52 | 61 | 63 |

### ITB 1024-bit

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 93 | 109 | 112 | 113 | 134 | 134 |
| **AES-CMAC** | 128 | 1024 | PRF | 79 | 94 | 94 | 95 | 109 | 114 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 65 | 81 | 83 | 78 | 90 | 93 |
| **AreionSoEM512** | 512 | 1024 | PRF | 65 | 72 | 72 | 74 | 78 | 79 |
| **AreionSoEM256** | 256 | 1024 | PRF | 64 | 66 | 65 | 72 | 77 | 76 |
| **ChaCha20** | 256 | 1024 | PRF | 45 | 53 | 53 | 50 | 57 | 57 |
| **BLAKE2s** | 256 | 1024 | PRF | 45 | 54 | 54 | 49 | 57 | 60 |
| **BLAKE3** | 256 | 1024 | PRF | 28 | 33 | 33 | 30 | 33 | 33 |

### ITB 2048-bit

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 57 | 68 | 70 | 69 | 76 | 77 |
| **AES-CMAC** | 128 | 2048 | PRF | 49 | 56 | 58 | 54 | 63 | 63 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 40 | 48 | 48 | 43 | 50 | 51 |
| **AreionSoEM512** | 512 | 2048 | PRF | 37 | 40 | 40 | 40 | 44 | 45 |
| **AreionSoEM256** | 256 | 2048 | PRF | 36 | 38 | 38 | 39 | 42 | 42 |
| **ChaCha20** | 256 | 2048 | PRF | 25 | 29 | 30 | 28 | 30 | 31 |
| **BLAKE2s** | 256 | 2048 | PRF | 26 | 30 | 29 | 28 | 31 | 31 |
| **BLAKE3** | 256 | 2048 | PRF | 15 | 17 | 17 | 16 | 17 | 17 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB 512-bit

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 245 | 305 | 348 | 440 | 594 | 667 |
| **AES-CMAC** | 128 | 512 | PRF | 216 | 279 | 324 | 360 | 522 | 588 |
| **AreionSoEM512** | 512 | 512 | PRF | 198 | 229 | 303 | 347 | 449 | 583 |
| **AreionSoEM256** | 256 | 512 | PRF | 194 | 235 | 302 | 349 | 461 | 566 |
| **BLAKE2b-512** | 512 | 512 | PRF | 184 | 273 | 278 | 283 | 376 | 400 |
| **ChaCha20** | 256 | 512 | PRF | 196 | 247 | 276 | 313 | 400 | 445 |
| **BLAKE2s** | 256 | 512 | PRF | 151 | 226 | 236 | 214 | 283 | 316 |
| **BLAKE3** | 256 | 512 | PRF | 119 | 161 | 182 | 156 | 199 | 236 |

### ITB 1024-bit

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 216 | 277 | 314 | 372 | 484 | 545 |
| **AES-CMAC** | 128 | 1024 | PRF | 187 | 247 | 278 | 293 | 395 | 449 |
| **AreionSoEM512** | 512 | 1024 | PRF | 168 | 197 | 268 | 274 | 367 | 449 |
| **AreionSoEM256** | 256 | 1024 | PRF | 161 | 204 | 262 | 266 | 347 | 432 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 156 | 215 | 222 | 198 | 260 | 285 |
| **ChaCha20** | 256 | 1024 | PRF | 162 | 192 | 216 | 234 | 281 | 315 |
| **BLAKE2s** | 256 | 1024 | PRF | 112 | 174 | 176 | 136 | 185 | 210 |
| **BLAKE3** | 256 | 1024 | PRF | 84 | 108 | 123 | 95 | 130 | 148 |

### ITB 2048-bit

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 184 | 229 | 259 | 299 | 366 | 404 |
| **AES-CMAC** | 128 | 2048 | PRF | 155 | 189 | 214 | 226 | 279 | 305 |
| **AreionSoEM512** | 512 | 2048 | PRF | 133 | 179 | 211 | 194 | 273 | 314 |
| **AreionSoEM256** | 256 | 2048 | PRF | 130 | 174 | 203 | 195 | 251 | 300 |
| **ChaCha20** | 256 | 2048 | PRF | 116 | 139 | 155 | 155 | 179 | 203 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 110 | 156 | 160 | 138 | 164 | 192 |
| **BLAKE2s** | 256 | 2048 | PRF | 67 | 114 | 115 | 81 | 102 | 127 |
| **BLAKE3** | 256 | 2048 | PRF | 48 | 71 | 77 | 54 | 73 | 85 |
