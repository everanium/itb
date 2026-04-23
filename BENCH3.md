# ITB Triple Ouroboros Benchmark Results

## Intel Core i7-11700K (16 HT, VMware, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 122 | 155 | 163 | 141 | 175 | 177 |
| **AES-CMAC** | 128 | 512 | PRF | 114 | 144 | 133 | 136 | 158 | 163 |
| **BLAKE2b-512** | 512 | 512 | PRF | 104 | 124 | 129 | 115 | 139 | 145 |
| **AreionSoEM512** | 512 | 512 | PRF | 101 | 109 | 109 | 117 | 119 | 120 |
| **AreionSoEM256** | 256 | 512 | PRF | 99 | 98 | 97 | 110 | 113 | 114 |
| **BLAKE2s** | 256 | 512 | PRF | 67 | 88 | 91 | 82 | 96 | 98 |
| **ChaCha20** | 256 | 512 | PRF | 64 | 80 | 88 | 75 | 92 | 93 |
| **BLAKE3** | 256 | 512 | PRF | 46 | 52 | 53 | 45 | 50 | 53 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 79 | 109 | 109 | 97 | 115 | 115 |
| **AES-CMAC** | 128 | 1024 | PRF | 76 | 93 | 93 | 91 | 99 | 103 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 67 | 79 | 79 | 63 | 85 | 86 |
| **AreionSoEM512** | 512 | 1024 | PRF | 63 | 72 | 72 | 69 | 77 | 78 |
| **AreionSoEM256** | 256 | 1024 | PRF | 60 | 66 | 67 | 64 | 70 | 70 |
| **BLAKE2s** | 256 | 1024 | PRF | 49 | 51 | 55 | 50 | 53 | 56 |
| **ChaCha20** | 256 | 1024 | PRF | 46 | 49 | 52 | 49 | 52 | 49 |
| **BLAKE3** | 256 | 1024 | PRF | 26 | 29 | 29 | 25 | 29 | 29 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 59 | 68 | 68 | 66 | 73 | 70 |
| **AES-CMAC** | 128 | 2048 | PRF | 50 | 52 | 58 | 51 | 58 | 59 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 40 | 45 | 48 | 42 | 46 | 51 |
| **AreionSoEM512** | 512 | 2048 | PRF | 35 | 40 | 41 | 38 | 41 | 42 |
| **AreionSoEM256** | 256 | 2048 | PRF | 34 | 38 | 39 | 37 | 40 | 40 |
| **BLAKE2s** | 256 | 2048 | PRF | 25 | 30 | 30 | 26 | 30 | 31 |
| **ChaCha20** | 256 | 2048 | PRF | 26 | 28 | 28 | 27 | 28 | 28 |
| **BLAKE3** | 256 | 2048 | PRF | 14 | 15 | 15 | 14 | 14 | 15 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 224 | 289 | 320 | 353 | 468 | 525 |
| **AES-CMAC** | 128 | 512 | PRF | 201 | 258 | 296 | 289 | 384 | 470 |
| **AreionSoEM512** | 512 | 512 | PRF | 186 | 226 | 295 | 277 | 363 | 448 |
| **AreionSoEM256** | 256 | 512 | PRF | 186 | 232 | 288 | 264 | 352 | 439 |
| **BLAKE2b-512** | 512 | 512 | PRF | 172 | 253 | 271 | 248 | 362 | 424 |
| **ChaCha20** | 256 | 512 | PRF | 173 | 229 | 274 | 247 | 334 | 413 |
| **BLAKE2s** | 256 | 512 | PRF | 149 | 206 | 236 | 200 | 308 | 342 |
| **BLAKE3** | 256 | 512 | PRF | 111 | 149 | 183 | 148 | 211 | 245 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 203 | 261 | 293 | 301 | 419 | 468 |
| **AES-CMAC** | 128 | 1024 | PRF | 166 | 207 | 264 | 238 | 328 | 388 |
| **AreionSoEM512** | 512 | 1024 | PRF | 156 | 206 | 257 | 222 | 295 | 377 |
| **AreionSoEM256** | 256 | 1024 | PRF | 153 | 208 | 250 | 212 | 286 | 357 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 145 | 198 | 242 | 189 | 295 | 334 |
| **ChaCha20** | 256 | 1024 | PRF | 139 | 188 | 229 | 193 | 268 | 318 |
| **BLAKE2s** | 256 | 1024 | PRF | 119 | 157 | 181 | 154 | 230 | 239 |
| **BLAKE3** | 256 | 1024 | PRF | 85 | 115 | 127 | 104 | 147 | 163 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 170 | 227 | 257 | 243 | 333 | 391 |
| **AES-CMAC** | 128 | 2048 | PRF | 135 | 187 | 217 | 184 | 250 | 301 |
| **AreionSoEM512** | 512 | 2048 | PRF | 122 | 177 | 207 | 164 | 234 | 275 |
| **AreionSoEM256** | 256 | 2048 | PRF | 122 | 170 | 200 | 161 | 226 | 263 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 105 | 152 | 167 | 140 | 211 | 229 |
| **ChaCha20** | 256 | 2048 | PRF | 110 | 152 | 172 | 140 | 195 | 215 |
| **BLAKE2s** | 256 | 2048 | PRF | 81 | 101 | 123 | 98 | 150 | 154 |
| **BLAKE3** | 256 | 2048 | PRF | 56 | 72 | 93 | 66 | 94 | 104 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Bit Soup mode)

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 512 | PRF | 41 | 43 | 43 | 46 | 48 | 50 |
| **AES-CMAC** | 128 | 512 | PRF | 39 | 42 | 41 | 45 | 46 | 48 |
| **BLAKE2b-512** | 512 | 512 | PRF | 35 | 40 | 40 | 40 | 44 | 44 |
| **AreionSoEM512** | 512 | 512 | PRF | 36 | 40 | 39 | 41 | 44 | 45 |
| **AreionSoEM256** | 256 | 512 | PRF | 36 | 39 | 39 | 39 | 42 | 43 |
| **BLAKE2s** | 256 | 512 | PRF | 31 | 35 | 34 | 35 | 38 | 39 |
| **ChaCha20** | 256 | 512 | PRF | 33 | 36 | 35 | 36 | 38 | 40 |
| **BLAKE3** | 256 | 512 | PRF | 26 | 27 | 27 | 28 | 30 | 29 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 1024 | PRF | 35 | 39 | 39 | 39 | 42 | 44 |
| **AES-CMAC** | 128 | 1024 | PRF | 34 | 35 | 35 | 37 | 39 | 40 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 29 | 32 | 33 | 32 | 35 | 37 |
| **AreionSoEM512** | 512 | 1024 | PRF | 29 | 33 | 33 | 32 | 35 | 36 |
| **AreionSoEM256** | 256 | 1024 | PRF | 28 | 32 | 32 | 31 | 34 | 35 |
| **BLAKE2s** | 256 | 1024 | PRF | 24 | 27 | 27 | 26 | 29 | 30 |
| **ChaCha20** | 256 | 1024 | PRF | 26 | 28 | 28 | 28 | 29 | 30 |
| **BLAKE3** | 256 | 1024 | PRF | 17 | 19 | 19 | 18 | 20 | 20 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **SipHash-2-4** | 128 | 2048 | PRF | 28 | 32 | 32 | 31 | 34 | 35 |
| **AES-CMAC** | 128 | 2048 | PRF | 27 | 29 | 29 | 29 | 31 | 32 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 22 | 25 | 25 | 23 | 26 | 27 |
| **AreionSoEM512** | 512 | 2048 | PRF | 23 | 24 | 25 | 24 | 26 | 26 |
| **AreionSoEM256** | 256 | 2048 | PRF | 21 | 24 | 23 | 23 | 25 | 25 |
| **BLAKE2s** | 256 | 2048 | PRF | 17 | 19 | 19 | 18 | 20 | 20 |
| **ChaCha20** | 256 | 2048 | PRF | 18 | 19 | 19 | 19 | 20 | 20 |
| **BLAKE3** | 256 | 2048 | PRF | 11 | 12 | 12 | 11 | 12 | 13 |
