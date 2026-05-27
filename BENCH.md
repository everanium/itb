# ITB Single Ouroboros Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Results below were collected at `ITB_NONCE_BITS=128`. All nine PRF-grade hash primitives in the registry — Areion-SoEM-256, Areion-SoEM-512, SipHash-2-4, AES-CMAC, BLAKE2b-512, BLAKE2b-256, BLAKE2s, BLAKE3, ChaCha20 — dispatch through hand-written ZMM AVX-512 chain-absorb ASM kernels at the per-pixel hash hot path on x86_64 hosts with AVX-512 SIMD support; the AArch64 production path (AWS Graviton 2+ / Apple M1+ / Neoverse N1+/V1+/V2+) uses ARM Crypto Extension `AESE`/`AESMC` 4-lane parallel ASM for the Areion-SoEM-256/512 primitives and the upstream library NEON / ARM Crypto Extension paths for the AES-CMAC / BLAKE / ChaCha20 / SipHash family (`jedisct1/go-aes` ARM AES extension for AES-CMAC, `golang.org/x/crypto` NEON for the BLAKE / ChaCha20 family, `dchest/siphash` portable Go for SipHash-2-4). The C ABI and Python FFI stacks populate the batched arm automatically.

Lock Soup + Lock Batch is the faster Lock Soup variant: the per-chunk overlay derivation is amortised across a group of chunks. On x86 hosts carrying AVX-512F (plus AVX-512 VPOPCNTDQ for the permutation kernel) it runs through hand-written lane-parallel AVX-512 kernels — on the Intel i7-11700K this lifts Single Lock Soup throughput by roughly 1.1–2× over plain Lock Soup, and on AMD EPYC 9655P (Zen 5) more, with most primitives approaching their plain-path rates. AArch64 hosts (AWS Graviton 4) do not engage these kernels — Go's assembler carries no SVE2 support — so there Lock Batch amortises only the per-chunk hash call, a more modest ≈1.1–1.3× lift.

Lock Soup derives a fresh PRF-keyed bit-permutation mask per chunk, so per-byte primitive call rate is ~10× higher than the plain / Bit-Soup-only paths and the hash hot path becomes throughput-bound. AMD EPYC 9655P closes this gap on every primitive — Zen 5's 192 HT + full-width 512-bit ALU + absent AVX-512 frequency throttle absorb the higher call rate better than Rocket Lake's narrower issue width.

Reproduction:

```sh
ITB_NONCE_BITS=128 go test -bench='BenchmarkExtSingle*' -run='^$' -benchtime=5s -count=1
ITB_NONCE_BITS=128 ITB_LOCKSOUP=1 ITB_LOCKBATCH=1 go test -bench='BenchmarkExtSingle*' -run='^$' -benchtime=5s -count=1
ITB_NONCE_BITS=128 ITB_LOCKSOUP=1 go test -bench='BenchmarkExtSingle*' -run='^$' -benchtime=5s -count=1
```

Build-tag opt-outs that govern hash-kernel selection for hosts where the AVX-512+VL chain-absorb kernels are not engaged:

* `-tags=noitbasm` — disables only our chain-absorb asm; the per-pixel hash falls into `process_cgo`'s nil-`BatchHash` branch and runs 4 single-call invocations through the upstream asm directly. Useful on hosts without AVX-512+VL where the 4-lane wrapper would be dead weight; throughput tracks the OLDBENCH single-Func numbers below.

Pre-ZMM-optimisation reference numbers: [OLDBENCH.md](https://github.com/everanium/itb/blob/main/archive/OLDBENCH.md) — old benchmark results without full ASM AVX-512 ZMM kernel optimisations. Numerically these also serve as the expected ballpark under `-tags=noitbasm` (the encrypt path runs 4× single arm via upstream asm — the pre-ZMM dispatch shape).

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

## AWS Graviton 4 (c8g.4xlarge, 16 Cores, CGO mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 115 | 112 | 110 | 198 | 188 | 190 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 109 | 108 | 105 | 197 | 189 | 191 |
| **SipHash-2-4** | 128 | 512 | PRF | 126 | 131 | 132 | 253 | 272 | 272 |
| **AES-CMAC** | 128 | 512 | PRF | 120 | 126 | 124 | 223 | 243 | 240 |
| **BLAKE2b-512** | 512 | 512 | PRF | 81 | 86 | 87 | 124 | 133 | 135 |
| **BLAKE2b-256** | 256 | 512 | PRF | 59 | 65 | 52 | 81 | 86 | 86 |
| **BLAKE2s** | 256 | 512 | PRF | 68 | 65 | 67 | 90 | 95 | 91 |
| **BLAKE3** | 256 | 512 | PRF | 33 | 34 | 34 | 38 | 40 | 40 |
| **ChaCha20** | 256 | 512 | PRF | 19 | 42 | 46 | 19 | 47 | 56 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 83 | 83 | 81 | 126 | 121 | 121 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 82 | 80 | 81 | 124 | 121 | 121 |
| **SipHash-2-4** | 128 | 1024 | PRF | 100 | 104 | 106 | 162 | 177 | 179 |
| **AES-CMAC** | 128 | 1024 | PRF | 91 | 97 | 96 | 144 | 153 | 155 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 55 | 55 | 54 | 73 | 81 | 76 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 36 | 33 | 35 | 46 | 50 | 48 |
| **BLAKE2s** | 256 | 1024 | PRF | 40 | 38 | 38 | 52 | 55 | 51 |
| **BLAKE3** | 256 | 1024 | PRF | 18 | 19 | 19 | 20 | 21 | 21 |
| **ChaCha20** | 256 | 1024 | PRF | 10 | 24 | 27 | 10 | 25 | 30 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 56 | 56 | 56 | 71 | 71 | 71 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 55 | 54 | 55 | 70 | 69 | 70 |
| **SipHash-2-4** | 128 | 2048 | PRF | 72 | 76 | 75 | 98 | 106 | 107 |
| **AES-CMAC** | 128 | 2048 | PRF | 62 | 68 | 67 | 81 | 91 | 90 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 33 | 32 | 33 | 42 | 37 | 44 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 21 | 24 | 21 | 24 | 27 | 21 |
| **BLAKE2s** | 256 | 2048 | PRF | 21 | 23 | 23 | 25 | 30 | 23 |
| **BLAKE3** | 256 | 2048 | PRF | 8 | 10 | 9 | 11 | 9 | 11 |
| **ChaCha20** | 256 | 2048 | PRF | 5 | 13 | 15 | 5 | 13 | 15 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Lock Soup + Lock Batch mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 97 | 102 | 100 | 128 | 139 | 141 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 104 | 114 | 109 | 150 | 161 | 159 |
| **SipHash-2-4** | 128 | 512 | PRF | 80 | 86 | 85 | 107 | 114 | 114 |
| **AES-CMAC** | 128 | 512 | PRF | 94 | 97 | 99 | 118 | 121 | 127 |
| **BLAKE2b-512** | 512 | 512 | PRF | 112 | 113 | 112 | 132 | 139 | 142 |
| **BLAKE2b-256** | 256 | 512 | PRF | 76 | 83 | 82 | 98 | 102 | 106 |
| **BLAKE2s** | 256 | 512 | PRF | 80 | 82 | 83 | 100 | 105 | 106 |
| **BLAKE3** | 256 | 512 | PRF | 78 | 80 | 81 | 93 | 100 | 102 |
| **ChaCha20** | 256 | 512 | PRF | 78 | 83 | 84 | 93 | 98 | 101 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 88 | 95 | 92 | 120 | 125 | 129 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 99 | 106 | 103 | 138 | 148 | 149 |
| **SipHash-2-4** | 128 | 1024 | PRF | 68 | 76 | 77 | 92 | 95 | 98 |
| **AES-CMAC** | 128 | 1024 | PRF | 86 | 90 | 91 | 104 | 108 | 112 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 93 | 91 | 92 | 109 | 112 | 114 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 62 | 63 | 62 | 72 | 76 | 77 |
| **BLAKE2s** | 256 | 1024 | PRF | 65 | 65 | 66 | 77 | 78 | 82 |
| **BLAKE3** | 256 | 1024 | PRF | 65 | 67 | 68 | 79 | 84 | 83 |
| **ChaCha20** | 256 | 1024 | PRF | 45 | 62 | 63 | 74 | 75 | 77 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 80 | 84 | 85 | 102 | 108 | 110 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 89 | 93 | 93 | 121 | 126 | 128 |
| **SipHash-2-4** | 128 | 2048 | PRF | 58 | 62 | 62 | 72 | 75 | 76 |
| **AES-CMAC** | 128 | 2048 | PRF | 70 | 73 | 72 | 87 | 92 | 92 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 67 | 66 | 66 | 77 | 77 | 80 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 46 | 46 | 46 | 49 | 47 | 51 |
| **BLAKE2s** | 256 | 2048 | PRF | 47 | 47 | 49 | 50 | 53 | 54 |
| **BLAKE3** | 256 | 2048 | PRF | 51 | 52 | 52 | 58 | 61 | 62 |
| **ChaCha20** | 256 | 2048 | PRF | 48 | 46 | 47 | 52 | 52 | 55 |

## Intel Core i7-11700K (16 HT, VMware, CGO mode, Lock Soup mode)

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

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Lock Soup + Lock Batch mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 222 | 256 | 286 | 366 | 467 | 527 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 233 | 249 | 295 | 384 | 488 | 552 |
| **SipHash-2-4** | 128 | 512 | PRF | 206 | 230 | 260 | 328 | 420 | 475 |
| **AES-CMAC** | 128 | 512 | PRF | 180 | 229 | 265 | 331 | 431 | 483 |
| **BLAKE2b-512** | 512 | 512 | PRF | 221 | 238 | 275 | 355 | 461 | 517 |
| **BLAKE2b-256** | 256 | 512 | PRF | 186 | 215 | 251 | 307 | 401 | 466 |
| **BLAKE2s** | 256 | 512 | PRF | 197 | 220 | 250 | 311 | 401 | 461 |
| **BLAKE3** | 256 | 512 | PRF | 178 | 195 | 236 | 298 | 377 | 449 |
| **ChaCha20** | 256 | 512 | PRF | 202 | 229 | 187 | 72 | 240 | 333 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 214 | 236 | 273 | 347 | 442 | 494 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 225 | 236 | 276 | 370 | 467 | 512 |
| **SipHash-2-4** | 128 | 1024 | PRF | 191 | 216 | 245 | 303 | 371 | 445 |
| **AES-CMAC** | 128 | 1024 | PRF | 199 | 222 | 252 | 313 | 398 | 459 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 207 | 228 | 261 | 323 | 411 | 479 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 175 | 196 | 226 | 262 | 334 | 405 |
| **BLAKE2s** | 256 | 1024 | PRF | 182 | 200 | 236 | 277 | 347 | 413 |
| **BLAKE3** | 256 | 1024 | PRF | 177 | 193 | 233 | 275 | 334 | 410 |
| **ChaCha20** | 256 | 1024 | PRF | 61 | 146 | 178 | 71 | 221 | 315 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 198 | 207 | 262 | 317 | 399 | 469 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 212 | 224 | 265 | 336 | 407 | 452 |
| **SipHash-2-4** | 128 | 2048 | PRF | 172 | 183 | 228 | 264 | 309 | 390 |
| **AES-CMAC** | 128 | 2048 | PRF | 181 | 196 | 240 | 283 | 353 | 414 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 176 | 195 | 235 | 279 | 328 | 426 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 146 | 171 | 198 | 220 | 257 | 324 |
| **BLAKE2s** | 256 | 2048 | PRF | 150 | 182 | 206 | 230 | 270 | 342 |
| **BLAKE3** | 256 | 2048 | PRF | 159 | 175 | 208 | 240 | 277 | 358 |
| **ChaCha20** | 256 | 2048 | PRF | 59 | 132 | 164 | 68 | 195 | 270 |

## AMD EPYC 9655P (96-Core, Bare metal, CGO mode, Lock Soup mode)

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

## AWS Graviton 4 (c8g.4xlarge, 16 Cores, CGO mode, Lock Soup + Lock Batch mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 65 | 64 | 64 | 87 | 86 | 87 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 65 | 64 | 63 | 87 | 84 | 87 |
| **SipHash-2-4** | 128 | 512 | PRF | 65 | 73 | 72 | 92 | 102 | 103 |
| **AES-CMAC** | 128 | 512 | PRF | 63 | 70 | 69 | 87 | 95 | 97 |
| **BLAKE2b-512** | 512 | 512 | PRF | 50 | 54 | 53 | 64 | 68 | 71 |
| **BLAKE2b-256** | 256 | 512 | PRF | 37 | 40 | 41 | 48 | 49 | 55 |
| **BLAKE2s** | 256 | 512 | PRF | 40 | 39 | 43 | 49 | 57 | 46 |
| **BLAKE3** | 256 | 512 | PRF | 24 | 26 | 26 | 26 | 29 | 25 |
| **ChaCha20** | 256 | 512 | PRF | 15 | 31 | 35 | 16 | 35 | 40 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 53 | 52 | 53 | 69 | 68 | 69 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 53 | 52 | 52 | 69 | 66 | 68 |
| **SipHash-2-4** | 128 | 1024 | PRF | 57 | 63 | 63 | 80 | 85 | 87 |
| **AES-CMAC** | 128 | 1024 | PRF | 53 | 60 | 59 | 74 | 78 | 80 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 37 | 40 | 39 | 51 | 53 | 47 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 27 | 29 | 27 | 28 | 33 | 32 |
| **BLAKE2s** | 256 | 1024 | PRF | 27 | 32 | 29 | 33 | 33 | 32 |
| **BLAKE3** | 256 | 1024 | PRF | 15 | 16 | 16 | 16 | 18 | 17 |
| **ChaCha20** | 256 | 1024 | PRF | 9 | 20 | 22 | 9 | 21 | 24 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 40 | 40 | 41 | 49 | 48 | 49 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 40 | 39 | 40 | 48 | 48 | 49 |
| **SipHash-2-4** | 128 | 2048 | PRF | 46 | 51 | 51 | 61 | 64 | 66 |
| **AES-CMAC** | 128 | 2048 | PRF | 42 | 47 | 47 | 54 | 58 | 59 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 26 | 26 | 26 | 31 | 31 | 30 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 19 | 17 | 17 | 21 | 19 | 23 |
| **BLAKE2s** | 256 | 2048 | PRF | 19 | 19 | 20 | 22 | 19 | 24 |
| **BLAKE3** | 256 | 2048 | PRF | 9 | 9 | 9 | 9 | 10 | 8 |
| **ChaCha20** | 256 | 2048 | PRF | 5 | 12 | 13 | 5 | 11 | 13 |

## AWS Graviton 4 (c8g.4xlarge, 16 Cores, CGO mode, Lock Soup mode)

### ITB Single 512-bit (security: P × 2^512)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 58 | 57 | 57 | 75 | 73 | 75 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 50 | 49 | 48 | 62 | 61 | 62 |
| **SipHash-2-4** | 128 | 512 | PRF | 62 | 71 | 71 | 92 | 100 | 103 |
| **AES-CMAC** | 128 | 512 | PRF | 60 | 70 | 70 | 85 | 98 | 97 |
| **BLAKE2b-512** | 512 | 512 | PRF | 37 | 38 | 40 | 47 | 48 | 46 |
| **BLAKE2b-256** | 256 | 512 | PRF | 32 | 35 | 31 | 40 | 42 | 40 |
| **BLAKE2s** | 256 | 512 | PRF | 34 | 34 | 34 | 40 | 40 | 38 |
| **BLAKE3** | 256 | 512 | PRF | 19 | 20 | 20 | 19 | 22 | 23 |
| **ChaCha20** | 256 | 512 | PRF | 12 | 26 | 29 | 12 | 28 | 32 |

### ITB Single 1024-bit (security: P × 2^1024)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 49 | 49 | 47 | 61 | 60 | 61 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 42 | 41 | 42 | 52 | 52 | 52 |
| **SipHash-2-4** | 128 | 1024 | PRF | 54 | 63 | 63 | 76 | 85 | 86 |
| **AES-CMAC** | 128 | 1024 | PRF | 51 | 59 | 59 | 74 | 79 | 81 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 29 | 32 | 30 | 37 | 38 | 38 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 24 | 25 | 26 | 29 | 28 | 32 |
| **BLAKE2s** | 256 | 1024 | PRF | 24 | 26 | 26 | 28 | 29 | 29 |
| **BLAKE3** | 256 | 1024 | PRF | 11 | 14 | 14 | 14 | 15 | 15 |
| **ChaCha20** | 256 | 1024 | PRF | 8 | 18 | 20 | 8 | 18 | 22 |

### ITB Single 2048-bit (security: P × 2^2048)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 37 | 37 | 38 | 44 | 44 | 45 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 34 | 33 | 34 | 39 | 39 | 40 |
| **SipHash-2-4** | 128 | 2048 | PRF | 44 | 51 | 50 | 57 | 62 | 64 |
| **AES-CMAC** | 128 | 2048 | PRF | 40 | 47 | 47 | 54 | 59 | 58 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 23 | 23 | 23 | 26 | 25 | 25 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 16 | 16 | 16 | 19 | 16 | 17 |
| **BLAKE2s** | 256 | 2048 | PRF | 17 | 18 | 18 | 20 | 18 | 18 |
| **BLAKE3** | 256 | 2048 | PRF | 8 | 8 | 8 | 9 | 9 | 9 |
| **ChaCha20** | 256 | 2048 | PRF | 4 | 11 | 13 | 4 | 11 | 13 |
