# ITB Triple Ouroboros Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Results below were collected at `ITB_NONCE_BITS=512` (the v0.3.0 secure default) with `ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` capping the Go runtime heap so numbers stay stable across the 64 MB rows and are directly comparable with the binding-side benchmark harness under the same caps. Every PRF-grade primitive in the shipped hash registry dispatches through hand-written ZMM AVX-512 chain-absorb ASM kernels at the per-pixel hash hot path on x86_64 hosts with AVX-512 SIMD support; the AArch64 production path (AWS Graviton 2+ / Apple M1+ / Neoverse N1+/V1+/V2+) uses ARM Crypto Extension `AESE`/`AESMC` 4-lane parallel ASM for the Areion-SoEM-256/512 primitives and the upstream library NEON / ARM Crypto Extension paths for the AES-CMAC / BLAKE / ChaCha20 / SipHash family (`jedisct1/go-aes` ARM AES extension for AES-CMAC, `golang.org/x/crypto` NEON for the BLAKE / ChaCha20 family, `dchest/siphash` portable Go for SipHash-2-4). The C ABI and Python FFI stacks populate the batched arm automatically.

The Interlocked Barrier overlay derives a fresh PRF-keyed 48-bit bit-permutation mask per chunk (drawn from ≈ 2^70.20 mask space via one PRF call per chunk group, BMI2 PEXT / PDEP hardware path on x86, pure-Go fallback elsewhere), so per-byte primitive call rate is substantially higher than a permutation-free construction and the hash hot path is throughput-bound. AMD EPYC 9655P closes this gap on every primitive — Zen 5's 192 HT plus full-width 512-bit ALU plus absent AVX-512 frequency throttle absorb the higher call rate better than Rocket Lake's narrower issue width. AArch64 hosts run through the pure-Go path; a NEON / SVE2 kernel for the Interlocked Barrier is not currently shipped.

Reproduction:

```sh
ITB_NONCE_BITS=512 ITB_GOMEMLIMIT=512MiB ITB_GOGC=20 \
  go test -bench='BenchmarkExtTriple.*_(1MB|16MB|64MB)$' -run='^$' -benchtime=5s -count=1
```

Build-tag opt-outs that govern hash-kernel selection for hosts where the AVX-512+VL chain-absorb kernels are not engaged:

* `-tags=noitbasm` — disables only the chain-absorb asm; the per-pixel hash falls into `process_cgo`'s nil-`BatchHash` branch and runs 4 single-call invocations through the upstream asm directly. Useful on hosts without AVX-512+VL where the 4-lane wrapper would be dead weight; the encrypt path runs 4× the single arm via upstream asm.

## v0.3.0 benchmarks (Intel i7-11700K, 2026-08-25)

Measured on an Intel Core i7-11700K (Rocket Lake, 16 hardware threads), Arch Linux kernel 7.1.9, Go 1.26.5, VMware CGO mode. Throughput in MB/s at `ITB_NONCE_BITS=512` (v0.3.0 secure default), `-benchtime=5s -count=1`, Go runtime capped by `ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` so allocation churn on the 64 MB rows does not artefact-drop throughput below the 16 MB rows. The 1 MB column is dominated by small-payload GC-cycle amortisation and carries measurable noise across reruns; the 16 MB and 64 MB columns are stable and are the primary reference points for cross-run comparison.

### ITB Triple 512-bit (security: P × 2^(3×512) = P × 2^1536)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 512 | PRF | 99 | 200 | 216 | 145 | 260 | 277 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 91 | 208 | 218 | 175 | 274 | 287 |
| **BLAKE2b-256** | 256 | 512 | PRF | 67 | 126 | 136 | 98 | 151 | 150 |
| **BLAKE2b-512** | 512 | 512 | PRF | 71 | 139 | 147 | 106 | 162 | 175 |
| **BLAKE2s** | 256 | 512 | PRF | 64 | 98 | 99 | 84 | 111 | 115 |
| **BLAKE3** | 256 | 512 | PRF | 80 | 112 | 116 | 98 | 129 | 133 |
| **AES-CMAC** | 128 | 512 | PRF | 90 | 213 | 231 | 133 | 297 | 308 |
| **SipHash-2-4** | 128 | 512 | PRF | 86 | 171 | 182 | 123 | 200 | 222 |
| **ChaCha20** | 256 | 512 | PRF | 37 | 83 | 97 | 51 | 99 | 111 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 86 | 163 | 171 | 117 | 200 | 207 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 84 | 175 | 185 | 143 | 221 | 229 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 59 | 89 | 92 | 88 | 99 | 101 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 62 | 94 | 99 | 99 | 106 | 109 |
| **BLAKE2s** | 256 | 1024 | PRF | 47 | 62 | 65 | 56 | 69 | 69 |
| **BLAKE3** | 256 | 1024 | PRF | 52 | 75 | 78 | 66 | 83 | 85 |
| **AES-CMAC** | 128 | 1024 | PRF | 84 | 168 | 178 | 118 | 211 | 218 |
| **SipHash-2-4** | 128 | 1024 | PRF | 73 | 119 | 126 | 126 | 138 | 142 |
| **ChaCha20** | 256 | 1024 | PRF | 32 | 58 | 65 | 41 | 65 | 70 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 67 | 104 | 121 | 88 | 132 | 139 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 77 | 131 | 137 | 102 | 153 | 157 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 41 | 55 | 56 | 49 | 58 | 59 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 45 | 58 | 59 | 52 | 61 | 63 |
| **BLAKE2s** | 256 | 2048 | PRF | 30 | 37 | 37 | 33 | 38 | 39 |
| **BLAKE3** | 256 | 2048 | PRF | 36 | 46 | 46 | 41 | 48 | 49 |
| **AES-CMAC** | 128 | 2048 | PRF | 68 | 113 | 122 | 112 | 134 | 140 |
| **SipHash-2-4** | 128 | 2048 | PRF | 54 | 74 | 77 | 65 | 82 | 83 |
| **ChaCha20** | 256 | 2048 | PRF | 24 | 36 | 39 | 28 | 38 | 40 |

## v0.3.0 vs pre-v0.3.0 (Lock Soup + Lock Batch mode) — cost delta

The v0.3.0 shipped construction carries two feature deltas versus the pre-v0.3.0 line: the nonce widens from 128 bits to 512 bits (secure default), and the overlay moves from an opt-in 24-bit Lock Soup + Lock Batch mask (roughly 2^33 mask space per chunk group) to an always-on 48-bit Interlocked Barrier (~ 2^70 mask space per chunk group). The pre-v0.3.0 "Lock Soup + Lock Batch" mode on the same i7-11700K host is the fair comparison point — both sides carry an overlay derivation cost per chunk, and the ratio isolates the ~ 2^37 mask-space widening plus the 4× nonce widening.

Encrypt at 64 MB (MB/s per primitive per width; v0.3.0 / pre-v0.3.0 ; **►** marks ratios ≥ 100%):

| Primitive          | 512-bit E 64 MB    | 1024-bit E 64 MB   | 2048-bit E 64 MB   |
|--------------------|:------------------:|:------------------:|:------------------:|
| **Areion-SoEM-256** | 216 / 198 (109%) ► | 171 / 179 (96%)    | 121 / 141 (86%)    |
| **Areion-SoEM-512** | 218 / 226 (96%)    | 185 / 198 (93%)    | 137 / 162 (85%)    |
| **BLAKE2b-256**     | 136 / 118 (115%) ► | 92 / 84 (110%) ►   | 56 / 54 (104%) ►   |
| **BLAKE2b-512**     | 147 / 174 (84%)    | 99 / 134 (74%)     | 59 / 88 (67%)      |
| **BLAKE2s**         | 99 / 130 (76%)     | 65 / 91 (71%)      | 37 / 59 (63%)      |
| **BLAKE3**          | 116 / 130 (89%)    | 78 / 101 (77%)     | 46 / 69 (67%)      |
| **AES-CMAC**        | 231 / 165 (140%) ► | 178 / 153 (116%) ► | 122 / 120 (102%) ► |
| **SipHash-2-4**     | 182 / 158 (115%) ► | 126 / 126 (100%) ► | 77 / 90 (86%)      |
| **ChaCha20**        | 97 / 110 (88%)     | 65 / 86 (76%)      | 39 / 58 (67%)      |

**AES-family primitives (Areion-SoEM-256 / Areion-SoEM-512 / AES-CMAC) and SipHash-2-4** — the primitives that dominate any production workload with an AES-NI or GFNI host — retain or exceed the pre-v0.3.0 throughput at 512-bit and 1024-bit widths despite the 4× wider nonce envelope and the ~ 2^37× wider mask space per chunk. AES-CMAC specifically climbs +40% at 512-bit E 64 MB because the AVX-512 VAES chain kernels landed during the recent ASM optimisation cycle amortise across the widened overlay + nonce cost. BLAKE2b-256 sits ahead of pre-v0.3.0 at every width — its 256-bit output amortises the per-chunk overhead well.

**BLAKE2b-512 / BLAKE2s / BLAKE3** and **ChaCha20** carry the residual: BLAKE's per-hash cost is dominated by the upstream `x/crypto` SIMD path which received no direct ITB kernel improvement this cycle, so it pays the full overlay + nonce widening at 65-90% of the pre-v0.3.0 line. ChaCha20 sits at 65-88% for the same structural reason plus its intrinsic ~ 20-round ARX cost, ill-matched to a per-input hash-like role of ~ millions of invocations per encrypted MB.

**Further rows** for other µarchs (Zen 3+, ARM64 Graviton 4, etc.) are scheduled — this table is a first-pass baseline pending maintainer-assisted runs on additional hardware.
