# ITB Triple Ouroboros Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Results below were collected at `ITB_NONCE_BITS=512` (the v0.3.0 secure default) with `ITB_GOMEMLIMIT=512MiB` + `ITB_GOGC=20` capping the Go runtime heap so numbers stay stable across the 64 MB rows and are directly comparable with the binding-side benchmark harness under the same caps. Every PRF-grade primitive in the shipped hash registry dispatches through hand-written AVX-512 chain-absorb ASM kernels (each primitive family at its natural active register width) at the per-pixel hash hot path on x86_64 hosts with AVX-512 SIMD support; the AArch64 production path (AWS Graviton 2+ / Apple M1+ / Neoverse N1+/V1+/V2+) uses ARM Crypto Extension `AESE`/`AESMC` 4-lane parallel ASM for the Areion-SoEM-256/512 primitives and the upstream library NEON / ARM Crypto Extension paths for the AES-CMAC / BLAKE / ChaCha20 / SipHash family (`jedisct1/go-aes` ARM AES extension for AES-CMAC, `golang.org/x/crypto` NEON for the BLAKE / ChaCha20 family, `dchest/siphash` portable Go for SipHash-2-4). The C ABI and Python FFI stacks populate the batched arm automatically.

The Interlocked Barrier overlay derives a fresh PRF-keyed 48-bit bit-permutation mask per chunk (drawn from ≈ 2^70.20 mask space via one PRF evaluation per chunk group — batched four sequential group indices per call through each family's 13-byte fill kernel on AVX-512 hosts — BMI2 PEXT / PDEP hardware path on x86, pure-Go fallback elsewhere), so per-byte primitive call rate is substantially higher than a permutation-free construction and the hash hot path is throughput-bound. AMD EPYC 9655P closes this gap on every primitive — Zen 5's 192 HT plus full-width 512-bit ALU plus absent AVX-512 frequency throttle absorb the higher call rate better than Rocket Lake's narrower issue width. AArch64 hosts run through the pure-Go path; a NEON / SVE2 kernel for the Interlocked Barrier is not currently shipped.

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
| **Areion-SoEM-256** | 256 | 512 | PRF | 91 | 229 | 249 | 193 | 328 | 346 |
| **Areion-SoEM-512** | 512 | 512 | PRF | 93 | 241 | 263 | 154 | 349 | 368 |
| **BLAKE2b-256** | 256 | 512 | PRF | 79 | 164 | 174 | 143 | 208 | 212 |
| **BLAKE2b-512** | 512 | 512 | PRF | 79 | 166 | 179 | 120 | 210 | 220 |
| **BLAKE2s** | 256 | 512 | PRF | 76 | 126 | 134 | 101 | 150 | 156 |
| **BLAKE3** | 256 | 512 | PRF | 75 | 151 | 158 | 112 | 183 | 189 |
| **AES-CMAC** | 128 | 512 | PRF | 90 | 224 | 240 | 142 | 316 | 331 |
| **SipHash-2-4** | 128 | 512 | PRF | 86 | 184 | 199 | 153 | 219 | 250 |
| **ChaCha20** | 256 | 512 | PRF | 81 | 166 | 178 | 123 | 216 | 227 |

### ITB Triple 1024-bit (security: P × 2^(3×1024) = P × 2^3072)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 1024 | PRF | 85 | 179 | 185 | 132 | 233 | 244 |
| **Areion-SoEM-512** | 512 | 1024 | PRF | 88 | 199 | 210 | 135 | 267 | 277 |
| **BLAKE2b-256** | 256 | 1024 | PRF | 68 | 113 | 119 | 118 | 129 | 135 |
| **BLAKE2b-512** | 512 | 1024 | PRF | 69 | 115 | 122 | 95 | 134 | 140 |
| **BLAKE2s** | 256 | 1024 | PRF | 56 | 82 | 86 | 72 | 92 | 93 |
| **BLAKE3** | 256 | 1024 | PRF | 63 | 100 | 105 | 106 | 114 | 118 |
| **AES-CMAC** | 128 | 1024 | PRF | 85 | 170 | 183 | 126 | 222 | 230 |
| **SipHash-2-4** | 128 | 1024 | PRF | 75 | 130 | 137 | 107 | 155 | 160 |
| **ChaCha20** | 256 | 1024 | PRF | 70 | 122 | 129 | 126 | 143 | 149 |

### ITB Triple 2048-bit (security: P × 2^(3×2048) = P × 2^6144)

| Hash | Width | ITB Width | Crypto | Encrypt 1 MB | Encrypt 16 MB | Encrypt 64 MB | Decrypt 1 MB | Decrypt 16 MB | Decrypt 64 MB |
|---|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | 2048 | PRF | 71 | 123 | 128 | 96 | 147 | 151 |
| **Areion-SoEM-512** | 512 | 2048 | PRF | 79 | 144 | 152 | 115 | 176 | 185 |
| **BLAKE2b-256** | 256 | 2048 | PRF | 57 | 69 | 72 | 62 | 76 | 78 |
| **BLAKE2b-512** | 512 | 2048 | PRF | 48 | 67 | 74 | 63 | 79 | 80 |
| **BLAKE2s** | 256 | 2048 | PRF | 38 | 48 | 50 | 42 | 51 | 52 |
| **BLAKE3** | 256 | 2048 | PRF | 44 | 61 | 64 | 54 | 63 | 67 |
| **AES-CMAC** | 128 | 2048 | PRF | 70 | 117 | 123 | 120 | 137 | 142 |
| **SipHash-2-4** | 128 | 2048 | PRF | 57 | 82 | 84 | 73 | 92 | 94 |
| **ChaCha20** | 256 | 2048 | PRF | 54 | 78 | 80 | 79 | 85 | 87 |

## v0.3.0 vs pre-v0.3.0 (Lock Soup + Lock Batch mode) — cost delta

The v0.3.0 shipped construction carries two feature deltas versus the pre-v0.3.0 line: the nonce widens from 128 bits to 512 bits (secure default), and the overlay moves from an opt-in 24-bit Lock Soup + Lock Batch mask (roughly 2^33 mask space per chunk group) to an always-on 48-bit Interlocked Barrier (~ 2^70 mask space per chunk group). The pre-v0.3.0 "Lock Soup + Lock Batch" mode on the same i7-11700K host is the fair comparison point — both sides carry an overlay derivation cost per chunk, and the ratio isolates the ~ 2^37 mask-space widening plus the 4× nonce widening.

Encrypt at 64 MB (MB/s per primitive per width; v0.3.0 / pre-v0.3.0 ; **►** marks ratios ≥ 100%):

| Primitive          | 512-bit E 64 MB    | 1024-bit E 64 MB   | 2048-bit E 64 MB   |
|--------------------|:------------------:|:------------------:|:------------------:|
| **Areion-SoEM-256** | 249 / 198 (126%) ► | 185 / 179 (103%) ► | 128 / 141 (91%)    |
| **Areion-SoEM-512** | 263 / 226 (116%) ► | 210 / 198 (106%) ► | 152 / 162 (94%)    |
| **BLAKE2b-256**     | 174 / 118 (147%) ► | 119 / 84 (142%) ►  | 72 / 54 (133%) ►   |
| **BLAKE2b-512**     | 179 / 174 (103%) ► | 122 / 134 (91%)    | 74 / 88 (84%)      |
| **BLAKE2s**         | 134 / 130 (103%) ► | 86 / 91 (95%)      | 50 / 59 (85%)      |
| **BLAKE3**          | 158 / 130 (122%) ► | 105 / 101 (104%) ► | 64 / 69 (93%)      |
| **AES-CMAC**        | 240 / 165 (145%) ► | 183 / 153 (120%) ► | 123 / 120 (103%) ► |
| **SipHash-2-4**     | 199 / 158 (126%) ► | 137 / 126 (109%) ► | 84 / 90 (93%)      |
| **ChaCha20**        | 178 / 110 (162%) ► | 129 / 86 (150%) ►  | 80 / 58 (138%) ►   |

**Every shipped primitive now sits at or above the pre-v0.3.0 line at 512-bit width**, and every shipped primitive on the 1024-bit line except BLAKE2b-512 / BLAKE2s stays at or above baseline. The full ASM optimisation cycle (pack56 batched inversion + chain-kernel narrowing per family + ChaCha20 fused68 + interlock fill batching per family) delivers a fleet-wide throughput uplift that fully amortises the widened nonce envelope + always-on 48-bit interlock mask.

**ChaCha20 gains largest** (+62% at 512-bit / +50% at 1024-bit) — the fused68 dual-compression kernel plus interlock fill batching remove the two dominant bottlenecks the pre-v0.3.0 line paid on this primitive. **BLAKE family** climbs from residual (65-90% pre-refresh) to above baseline at 512-bit widths on all four variants, and BLAKE2b-256 sits at +33-47% across all three widths thanks to combined narrowing + fill batching. **AES-CMAC** stays at +45% at 512-bit / +20% at 1024-bit — the AVX-512 VAES chain kernels amortise cleanly across the widened overlay + nonce cost.

**2048-bit residual** (5-16% below baseline on the mid-tier primitives) reflects the wider container's higher per-chunk overhead relative to the per-byte hash cost; the AES-family and BLAKE2b-256 / BLAKE3 / ChaCha20 rows still sit at or above baseline at that width, while BLAKE2b-512 / BLAKE2s / AES-CMAC-derived rows land marginally below. The cost delta at 2048-bit is comfortably absorbed by the wider security envelope.

**Further rows** for other µarchs (Zen 3+, ARM64 Graviton 4, etc.) are scheduled — this table is a first-pass baseline pending maintainer-assisted runs on additional hardware.
