## ITB Hardware-Level Threat Analysis

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](README.md) for jurisdictional certification details.

## Scope

ITB claims no resistance to physical or hardware-level attacks; the analysis below evaluates the architectural properties of the construction's data path rather than proven hardware security guarantees.

This assessment examines ITB's execution paths against known microarchitectural and hardware-level attack classes across both runtime backends:
- **Go Software Backend:** (`CGO_ENABLED=0`), engaging Go-assembly vector kernels where supported.
- **CGO Acceleration Backend:** (`process_pixels.c`, GCC `-O3`), leveraging AVX2/AVX-512 on x86-64 and NEON on ARM64.

**Core Architectural Invariant:** All secret-dependent operations (`noisePos`, `dataRotation`, `channelXOR`) execute exclusively through register-to-register arithmetic and bitwise logic (AND, OR, XOR, bit shifts). The data path contains **zero secret-dependent memory accesses** (no S-boxes, no T-tables, no key-dependent lookup tables). The classic memory-access primitive exploited by microarchitectural disclosure attacks (`table[secret_key]`) is absent.

---

## Category 1: Speculative Execution Variants

Speculative execution disclosure requires a gadget: a secret-dependent memory access that leaves a measurable cache or microarchitectural footprint. ITB's data path contains no secret-dependent memory index gadgets.

| Attack | CVE / Date | Mechanism | ITB Data Path Analysis | Status |
|---|---|---|---|---|
| **Spectre v1** | CVE-2017-5753 | Mistrained branch → speculative `array[secret]` → cache trace | No secret-dependent indexing; `noisePos` and `dataRotation` act strictly as shift counts. | No gadget |
| **Spectre v2** | CVE-2017-5715 | Poisoned BTB → speculative branch target injection | Secret-dependent operations are register-only; mispredicted control flow executes no secret loads. | No gadget |
| **Spectre v4** | CVE-2018-3639 | Speculative store bypass (SSB) reads stale load before store completes | Register-to-register transforms (`rotateBits7`); no overlapping store-to-load on identical addresses. | No gadget |
| **Retbleed** | CVE-2022-29900/01 | Exploits return instructions as speculative execution gadgets | Requires secret-dependent memory access gadget; none present in the data path. | No gadget |
| **Inception** | CVE-2023-20569 | Branch predictor training to attacker-chosen target (AMD Zen) | Same requirement: disclosure gadget with secret-dependent memory index. | No gadget |
| **Downfall / GDS** | CVE-2022-40982 | Gather Data Sampling leaks SIMD registers via `GATHER` instructions | CGO backend avoids `GATHER` instructions; AVX-512 VBMI uses intra-register `VPERMB` byte permutations. | Not applicable |
| **GhostRace** | CVE-2024-2193 | Speculative execution combined with race conditions on shared data | Worker lanes operate on disjoint memory slices; no secret-dependent branching on shared state. | No gadget |
| **Indirector** | 2024 | High-precision Branch Target Buffer (BTB) manipulation (Intel) | Fundamental requirement remains a secret-dependent disclosure gadget. | No gadget |
| **BHI** | CVE-2022-0001 / CVE-2024-2201 | Branch History Injection across privilege boundaries | Fundamental requirement remains a secret-dependent disclosure gadget. | No gadget |
| **SLAM** | 2023 | Linear Address Masking exploitation for uncanonical address loads | Requires memory disclosure gadget indexing via secrets (`memory[secret]`). | No gadget |
| **Training Solo** | CVE-2024-28956 | History-based cross-process branch predictor poisoning | Fundamental requirement remains a secret-dependent disclosure gadget. | No gadget |
| **Branch Privilege Injection** | CVE-2024-45332 | Speculative privilege escalation via branch predictor state | Same structural requirement: secret-dependent memory disclosure gadget. | No gadget |
| **TSA** | 2025 | Transient Scheduler Attacks reading stale queue data (AMD Zen 3/4) | Leaks residual microarchitectural queue state; not specific to ITB computation. | Not ITB-specific |

---

## Category 2: Data Sampling & Stale Buffer Leaks

Data sampling attacks extract transient state from internal CPU microarchitectural structures (line fill buffers, store buffers, register files). If process memory contains cryptographic seeds, stale fragments may transiently inhabit CPU buffers, identical to any symmetric cipher implementation (AES round keys, ChaCha20 state).

| Attack | CVE / Date | Target Structure | ITB Impact Analysis | Status |
|---|---|---|---|---|
| **MDS (RIDL, Fallout, ZombieLoad)** | CVE-2018-12126/27/30, CVE-2019-11091 | Line fill buffers, store buffers, load ports | Seeds and plaintext transiently occupy CPU buffers; identical posture to standard AES/ChaCha20. | Not ITB-specific |
| **MMIO Stale Data** | CVE-2022-21123/25/66 | Memory-mapped I/O buffers | ITB performs no memory-mapped I/O operations. | Not applicable |
| **RFDS** | 2024 (Intel Atom) | Register file residual states | Intermediate seed hash values may linger in physical registers until overwritten. | Not ITB-specific |
| **Zenbleed** | CVE-2023-20593 | AVX register file leak (AMD Zen 2) | AVX registers could expose intermediate state; resolved by vendor microcode update. | Mitigated by CPU microcode |

---

## Category 3: Cache, Interconnect & Power Contention

| Attack | Year | Mechanism | ITB Data Path Analysis | Status |
|---|---|---|---|---|
| **Hertzbleed** | 2022 | Frequency throttling converts data-dependent power into remote timing | Scalar operations use fixed-latency register XOR/shift. Vector kernels (AVX2, AVX-512, VAES, NEON) adhere to constant-time execution floors. | No known attack surface |
| **SQUIP** | 2022 | Scheduler queue contention leaks execution pattern across SMT threads | Pixel processing follows uniform, invariant instruction sequences regardless of secret values. | No known attack surface |
| **Interconnect Contention** | Various | Bus and interconnect contention leaks spatial memory patterns | Container access pattern (`startPixel`) represents an acknowledged, documented cache footprint limitation. | Documented limitation |

---

## Category 4: Memory Integrity & Residue

| Attack | Mechanism | ITB Impact Analysis | Status |
|---|---|---|---|
| **Rowhammer** | Repeated DRAM row activations induce charge disturbance in adjacent rows | Bit-flips could corrupt seed structures, container buffers, or plaintext in RAM. | General hardware threat |
| **RAMBleed** | Physical side-channel reading memory via Rowhammer-induced flips | Memory disclosure of adjacent rows could leak seed bytes; identical to standard cipher keys. | General hardware threat |

### Memory Hardening & Residue Analysis

- **Hardware Memory Protection:** Deployments in hostile hosting environments should mandate ECC DRAM to mitigate disturbance errors, coupled with hardware memory encryption (AMD SEV, Intel SGX/TDX, ARM CCA).
- **Heap Residue Management:** Sensitive structures reside in process heap memory during execution (expanded seed components `Seed.Components []uint64`, intermediate hash states, and active payload buffers). The runtime executes `secureWipe` (lowering to `runtime.memclrNoHeapPointers`) on intermediate buffers immediately after use.
- **Runtime Boundaries:** Software zeroization cannot clear internal Go runtime scheduler structures or OS kernel buffers allocated during `crypto/rand` harvesting.
- **Process Memory Scrapers:** Attackers with direct process memory read access (e.g., hypervisor breakout, local debugger, kernel dump) can extract cryptographic seeds directly from userland heap, an exposure shared universally across all software cryptographic libraries.

---

## Category 5: Instruction-Set Side-Channel Profile

### 5.1 Shipped Assembly Kernels & Coverage

The accelerated execution engine spans hand-crafted assembly kernels across multiple microarchitectural tiers:

1. **Pixel Processing (`process_pixels.c`):**
   - **Tier A:** AVX-512F + AVX-512BW + AVX-512VL + GFNI + AVX-512VBMI (8-pixel batches).
   - **Tier A′:** AVX-512F + AVX-512BW + AVX-512VL without GFNI/VBMI (Cascade Lake class).
   - **Tier B:** AVX2 + GFNI (4-pixel batches).
   - **Tier B′:** AVX2 baseline without GFNI (Haswell, Zen 3 class).
   - **Tier C:** Portable scalar C fallback.
2. **Interlocked Barrier (`internal/interlock/`):**
   - **Combinadic Unrank:** AVX-512F 8/16-lane (`rankToMaskTripleUnrank48AVX512`), AVX2 4-lane (`rankToMaskTripleUnrank48AVX2`), NEON 8-lane (`rankToMaskTripleUnrank48NEON`).
   - **Chunk Apply / Unapply:** BMI2 hardware `PEXTQ` / `PDEPQ` batched kernels (`interlockasm48_batch_amd64.s`), SVE2 BitPerm `BEXT` / `BDEP` (`interlockasm48_sve2_arm64.s`), and branchless scalar `softPEXT48` / `softPDEP48`.
3. **Areion Permutation & Cascades (`internal/areionasm/`):**
   - VAES ZMM/YMM fused ChainHash cascade kernels, AES-NI XMM kernels, and ARM64 Crypto Extension `AESE` / `AESMC` kernels.
4. **Registry Hash Families (`hashes/internal/`):**
   - Fused ChainHash cascade kernels for each shipped registry primitive across AVX-512, AVX2, NEON, and 64-bit GPR scalar tiers.

### 5.2 Microarchitecture Floors & Tier Dispatch

- **Top Tier (AVX-512 + VAES):** Intel 11th Gen Core (Rocket Lake) and Xeon Scalable (Ice Lake-SP+); AMD Zen 4+. Fused ZMM cascades, AVX-512F unrank, and Tier A/A′ pixel kernels.
- **Mid Tier (AVX2 Baseline):** Intel Haswell through Comet Lake; AMD Zen 1–3. Features YMM vector cascades, AVX2 4-lane unrank (Haswell+ and Zen 3+), and Tier B/B′ pixel kernels. Hardware BMI2 `PEXT` / `PDEP` are constant-time on Haswell+ and Zen 3+.
- **AArch64 Tier (ARMv8-A + Crypto + SVE2):** Server baseline (AWS Graviton 2+, Neoverse N1/V1/V2, Apple Silicon) leverages NEON vector cascades and ARM Crypto Extension `AESE`/`AESMC`. SVE2 BitPerm (`FEAT_SVE_BitPerm`) accelerates chunking on Graviton 4 / Neoverse V2.
- **Portable Fallback Floor:** AMD Zen 1 / Zen 2 CPUs microcode-emulate `PEXT` / `PDEP` with data-dependent latency; such hosts (and Hygon) automatically route through the branchless portable Go fallbacks (`softPEXT48` / `softPDEP48`) and the Go rank-unrank path.
- **Dispatch Testing Knobs:** Test harnesses force individual tiers using `ITB_FORCE_HASH_TIER`, `ITB_FORCE_INTERLOCK_TIER`, `ITB_FORCE_INTERLOCK_PRF_FILL_TIER`, `ITB_FORCE_CHAINHASH_X4`, and `ITB_FORCE_PIXEL_TIER`.

---

### 5.3 Instruction-Level Side-Channel Inventory

The inventory below classifies each hardware instruction utilized in ITB by its microarchitectural latency profile. ITB does not rely on instruction-level timing invariance for foundational security; the barrier is established architecturally at the software layer.

| Instruction(s) | Component / Path | CPU Floor | Side-Channel Profile | ITB Architectural Exposure |
|---|---|---|---|---|
| `VAESENC`<br>`VAESENCLAST` | `areionasm`<br>`aescmacasm` (AMD64) | Intel Ice Lake+<br>AMD Zen 3+ (YMM)<br>Zen 4+ (ZMM) | Constant-time hardware AES across all supporting microarchitectures. Eliminates software S-box and T-table timing side-channels. | Areion-SoEM and AES-CMAC ChainHash execute entirely through vector AES. Lane staging uses fixed register-to-register moves (`VINSERTI64X2`, `VEXTRACTI64X2`, `VPXORQ`). |
| `AESENC`<br>`AESENCLAST`<br>`PXOR`, `MOVOU` | `areionasm`<br>`aescmacasm` (AES-NI) | Intel Westmere+<br>AMD Bulldozer+<br>(Universal on AVX2) | Constant-time hardware AES. Independent chains are interleaved to hide execution latency on single-issue AES ports without branches. | Deployed on AES-NI hosts lacking VAES (Cascade Lake, cloud VMs). Round keys and constants are read from public read-only tables at fixed offsets. |
| `AESE`<br>`AESMC` | `areionasm`<br>`aesitbasm` (AArch64) | ARMv8-A `+crypto`<br>(AWS Graviton 2+<br>Neoverse N1/V2, M1+) | Constant-time hardware AES per ARM Architecture Reference Manual. No table-lookup fallback paths. | Areion-SoEM and AES-ITB-128 fused cascades run via 4-lane parallel `AESE`/`AESMC` pipelines. Fallbacks utilize `aes.Round4HW`. |
| `VGF2P8AFFINEQB` | `process_pixels.c`<br>(Tier A / Tier B) | Intel Ice Lake+<br>AMD Zen 4+ | Constant-time GF(2) affine transformation with data-independent execution latency. | Computes per-pixel bit rotation (Phase 4) and noise-bit insert/extract (Phase 5). Affine matrices are fetched from 64-byte aligned single-cacheline tables. |
| `VPSLLVW`, `VPSRLVW`<br>`VPTERNLOGQ` | `process_pixels.c`<br>(Tier A′ No-GFNI) | AVX-512F+BW+VL<br>Intel Skylake-X+<br>AMD Zen 4+ | Variable vector shifts take secret-derived shift counts; latency is documented invariant on all AVX-512BW microarchitectures. | Batched pixel encoding on AVX-512 hosts lacking GFNI/VBMI (Cascade Lake Xeon). `VPTERNLOGQ` evaluates bitwise ternary logic with compile-time constants. |
| `VPSLLVQ`, `VPSLLW`<br>`VPMADDUBSW` | `process_pixels.c`<br>(Tier B′ No-GFNI) | AVX2 Baseline<br>Intel Haswell+<br>AMD Zen 1+ | Constant-time reciprocal throughput. Variable shifts use secret-derived counts with data-oblivious execution latency. | 4-pixel batch encoder on AVX2 hosts without GFNI (Haswell, Zen 3). Synthesizes rotation via shift-mask-OR and packs via multiply-add trees. |
| `VPERMB` | `process_pixels.c`<br>(Tier A) | Intel Ice Lake+<br>AMD Zen 4+ | Constant-time intra-register byte permutation. Operates strictly within vector registers; distinct from memory `GATHER` instructions. | Byte gathering from packed plaintext and lane compaction prior to masked stores. Permutation index vectors are public compile-time constants. |
| `VPMULTISHIFTQB` | `process_pixels.c`<br>(Tier A) | Intel Ice Lake+<br>AMD Zen 4+ | Constant-time bit-field extraction with data-independent latency. | Extracts eight 7-bit channel fields from 64-bit packed pixel descriptors. |
| `VPMADDUBSW`<br>`VPMADDWD` | `process_pixels.c`<br>(Decode Pack Step) | AVX2 / AVX-512BW<br>Haswell+, Zen 1+ | Fixed-latency integer multiply-add. Multiplier operands are compile-time constants; only multiplicands carry secret-derived channel values. | Folds eight 7-bit channel values into one 56-bit word per qword lane. Destination store addresses derive exclusively from public geometry parameters. |
| `PEXTQ`<br>`PDEPQ` | `internal/interlock/`<br>(AMD64 BMI2) | Intel Haswell+<br>AMD Zen 3+<br>(Hardware BMI2) | Constant-time execution on specified floor. Pre-Zen-3 AMD microcode-emulated paths are excluded and fall back to software Go kernels. | Executes 48-bit Interlocked Barrier chunk-apply and unapply. Balanced 16-of-48 lane partition guarantees invariant popcount (16 bits) across all lanes. |
| `VPERMT2Q`<br>`VPCMPUQ`<br>`VPTESTMQ` | `internal/interlock/`<br>(AVX-512 Unrank) | AVX-512F Baseline<br>Skylake-X+, Zen 4+ | Constant-time intra-register qword permute selecting binomial constants C(p, k). Register-only; no secret-indexed memory access. | Batched 8-lane and 16-lane Interlocked Barrier unrank kernels. Table row loads index by public loop counter p in [0, 48], never by secret values. |
| `VPERMD`<br>`VPCMPEQQ`<br>`PDEPQ` | `internal/interlock/`<br>(AVX2 Unrank) | AVX2 + BMI2<br>Haswell+, Zen 3+ | Constant-time intra-register dword permutation over in-register sources. Mask generation uses branchless predicate masks. | 4-lane AVX2 unrank kernel for systems without AVX-512. Produces bit-exact `[3][8]uint64` mask triples matching the AVX-512 implementation. |
| `VTBX`<br>`VCMHS`<br>`VUSHL` | `internal/interlock/`<br>(NEON Unrank) | ARMv8-A Baseline<br>(Advanced SIMD) | Constant-time register table lookups (`VTBX`) over in-register binomial tables. Data-oblivious variable register shifts (`VUSHL`). | 8-lane AArch64 unrank kernel (`rankToMaskTripleUnrank48NEON`). Produces bit-exact mask triples sharing one binomial row load across eight lanes. |
| `BEXT`<br>`BDEP` | `internal/interlock/`<br>(SVE2 BitPerm) | ARMv8.5-A+ SVE2<br>(Graviton 4, Neoverse V2) | Vector bit-extract/deposit operating across 64-bit lanes under mask vectors. Register-only; no memory-indexed addressing. | Hardware-accelerated batched chunk-apply on ARM64 (`chunk48LockBatchSVE2`). Independent of vector length (processes two 48-bit chunks per step). |
| `VPADDQ`, `VPXORQ`<br>`VPRORQ`, `VPTERNLOGQ` | `hashes/internal/*`<br>(AVX-512 AMD64) | AVX-512F+DQ<br>Skylake-X+, Zen 4+ | Single-cycle reciprocal throughput. Rotates use immediate compile-time constants. Embedded broadcasts (`.BCST`) read fixed stack offsets. | Fused cascade kernels for BLAKE2b, BLAKE2s, BLAKE3, SipHash-2-4, and ChaCha20. Operates in 4-lane and 8-lane vector strides. |
| `VPADDQ`, `VPXOR`<br>`VPSHUFB`, `VPSLLQ` | `hashes/internal/*`<br>(AVX2 AMD64) | AVX2 Baseline<br>Haswell+, Zen 1+ | Constant-time integer arithmetic. Rotates are synthesized via compile-time shuffle masks (`VPSHUFB`) and immediate shift-OR pairs. | AVX2 fused cascade kernels for registry hashes. Message words spill to fixed-offset stack frames without secret-indexed addressing. |
| `ADDQ`, `XORQ`<br>`ROLQ`, `RORQ` | `hashes/internal/*`<br>(GPR Scalar) | Any x86-64 / ARMv8-A<br>(Universal Baseline) | Constant-time scalar integer ALU instructions with immediate counts. Fixed-stride iterations over component arrays. | Single-lane fallback cascade kernels across all hash primitives. Loops track public round counts with branchless termination conditions. |
| `VADD`, `VEOR`<br>`VSHL`, `VSRI` | `hashes/internal/*`<br>(NEON ARM64) | ARMv8-A Baseline<br>(Universal Advanced SIMD) | Fixed-latency SIMD integer operations. Rotates synthesized via `VSHL` + `VSRI` with constant immediates from algorithm specifications. | 4-lane fused cascade kernels on AArch64 for BLAKE2b, BLAKE2s, BLAKE3, SipHash-2-4, and ChaCha20. |
| `VZEROUPPER` | Kernel Exits<br>(AVX2 / AVX-512) | AVX Baseline | Clears upper bits (128..511) of `YMM`/`ZMM` registers. Prevents AVX-SSE transition penalties. Does not zero lower 128-bit `XMM` state. | Issued at exit of AVX2/AVX-512 kernels. Mitigates register persistence window for upper vector state across context boundaries. |
| `VPXOR`, `VMOVDQA`<br>`VMOVDQU` | `areionasm`<br>`process_pixels.c` | AVX / AVX2 / AVX-512F | Constant-time vector load/store/XOR primitives. Aligned and unaligned memory access. | Core building blocks across all vector stages. Memory addresses derive from public container offsets and frame bases. |

---

### 5.4 Microarchitectural Implementation Details

#### GFNI Matrix-Table Lookup
The affine transformation matrices utilized by Tier A and Tier B kernels (`itb_gfni_rot_matrices`, `itb_gfni_spread_matrices`, `itb_gfni_gather_matrices` in `process_pixels.c`) are compile-time constants residing in read-only memory. Each table occupies a single 64-byte aligned cache line (`aligned(64)`). Because each table spans exactly one cache line (56 to 64 bytes), secret-derived rotation and noise indexes never select across cache-line boundaries. Access is branchless, ensuring a strictly uniform, index-independent data-cache footprint on modern cores (Rocket Lake+, Zen 3+).

#### Pixel-Index Wrap Arithmetic
The batched loops in `process_pixels.c` maintain linear pixel offsets modulo `totalPixels` using branchless conditional subtraction masks. Batch entry points evaluate a single fast-path condition (`basePixel + batchWidth <= totalPixels`) derived entirely from public container geometry and `startPixel`. Because `startPixel` access patterns are already documented as a known cache observation property, this branch reveals no information beyond the acknowledged container geometry.

#### Batched Store-Then-Load Sequences
When processing pixel batches that cross container boundaries, Tier A and Tier B paths stage intermediate bytes through stack-allocated buffers (`outBuf`) before copying them to the container. The source and destination addresses represent distinct stack offsets and container pointers. Consequently, Speculative Store Bypass (Spectre v4) cannot induce cross-channel leakage of secret-derived data, as the speculative load cannot alias an in-flight store to an identical address.

#### Pure-Go Portable Fallbacks
On platforms lacking supported vector extensions (legacy hardware, WebAssembly, or builds passing `-tags noitbasm`), execution falls back to pure Go implementations:
- **Interlocked Barrier:** Executes via `softPEXT48` and `softPDEP48` (branchless 48-iteration loops using bitwise AND, OR, and variable shifts without lookup tables or secret-dependent branching).
- **Hash Cascades:** Dispatches through scalar portable Go reference functions.
- **Areion & AES Primitives:** Falls back to `aes.Round4HW` or software constant-time implementations.

All fallback paths enforce register-only, branchless evaluation over secret inputs to preserve side-channel resistance across unaccelerated targets.

---

## Summary & Threat Model Verdict

1. **Absence of Memory Disclosure Gadgets:** ITB's data path executes secret-dependent operations (`noisePos`, `dataRotation`, `channelXOR`, barrier mask applications) entirely within CPU registers. The absence of secret-dependent table lookups (`table[secret]`) eliminates the primary disclosure gadget exploited by speculative execution (Spectre, Retbleed) and cache-timing attacks.
2. **Side-Channel Bound on Intermediate Recovery:** If physical side-channel attacks (DPA, SPA, electromagnetic analysis) extract intermediate states from the pixel data path, the observable value is restricted to per-pixel bit rotation amounts. Inverting these rotation values to recover master seed material is computationally infeasible under the PRF assumption.
3. **Multi-Layer Cryptographic Isolation:** Even if bit rotations were partially recovered, seed isolation ensures zero leakage of other operational domains:
   - Deriving plaintext requires the independent `startSeed` (determining start pixel) and the independent `noiseSeed` (masking noise bit positions).
   - The always-on 48-bit Interlocked Barrier interposes an independent ≈ 2^70.20 PRF-keyed mask partition per chunk derived from the isolated `lockSeed`.
   - Security against Known-Plaintext Attacks remains 4-factor under the PRF assumption (5-factor under Partial KPA; see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

---

## References

- [Spectre](https://spectreattack.com/) — Kocher et al., 2018
- [Meltdown](https://meltdownattack.com/) — Lipp et al., 2018
- [Downfall / GDS](https://downfall.page/) — Moghimi, 2023
- [Hertzbleed](https://hertzbleed.com/) — Wang et al., 2022
- [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html) — Ormandy, 2023
- [Rowhammer](https://googleprojectzero.blogspot.com/2015/03/exploiting-dram-rowhammer-bug-to-gain.html) — Seaborn & Dullien, 2015
- [Training Solo](https://www.vusec.net/projects/training-solo/) — VUSec, 2025
