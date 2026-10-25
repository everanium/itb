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
- **Heap Residue Management:** Sensitive structures reside in process heap memory during execution (expanded seed components `Seed.Components []uint64`, intermediate hash states, and active payload buffers). The runtime provides explicit `Pipeline.Close()` and `Cipherset.Close()` zeroization, executes `secureWipe` (lowering to `runtime.memclrNoHeapPointers`) on pooled/intermediate buffers and SoEM22 states immediately after use, runs `wipeInterlockWorker48` and `wipeInterlockWorker168` (pinned with `runtime.KeepAlive`) on per-worker 48-bit and 168-bit Rank Barrier scratch and mask arrays, and zeroes KDF, MAC, DRBG, keystream, and wrapper internal states before release. Hot-path buffer reuse is bounded through P-independent caches (`bufferCache`, `stageCache`, `tripleScratchCache`, `streamChunkCache`, and `wrapperScratchCache`) with high-water-mark zeroization (`releaseStage` and `scratchHW`, zeroing only the written prefix before release). Pre-allocated stream and PRF states are repositioned and reused in place across `ctr` (`ResetCounter`), `parallax`, and `internal/hashprf` without per-operation key or state heap allocations, and cold-path entry points zero transient master-key and session-blob staging buffers across the CAPI and language binding layers.
- **Stack & Register Epilogue Zeroization:** All eleven 48-bit and 168-bit Interlocked Barrier assembly files (`interlockasm48_{,x16_,avx2_,batch_}amd64.s`, `interlockasm48_{neon,sve2}_arm64.s`, `interlockasm168_{,avx2_,batch_}amd64.s`, `interlockasm168_{neon,sve2}_arm64.s`) execute with `NOSPLIT`, `$0` stack frames, and zero stack spills (the AMD64 unrank kernels stage `m1Local` in `out[1]` and `remaining` / `u` in `out[2]` in-place before the scalar `PDEPQ` remap tail, the 48-bit NEON kernel stages `remaining` in `out[2]`, and the 168-bit NEON kernel holds `m1Local` and `u` entirely in vector registers), zeroing vector registers (`ZMM`, `YMM`, `NEON V0..V31`, `SVE2 Z0..Z9` in `unchunk48LockBatchSVE2` and `Z0..Z6` / `Z0..Z8` in `chunk168LockBatchSVE2` / `unchunk168LockBatchSVE2`), opmasks (`K1..K7`), stack argument slots (in `Chunk168Lock` / `Unchunk168Lock`), and GPRs before `VZEROUPPER` / `RET` (verified by `TestFusedKernelsLeaveNoSecretInFrame`), while `splitRank168` zeroes `r` and `q`, `rankToMaskTriple168` / `rankToMaskTriple168FromSplit` zero `r`, `idx0`, `idx1`, `m1Local`, and `remaining`, and `fillLockMasksTriple48*` / `fillLockMasksTriple168Super*` / `wipeInterlockWorker{48,168}` zero per-worker scratch, `idx0`, `idx1`, and `out` via `clear` + `runtime.KeepAlive` (verified by `TestInterlock168StackZeroization`). Areion-SoEM (`internal/areionasm/` and `github.com/everanium/areion`) keeps `K1`, `k2`, and `w = K1 ⊕ k2` 100% register-resident across all five tiers (`zmm`, `ymm`, `vex`, `sse`, `neon`) with zero stack spills of subkeys or whitening, and zeroes key-holding registers (`K1`, `k2`, `w`) and the non-output permutation branch (`s2`) before `VZEROUPPER` / `RET`. Across the registry hash kernels (`blake2b`, `blake2s`, `blake3`, `aescmac`, `siphash`, `chacha20`), `avx512` BLAKE kernels hold multi-block chaining state `H[0..7]` in `X24..X31` / `Y24..Y31` / `Z24..Z31` with zero secret stack slots, `chacha20` builds `K ⊕ component ⊕ h` directly in `v[4..11]` in registers, and any stack-frame slots holding key/seed words, spilled state words (`v[15]` / `v[12]` on `avx2`, `v[11]` on `gpr_amd64`), or multi-block chaining values (`H[0..7]` on non-EVEX tiers) along with secret-holding vector and GPR registers are wiped before `RET`. Across the CTR keystream XOR and 4-lane Batch-PRF assembly packages (`internal/blake2bctr`, `internal/blake2sctr`, `internal/blake3ctr`, `internal/siphash24`, `internal/chacha20ctr`), every entry point executes with `NOSPLIT` and a `$0` stack frame (using GPR swap pairs `R8..R11` or `R12..R13` on `AVX2` BLAKE2b/2s/3 instead of stack spills) and wipes all touched vector registers (`X0..X31` / `Y0..Y31` / `Z0..Z31` on `AVX-512VL` and `Y0..Y15` on `AVX2` prior to `VZEROUPPER`, and `V0..V31` on `ARM64 NEON`), scratch GPRs, and stack argument slots before `RET`.
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
2. **Interlocked Barrier (`internal/interlock/`, `interlock48*.go`, `interlock168*.go`):**
   - **Rank Reduction & Combinadic Unrank:** Constant-time 128-bit reciprocal-multiplication rank splitting (`splitRank48Recip` via `MULQ` / `UMULH` with `interlockB48Recip` and `interlockA48Recip` for 48-bit 6-byte chunks) and constant-time branchless 512-bit (base `2^64`, 8 `uint64` limbs) Knuth Algorithm D two-step reciprocal rank splitting (`splitRank168` in `interlock168_rank_split.go`: 7 `divmodStepB168` steps dividing by 2-limb `B₁₆₈ = C(112, 56)` and 5 `modStepA168` steps reducing modulo 3-limb `A₁₆₈ = C(168, 56)` in GPRs for 168-bit 21-byte chunks, eliminating variable-latency `DIVQ` across all architectures), followed by `$0`-frame AVX-512F 8/16-lane (`rankToMaskTripleUnrank48AVX512`, `rankToMaskTripleUnrank48x16AVX512`, `rankToMaskTripleUnrank168AVX512` over `crow168Packed [303][64]uint64` = `155,136` bytes), AVX2 (`rankToMaskTripleUnrank48AVX2`, `2 × 4` YMM `rankToMaskTripleUnrank168AVX2`), and NEON 8-lane (`rankToMaskTripleUnrank48NEON`, `4 × 2` lane `rankToMaskTripleUnrank168NEON` over `crow168PackedNEON`) unrank kernels.
   - **Chunk Apply / Unapply:** BMI2 hardware `PEXTQ` / `PDEPQ` scalar and batched kernels (`interlockasm48_amd64.s`, `interlockasm48_batch_amd64.s`, `Chunk168Lock` / `Unchunk168Lock` in `interlockasm168_amd64.s`, `chunk168LockBatch` / `unchunk168LockBatch` in `interlockasm168_batch_amd64.s` producing 3 × 56-bit lanes across the 3 chunk words `64 + 64 + 40` bits via 3 `PEXTQ` / `PDEPQ` calls and `POPCNTQ < 64` stitch shifts per lane), SVE2 BitPerm `BEXT` / `BDEP` (`interlockasm48_sve2_arm64.s`, `chunk168LockBatchSVE2` / `unchunk168LockBatchSVE2` in `interlockasm168_sve2_arm64.s`), batched ARM64 constant-time set-bit-walk (`pext16` / `pdep16` via `RBIT` + `CLZ` in `interlockasm48_batch_arm64.go`, 56-step 3-limb `pext56` / `pdep56` via branchless word selection + `TrailingZeros64` in `interlockasm168_batch_arm64.go`), and branchless scalar `softPEXT48` / `softPDEP48` and `softPEXT168` / `softPDEP168`.
3. **AES-ITB-128 & Areion Cascades (`internal/aesitbasm/`, `internal/areionasm/`):**
   - VAES ZMM/YMM fused ChainHash cascade kernels, AES-NI XMM kernels, ARM64 Crypto Extension `AESE` / `AESMC` kernels, 4-lane batched SoEM22 (`Areion{256,512}SoEMPermutex4*`), and `aesitb128` DRBG noise-fill kernels.
4. **Registry Hash Families (`hashes/internal/`):**
   - Fused ChainHash cascade kernels for each shipped registry primitive across AVX-512, AVX2, NEON, and 64-bit GPR scalar tiers.
5. **CTR Keystream XOR & 4-Lane Batch-PRF Kernels (`internal/blake2bctr/`, `internal/blake2sctr/`, `internal/blake3ctr/`, `internal/siphash24/`, `internal/chacha20ctr/`):**
   - `$0`-frame (`NOSPLIT`) `AVX-512VL`, `AVX2`, and `ARM64 NEON` counter-mode keystream XOR and 4-lane batched PRF evaluation kernels shared by `ctr`, `wrapper`, `parallax`, `internal/drbg`, `internal/hashprf`, and `kdf`.

### 5.2 Microarchitecture Floors & Tier Dispatch

- **Top Tier (AVX-512 + VAES):** Intel 11th Gen Core (Rocket Lake) and Xeon Scalable (Ice Lake-SP+); AMD Zen 4+. Fused ZMM cascades, AVX-512F 48-bit and 168-bit unrank, and Tier A/A′ pixel kernels.
- **Mid Tier (AVX2 Baseline):** Intel Haswell through Comet Lake; AMD Zen 1–3. Features YMM vector cascades, AVX2 48-bit and 168-bit (`2 × 4` YMM) unrank, and Tier B/B′ pixel kernels. Hardware BMI2 `PEXT` / `PDEP` are constant-time on Haswell+ and Zen 3+.
- **AArch64 Tier (ARMv8-A + Crypto + SVE2):** Server baseline (AWS Graviton 2+, Neoverse N1/V1/V2, Apple Silicon) leverages NEON vector cascades (including 8-lane 48-bit and 168-bit NEON unrank) and ARM Crypto Extension `AESE`/`AESMC`. SVE2 BitPerm (`FEAT_SVE_BitPerm`) accelerates 48-bit and 168-bit chunking on Graviton 4 / Neoverse V2.
- **Portable Fallback Floor:** hosts without BMI2 route through the branchless portable Go fallbacks (`softPEXT48` / `softPDEP48`, `softPEXT168` / `softPDEP168`) and the Go rank-unrank paths (`rankToMaskTriple48`, `rankToMaskTriple168` / `rankToMaskTriple168FromSplit`).
- **AMD Zen 1 / Zen 2:** these CPUs carry BMI2 but microcode-emulate `PEXT` / `PDEP`, with a latency that grows with the mask popcount (three `PEXTQ`: ~23 / 65 / 126 / 183 ns at popcount 1 / 16 / 32 / 47 on an AWS c5a Zen 2 host). Every Rank Barrier mask has a fixed total popcount per lane (16 of 48 bits in 48-bit mode; 56 of 168 bits across three words in 168-bit mode), and on the same host three `PEXTQ` over 1024 random balanced mask triples measured 69.2 ns against 67.2 ns for one fixed triple. This is a single-host measurement, not a constant-time guarantee; these hosts run the hardware BMI2 kernels.
- **Dispatch Testing Knobs:** Test harnesses force individual tiers using `ITB_FORCE_HASH_TIER`, `ITB_FORCE_INTERLOCK_TIER`, `ITB_FORCE_INTERLOCK_PRF_FILL_TIER`, `ITB_FORCE_CHAINHASH_X4`, and `ITB_FORCE_PIXEL_TIER`.

---

### 5.3 Instruction-Level Side-Channel Inventory

The inventory below classifies each hardware instruction utilized in ITB by its microarchitectural latency profile. ITB does not rely on instruction-level timing invariance for foundational security; the barrier is established architecturally at the software layer.

| Instruction(s) | Component / Path | CPU Floor | Side-Channel Profile | ITB Architectural Exposure |
|---|---|---|---|---|
| `VAESENC`<br>`VAESENCLAST` | `aesitbasm`<br>`areionasm`<br>`aescmacasm` (AMD64) | Intel Ice Lake+<br>AMD Zen 3+ (YMM)<br>Zen 4+ (ZMM) | Constant-time hardware AES across all supporting microarchitectures. Eliminates software S-box and T-table timing side-channels. | AES-ITB-128, Areion-SoEM, and AES-CMAC ChainHash execute entirely through vector AES. Lane staging uses fixed register-to-register moves (`VINSERTI64X2`, `VEXTRACTI64X2`, `VPXORQ`). |
| `AESENC`<br>`AESENCLAST`<br>`PXOR`, `MOVOU` | `aesitbasm`<br>`areionasm`<br>`aescmacasm` (AES-NI) | Intel Westmere+<br>AMD Bulldozer+<br>(Universal on AVX2) | Constant-time hardware AES. Independent chains are interleaved to hide execution latency on single-issue AES ports without branches. | Deployed on AES-NI hosts lacking VAES (Cascade Lake, cloud VMs). Round keys and constants are read from public read-only tables at fixed offsets. |
| `AESE`<br>`AESMC` | `aesitbasm`<br>`areionasm`<br>`aescmacasm` (AArch64) | ARMv8-A `+crypto`<br>(AWS Graviton 2+<br>Neoverse N1/V2, M1+) | Constant-time hardware AES per ARM Architecture Reference Manual. No table-lookup fallback paths. | AES-ITB-128, Areion-SoEM, and AES-CMAC fused cascades run via 4-lane parallel `AESE`/`AESMC` pipelines. Fallbacks utilize `aes.Round4HW`. |
| `VGF2P8AFFINEQB` | `process_pixels.c`<br>(Tier A / Tier B) | Intel Ice Lake+<br>AMD Zen 4+ | Constant-time GF(2) affine transformation with data-independent execution latency. | Computes per-pixel bit rotation (Phase 4) and noise-bit insert/extract (Phase 5). Affine matrices are fetched from 64-byte aligned single-cacheline tables. |
| `VPSLLVW`, `VPSRLVW`<br>`VPTERNLOGQ` | `process_pixels.c`<br>(Tier A′ No-GFNI) | AVX-512F+BW+VL<br>Intel Skylake-X+<br>AMD Zen 4+ | Variable vector shifts take secret-derived shift counts; latency is documented invariant on all AVX-512BW microarchitectures. | Batched pixel encoding on AVX-512 hosts lacking GFNI/VBMI (Cascade Lake Xeon). `VPTERNLOGQ` evaluates bitwise ternary logic with compile-time constants. |
| `VPSLLVQ`, `VPSLLW`<br>`VPMADDUBSW` | `process_pixels.c`<br>(Tier B′ No-GFNI) | AVX2 Baseline<br>Intel Haswell+<br>AMD Zen 1+ | Constant-time reciprocal throughput. Variable shifts use secret-derived counts with data-oblivious execution latency. | 4-pixel batch encoder on AVX2 hosts without GFNI (Haswell, Zen 3). Synthesizes rotation via shift-mask-OR and packs via multiply-add trees. |
| `VPERMB` | `process_pixels.c`<br>(Tier A) | Intel Ice Lake+<br>AMD Zen 4+ | Constant-time intra-register byte permutation. Operates strictly within vector registers; distinct from memory `GATHER` instructions. | Byte gathering from packed plaintext and lane compaction prior to masked stores. Permutation index vectors are public compile-time constants. |
| `VPMULTISHIFTQB` | `process_pixels.c`<br>(Tier A) | Intel Ice Lake+<br>AMD Zen 4+ | Constant-time bit-field extraction with data-independent latency. | Extracts eight 7-bit channel fields from 64-bit packed pixel descriptors. |
| `VPMADDUBSW`<br>`VPMADDWD` | `process_pixels.c`<br>(Decode Pack Step) | AVX2 / AVX-512BW<br>Haswell+, Zen 1+ | Fixed-latency integer multiply-add. Multiplier operands are compile-time constants; only multiplicands carry secret-derived channel values. | Folds eight 7-bit channel values into one 56-bit word per qword lane. Destination store addresses derive exclusively from public geometry parameters. |
| `PEXTQ`<br>`PDEPQ` | `internal/interlock/`<br>(AMD64 BMI2) | Intel Haswell+<br>AMD Zen 1+<br>(BMI2) | Constant-time execution on Intel Haswell+ and AMD Zen 3+. On AMD Zen 1 / Zen 2 the microcode-emulated latency grows with the mask popcount, which is fixed (see the AMD Zen 1 / Zen 2 entry above). | Executes 48-bit (`Chunk48Lock` / `Unchunk48Lock`, `chunk48LockBatch` / `unchunk48LockBatch`) and 168-bit (`Chunk168Lock` / `Unchunk168Lock`, `chunk168LockBatch` / `unchunk168LockBatch` extracting/depositing 3 × 56-bit lanes across the 3 chunk words `64 + 64 + 40` bits via 3 `PEXTQ` / `PDEPQ` calls per lane stitched with `POPCNTQ` shifts `< 64`) Interlocked Barrier chunk-apply/unapply and the unrank remap tails. Balanced 16-of-48 and 56-of-168 lane partitions guarantee invariant total popcounts (16 and 56 bits) across all lanes. |
| `VPERMI2Q`<br>`VPERMT2Q`<br>`VPBLENDMQ`<br>`VPCMPUQ`<br>`VPTESTMQ` | `internal/interlock/`<br>(AVX-512 Unrank) | AVX-512F Baseline<br>Skylake-X+, Zen 4+ | Constant-time intra-register qword permute and blend selecting binomial constants C(p, k). Register-only; no secret-indexed memory access. | Batched 8-lane and 16-lane 48-bit (`rankToMaskTripleUnrank48{,x16}AVX512`) and 8-lane 168-bit (`rankToMaskTripleUnrank168AVX512` over `crow168Packed [303][64]uint64` = `155,136` bytes with 3-limb / 2-limb / 1-limb borrow propagation in `K1..K7`) Interlocked Barrier unrank kernels (`$0-32` zero-byte stack frame; `m1Local` and `remaining` / `u` staged in `out[1]` and `out[2]` in-place). Table row loads index by public loop counter p (`[0, 47]` or `[0, 167]`), never by secret values. |
| `VPERMD`<br>`VPCMPEQQ`<br>`PDEPQ` | `internal/interlock/`<br>(AVX2 Unrank) | AVX2 + BMI2<br>Haswell+, Zen 1+ | Constant-time intra-register dword permutation over in-register sources. Mask generation uses branchless predicate masks. | 4-lane 48-bit (`rankToMaskTripleUnrank48AVX2`) and 8-lane `2 × 4` YMM 168-bit (`rankToMaskTripleUnrank168AVX2` over `crow168Packed` with 3-limb / 2-limb / 1-limb sign-flipped `VPCMPGTQ` borrow propagation) AVX2 unrank kernels (`$0-32` zero-byte stack frame; in-place `PDEPQ` + `POPCNTQ` remap over `out`) for systems without AVX-512. Produces bit-exact mask triples matching the AVX-512 implementation. |
| `VTBX`<br>`VCMHS`<br>`VUSHL` | `internal/interlock/`<br>(NEON Unrank) | ARMv8-A Baseline<br>(Advanced SIMD) | Constant-time register table lookups (`VTBX`) over in-register binomial tables. Data-oblivious variable register shifts (`VUSHL`). | 8-lane AArch64 unrank kernels (`rankToMaskTripleUnrank48NEON` sharing each binomial row load across 8 lanes, and `4 × 2` lane `rankToMaskTripleUnrank168NEON` over `crow168PackedNEON` in `V0..V31` sharing each row load across the 2 lanes of the active `.D2` pair, `$0-32` zero-byte stack frame). Produces bit-exact mask triples. |
| `BEXT`<br>`BDEP` | `internal/interlock/`<br>(SVE2 BitPerm) | ARMv8.5-A+ SVE2<br>(Graviton 4, Neoverse V2) | Vector bit-extract/deposit operating across 64-bit lanes under mask vectors. Register-only; no memory-indexed addressing. | Hardware-accelerated batched chunk-apply on ARM64 (`chunk48LockBatchSVE2` / `unchunk48LockBatchSVE2` in `Z0..Z9`, and `chunk168LockBatchSVE2` in `Z0..Z6` / `unchunk168LockBatchSVE2` in `Z0..Z8` with `VCNT` stitch shifts, `$0` stack frame). |
| `VPADDQ`, `VPXORQ`<br>`VPRORQ`, `VPTERNLOGQ` | `hashes/internal/*`<br>`internal/*ctr`<br>`internal/siphash24`<br>(AVX-512 AMD64) | AVX-512F+DQ+VL<br>Skylake-X+, Zen 4+ | Single-cycle reciprocal throughput. Rotates use immediate compile-time constants. Embedded broadcasts (`.BCST`) read fixed stack or RODATA offsets. | Fused cascade and `$0`-frame CTR keystream XOR / 4-lane Batch-PRF kernels for BLAKE2b, BLAKE2s, BLAKE3, SipHash-2-4, and ChaCha20. Operates in 4-lane and 8-lane vector strides with register-only ARX execution and constant-time lane-interleave permutations (`VPUNPCK*`, `VSHUFI64X2`, `VPERM2I128`); BLAKE multi-block chaining state `H[0..7]` stays register-resident in `X24..X31` / `Y24..Y31` / `Z24..Z31`. |
| `VPADDQ`, `VPXOR`<br>`VPSHUFB`, `VPSLLQ` | `hashes/internal/*`<br>`internal/*ctr`<br>`internal/siphash24`<br>(AVX2 AMD64) | AVX2 Baseline<br>Haswell+, Zen 1+ | Constant-time integer arithmetic. Rotates are synthesized via compile-time shuffle masks (`VPSHUFB`) and immediate shift-OR pairs. | AVX2 fused cascade and `$0`-frame CTR keystream XOR / 4-lane Batch-PRF kernels for registry hashes (using GPR swap pairs `R8..R11` or `R12..R13` on BLAKE2b/2s/3 instead of stack spills, and constant-time `VPUNPCK*` + `VPERM2I128` lane interleave). ChaCha20 rebuilds `K ⊕ component ⊕ h` in registers per round; message and slot words use fixed-offset stack frames without secret-indexed addressing. |
| `ADDQ`, `XORQ`<br>`ROLQ`, `RORQ` | `hashes/internal/*`<br>(GPR Scalar) | Any x86-64 / ARMv8-A<br>(Universal Baseline) | Constant-time scalar integer ALU instructions with immediate counts. Fixed-stride iterations over component arrays. | Single-lane fallback cascade kernels across all hash primitives. Loops track public round counts with branchless termination conditions. |
| `VADD`, `VEOR`<br>`VSHL`, `VSRI` | `hashes/internal/*`<br>`internal/*ctr`<br>`internal/siphash24`<br>(NEON ARM64) | ARMv8-A Baseline<br>(Universal Advanced SIMD) | Fixed-latency SIMD integer operations. Rotates synthesized via `VSHL` + `VSRI` (plus `VREV64`/`VREV32`/`VTBL` byte rotates) with constant immediates from algorithm specifications. | 4-lane fused cascade and `$0`-frame CTR keystream XOR / 4-lane Batch-PRF kernels on AArch64 for BLAKE2b, BLAKE2s, BLAKE3, SipHash-2-4, and ChaCha20, using register-only ARX execution and constant-time `VZIP1`/`VZIP2` lane-interleave permutations. |
| `VZEROUPPER` | Kernel Exits<br>(AVX2 / AVX-512) | AVX Baseline | Clears upper bits (128..511) of `YMM`/`ZMM` registers. Prevents AVX-SSE transition penalties. Does not zero lower 128-bit `XMM` state. | Kernel epilogues explicitly zero secret-carrying vector registers (`XMM`/`YMM`/`ZMM`/`NEON`/`SVE2`), opmasks (`K1..K7`), GPRs, and any secret-holding stack-frame slots prior to `VZEROUPPER` / `RET`. |
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
- **Rank Barrier:** 128-bit rank reduction executes via `splitRank48Recip` (constant-time 64-bit reciprocal multiplications with `interlockB48Recip` and `interlockA48Recip` and branchless correction), and 512-bit rank reduction executes via `splitRank168` in `interlock168_rank_split.go` (constant-time branchless Knuth Algorithm D two-step reciprocal reduction in base `2^64`: 7 `divmodStepB168` steps against 2-limb `B₁₆₈ = C(112, 56)` using `interlockMuB168_{0,1}` and 5 `modStepA168` steps against 3-limb `A₁₆₈ = C(168, 56)` using `interlockMuA168_{0,1,2}` via `bits.Mul64` / `bits.Add64` / `bits.Sub64` in GPRs, eliminating variable-latency hardware `DIVQ` across all architectures). Chunk application on ARM64 without SVE2 BitPerm uses the fixed 16-step (`pext16` / `pdep16` via `RBIT` + `CLZ` in `interlockasm48_batch_arm64.go`) and 56-step 3-limb (`pext56` / `pdep56` via branchless non-zero word selection and `bits.TrailingZeros64` in `interlockasm168_batch_arm64.go`) set-bit-walks, while portable targets execute `softPEXT48` / `softPDEP48` and `softPEXT168` / `softPDEP168` (fixed 48-iteration and 56-iteration branchless loops using arithmetic word-selection masks, LSB isolation, bitwise AND/OR, and variable shifts without lookup tables or secret-dependent branching).
- **Hash Cascades:** Dispatches through scalar portable Go reference functions.
- **Areion & AES Primitives:** `github.com/everanium/areion` executes a constant-time 64-bit bitsliced Boyar–Peralta S-box and branchless MixColumns `purego` fallback (zero lookup tables, zero secret-dependent memory accesses), while AES primitives fall back to `aes.Round4HW` or software constant-time implementations.

All fallback paths enforce register-only, branchless evaluation over secret inputs to preserve side-channel resistance across unaccelerated targets.

---

## Summary & Threat Model Verdict

1. **Absence of Memory Disclosure Gadgets:** ITB's data path executes secret-dependent operations (`noisePos`, `dataRotation`, `channelXOR`, barrier mask applications) entirely within CPU registers. The absence of secret-dependent table lookups (`table[secret]`) eliminates the primary disclosure gadget exploited by speculative execution (Spectre, Retbleed) and cache-timing attacks.
2. **Side-Channel Bound on Intermediate Recovery:** If physical side-channel attacks (DPA, SPA, electromagnetic analysis) extract intermediate states from the pixel data path, the observable value is restricted to per-pixel bit rotation amounts. Inverting these rotation values to recover master seed material is computationally infeasible under the PRF assumption.
3. **Multi-Layer Cryptographic Isolation:** Even if bit rotations were partially recovered, seed isolation ensures zero leakage of other operational domains:
   - Deriving plaintext requires the independent `startSeed` (determining start pixel) and the independent `noiseSeed` (masking noise bit positions).
   - The always-on Interlocked Barrier interposes an independent ≈ 2^70.20 (48-bit mode, 6-byte chunks) or ≈ 2^258.60 (168-bit mode, 21-byte chunks) PRF-keyed mask partition per chunk derived from the isolated `lockSeed`.
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
