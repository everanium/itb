# ITB: Hardware-Level Threat Analysis

> **Disclaimer.** This analysis is self-assessment by the author and has not been independently verified. ITB does not claim resistance to any hardware-level attack. The information-theoretic barrier is a **software-level property**, reinforced by two independent barrier mechanisms: noise absorption from CSPRNG, and encoding ambiguity (56^P without CCA, 7^P under CCA) from triple-seed isolation. Architectural layers deny the point of application: independent startSeed and 8-noisePos ambiguity from independent noiseSeed under Full KPA, plus gcd(7,8)=1 byte-splitting under Partial KPA. Full KPA defense is 3-factor under PRF assumption (4-factor under Partial KPA) — see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance). It provides no guarantees against hardware-level attacks. The observations below describe architectural properties of the construction's data path, not proven security guarantees. PRF-grade hash functions are required. No warranty is provided.

## Scope

This document analyzes ITB's data path against known hardware-level attack classes. The analysis applies to both the pure Go backend and the CGO backend (GCC `-O3`, AVX2 on x86-64, NEON on ARM64). Analysis based on GCC 13/14 output; other compilers or versions may produce different instruction sequences.

**Key architectural property:** ITB's secret-dependent operations (`noisePos`, `dataRotation`, `channelXOR`) use only register operations (bitwise shift, XOR, AND, OR). There are no secret-dependent array accesses (no S-box, no T-tables, no key-dependent table lookups). The root cause exploited by many microarchitectural attacks against ciphers with secret-dependent table lookups — `table[secret_index]` — is absent from ITB's data path. This has not been independently verified.

## Category 1: Speculative Execution Variants

All speculative execution attacks require a disclosure gadget: a secret-dependent memory access that leaves a cache or microarchitectural trace. ITB's data path does not contain such a gadget. This has not been independently verified.

| Attack | CVE | Mechanism | ITB Data Path | Status |
|---|---|---|---|---|
| Spectre v1 (bounds check bypass) | CVE-2017-5753 | Mistrained branch → speculative `array[secret]` → cache trace | No secret-dependent array indexing; `noisePos`/`dataRotation` used as shift amounts only | No known gadget |
| Spectre v2 (branch target injection) | CVE-2017-5715 | Poisoned BTB → speculative jump to gadget | Secret-dependent ops are register-only; no memory access under misprediction | No known gadget |
| Spectre v4 (speculative store bypass) | CVE-2018-3639 | Speculative load reads stale value before store completes | `rotateBits7` is register-to-register; no store→load on same address | No known gadget |
| Retbleed | CVE-2022-29900/01 | Exploits return instructions as speculative gadgets | Same requirement: needs secret-dependent memory access gadget | No known gadget |
| Inception / AMD Phantom | CVE-2023-20569 | Trains branch predictor to attacker-chosen address | Same requirement | No known gadget |
| Downfall / GDS | CVE-2022-40982 | Gather Data Sampling leaks from SIMD registers via `gather` instruction | CGO backend does not use `gather` instructions (verified with GCC 13/14); AVX-512 VBMI paths use `VPERMB` (intra-register byte-permute, distinct from `GATHER` which reads from memory by index vector). See [Category 5](#category-5-instruction-set-side-channel-profile) for the per-instruction inventory | Not applicable |
| GhostRace | CVE-2024-2193 | Spectre + race conditions on shared data | No secret-dependent branching on shared data | No known gadget |
| Indirector | 2024 (no CVE) | High-precision BPU manipulation (Intel) | Same fundamental requirement: disclosure gadget | No known gadget |
| BHI (Branch History Injection) | CVE-2022-0001 / CVE-2024-2201 | Intra-mode BTI with branch history manipulation | Same requirement | No known gadget |
| SLAM | 2023 | Spectre via Linear Address Masking | Same pattern: needs `memory[secret]` | No known gadget |
| Training Solo | CVE-2024-28956 | History-based Spectre-v2 extension (Intel/ARM) | Same requirement | No known gadget |
| Branch Privilege Injection | CVE-2024-45332 | Privilege escalation via branch prediction (Intel) | Same class | No known gadget |
| TSA (Transient Scheduler Attacks) | 2025 | Leaks stale data from scheduler (AMD Zen 3/4) | Leaks data from other processes, not from ITB's secret-dependent computation | Not ITB-specific |

## Category 2: Data Sampling / Stale Data Leaks

These attacks read stale data from internal CPU buffers (line fill buffers, store buffers, register files). If the ITB process handles seeds, stale seed bytes may remain in CPU buffers. This is identical for all software symmetric ciphers (AES round keys, ChaCha20 state) — not specific to ITB. This has not been independently verified.

| Attack | CVE | Mechanism | ITB Impact | Status |
|---|---|---|---|---|
| MDS (RIDL, Fallout, ZombieLoad) | CVE-2018-12126/27/30, CVE-2019-11091 | Leak data from line fill / store buffers | Seeds/plaintext may remain in buffers; identical to AES/ChaCha20 | Not ITB-specific |
| MMIO Stale Data | CVE-2022-21123/25/66 | Leak data from memory-mapped I/O operations | ITB does not use MMIO | Not applicable |
| RFDS (Register File Data Sampling) | 2024, Intel Atom | Leaks stale register values | dataSeed hash values could remain in registers; identical for AES round keys | Not ITB-specific |
| Zenbleed | CVE-2023-20593 | AVX register file leak (AMD Zen 2 only) | CGO backend AVX2 registers could retain hash values; fixed by microcode update, Zen 2 only | Not ITB-specific; mitigated by vendor |

## Category 3: Cache / Interconnect / Power Contention

| Attack | Year | Mechanism | ITB Data Path | Status |
|---|---|---|---|---|
| Hertzbleed | 2022 | CPU frequency throttling converts power analysis to remote timing; data-dependent power → frequency → timing | ITB's secret-dependent scalar operations are register-only XOR/shift with data-independent latency. Vector paths use AVX2 / AVX-512 / GFNI / VBMI / VAES / BMI2 instructions; see [Category 5](#category-5-instruction-set-side-channel-profile) for the per-instruction profile, including the AMD Zen 1 / Zen 2 BMI2 PEXT/PDEP microcode-emulation caveat. DVFS transitions under these instructions have not been independently measured | No known attack surface |
| SQUIP | 2022 | Scheduler queue contention leaks execution patterns across SMT threads (AMD) | ITB's per-pixel processing executes the same instruction sequence per pixel regardless of secret values; no secret-dependent branching (not independently verified) | No known attack surface |
| Interconnect side-channels | Various | Shared bus contention leaks access patterns | Container access pattern (startPixel) is already documented as cache side-channel limitation | Documented limitation |

## Category 4: Memory Integrity

| Attack | Mechanism | ITB Impact | Status |
|---|---|---|---|
| Rowhammer | Repeated DRAM row activation flips bits in adjacent rows | Could corrupt seeds, container, or plaintext in memory; general memory integrity attack affecting all software | Not ITB-specific |
| RAMBleed | Reads data through Rowhammer-induced bit flips | Could read seed bytes from adjacent DRAM rows; identical for AES keys | Not ITB-specific |

**Mitigation:** ECC memory detects and corrects single-bit flips. For high-security deployments, ECC memory is recommended alongside hardware memory encryption (AMD SEV, Intel SGX/TDX, ARM CCA).

**Heap memory exposure.** Sensitive data resides in heap memory during the lifetime of the process: seed components (`Seed.Components []uint64`), intermediate hash buffers, and plaintext during encode/decode. The library mitigates by calling `secureWipe` on intermediate buffers after use, but cannot wipe Go runtime internals or kernel buffers used during `crypto/rand` generation. Additionally, cached hash wrappers (e.g., `makeAESHash()`, `makeBlake3Hash()`) store a fixed random key in a closure for the lifetime of the session — this key persists in heap memory and is not wiped until the process exits. If an attacker can read heap memory (Meltdown, memory dump, debugger), they can read seeds and cached keys directly — regardless of the cipher used. This is identical for all software symmetric ciphers and is not specific to ITB.

## Category 5: Instruction-Set Side-Channel Profile

This category documents the side-channel profile of individual CPU instructions used in ITB's hardware-accelerated paths. Coverage spans `process_pixels.c` (the per-pixel encode/decode kernel — Tier A: AVX-512F + AVX-512BW + AVX-512VL + GFNI + AVX-512VBMI; Tier B: AVX2 + GFNI; Tier C: portable scalar C), `internal/areionasm/areion_amd64.s` (VAES + AVX-512 / AVX2 implementation of the Areion-SoEM permutation), and `internal/locksoupasm/locksoupasm_amd64.s` (BMI2 + AVX-512 VBMI implementation of Lock Soup keyed bit-permutation kernels).

The inventory below classifies each instruction by its known data-dependent latency profile across supporting microarchitectures. ITB's correctness does not depend on any of these instructions being constant-time; the architectural barrier is software-level. The table records the instruction-level reality so that deployments targeting hardware-aware threat models can audit against it. This analysis has not been independently verified.

| Instruction | Used In | CPU Support | Side-Channel Profile | ITB Exposure |
|---|---|---|---|---|
| `VAESENC` / `VAESENCLAST` | `areion_amd64.s` | VAES on YMM: Ice Lake+ / Tiger Lake / Zen 3+; VAES on ZMM: Ice Lake-SP+ / Zen 4+ | Constant-time hardware AES on all known supporting microarchitectures. No T-table fallback in this path; immune to classical AES cache-timing attacks (Bernstein 2005, Osvik / Shamir / Tromer 2006) targeting software S-box / T-table implementations | Areion-SoEM permutation runs entirely in this path on hosts with VAES; the pure-Go fallback uses `aes.Round4HW` from `github.com/jedisct1/go-aes` and inherits that upstream implementation's properties |
| `VGF2P8AFFINEQB` (GFNI) | `process_pixels.c` Tier A / B | Ice Lake+ / Tremont+ / Zen 4+ | Constant-time GF(2)-affine transformation. No published side-channel attacks. Latency is not data-dependent | Tier A / B Phase 4 (per-pixel rotation) and Phase 5 (noise-bit insert / extract) lower to single-instruction GFNI affine. Affine matrices are constructed in scalar C loops bounded to 8 iterations from `noisePos` / `dataRotation`; the loops have constant trip count, and the constructed matrices then enter constant-time GFNI |
| `VPERMB` (AVX-512 VBMI) | `process_pixels.c` Tier A; `locksoupasm_amd64.s` Single Lock Soup | Cannon Lake+ / Ice Lake+ / Tiger Lake / Zen 4+ | Constant-time byte-permutation within a vector register. **Not** a memory-gather instruction — Downfall (CVE-2022-40982) targets `vpgatherdd` / `vpgatherqq` and similar `GATHER` family instructions that read from memory by index vector; `VPERMB` shuffles bytes within an existing register | Tier A Phase 1 (8-pixel byte gather from packed plaintext); Single Lock Soup per-chunk keyed permutation kernel |
| `VPMULTISHIFTQB` (AVX-512 VBMI) | `process_pixels.c` Tier A | Ice Lake+ / Zen 4+ | Constant-time. Latency is not data-dependent | Tier A Phase 1: 8 × 7-bit field extraction from 64-bit packed pixel descriptors |
| `VPMOVM2B` / `VPABSB` / `VPTESTMB` / `KMOVD` | `locksoupasm_amd64.s` Single Lock Soup | AVX-512BW / AVX-512F | Constant-time. Latency is not data-dependent | Single Lock Soup VPERMB-based permutation kernel: mask-register / vector-register interconversion around the `VPERMB` core |
| `PEXTL` / `PDEPL` (BMI2) | `locksoupasm_amd64.s` Triple Lock Soup | BMI2: Haswell+ Intel; AMD Excavator+ nominally, but **on Zen 1 and Zen 2 PEXT/PDEP are microcode-emulated with data-dependent latency** (Agner Fog instruction tables; AMD Software Optimization Guide). Constant-time hardware implementation only on Intel Haswell+ and AMD Zen 3+ | The Zen 1 / Zen 2 microcode-emulated PEXT/PDEP latency is primarily a function of mask popcount. Triple Lock Soup masks satisfy the architectural invariant `popcount(m_i) = 8` for all three lane masks (balanced 8-of-24 partition; see [ITB3.md § Lock Soup](ITB3.md#lock-soup-insane-interlocked-mode-opt-in-overlay-on-bit-soup)), so secret-derived mask popcount does not modulate latency. The `x` argument (the chunk's 24 plaintext bits) is secret, and on Zen 1 / Zen 2 microcode-emulated paths there is no published guarantee that latency is constant-time in `x` for fixed-popcount mask. Deployments targeting hardware adversaries on Zen 1 / Zen 2 should treat this as an unmitigated path |
| `VZEROUPPER` | `areion_amd64.s` exit; `locksoupasm_amd64.s` exit | AVX | Housekeeping. Zeros bits 128..511 of `YMM0..YMM15` (i.e. `ZMM0..ZMM15` upper halves); does **not** zero `Y0..Y15` lower 128 bits. `VZEROALL` (not used here) would clear all `YMM0..YMM15` including lower 128 bits | After `VAESENC` / `VPERMB` paths complete, the lower 128 bits of `YMM0..YMM15` may retain Areion round constants or Lock Soup permutation state until the next vector instruction overwrites them. RFDS treats this as a baseline exposure for any vector-using process; it is not specific to ITB. Exit `VZEROUPPER` reduces the persistence window of upper halves but does not eliminate lower-half exposure |
| `VPXOR` / `VPAND` / `VPOR` / `VMOVDQU` / `VPSRLQ` | `areion_amd64.s`; `process_pixels.c` Tier A / B | AVX2 / AVX-512F | Constant-time. Single-cycle reciprocal throughput on supporting microarchitectures | Building blocks for the rest of the kernels. Memory addressing for `VMOVDQU` / `_mm*_load_si*` depends on `pixelOffset` (derived from `startPixel`), so the load address pattern inherits the existing startPixel cache side-channel observation already documented in [Category 3](#category-3-cache--interconnect--power-contention) |

**Construction-loop disclosure (matrix building).** The GFNI matrix builders (`gfniRotMatrix`, `gfniSpreadMatrix`, `gfniGatherMatrix` in `process_pixels.c`) construct affine matrices in scalar C loops over `noisePos` / `dataRotation` immediates. Loop trip counts are constant (8 iterations), independent of secret values; the loops produce a 64-bit packed matrix that is then fed to `_mm256_load_si256` / `_mm512_load_si512` for affine application. Memory writes during construction are to short-lived stack buffers; the addresses written are stack offsets (not secret-address-dependent), but the values written are derived from secrets. Aliasing into an attacker-shared cacheline is bounded by the stack buffer lifetime.

**Batched store / load chains (Tier A / Tier B).** The batched paths in `process_pixels.c` write per-pixel computed bytes into a stack-resident `outBuf` via `_mm256_store_si256` / `_mm512_store_si512` and then `memcpy` from `outBuf` into the container at `pixelOffset[b]`. This produces a store-then-load chain on adjacent stack addresses. The chain is not secret-address-dependent: source and destination addresses are stack offsets and `pixelOffset[b]` (derived from `startPixel`, already-documented exposure). Spectre v4 (SSB) exploitation requires speculative load reading a stale value before a same-address store completes; here source and destination are different addresses, and Speculative Store Bypass would not produce a cross-channel disclosure of secret-derived bytes that the architectural store does not also produce.

**Pure-Go fallback paths.** When the BMI2 / AVX-512 VBMI hardware paths are unavailable (build tag `purego`, ARM platforms, pre-Haswell x86, WASM), Lock Soup runs through pure-Go fallback kernels: `softPEXT24` / `softPDEP24` (Triple Lock Soup forward / inverse) and `softPermute24` (Single Lock Soup). All three kernels are register-only and branchless: secret-derived mask bits, plaintext bits, and permutation indices feed bitwise AND / OR / variable-shift operations on register values, with the loop counter as the only branching condition (constant 24-iteration loop). On platforms with hardware-constant variable shift (modern x86 with `SHRX` / `SHLX` / `SHL` / `SHR` register operands; ARM with `LSR` / `LSL` / `ROR`), every iteration runs in fixed time regardless of the secret values in the input or mask. There is no secret-indexed memory access (no `table[secret_index]` lookup table), no secret-dependent branch, and no Spectre v1 disclosure surface in any of the three fallback kernels. Throughput is 5–7× lower than the BMI2 / AVX-512 VBMI hardware paths; the fallback exists for portability, not for production-throughput deployments.

## Summary

None of the hardware-level attacks analyzed above were found to introduce a new attack surface specific to ITB beyond what is already documented (startPixel cache side-channel, heap memory exposure). The construction's register-only data path for secret-dependent operations (`noisePos`, `dataRotation`, `channelXOR`) does not provide the disclosure gadget required by speculative execution attacks or the data-dependent memory access pattern required by cache-based attacks.

Note: ciphers whose implementations use secret-dependent table lookups (e.g., non-constant-time software S-box or T-table implementations) are known to provide disclosure gadgets exploitable by speculative execution, cache timing, and power analysis attacks. ITB's data path does not contain this pattern. However, modern hardware-accelerated implementations of standard ciphers (e.g., AES-NI) also avoid table lookups and are similarly not susceptible to these specific vectors. This is an architectural observation, not a security guarantee.

If a DPA/SPA attack were to recover intermediate values from ITB's data path, the most directly observable value would be the rotation amount per pixel — not the key itself. Recovering the key from rotation values would require inverting ChainHash, which is blocked under the PRF assumption (inversion is infeasible). Even in the event of a partial PRF weakness, the attacker would additionally need startPixel (derived from independent startSeed, not transmitted) to apply inversion, and would still face the 8-noisePos ambiguity from the independent noiseSeed — the KPA defense is 3-factor under PRF assumption (4-factor under Partial KPA) (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). This analysis has not been independently verified and assumes the attacker targets ITB's register operations rather than the hash function itself.

## References

- [Spectre](https://spectreattack.com/) — Kocher et al., 2018
- [Meltdown](https://meltdownattack.com/) — Lipp et al., 2018
- [Downfall/GDS](https://downfall.page/) — Moghimi, 2023
- [Hertzbleed](https://hertzbleed.com/) — Wang et al., 2022
- [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html) — Ormandy, 2023
- [Rowhammer](https://googleprojectzero.blogspot.com/2015/03/exploiting-dram-rowhammer-bug-to-gain.html) — Seaborn & Dullien, 2015
- [Training Solo](https://www.vusec.net/projects/training-solo/) — VUSec, 2025
