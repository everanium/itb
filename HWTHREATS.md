# ITB: Hardware-Level Threat Analysis

> **Disclaimer.** This analysis is self-assessment by the author and has not been independently verified. ITB does not claim resistance to any hardware-level attack. The information-theoretic barrier is a ***software-level property*** — it provides no guarantees against hardware-level attacks. The observations below describe architectural properties of the construction's data path, not proven security guarantees. PRF-grade hash functions are required. No warranty is provided.

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
| Downfall / GDS | CVE-2022-40982 | Gather Data Sampling leaks from SIMD registers via `gather` instruction | CGO backend does not use `gather` (verified with GCC 13/14); auto-vectorization uses `vpxor`/`vpsllw`/`vpand` | Not applicable |
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
| Hertzbleed | 2022 | CPU frequency throttling converts power analysis to remote timing; data-dependent power → frequency → timing | ITB's secret-dependent operations are register-only XOR/shift; these instructions have data-independent latency and do not trigger DVFS transitions (not independently measured) | No known attack surface |
| SQUIP | 2022 | Scheduler queue contention leaks execution patterns across SMT threads (AMD) | ITB's per-pixel processing executes the same instruction sequence per pixel regardless of secret values; no secret-dependent branching (not independently verified) | No known attack surface |
| Interconnect side-channels | Various | Shared bus contention leaks access patterns | Container access pattern (startPixel) is already documented as cache side-channel limitation | Documented limitation |

## Category 4: Memory Integrity

| Attack | Mechanism | ITB Impact | Status |
|---|---|---|---|
| Rowhammer | Repeated DRAM row activation flips bits in adjacent rows | Could corrupt seeds, container, or plaintext in memory; general memory integrity attack affecting all software | Not ITB-specific |
| RAMBleed | Reads data through Rowhammer-induced bit flips | Could read seed bytes from adjacent DRAM rows; identical for AES keys | Not ITB-specific |

**Mitigation:** ECC memory detects and corrects single-bit flips. For high-security deployments, ECC memory is recommended alongside hardware memory encryption (AMD SEV, Intel SGX/TDX, ARM CCA).

**Heap memory exposure.** Sensitive data resides in heap memory during the lifetime of the process: seed components (`Seed.Components []uint64`), intermediate hash buffers, and plaintext during encode/decode. The library mitigates by calling `secureWipe` on intermediate buffers after use, but cannot wipe Go runtime internals or kernel buffers used during `crypto/rand` generation. Additionally, cached hash wrappers (e.g., `makeAESHash()`, `makeBlake3Hash()`) store a fixed random key in a closure for the lifetime of the session — this key persists in heap memory and is not wiped until the process exits. If an attacker can read heap memory (Meltdown, memory dump, debugger), they can read seeds and cached keys directly — regardless of the cipher used. This is identical for all software symmetric ciphers and is not specific to ITB.

## Summary

None of the hardware-level attacks analyzed above were found to introduce a new attack surface specific to ITB beyond what is already documented (startPixel cache side-channel, heap memory exposure). The construction's register-only data path for secret-dependent operations (`noisePos`, `dataRotation`, `channelXOR`) does not provide the disclosure gadget required by speculative execution attacks or the data-dependent memory access pattern required by cache-based attacks.

Note: ciphers whose implementations use secret-dependent table lookups (e.g., non-constant-time software S-box or T-table implementations) are known to provide disclosure gadgets exploitable by speculative execution, cache timing, and power analysis attacks. ITB's data path does not contain this pattern. However, modern hardware-accelerated implementations of standard ciphers (e.g., AES-NI) also avoid table lookups and are similarly not susceptible to these specific vectors. This is an architectural observation, not a security guarantee.

If a DPA/SPA attack were to recover intermediate values from ITB's data path, the most directly observable value would be the rotation amount per pixel — not the key itself. Recovering the key from rotation values would require inverting ChainHash, which is blocked by non-invertibility (PRF property). This analysis has not been independently verified and assumes the attacker targets ITB's register operations rather than the hash function itself.

## References

- [Spectre](https://spectreattack.com/) — Kocher et al., 2018
- [Meltdown](https://meltdownattack.com/) — Lipp et al., 2018
- [Downfall/GDS](https://downfall.page/) — Moghimi, 2023
- [Hertzbleed](https://hertzbleed.com/) — Wang et al., 2022
- [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html) — Ormandy, 2023
- [Rowhammer](https://googleprojectzero.blogspot.com/2015/03/exploiting-dram-rowhammer-bug-to-gain.html) — Seaborn & Dullien, 2015
- [Training Solo](https://www.vusec.net/projects/training-solo/) — VUSec, 2025
