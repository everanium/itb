## Reference Application Blueprint — Lean 4 Verification (`APPS.md`)

Machine-checked formal verification in **Lean 4** (`leanprover/lean4:v4.35.0`) of the reference application-level **`3-to-8` Multi-KEM Key Agreement** (`deriveSeeds3to8`), **3-of-3 Intra-Epoch Ratchet Root** (`deriveRatchetRoot`), **3-Part Configuration Slicing** (`splitProfile3` / `joinProfile3`), and **Downgrade-Safe Schema Clamping** (`min(appVer_A, appVer_B)`) presented in [`../../APPS.md`](../../APPS.md).

> **Scope note:** This subdirectory verifies **only the reference application integration blueprint** illustrated in [`../../APPS.md`](../../APPS.md). It is **not** part of the core ITB symmetric cipher specification; the core cipher construction is independent of how callers provision keys or negotiate application profiles.

Every theorem in [`ThreeToEight.lean`](ThreeToEight.lean) (`namespace Apps.ThreeToEight`) is verified from first principles by the Lean 4 kernel using only the standard library (`Init`), with **zero `sorry` placeholders**, **zero user-defined `axiom` declarations**, and **zero external package dependencies**.

---

## Theorem Inventory (`Apps.ThreeToEight`)

| Theorem / Definition | Mathematical Statement | Reference in `APPS.md` |
|---|---|---|
| `three_kem_nonempty_subsets_count` | A 3-channel hybrid KEM (`c ∈ {0, 1, 2}`) admits exactly `2^3 - 1 = 7` non-empty channel subsets (`mask ∈ {1..7}`) | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys) |
| `slotSubsets`, `slotSubsets_in_range`, `slotSubsets_surjective_on_seven_masks` | The assignment `slotSubsets = [8]int{1, 2, 4, 6, 5, 3, 7, 7}` maps every slot `s ∈ Fin 8` into `{1..7}` and covers all 7 non-empty subset masks surjectively | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys), [§ 5](../../APPS.md#5-reference-implementation-go) (`slotSubsets`) |
| `channelInMask`, `stageA_subset_participation_counts` | Every mask `1..7` activates at least one channel, and each channel `c ∈ Fin 3` participates in exactly 4 of the 7 subset masks (`3 · 4 = 12` Stage A KDF derivations) | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys), [§ 5](../../APPS.md#5-reference-implementation-go) (Stage A loop) |
| `AppsKDFDomain`, `stageA_stageB_domain_disjoint` | Stage A labels (`"itb-chat-v1\|prk-subset-%d\|ch-%d\|%s"`) and Stage B labels (`"itb-chat-v1\|slot-%d\|sub-%d\|ch-%d\|%s"`) are strictly disjoint, preventing XOR self-cancellation between `subsetPRK[sub]` and `slotShare` | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys), [§ 5](../../APPS.md#5-reference-implementation-go) |
| `stageB_labels_injective` | All `8 · 3 = 24` Stage B per-slot, per-channel KDF derivation labels are pairwise distinct across `(slot, ch) ∈ Fin 8 × Fin 3` | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys), [§ 5](../../APPS.md#5-reference-implementation-go) (Stage B loop) |
| `cfgFrag_labels_injective`, `ratchetRoot_domain_disjoint`, `rekey_domain_disjoint_and_injective` | All `3 · 3 = 9` configuration-masking labels (`cfgFrag`), all `3` intra-epoch ratchet labels (`ratchetRoot`), and all per-message symmetric ratchet labels (`rekeyPerm`, `rekeyWrap`) are pairwise distinct and disjoint from Stage A and Stage B | [APPS.md § 3](../../APPS.md#3-3-part-configuration-slicing-via-tripleinspect), [§ 4](../../APPS.md#4-end-to-end-chat-architecture-with-versioned-chameleon-epochs), [§ 5](../../APPS.md#5-reference-implementation-go) |
| `two_of_three_unbroken_channel`, `fin3_cases` | Under any 2-of-3 channel compromise (`c1 ≠ c2` in `Fin 3`), there exists a third unbroken channel `u ∈ Fin 3` with `u ≠ c1` and `u ≠ c2` | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys) |
| `triKDFXorFold`, `triKDFXorFold_inv_ch{0,1,2}`, `triKDFXorFold_surjective_ch{0,1,2}`, `triKDFXorFold_injective_ch{0,1,2}` | For any bit width `w` and any two compromised channel shares, the 3-way Tri-KDF XOR fold `base ⊕ sh0 ⊕ sh1 ⊕ sh2` is a bijection on `BitVec w` with respect to the remaining unbroken channel share | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys) |
| `evalSubsetPRK`, `evalSlotMaster`, `deriveSeeds3to8_all_or_nothing_bijection`, `deriveSeeds3to8_joint_8slot_bijection` | In `deriveSeeds3to8`, for every unbroken channel `u ∈ Fin 3`: (1) each Stage B share `(s, u)` is a bijection onto `BitVec 512` leaving all other slots `s' ≠ s` invariant, and (2) the 8-tuple of Stage B shares `wVec : Fin 8 → BitVec 512` on channel `u` is a simultaneous bijection onto `(BitVec 512)^8` across all 8 slots (including slots 6 and 7 that share `subsetPRK[7]`) | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys), [§ 5](../../APPS.md#5-reference-implementation-go) (`deriveSeeds3to8`) |
| `fold8Way`, `fold8Way_surjective`, `fold8Way_bijection` | Inside `triple.InitKeys`, the 8-way XOR fold `k0 ⊕ ... ⊕ k7` deriving `PermMaster`, `WrapMaster`, and `macKey` is a bijection on `BitVec w` with respect to any single slot contribution | [APPS.md § 2](../../APPS.md#2-multi-assurance-3-to-8-key-agreement-initkeys) |
| `evalRatchetRoot`, `deriveRatchetRoot_bijection` | In `deriveRatchetRoot`, for any unbroken channel `u ∈ Fin 3` and any two compromised channel shares, the map `w ↦ evalRatchetRoot` is a bijection onto `BitVec 512` (`64`-byte ratchet root) | [APPS.md § 4](../../APPS.md#4-end-to-end-chat-architecture-with-versioned-chameleon-epochs), [§ 5](../../APPS.md#5-reference-implementation-go) (`deriveRatchetRoot`) |
| `profilePadLen`, `profilePadLen_spec` | Padding any JSON profile length `n` by `padLen = (3 - n mod 3) mod 3` whitespace bytes satisfies `padLen < 3` and `(n + padLen) mod 3 = 0` | [APPS.md § 3](../../APPS.md#3-3-part-configuration-slicing-via-tripleinspect), [§ 5](../../APPS.md#5-reference-implementation-go) (`splitProfile3`) |
| `split_join_fragment_roundtrip`, `splitProfile3_fragment_secrecy`, `splitProfile3_joint_3fragment_bijection` | Masking each configuration fragment with three channel pads (`plain ⊕ pad0 ⊕ pad1 ⊕ pad2`) and unmasking with the same three pads recovers `plain` bit-for-bit, and any single unbroken channel `u ∈ Fin 3` induces a simultaneous 3-fragment bijection `(BitVec w)^3 ↔ (BitVec w)^3` | [APPS.md § 3](../../APPS.md#3-3-part-configuration-slicing-via-tripleinspect), [§ 5](../../APPS.md#5-reference-implementation-go) (`splitProfile3`, `joinProfile3`) |
| `appVer_clamp_spec` | Downgrade-safe schema clamping `effectiveVer = min(appVer_A, appVer_B)` satisfies `min(a, b) ≤ a`, `min(a, b) ≤ b`, `min(a, b) = min(b, a)`, and `min(a, a) = a` | [APPS.md § 4](../../APPS.md#4-end-to-end-chat-architecture-with-versioned-chameleon-epochs) |

---

## Reproducing the Verification

From the `lean/` directory, build either the `Apps` target directly or the full default target set:

```sh
cd lean
lake build Apps
```

## See also

- [APPS.md](../../APPS.md) — Reference application integration guide (key establishment, session management, and configuration synchronization).
