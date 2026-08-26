# ITB Red-Team Empirical Validation

This document records the **v0.3.0** adversarial re-verification of ITB. The shipped construction under test is **Triple Ouroboros** — the byte-level 3-snake split — over the **8-seed** constellation, with the **always-on Interlocked Barrier** as its non-disableable core. There is no Single Ouroboros, no overlay toggle, and no Bit Soup mode; every pre-v0.3.0 measurement conditioned on "Single" or "overlay disengaged" describes a construction that no longer ships.

The complete pre-v0.3.0 empirical record is preserved verbatim in **[REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md)** and is cross-referenced by phase throughout — the archived detail is not re-inlined here.

## The Interlocked Barrier is a two-part composition

Every verdict below is read against the **full** barrier, which is two layers acting in series, not one. Treating either part in isolation misstates what the construction resists.

**Part 1 — the 48-bit interlock permutation** (`interlock48.go`). Before COBS framing and pixel encoding, the interleaved payload is chunked into 48-bit (6-byte) words. Each chunk is partitioned into three disjoint 16-of-48 lanes by a balanced mask triple `(m0, m1, m2)` — `popcount(mᵢ) = 16`, `m0 ∪ m1 ∪ m2 = 2^48 − 1` — drawn per chunk from a space of ≈ 2^70.20 balanced partitions, PRF-keyed by the `lockSeed` and the nonce (`rankToMaskTriple48`, `chunk48lock`, `splitForTriple48LockedCfg`). The mapping from a plaintext bit to the lane it lands in is a hidden per-chunk secret. Part 1 alone is a keyed permutation: it re-orders bits but does not XOR key material into them.

**Part 2 — the per-pixel absorption stage** (`process_pixels.c`). Each pixel packs 56 payload bits into 8 channel bytes of 7 data bits each. Per pixel, keyed by the `dataSeed` / `noiseSeed` ChainHash outputs, the encode path (Phase 3 XOR, Phase 4 rotate, Phase 5 noise-insert; scalar tail at the same phase structure) applies, per 7-bit field: a **channelXOR** with 7 PRF-mask bits, a **rotate7** by a per-pixel amount in `[0,6]`, and insertion around a **per-pixel noise bit** taken from the original CSPRNG container byte at a per-pixel `noisePos`. The decode path inverts exactly (noise-strip, inverse rotate, XOR). `rotateBits7` and the noise merge are the core of [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier) / [Proof 4](PROOFS.md#proof-4-rotation-barrier) / [Proof 5](PROOFS.md#proof-5-noise-barrier-bound) / [Proof 7](PROOFS.md#proof-7-bias-neutralization). Part 2 alone is an XOR-with-key-material-plus-noise stage: it whitens each byte to the 1:1 signal/noise floor but does not permute bit-to-position.

**Together** the two parts close the COA / KPA / CPA families under the PRF assumption. Part 1 denies the attacker a stable bit-position-to-lane anchor; Part 2 denies a per-byte observation channel (`P(observed | hash) = 1/2`). A crib that is known plaintext still reaches neither a fixed position (Part 1) nor an observable byte (Part 2). Neither part alone is sufficient — Part 1 alone is invertible once a primitive is inverted, Part 2 alone leaves a fixed bit-position map — and the shipped construction never runs either alone: both are always on and non-disableable.

**Eight-seed isolation** (`seed256.go` / `seed512.go`). Eight seeds are drawn as independent CSPRNG components and enforced pairwise-distinct at the API: `noiseSeed`, `lockSeed`, `dataSeed1..3`, `startSeed1..3`. No seed is reused across the three snakes. The nonce is absorbed once per session through the full ChainHash chain by `deriveInterLockSeed` (`seed256.go:171-176`): a domain tag plus the nonce feed the chained hash, and the barrier's per-chunk masks are keyed from that output. Full knowledge of any seed subset yields zero bits on the rest; the `lockSeed` that keys Part 1 is isolated from the `noiseSeed` that keys the noise channel and from the per-snake `dataSeed`/`startSeed`.

**Three-snake construction.** Each of the three snakes has its own `startPixel`, derived from its own `startSeed` and the nonce, and **different per snake**. None of the three is transmitted. An attacker holding the container does not know where any snake's payload begins, so no plaintext boundary is visible in any snake; there is no start marker and no end marker on the wire.

## Construction under test and shared conventions

Every track drives the shipped core Triple entrypoints (`Encrypt3x256Cfg` / `Encrypt3x512Cfg` and their decrypt duals, or the streaming `EncryptStream3xCfg` / `EncryptStreamAuth3xCfg` families) over the 8 mandatory distinct seeds. Parallax and the outer-cipher wrapper are independent layers above the barrier; except where a probe explicitly toggles the wrapper, the measured surface is the barrier layer alone.

**Discipline carried on every claim.** Every empirical verdict is **sample-bounded**: a null result means no measurable signal above the finite-sample floor at the stated sample size N under the stated threat model, never that no signal exists. PRF-grade closure claims are **PRF-conditional**. The independent-stream reference throughout is the byte-equal rate of two uniform random streams, **1/256 ≈ 0.00391**.

**Nonce-Reuse is a lab-only assumption.** A caller cannot force nonce reuse — the nonce is drawn from `crypto/rand` on every call — but it is the only condition under which the pre-v0.3.0 suite ever measured signal, so several probes below adopt it to give the attacker its best case.

**Attacker-realism.** Every recovery decision uses only attacker-visible inputs (ciphertext bytes, the public crib, the public nonce and dimension header, the seed-independent public per-pixel `const`); ground-truth seed values appear only in terminal-stage audit printouts, never in a decision.

**Barrier constants** (architectural, from the Part 1 mask-space counting argument; the single canonical numeric reference):

| Constant | Value |
|---|---|
| Chunk width | 48 bits / 6 bytes |
| Mask triple | three balanced 16-of-48 partitions |
| Mask-space cardinality per chunk (A · B) | ≈ **2^70.20** |
| Partition constants A = C(48,16), B = C(32,16) | 2,254,848,913,647 · 601,080,390 |
| gcd(A, B) anti-collapse trap | **66,861** = 3² · 17 · 19 · 23 |
| Preimage count per chunk (fresh-nonce under-determination) | ≈ **2^57.80** |
| Per-chunk bias | ≈ **2^-57.8** |
| Per-message accumulated bias | ≈ **2^-34.4** |
| Distinguisher sample budget | ≈ **2^115.6** chunks (beyond attainable) |

The container floor is uniform across all modes: the minimum pixel count is `ceil(keyBits / log2(7))` (`MinPixelsAuth`, aliased by `MinPixels`), so plain and MAC-authenticated paths share one envelope.

## Per-attack verdicts

Each verdict assumes the full barrier active (v0.3.0 default, non-disableable) and, where it invokes primitive strength, the PRF assumption and fresh per-message nonces. BLAKE3 is the representative PRF-grade primitive; the closure argument consumes only the PRF property, not any BLAKE3-specific structure, so a single representative generalises across the PRF-grade registry subset (see [PRF-grade equivalence](#prf-grade-versus-broken-primitive-equivalence)).

| Attack | Threat model | Verdict | Basis |
|---|---|---|---|
| **COA** | ciphertext only, fresh nonce | closed | Part 2 absorption + Part 1 permutation; wire uniform at the sample floor |
| **Crib KPA** | public-schema crib, fresh nonce | closed under PRF | crib reaches no fixed lane (Part 1) and no observable byte (Part 2) |
| **Full KPA** | complete P/C pairs, fresh nonce | closed under PRF | instance-formulation under-determination; ≈ 2^57.80 preimages/chunk |
| **Partial KPA** | partial known plaintext, fresh nonce | closed under PRF, a fortiori | superset of Full KPA candidate sets; `gcd(7,8)=1` byte-splitting adds a factor |
| **CPA** | chosen plaintext, fresh nonce | closed under PRF | fresh nonce re-draws masks / noise / rotation / startPixels per message |
| **Nonce reuse** | forced fixed nonce (lab) | plaintext-recovery null, traffic-analysis residue | mask-scrambled per-snake XOR under-determines the demasker's `(noisePos, rotation)` anchor; classical keystream-reuse recovers **0/n bytes** across every attacker-realistic probe |
| **Related-seed** | 1-bit seed Δ (lab) | outside shipped API; diffused | 8-seed isolation; Δ avalanches, no low-weight trace |
| **Related-nonce** | 1-bit nonce Δ, same seeds (lab) | diffused | nonce re-absorbed through full ChainHash chain per session |
| **Differential** | XOR-differential probe (lab) | neutralised on primitive-attributable axes | barrier diffuses; PRF-grade axes leave no followable characteristic |

### COA — ciphertext-only

Under passive observation the wire is `[nonce][W][H][container]`. The container bytes are individually uniform: every 7-bit data field is XOR-masked and rotated (Part 2) then bit-permuted across lanes (Part 1), and each channel byte carries a fresh CSPRNG noise bit. Measured container-body byte-equal and zero rates sit at the 1/256 floor at the tested sample sizes; the only non-uniform bytes on the wire are the fixed cleartext dimension header (§4.0), which restates the container size the wire length already exposes. No plaintext, key, or boundary channel is present.

### Crib KPA and Full KPA

**Threat model.** Crib / Full KPA under the PRF assumption with fresh nonces; the Nonce-Reuse variant is treated separately. **Verdict — closed at the instance-formulation layer, sample-bounded.** The 4-probe minimum drives BLAKE3-256 through the core Triple entrypoint (`redteam_prf_blake3_test.go`, `go test -run TestRedteamPRF -v ./`, combined wall-clock under one second):

| Probe | Threat model | Sample | Observable | Floor | Verdict |
|---|---|---|---|---|---|
| 1 — Crib KPA, fresh nonce | Crib KPA, PRF, fresh-nonce | N = 200, 4 KB, shared crib | crib-region byte-equal **0.00430**; \|Pearson\| **0.01023** | 0.00391 | **null** — crib anchors nothing |
| 2 — Nonce-reuse | Nonce-Reuse, **lab-only** | N = 200, fixed nonce | byte-equal **0.02124**; \|Pearson\| **0.01440** | 0.00391 | small correlation (~5.4× floor); lab-only |
| 3 — Related-seed Δ | Related-Seed, **lab-only** | N = 128, 1-bit Δ, fixed nonce | dataSeed1 Δ bit-diff **0.24057**; lockSeed Δ **0.47728** | diffused | **null for exploitability** |
| 4 — Full KPA, shared state | Full KPA, PRF, fresh-nonce | N = 64 pairs, shared bundle | pairwise byte-equal **0.00464**; all round-trips exact | 0.00391 | **null** — no aggregable correlation |

The architectural reason is the two-part composition. Part 1: each 48-bit chunk draws its mask triple from ≈ 2^70.20 balanced partitions, so a crib fixes no bit-position-to-lane mapping a solver could anchor; even granting the 48 known bits of a chunk under Full KPA, the mask has ≈ 2^57.80 preimages and is unobservable without the `lockSeed`, so no per-bit constraint can be written down. Part 2: the per-pixel 1:1 signal/noise ambiguity ([Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)) leaves no observed byte that ranks candidates. Seed recovery is **instance-formulation-bounded, not solver-bounded** — the seed-recovery brute force the architecture rules out is documented, not run against wall-clock. The residual honest caveat: **systematic partial PRF inversion is raised in cost but not eliminated, and total PRF inversion circumvents the barrier entirely.** Pre-v0.3.0 obstacle detail (Proof 4a, the Phase 2b KL floor, the Phase 2c startPixel rank-fraction ≈ 0.5) is preserved in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md).

### Partial KPA

No dedicated probe is run: the result follows a fortiori from the Full / Crib KPA null. A Partial KPA attacker holds strictly less known plaintext, so its achievable-key sets per pixel are a superset of the full-crib sets and its cross-pixel intersection can only be larger — it recovers no key where the stronger full-crib attacker recovers none. The `gcd(7,8)=1` byte-splitting obstacle (every plaintext byte spans two channels; a missing adjacent byte blocks per-channel candidate formulation) is an additional independent factor active only under Partial KPA. On real binary formats the demasking prerequisite (byte-level position precision over ≳ 90 % of plaintext) is not met at all — see [ITB.md §9.1](ITB.md#91-why-binary-formats-defeat-partial-kpa-demasking-entirely).

### CPA — chosen-plaintext, fresh nonce

Under fresh-nonce CPA the attack surface reduces to statistical ciphertext properties. Each message draws fresh masks (Part 1), fresh noise positions, rotations, and startPixels (Part 2); chosen plaintext gives no observable handle on any of these because the lane assignment is a hidden per-chunk secret and each byte is at the 1:1 floor. The pre-v0.3.0 record placed ITB ciphertext at the finite-sample statistical floor — indistinguishable from `/dev/urandom` within the tested tolerance — across the full primitive spectrum on every statistical surface measured ([REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md), Phase 1 / 2b / 3a / 3b). The verdict is **closure under the PRF assumption with fresh nonces**, sample-bounded. The statistical-floor claim applies to the wire container body and the payload-channel probes; the cleartext dimension header (§4.0) is the one non-uniform structural field and carries no plaintext or key channel.

### Nonce reuse (lab-only)

Nonce reuse is **not reachable through the shipped API** — the nonce is drawn from `crypto/rand` per call. Forced via a test-only override, it is the one condition that surfaces any signal. Under a reused nonce with the same seeds, Part 1's per-chunk masks repeat, the noise positions and startPixels repeat, and the nonce-deterministic container structure aligns across the colliding pair. What is **not** repeated under nonce reuse: the fresh CSPRNG noise bit that Part 2 inserts at each pixel's `noisePos`, and the fresh CSPRNG tail-fill beyond the COBS terminator. The XOR of two colliding ciphertexts therefore carries `rotate7(snake_XOR_bits, r)` at every non-noise bit position and a fresh random bit at the noise position — the classical two-time pad structure a stream cipher would present is present **only up to the barrier's Part 1 permutation of the plaintext bits into three lane-scrambled snake payloads**.

**Empirical re-verification** — `redteam_nonce_reuse_test.go`, worst-case primitive: **FNV-1a on every one of the 8 seed roles** (below-spec lab primitive, one per role, with independent random keys). All measurements are attacker-visible — every decision uses ciphertext bytes, the public wire header, and known plaintext bytes only. The single documented lab peek is the three snake `startPixel` offsets, tagged at the call site and consumed only by the Layer B / C probes; the mask-oracle peek used by the upper-bound reference is called out explicitly as **not attacker-realistic**.

| Probe | Attacker capability | Sample | Observable | Verdict |
|---|---|---|---|---|
| A — Wire byte-histogram of `C1 XOR C2` | Full KPA, random plaintext pair | N = 40, sizes 128–512 B | container-body byte-equal rate `0.00421`–`0.00500` (`1.05–1.32×` the 1/256 floor); chi² 282–641 vs uniform df=255 | **null** at the tested sample size — floor-level |
| A — Wire byte-histogram of `C1 XOR C2` | Full KPA, near-identical plaintext pair (single-bit XOR) | N = 40, sizes 128–512 B | byte-equal rate `0.019`–`0.063` (`4.9×`–`16×` floor); chi² 24 500–361 000 | traffic-analysis residue — reveals `P1 ≈ P2` but the excess bytes are CSPRNG-noise-bit driven, not plaintext |
| A′ — Naive Crib KPA on the wire | Full KPA (assumes `snake_payload_byte == plaintext_byte`) | 5 pairs × 3 snakes × 8 probe pixels | fully-anchoring startPixels: **0** on every random-plaintext cell; **0** on every near-identical cell | **null** — Part 1's mask removes the fixed bit-position-to-lane anchor |
| B — Startpixel-known Layer 1 | Full KPA + `[lab-peek: sp_i]`, random pair | 1 pair, ≈ 208 pixels per snake | pixels admitting any `(np, r)` yielding all-zero extract: **0 / 208** per snake | **null** at random-plaintext floor |
| B — Startpixel-known Layer 1 | Full KPA + `[lab-peek: sp_i]`, near-quiet pair | 1 pair, ≈ 208 pixels per snake, one 6-B differing chunk | ≈ 8 % of snake pixels admit any `(np, r)` with ≈ 7 candidates each (mean log₂ ≈ 2.81) | no unique per-pixel recovery even on the maximally quiet plaintext shape |
| B′ — Mask-oracle upper bound (NOT attacker-realistic) | Full KPA + `[lab-peek: sp_i]` + `[lab-peek: masks]` | 1 pair, deterministic COBS prefix | unique `(np, r)` recovered on ≈ 100 % of probed pixels per snake | pre-v0.3.0 demasker precision — the barrier's closure lives in the mask secrecy |
| C — FNV-1a algebraic precondition | Full KPA + `[lab-peek: sp_i]`, naive mask assumption | 1 pair, ≈ 208 pixels per snake | pixels with unique `(np, r)`: **0 / 208** per snake — no reconstructed ChainHash stream to invert | Layer C **architecturally foreclosed** by the Layer 1 precondition |
| D — Multi-pair per-position statistics | N = 30 nonce-reuse ciphertexts, Full KPA | ≈ 1668 snake body bytes | mean distinct byte values per position `28.25`–`28.31` vs uniform `28.36`; 2–3 positions per snake at distinct ≤ 2 | residue is the constant plaintext length-prefix bits, restated by the public wire dimension header (no additional confidentiality leak) |
| Cross-message decrypt of `P3` from `(C1, C2, P1, P2, C3)` | Full KPA, attacker-realistic | 1 pair, 320 B, forced fixed nonce | **regime A** (no peek): 0 bytes matched — the constraint anchors zero pixels so nothing to apply. **Regime B** (sp peek): 0 bytes. **Regime B′** (sp + mask oracle peek): ≈ **96 %** on the deterministic COBS prefix | attacker-realistic recovery of any bytes of a third message is null; the mask oracle recovers the pre-v0.3.0 rate |

The pre-v0.3.0 Single-Ouroboros / barrier-off configuration under the identical threat model (Full KPA + forced nonce reuse) yielded ~99.17 % raw byte match on the colliding pair via `nonce_reuse_demask.py` ([REDTEAM-v0.2.md § Phase 2d](archive/REDTEAM-v0.2.md)). Against v0.3.0's always-on 48-bit interlock, the same recovery path collapses to zero for every attacker-realistic capability tier: the demasker's Layer 1 constraint match requires known snake-payload XOR bits at each pixel, and those bits are `PEXT48(P1_chunk XOR P2_chunk, m_i_per_chunk)` where `m_i_per_chunk` is drawn from the ≈ 2^70.20-per-chunk mask space keyed by the unknown `lockSeed`. The mask-oracle upper bound (Layer B′) confirms this is a pure instance-formulation closure — no per-pixel obfuscation is doing additional work; the barrier's plaintext-recovery closure under nonce reuse lives entirely in the `lockSeed` secrecy.

**Verdict — plaintext-recovery null, sample-bounded; traffic-analysis residue on near-identical plaintext pairs.** Under nonce reuse with the below-spec primitive on every seed role, no attacker-realistic probe recovers a byte of a third message encrypted under the same forced-collided nonce. The near-identical-pair byte-histogram is the residual signature: an outside observer of two ciphertexts under a colliding nonce can distinguish "near-identical plaintexts" from "independent plaintexts" at 16× the 1/256 floor at 512 B, but the excess is dominated by the fresh CSPRNG noise bit at each pixel's `noisePos` — the deviation carries no plaintext bit, no key bit, and no `noisePos` / `rotation` / `channelXOR` value. The classical stream-cipher "two-time pad" outcome is scoped by the barrier to a distinguisher, not a decryption oracle. **Nonce reuse remains a usage precondition the barrier does not architecturally remove at the traffic-analysis layer** — the mandatory internal nonce is API discipline, and the outer cipher (when engaged) additionally whitens the wire against the near-identical-pair distinguisher.

The reproduction is one command:

```
go test -run TestRedTeamNonceReuse -v ./
scripts/redteam/itb/nonce_reuse/run.sh          # same, with JSON aggregation
```

Pre-v0.3.0 demasker / NIST STS PRF-separation detail is in [REDTEAM-v0.2.md § Phase 2d — Nonce-Reuse](archive/REDTEAM-v0.2.md); the archived detail applies to the retired Single Ouroboros / barrier-off construction and does not re-cross to the shipped v0.3.0 line.

### Related-seed and related-nonce differential

Neither is reachable through the shipped API — the 8-seed intake draws independent CSPRNG components and rejects pointer collisions, and the nonce is internal. Forced in the lab (a seed or nonce and its 1-bit-delta twin, every other input fixed): a dataSeed1 delta produces a ciphertext bit-diff fraction of **0.24057** — structurally scoped to one snake's third, then diffused by Part 1's permutation and the COBS / interleave, landing above the one-snake floor (≈ 0.167). A lockSeed delta re-draws every mask triple and reaches **0.47728**, approaching full avalanche (0.5). Neither channel leaves a low-weight, position-predictable differential — the **8-seed isolation made observable**: each seed's influence is scoped to its own channel and the barrier diffuses the delta rather than localising it. A related-nonce delta re-absorbs through the full ChainHash chain of `deriveInterLockSeed` per session, diffusing identically. Any residual related-seed exposure would be an **upstream key-management** defect (a defective KDF supplying correlated seeds), not a barrier property. Pre-v0.3.0 1008-cell single-axis sweep detail is in [REDTEAM-v0.2.md § Phase 2e](archive/REDTEAM-v0.2.md).

## Broken-primitive stress — FNV-1a and CRC128

The below-spec lab controls stress the shipped construction with the hardest algebraic weaknesses available: a fully **GF(2)-linear** primitive (CRC128, two keyed CRC64 lanes) and an **invertible non-linear** one (FNV-1a, a bijective multiply over Z/2^128 with a triangular low-lane T-function). Neither is a production hash; neither appears in the shipped registry. They lead this discussion because the methodology seeks the hardest stress cases, not the easiest PRF wins.

### FNV-1a "broken" narrative — scope

FNV-1a and CRC128 were broken in the pre-v0.3.0 record, but only under a construction that no longer ships: **Single Ouroboros with the barrier disabled** — a configuration v0.3.0 removes (the Interlocked Barrier is always-on and non-disableable). Under that legacy configuration the GF(2)-linear collapse recovered a CRC128 compound key in about one second (v0.2 `Phase 2f`), and a SAT solver recovered an FNV-1a lo-lane state in about eight single-core hours (v0.2 `Phase 2g`). **Under v0.3.0's always-on barrier, no algebraic leakage from either control was measurable at the tested sample sizes**, and the linear / SAT instance cannot be formulated at all. This is a scope statement, not a safety claim for FNV-1a: the primitive remains below spec, the closure is an instance-formulation argument under the barrier, and total inversion of the primitive still circumvents the barrier.

### CRC128 Crib KPA and Nonce-reuse

The recovery is ported from the pre-v0.3.0 CRC128 Crib KPA (`crib_crc128_kpa.py` / `crib_crc128_kpa_full.py`) and run as `go test -run TestRedTeamBrokenCRC128CribKPA ./` (≈ 0.09 s): a 625-candidate startPixel scan against a four-pixel crib, recovering the observable 56-bit compound key over all noise-position and rotation guesses — a strictly stronger attacker than the pre-v0.3.0 algebraic filter.

**Verdict — null.** Against a legacy Single, barrier-off control encode the ported filter anchors exactly one shift and returns one survivor (the true key), confirming sensitivity. Against the shipped `Encrypt3x128Cfg` ciphertext the filter anchors **zero** shifts and returns **zero** survivors across all 625 candidate startPixels; the ciphertext round-trips, so it is a genuine encryption. Part 1 permutes the plaintext into the snakes before pixel encoding, so the crib bytes the attacker substitutes as "pixel p's plaintext" are the wrong bytes and there is no fixed bit-position-to-lane anchor for the linear system. Under a forced nonce collision (`TestRedTeamBrokenCRC128NonceReuse`, ≈ 0.01 s) the Crib KPA still returns zero survivors from either colliding ciphertext: nonce reuse repeats the masks but does not hand the attacker the permutation, so the crib remains unanchored.

### FNV-1a lo-lane SAT — architecturally foreclosed

**Threat model — fresh nonce Full KPA, FNV-1a on every seed role.** Each of the 8 mandatory seeds (noiseSeed, lockSeed, dataSeed1..3, startSeed1..3) is keyed by FNV-1a with independent random key material; nonces are fresh per message. The pre-v0.3.0 record recovered a functional FNV-1a lo-lane compound key in ≈ 8 h single-core against Single Ouroboros with the overlay disengaged, yielding 83–85 % byte-level plaintext recovery on JSON / HTML holdouts (v0.2 `Phase 2g`; archived detail in [REDTEAM-v0.2.md § Phase 2g](archive/REDTEAM-v0.2.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based)).

**Verdict — null anchoring at every candidate startPixel across every attacker regime, sample-bounded.** The `redteam_broken_fnv1a_sat_test.go` probes drive FNV-1a on all 8 seeds through `Encrypt3x128Cfg` on a 157-byte JSON crib (public-schema prefix — identifier field, ISO timestamp) and measure the naive-crib SAT anchoring at three regimes:

| Probe | Regime | Sample | Observable | Verdict |
|---|---|---|---|---|
| F1 pre-anchor structure | attacker-realistic (no seed peek) | 3 snakes × 208 candidate startPixels × 6 crib pixels | per-pixel achievable xor_mask56 set size mean ≈ **55.8**; max cross-pixel set intersection over every candidate startPixel: **0 / 0 / 0** | pre-v0.3.0 CRC128-style compound-K intersection filter yields no anchor reduction; discriminator moves to SAT |
| F2 true-anchor upper bound | `[lab-peek: true_seeds]` noiseSeed + dataSeed_i granted | 3 snakes × 208 startPixels × 6 crib pixels × 8 channels | full-channel anchor shifts **0 / 208, 0 / 208, 0 / 209**; max per-shift channel matches **3 / 48** against chance floor **0.375** | even the oracle attacker with (np, r) handed over fails at chance floor; naive-crib xor_mask56 never equals the true dataHash prefix |
| F4 startPixel-peek | `[lab-peek: sp_i]` + `[lab-peek: true_seeds]` | 3 snakes at disclosed sp_i | channel matches at true sp = **0, 4, 0 / 48**; shift-averaged floor = **0.32, 0.41, 0.39** | disclosing per-snake startPixel does not restore the anchor; match count at sp_i is at the same floor as any other shift |

The mechanism is **multi-seed joint coupling**: every attacker-visible byte is the composition of independent contributions from noiseSeed (per-pixel noisePos), lockSeed (per-chunk 48-bit mask triple over ≈ 2^70.20 space), dataSeed_i (per-pixel channel-XOR + rotation), and startSeed_i (per-snake sp_i). No per-chain observation channel exists. Even granting 5–6 of the 8 chains as lab peek (F2 + F4 posture, corresponding to a hypothetical break of noiseSeed + dataSeed_i + startSeed_i) leaves the joint constraint under-determined by the interlock permutation, which continues to move the crib bytes off every attacker-predicted position.

**Instance-formulation closure, not solver-throughput closure.** The pre-v0.3.0 SAT harness (`sat_harness_4round.py`) anchored on the Single Ouroboros mapping "plaintext byte K → container pixel (startPixel + K/7) mod totalPixels, channel K%7". Under the v0.3.0 barrier that mapping does not hold: the 48-bit interlock permutation displaces the assumed crib bytes at nearly every position, corroborated by the F5 displacement measurement on the same JSON crib (per-snake fractions **1/53, 0/52, 1/52**, at or below the ≈ 1/40 same-symbol coincidence rate of the 40-symbol JSON alphabet). The pre-v0.3.0 SAT instance thus **cannot be written down against the shipped construction** — no amount of Bitwuzla throughput converts an unformulable instance into a solvable one.

**Bitwuzla SAT run corroborates.** A compact adaptation of the pre-v0.3.0 harness under `scripts/redteam/itb/fnv1a_sat/sat_probe.py` encodes the naive-crib SAT anchor as a symbolic FNV-1a 4-round chain (256-bit dataSeed_i lo-lane unknown) plus per-pixel disjunction over the 56 (np, r) tuples chained through the bit-slice + rotation constraint. Under the maximum-peek attacker regime (true (np, r) granted via lab peek — 5 of 8 chains inverted for free — and true sp_i disclosed as the Layer 3 exception), Bitwuzla 0.9.1 returns **UNSAT** on all 3 snakes at N = 2 crib pixels in ≈ 7–10 s per snake. Even the strongest-attacker single-chain SAT — attacker granted every seed except the dataSeed_i lo lane — fails to find a satisfying dataSeed_i under the naive-crib anchoring premise. The full coupled-8-chain SAT (all 8 chains unknown plus the ≈ 2^70.20 per-chunk interlock mask triples symbolic) is trivially harder; the isolated-chain UNSAT is a strict upper bound.

**Positive control corroborated.** `TestRedTeamBrokenFNV1aCribKPAControl` drives the same 8-seed FNV-1a configuration through the low-level `process128Cfg` encoder (Single Ouroboros, barrier off — not reachable through the shipped API) and confirms the anchor logic recovers the true xor_mask56 at every one of the first 6 crib pixels under true (sp, np, r), matching the pre-v0.3.0 SAT anchoring premise bit-exact. The barrier null is contrasted against a filter that IS sensitive on the retired configuration.

### Barrier crib-anchor displacement (both controls)

A structural probe (`TestRedTeamBrokenBarrierDisplacement`, ≈ 0.07 s; holds true seeds to observe **what the barrier did**, not an attack path) encrypts a fully attacker-known structured crib and measures the fraction of leading crib bytes still sitting at their assumed post-split position. For both the GF(2)-linear (CRC128) and the non-linear invertible (FNV-1a) control the fraction sits at or below ≈ 0.0056 (CRC128: 1 in 180; FNV-1a: 0 in 180), below the ≈ 0.0385 same-symbol coincidence rate of the 26-symbol crib. Anchor destruction is **primitive-agnostic** — it does not depend on any algebraic property the primitive lacks, which is why the same mechanism closes the CRC128 linear collapse and the FNV-1a lo-lane SAT.

### Reproduction

```
go test -run TestRedTeamBroken -v ./                  # all broken-primitive probes
go test -run TestRedTeamBrokenCRC128CribKPA -v ./
go test -run TestRedTeamBrokenBarrierDisplacement -v ./
go test -run TestRedTeamBrokenCRC128NonceReuse -v ./
go test -run TestRedTeamBrokenFNV1a -v ./             # FNV-1a lo-lane SAT probes F1..F6
./scripts/redteam/itb/fnv1a_sat/run.sh                # aggregate the FNV-1a probes + optional Bitwuzla SAT
```

The harness is `redteam_broken_test.go` (CRC128 + shared adapters) and `redteam_broken_fnv1a_sat_test.go` (FNV-1a probes F1..F6), package `itb`; the CRC128 / FNV-1a adapters and the ported filter carry inline provenance comments pointing at the retired lab scaffolds and the Python arsenal routines they adapt. The compact Bitwuzla harness lives at `scripts/redteam/itb/fnv1a_sat/sat_probe.py`; it consumes the corpus emitted by `TestRedTeamBrokenFNV1aCribKPAEmitCorpus` under `tmp/redteam/fnv1a_sat/f6_corpus_bundle.json` and runs against the maximum-peek attacker regime described above.

## PRF-grade versus broken-primitive equivalence

Under the always-on barrier, both classes converge to the same observable outcome — no measurable signal at the tested sample sizes — by two different mechanisms:

- **PRF-grade primitive — architectural closure.** The primitive is already null by the PRF assumption; the ChainHash output is indistinguishable from random before the barrier is applied. The barrier adds instance-formulation under-determination on top of an already-null primitive. Probe 1 and Probe 4 corroborate the null empirically.
- **Below-spec broken primitive — architectural under-determination.** The primitive leaks in isolation, but under the always-on barrier the attacker cannot formulate the linear or invertible system at all: the bit-position-to-lane mapping is a hidden per-chunk ≈ 2^70.20 secret, so the GF(2)-linear pixel-independent collapse that broke CRC128 pre-v0.3.0 has no analogue.

The equivalence is that **the barrier's mask-formulation under-determination is the dominant term regardless of the primitive's own strength.** For a PRF the primitive supplies the null and the barrier is redundant-but-additive; for a broken primitive the barrier supplies the null the primitive fails to. The below-spec closure is an instance-formulation argument, so it holds without invoking the PRF assumption for that class — though it, too, is an architectural claim under fresh nonces, conditional on the absence of a structural shortcut against the barrier's own reduction arithmetic, not an independently certified result.

## Why one representative PRF-grade primitive is sufficient

For a PRF-grade primitive the null is a **definitional consequence of the PRF assumption**, not an accident of the tested sample: a secure PRF's ChainHash output is computationally indistinguishable from random before the barrier is ever applied, so the attack surface reduces to statistical ciphertext properties already at the finite-sample floor. Each registry member enters the construction through the same ChainHash interface and is consumed by the same barrier; expanding empirical breadth across every member would multiply runs without changing the argument. The representative-primitive approach documents the null rigorously on BLAKE3 and generalises through the shared assumption. The pre-v0.3.0 spectrum (deliberately broken controls through paper-grade PRFs) recorded that **no PRF-grade primitive was broken at any phase, under any threat model, and no break survived engagement of the overlay** ([REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md), Phase 2 tables); the plaintext-recovery breaks were obtained only against below-spec primitives, only against Single Ouroboros, and only with the overlay disengaged.

## Phase 4 — Construction-level creative probes (Triple + Interlocked Barrier)

This phase targets the **construction itself** — properties that do not depend on which hash keys the barrier. Each probe drives either the Triple facade wire or the barrier kernels directly and reports a sample-bounded verdict; every wire statistic is computed from bytes an attacker holding the ciphertext already has. The probes ship as Go tests (`harness_test.go` for kernel probes, `triple/harness_wire_test.go` for wire probes), gating their full-sample loops behind `ITB_HARNESS_FULL=1`.

### 4.0 Layer attribution — what actually appears on the wire

The barrier-only wire (`[nonce][W][H][container]`, wrapper off) is uniform at the byte-value level **except for the cleartext container-dimension header**. The container body is individually uniform: every payload byte — COBS data, the COBS terminator `0x00`, and the CSPRNG tail fill alike — passes through Part 2 (channelXOR + rotate7 + noise-insert) and Part 1's lane permutation before reaching the wire, so no payload byte survives as its pre-barrier value. Measured at N = 3000–4000 256-byte messages, the container-body zero rate sits at the 1/256 floor (≈ 0.391 %), and no payload-derived byte value is over-represented above the sampling floor.

The one structural signature is the **big-endian `W` and `H` dimension fields** written in cleartext ahead of the container (`out = nonce ‖ W ‖ H ‖ container` in `Encrypt3x256Cfg`). For a fixed plaintext size the container is a deterministic size, so these four bytes are identical across messages: their high bytes are `0x00` and their low bytes are the dimension value. Pooled over many messages this over-represents the `0x00` bin (the two high bytes) and one companion value (the shared low byte) by a **relative ≈ +5 %** each — an **absolute** excess of roughly 0.02 percentage points on the `0x00` rate. A byte-histogram chi-square, the sharp instrument for granular bias, detects it (barrier-only per-profile χ² ≈ 1890–2130 at N = 8000, df = 255, uniform band [142, 368]); Shannon entropy stays **≈ 7.99998 bits/byte** and the wire is incompressible (flate ratio 1.0002).

Two consequences fix the scope of this signature:

- **It is not a confidentiality leak.** The dimension header restates the container size, which the wire length already reveals. The COBS terminator is **not** on the wire — it is absorbed by Part 2, so its position (set by the secret per-snake `startPixel` and the payload length) is nowhere observable. The signature carries no plaintext, no key, no terminator position, and no startPixel. Confidentiality against COA / KPA / CPA is delivered by the barrier composition itself, not by any wire-whitening pass.
- **The outer cipher removes it for format deniability.** Engaging the wrapper encrypts the whole wire including the dimension header, dropping the byte chi-square into the uniform band (≈ 254–260) and the `0x00` deviation from +5 % to ± 0.05 %. **The outer cipher delivers wire-level format deniability — a traffic-analysis / format-fingerprint property — not confidentiality**, which is the barrier's job. This scopes every "indistinguishable from random" byte-histogram claim: at the barrier-only layer the claim holds for the container body and the payload-channel probes; the cleartext dimension header is the sole exception and is whitened by the wrapper.

The finding is primitive-agnostic: the dimension header is written identically regardless of which hash keys the seeds, so a broken primitive and a PRF-grade primitive produce the same signature when the wrapper is off. It is not a primitive leak.

### 4.1 Probe C1 — cross-profile wire distinguishability and mode ambiguity

**Question.** Can a wire observer tell the **Streaming AEAD** MAC profile from the **Non-AEAD** profile from byte statistics alone? The mode-ambiguity doctrine ships both with a wire-identical envelope so a MITM cannot assume a MAC-check oracle exists.

**Setup.** The facade encrypts N = 8000 fresh-random 256-byte messages under each profile, parallax off, at both wrapper postures. The load-bearing statistic is the two-sample **homogeneity** chi-square between the AEAD and Non-AEAD pools (df = 255).

| Posture | AEAD wire χ² | Non-AEAD wire χ² | `0x00` dev (both) | AEAD↔Non-AEAD homogeneity χ² |
|---|---|---|---|---|
| Wrapper off (barrier only) | 1889.6 | 2126.9 | +5.3 % | **244.8** |
| Wrapper on (outer cipher) | 268.8 | 256.6 | ±0.1 % | **286.5** |

**Verdict — mode ambiguity holds (sample-bounded).** The homogeneity chi-square is **inside the uniform band whether or not the wrapper is engaged** (244.8 / 286.5, band top 368). The two modes carry one identical container law — the dimension-header signature is identical in both, so it cancels in the two-sample test — and no wire byte statistic separates them at the tested sample size. The MAC rides inside the encryption envelope; the Non-AEAD path fills the corresponding region with CSPRNG dummy of matching length. **Positive control:** the barrier-only per-profile chi-square (1890 / 2127, far above the band) confirms the probe detects the signature that is actually present, so the in-band homogeneity result is a real null.

### 4.2 Probe C2 — mask-space structural uniformity and the gcd anti-collapse trap

**Question.** Does the per-chunk mask-triple derivation realise the architectural ≈ 2^70.20 balanced-partition space, or does an implementation detail collapse it? This is a white-box structural harness, not an attack.

**Result.** Over N = 200000 random draws (gcd witness at N = 500000): every triple satisfies `popcount = 16` per lane, `m0 | m1 | m2 = 0x0000_FFFF_FFFF_FFFF`, and pairwise-disjoint lanes (100 % of draws); per-bit balance within 2.18 σ across all 48 positions; reduced-index chi-square 228.7 / 241.5 (band [142, 368]). The gcd anti-collapse trap: under the shipped two-step reduction the fraction landing on `idx0 ≡ idx1 (mod 66861)` is 1.600 × 10⁻⁵, matching the full-space expectation 1/66861 ≈ 1.496 × 10⁻⁵; the rejected same-rank double-mod would confine **every** draw to that diagonal.

**Verdict — null structural deviation.** The mask space is full and balanced and the two-step reduction avoids the residue-class trap, corroborating the Part 1 cardinality claim at the derivation layer. This is a structural-correctness result under the standing assumption that the lockSeed's PRF output is indistinguishable from uniform, not a security proof. Primitive-agnostic; the per-attack tracks cite C2 rather than re-running it.

### 4.3 Probe C3 — tail-fill CSPRNG residue, size-stability

The Non-AEAD profile (wrapper off) encrypts N = 8000 wires at plaintext sizes {1, 6, 32, 4096} bytes. Entropy stays 7.99998 and flate 1.0002 at every size; the dimension-header `0x00` relative deviation ranges only over [4.87 %, 5.24 %] across the four-order size span. **Verdict — null size-leak:** the tail-fill-dominated small-plaintext wire carries the same container law as the payload-dominated large-plaintext wire, so no size-dependent fill anomaly is present at the tested sample size beyond the length the wire already reveals.

### 4.4 Probe C4 — cross-snake independence

The kernel probe (C4b) drives `chunk48lock` with N = 200000 random chunks under fresh mask triples; the wire probe (C4a) aligns N = 30000 wires column-wise. **C4b:** max |r| = 0.00545 against the sampling floor 0.00224 — cross-lane correlation at the floor. **C4a:** max |r| = 0.01853 against floor 0.00577 — ~3.2× the floor, below the 8× threshold; the attribution is the marginal dimension-header / container-framing residual, **not** a barrier cross-snake leak (the kernel probe, which bypasses framing, shows none). **Verdict — null cross-snake coupling at the barrier; a small container-framing residual at the wire** the outer cipher would remove.

### 4.5 Probe C5 — cumulative bias floor

The kernel probe pools lane-output bits over N = 300000 chunks; the wire probe pools N = 4000 4096-byte wires at both postures. **C5-core:** max per-bit deviation 2.240 × 10⁻³ against floor 1.826 × 10⁻³ (maxZ 2.45) — the architectural per-chunk bias 2^-57.8 is ~15 orders of magnitude below detectability. **C5 wire:** barrier-only 2.582 × 10⁻⁴ (container tilt), wrapped 1.612 × 10⁻⁴ against floor 1.588 × 10⁻⁴. **Verdict — no measurable cumulative bias at the tested sample size** (turning the granularity into a distinguisher needs ≈ 2^115.6 chunks); the small barrier-only tilt is the dimension-header signature the outer cipher removes.

### 4.6 Probe C6 — nonce-freshness and per-message divergence

A single session encrypts the same 256-byte plaintext N = 10000 times (fresh internal nonce per call). **Result:** 10000 distinct wires out of 10000, mean pairwise Hamming distance 0.4999 of the body bits (ideal 0.5). **Verdict — null collision:** the internal per-call nonce drives fresh masks, noise positions, and per-snake offsets, so the wire body is effectively an independent random draw per message — empirical corroboration of the fresh-nonce under-determination without enumerating the ≈ 2^57.80 preimage space.

### 4.7 Phase 4 summary

| Probe | Layer | Sample | Verdict |
|---|---|---|---|
| C1 mode ambiguity | facade wire | 8000 msg × 4 cells | Modes indistinguishable (homogeneity in-band); outer cipher whitens the dimension-header signature |
| C2 mask-space | barrier kernel | 200k–500k draws | Full balanced space; gcd trap avoided; null deviation |
| C3 tail-fill | facade wire | 8000 msg × 4 sizes | Size-stable; null size-leak |
| C4 cross-snake | kernel + wire | 200k / 30k | Null coupling at barrier; small framing residual at wire |
| C5 cumulative bias | kernel + wire | 300k / 39.6 M B | No measurable bias; tracks sampling floor |
| C6 nonce freshness | facade wire | 10000 msg | All wires distinct; ~50 % pairwise Hamming |

Every construction-level probe returns a null or an explained-structural result. The one non-trivial finding — that the barrier-only wire carries a cleartext dimension-header byte signature that the outer cipher, not the barrier, whitens — is a scoping clarification, not a weakness: it names the layer that delivers wire-level format deniability and confirms that the COBS terminator and every payload byte are absorbed by the barrier itself. All results are conditional on the configured primitive behaving as a secure PRF and on fresh nonces, and all statements are bounded by the tested sample size.

**Reproduction.**

```
ITB_HARNESS_FULL=1 go test -run 'TestHarnessC[245]' -v ./           # kernel probes C2, C4b, C5-core
ITB_HARNESS_FULL=1 go test -run 'TestHarnessC[13456]' -v ./triple/  # wire probes C1, C3, C4a, C5, C6
go test -run TestHarness ./ ./triple/                               # fast smoke run
```

## Cross-track synthesis

The tracks converge on one sample-bounded, PRF-conditional outcome — **no measurable signal at the tested sample sizes under the stated threat models** — reached through complementary evidence.

**Both primitive classes converge by two mechanisms.** For a PRF-grade primitive the primitive supplies the null and the barrier is redundant-but-additive; for a below-spec broken primitive the barrier supplies the null the primitive fails to, because the bit-position-to-lane mapping is a hidden per-chunk ≈ 2^70.20 secret. The broken-primitive empty shadow-K survivor sets and the PRF-grade floor-level crib / pairwise byte-equal rates are two halves of one finding.

**The shared barrier core is measured once.** Both tracks rest on the ≈ 2^70.20 Part 1 mask-space cardinality and 3-snake independence, corroborated at the derivation and kernel layers by [Probe C2](#42-probe-c2--mask-space-structural-uniformity-and-the-gcd-anti-collapse-trap) and [Probe C4](#44-probe-c4--cross-snake-independence).

**Wire-level scoping.** [§4.0](#40-layer-attribution--what-actually-appears-on-the-wire) establishes that the barrier absorbs every payload byte including the COBS terminator; the sole non-uniform wire byte is the cleartext dimension header, a length-restating structural field the outer cipher whitens for format deniability. Confidentiality against COA / KPA / CPA is delivered by the barrier composition, and every "indistinguishable from random" byte-histogram claim is scoped to the container body and the payload-channel probes.

## Conclusion

The v0.3.0 re-verification produced a uniform null verdict at the tested sample sizes: the broken-primitive controls yield empty shadow-K survivor sets with no anchoring crib shift; the PRF-grade representative sits at the independent-stream floor on the crib and Full KPA probes; and every construction-level probe returns a null or an explained-structural result. The one condition that surfaces any signal is nonce reuse — a lab-only assumption a caller cannot force — and even there the correlation stays far below a plaintext-recovery channel.

The architectural closure narrative rests on the two-part barrier: **Part 1** (the 48-bit interlock permutation) moves the KPA / CPA closure to the instance-formulation layer — a known crib anchors no fixed bit-to-lane mapping, and the mask has ≈ 2^57.80 preimages per chunk with no ranking signal among the ≈ 2^70.20 masks — while **Part 2** (per-pixel channelXOR / rotate7 / noise) denies a per-byte observation channel at the 1:1 signal/noise floor. The layer-attribution finding closes the pass with a scoping correction: the cleartext dimension header is the only structural wire byte, the outer cipher whitens it for format deniability, and confidentiality is the barrier's own contribution.

All verdicts are sample-bounded and, where they invoke primitive strength, PRF-conditional. The closure is an architectural claim corroborated by these measurements and by the pre-v0.3.0 evidence for the shared pixel construction, not an independently certified result. Total or systematic PRF inversion circumvents the barrier; nonce reuse leaves a near-identical-plaintext traffic-analysis distinguisher the barrier does not remove but no attacker-realistic plaintext-recovery channel at the tested sample size; and upstream key-management, side channels, key compromise, implementation defects, and CCA via a deployment decryption oracle sit outside what the barrier itself closes and are treated at the construction level in SECURITY.md and PROOFS.md. The complete pre-v0.3.0 empirical detail remains in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md).

## Pre-v0.3.0 empirical archive

The complete pre-v0.3.0 empirical record — the full Phase 1 through Phase 3b suite, every result table, and every Single-Ouroboros / overlay-off measurement — is preserved verbatim in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md). The v0.3.0 re-verification above supersedes it for the shipped construction; the archive is retained for the pre-v0.3.0 evidence the tracks cross-reference. The retired phase headings below are anchor bridges that resolve inbound references from the sibling documentation to their archived location.

### Phase 2a extension — hash-agnostic bias-neutralization audit (axis-1 + axis-2)

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) under the identically-named section. The primitive-shelf bias-neutralization methodology is carried forward in HARNESS.md.

### Phase 2d — Nonce-Reuse

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) § Phase 2d — Nonce-Reuse: the 96-cell Partial KPA matrix, demasker validation, and NIST STS PRF-separation result. The v0.3.0 nonce-reuse verdict is in the [per-attack verdicts](#nonce-reuse-lab-only) above.

### What a successful Partial KPA demask actually gets the attacker

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) under the identically-named Phase 2d subsection: a successful demask yields the hash-output stream, never new plaintext beyond the attacker's own Full KPA input.

### Phase 2e — Related-seed differential

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) § Phase 2e — Related-seed differential: the 1008-cell single-axis XOR-differential sweep. The v0.3.0 related-seed verdict is in the [per-attack verdicts](#related-seed-and-related-nonce-differential) above.

### Phase 2g — Multi Crib KPA against FNV-1a + ITB (SAT-based)

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) § Phase 2g — Multi Crib KPA against FNV-1a + ITB (SAT-based): the ≈ 8 h single-core SAT recovery against Single / overlay-off. The v0.3.0 FNV-1a verdict is in the [FNV-1a lo-lane SAT](#fnv-1a-lo-lane-sat--architecturally-foreclosed) section above.
