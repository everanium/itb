# HARNESS.md — Non-cryptographic Hash Primitive Analysis Shelf

*(public sibling of [REDTEAM.md](REDTEAM.md) / [ITB.md](ITB.md) / [SCIENCE.md](SCIENCE.md) / [PROOFS.md](PROOFS.md). Three-axis empirical study of non-cryptographic hash primitives wrapped into ITB `ChainHash128` — bias-absorption (Axes A, A', B) and SAT KPA seed-recovery resistance (Axis C). Scope restricted to primitives whose Go reference and Python mirror each fit in ≤ ~500 LOC.)*

## 1. Scope

The shelf measures four non-cryptographic hash primitives plugged into ITB `ChainHash128` to validate two architectural properties:

1. **Bias absorption** — whether ITB's encoding pipeline (rotation + noise barrier + COBS framing + CSPRNG fill) neutralises a primitive's documented SMHasher weaknesses on the attacker-observable ciphertext surface (Axes A, A', B).
2. **SAT-based seed-recovery resistance** — whether commodity-scale Bitwuzla / Z3 KPA can recover the per-primitive seed at minimum ITB deployment (`keyBits = 512`, ChainHash-4 lo-lane) within reasonable wall-clock (Axis C).

The shelf complements [REDTEAM.md Phase 2a extension](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) (which targets the four cryptographic primitives in the Hash matrix) by extending bias-absorption coverage to non-cryptographic hashes, and complements [REDTEAM.md Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) by characterising raw-chain SAT KPA cost on each primitive in isolation.

Primitive selection criteria:

- Non-cryptographic (primary design goal is speed / distribution quality).
- Multi-round ARX or multiply-and-mix structure; no closed-form seed recovery known.
- Not publicly broken under KPA (no published seed-recovery paper, no packaged inverter).
- Reference + Python mirror each ≤ ~500 LOC.

Four primitives in scope: **t1ha1_64le**, **SeaHash**, **mx3**, **SipHash-1-3**.

## 2. Methodology

Four orthogonal axes:

**Axis A — hLo-projected lab bias.** SMHasher-style avalanche on the local Python mirror, projected onto the hLo lane that ITB observes through `ChainHash128`'s parallel two-lane wrapper. Random-input flip-1-bit measurement; max bias is `2 × |P(flip) − 0.5| × 100 %` over all (input_bit, output_bit) pairs.

**Axis A' — structural-input bias.** Per-bit output frequency, byte-distribution chi-square (df = 255), and adjacency XOR statistics, all at fixed seed against varying structured inputs (`json_structured`, `html_structured`). Mirrors the ITB-realistic threat model where seeds are deployment invariants and inputs share schema.

**Axis B — ITB-wrapped bias.** [Phase 2a extension probe](REDTEAM.md#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) against `known_ascii` corpora encrypted with the primitive plugged into `ChainHash128` at `keyBits = 1024`, BF = 1, N = 2 nonce-reuse. Verdict `neutralized ✓` when `|Δ50|` of the per-shift conflict-rate distribution is below 1 %.

**Axis C — SAT KPA seed recovery.** Bitwuzla / Z3 KPA against synthetic `(message, hash(message, k))` pairs at raw chain hash and `ChainHash-1` wrap levels. Cells classified by tier:

| Tier | Criterion | Cryptographic meaning |
|------|-----------|------------------------|
| **0 TRASH** | training-forward fails | SAT encoding drift |
| **1 TRAINING-ONLY** | valid + holdout = 0 / N | multi-seed collision restricted to training |
| **2 PARTIAL** | valid + 0 < holdout < N | partial functional similarity |
| **3 FUNCTIONAL-EQ** | valid + holdout = N / N | functionally indistinguishable from ground truth — usable K |
| **4 BIT-EXACT** | recovered = ground truth byte-for-byte | identical seed |

False-positive rate at N = 32 holdout: `2⁻²⁰⁴⁸`, astronomically small.

## 3. Results

### 3.1. Axis A — lab bias on raw primitive

Random-input avalanche. Reference: published [`rurban/smhasher`](https://github.com/rurban/smhasher) numbers.

| Primitive | key_bits | n_keys | measured max bias | published (rurban) | reproduction ratio |
|:----------|---------:|------:|------------------:|-------------------:|:-------------------|
| **t1ha1_64le** | 256 | 65 536 | 1.82 % | not separately reported | noise-dominated (max-noise floor ≈ 1.78 %) |
| **t1ha1_64le** | 512 | 65 536 | **3.19 %** | 3.77 % | **85 %** |
| **t1ha1_64le** | 1024 | 65 536 | **3.24 %** | 3.95 % | **82 %** |
| **SeaHash**    | 256 | 65 536 | 1.45 % | not separately reported (clean) | at noise (PerlinNoise is the documented weakness, not avalanche) |
| **SeaHash**    | 512 | 65 536 | 1.87 % | not separately reported (clean) | at noise |
| **SeaHash**    | 1024 | 65 536 | 1.68 % | not separately reported (clean) | at noise |
| **mx3**        | 256  | 65 536 | 1.55 % | not separately reported (clean) | at noise (PerlinNoise AV 1.48 × 10¹² × is the documented weakness, not avalanche) |
| **mx3**        | 2048 | 65 536 | 1.89 % | not separately reported (clean) | at noise |
| **mx3**        | 8192 | 65 536 | 2.08 % | not separately reported (clean) | at noise |
| **SipHash-1-3** | 256  | 65 536 | 1.88 % | ~0.9 % (reduced-round profile) | at noise (max-noise floor ≈ 1.66 %; ~13 % above floor — borderline, consistent with reduced-round avalanche signature surviving into the hLo projection) |
| **SipHash-1-3** | 2048 | 65 536 | 1.78 % | ~0.9 % (reduced-round profile) | at noise; bias stable across key size (ARX scaling) |
| **SipHash-1-3** | 8192 | 65 536 | 1.71 % | ~0.9 % (reduced-round profile) | at noise; bias stable |

t1ha1's published avalanche scaling is partially reproduced (82–85 % of rurban magnitude). SeaHash and mx3 are at-noise on avalanche (their documented weaknesses are PerlinNoise on coordinate-structured inputs, not exercised by random-flip avalanche). SipHash-1-3 sits at-noise but slightly above max-noise floor — consistent with the reduced 1+3 round avalanche signature.

### 3.2. Axis A' — structural-input bias (fixed seed + varying schema)

| Primitive | format | n_instances × instance_size | bit_bias max | noise-max floor | byte χ² p | adj_xor max | verdict |
|:----------|:-------|:----------------------------|-------------:|----------------:|----------:|------------:|:--------|
| **t1ha1_64le** | json_structured | 65 536 × 4 KB  | 0.51 % | 0.58 % | 0.40 | 0.36 % | **no bias detected** |
| **t1ha1_64le** | json_structured | 4 096 × 64 KB | 2.30 % | 2.25 % | 0.44 | 1.77 % | **no bias detected** |
| **t1ha1_64le** | html_structured | 65 536 × 4 KB  | 0.45 % | 0.58 % | 0.63 | 0.58 % | **no bias detected** |
| **t1ha1_64le** | html_structured | 4 096 × 64 KB | 2.39 % | 2.25 % | 0.13 | 2.04 % | **no bias detected** |
| **SeaHash**    | json_structured | 65 536 × 4 KB  | 0.48 % | 0.58 % | 0.24 | 0.48 % | **no bias detected** |
| **SeaHash**    | json_structured | 4 096 × 64 KB | 2.42 % | 2.25 % | 0.82 | 1.70 % | **no bias detected** |
| **SeaHash**    | html_structured | 65 536 × 4 KB  | 0.54 % | 0.58 % | 0.11 | 0.47 % | **no bias detected** |
| **SeaHash**    | html_structured | 4 096 × 64 KB | 2.34 % | 2.25 % | 0.64 | 2.38 % | **no bias detected** |
| **mx3**        | json_structured | 65 536 × 4 KB  | 0.41 % | 0.58 % | 0.08 | 0.43 % | **no bias detected** |
| **mx3**        | json_structured | 4 096 × 64 KB | 2.00 % | 2.25 % | 0.13 | 1.89 % | **no bias detected** |
| **mx3**        | html_structured | 65 536 × 4 KB  | 0.49 % | 0.58 % | 0.91 | 0.46 % | **no bias detected** |
| **mx3**        | html_structured | 4 096 × 64 KB | 2.12 % | 2.25 % | 0.40 | 2.72 % | **no bias detected** |
| **SipHash-1-3** | json_structured | 65 536 × 4 KB  | 0.46 % | 0.58 % | 0.54 | 0.43 % | **no bias detected** |
| **SipHash-1-3** | json_structured | 4 096 × 64 KB | 2.39 % | 2.25 % | 0.17 | 1.99 % | **no bias detected** |
| **SipHash-1-3** | html_structured | 65 536 × 4 KB  | 0.53 % | 0.58 % | 0.16 | 0.45 % | **no bias detected** |
| **SipHash-1-3** | html_structured | 4 096 × 64 KB | 2.08 % | 2.25 % | 0.62 | 1.87 % | **no bias detected** |

Every cell within noise envelope. Under fixed seed + varying structured input, the hLo projection is statistically indistinguishable from random at the probe's resolution.

### 3.3. Axis B — ITB-wrapped raw-mode bias

| Primitive | size | format | Single \|Δ50\| | Triple Byte Level \|Δ50\| | Triple Bit Soup \|Δ50\| | shelf verdict |
|:----------|-----:|:-------|---------------:|--------------------------:|------------------------:|:--------------|
| **t1ha1_64le** | 512 KB | ascii | **0.607 %** ✓ | — | — | **neutralized ✓** on Single |
| **t1ha1_64le** | 1 MB   | ascii | **0.244 %** ✓ | — | — | **neutralized ✓** on Single |
| **SeaHash**    | 512 KB | ascii | **0.816 %** ✓ | — | — | **neutralized ✓** on Single |
| **SeaHash**    | 1 MB   | ascii | **0.140 %** ✓ | — | — | **neutralized ✓** on Single |
| **mx3**        | 512 KB | ascii | **0.363 %** ✓ | — | — | **neutralized ✓** on Single |
| **mx3**        | 1 MB   | ascii | **0.119 %** ✓ | — | — | **neutralized ✓** on Single |
| **SipHash-1-3** | 512 KB | ascii | **0.559 %** ✓ | — | — | **neutralized ✓** on Single |
| **SipHash-1-3** | 1 MB   | ascii | **0.489 %** ✓ | — | — | **neutralized ✓** on Single |

`—` in Triple columns: not measured because Single already established absorption. All measured primitives `neutralized ✓` at the 1 % threshold on both corpus sizes. The published SMHasher weaknesses (avalanche-scaling for t1ha1, PerlinNoise for SeaHash and mx3, reduced-round avalanche for SipHash-1-3) do not reach the attacker-observable ITB ciphertext surface.

### 3.4. Axis C — SAT KPA resistance (raw + ChainHash-1)

| Primitive | Raw KPA | ChainHash-1 | shelf verdict |
|:----------|:--------|:------------|:--------------|
| **t1ha1_64le** | **Timeout at 5-min budget** on rounds = 1 obs = 8 across Z3 and Bitwuzla | — (rounds = 1 already in timeout regime) | **Resistant at tested budget** |
| **SeaHash**    | **Timeout at 5-min budget** across all 4 encodings (`{native, explicit}` × `{native, case-split}`) on Z3 and Bitwuzla (8 cells) | — (rounds = 1 already in timeout regime) | **Resistant at tested budget** |
| **mx3**        | **SAT-broken** — Tier 3 FUNCTIONAL-EQ at obs = 8 / rounds = 1 (Z3 native ≈ 5 s, Bitwuzla native ≈ 2 s, holdout = 32 / 32) | **SAT-broken** — same wall-clock as Raw KPA (at rounds = 1 ChainHash composition degenerates to a single `mx3_hash` call: hi-lane seed unconstrained, lo-lane seed recovered functionally-equivalent to ground truth) | **Dangerous** — Raw + ChainHash-1 broken in seconds on commodity |
| **SipHash-1-3** | **Timeout at 5-min budget** on rounds = 1 obs = 8 across Z3 and Bitwuzla | — (rounds = 1 already in timeout regime) | **Resistant at tested budget** |

mx3 is the lone `Dangerous` row: the parallel two-lane construction collapses at rounds = 1 (hi-lane seed never enters the chain output's symbolic expression, and the lo-lane seed is functionally recoverable in seconds). Higher-round chains push mx3 into the timeout regime even on commodity budgets. Triple Bit Soup mode is expected to neutralise mx3 at the construction layer; that measurement is not yet on the shelf.

## 4. Primitive shelf

| # | Primitive | Axis A signature (published) | Axis A / A' / B | Axis C |
|--:|-----------|:-----------------------------|:----------------|:-------|
| 1 | **t1ha1_64le** (Yuriev) | Avalanche 3.77–3.95 % at 512–1024-bit keys | measured | **Resistant at tested budget** |
| 2 | **SeaHash** (Ticki, 2016) | PerlinNoise 2.2 × 10¹² × | measured | **Resistant at tested budget** |
| 3 | **mx3** (Maiga, 2022) | PerlinNoise AV 1.48 × 10¹² × | measured | **Dangerous** |
| 4 | **SipHash-1-3** (reduced-round) | 0.9 % avalanche bias (reduced-round) | measured | **Resistant at tested budget** |

Shelf verdict labels:

- **neutralized ✓** — Axis B passes (`|Δ50| < 1 %`) on Single Ouroboros; Triple modes redundant once Single absorption is established.
- **Resistant at tested budget** — Axis C SAT KPA timed out across all tested encodings × backends within the budget. The weakest positive label this shelf emits — always qualified with the measured budget.
- **Dangerous** — Raw chain or ChainHash-1 SAT-broken in commodity time; higher-round chain unmeasured or unreachable at the tested budget.
- **Fully broken** — Axis C Raw or ChainHash-1 produced functionally-equivalent K AND higher-round chain breakable in the same regime.

## 5. Reproduction

### 5.1. t1ha1_64le

```bash
# Axis A — avalanche on raw primitive
python3 scripts/redteam/phase2_theory_t1ha1/lab_bias_t1ha1.py \
    --n-keys 65536 --key-sizes 32,64,128 \
    --json-report tmp/attack/t1ha1stress/axis_a_lab_bias.json

# Axis A' — structural-input bias (json + html × 4 KB / 64 KB)
python3 scripts/redteam/phase2_theory_t1ha1/lab_struct_t1ha1.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/t1ha1stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/phase2_theory_t1ha1/lab_struct_t1ha1.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/t1ha1stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/phase2_theory_t1ha1/lab_struct_t1ha1.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/t1ha1stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/phase2_theory_t1ha1/lab_struct_t1ha1.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/t1ha1stress/axis_a_struct_html_n4096_65536.json

# Axis B — ITB-wrapped raw-mode bias
bash scripts/redteam/harness_bias_audit_t1ha1.sh

# Axis C — raw chain SAT KPA (rounds = 1 obs = 8, 5-min budget)
python3 scripts/redteam/phase2_theory_t1ha1/sat_calibration_raw_t1ha1.py \
    --rounds 1 --obs 8 --timeout-sec 300 --solver z3 \
    --json-report tmp/attack/t1ha1stress/axis_c_raw_z3.json
python3 scripts/redteam/phase2_theory_t1ha1/sat_calibration_raw_t1ha1.py \
    --rounds 1 --obs 8 --timeout-sec 300 --solver bitwuzla \
    --json-report tmp/attack/t1ha1stress/axis_c_raw_bw.json
```

### 5.2. SeaHash

```bash
# Axis A
python3 scripts/redteam/phase2_theory_seahash/lab_bias_seahash.py \
    --n-keys 65536 --key-sizes 32,64,128 \
    --json-report tmp/attack/seahashstress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/seahashstress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/seahashstress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/seahashstress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/phase2_theory_seahash/lab_struct_seahash.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/seahashstress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/harness_bias_audit_seahash.sh

# Axis C — raw chain SAT KPA (4 encodings × 2 backends, 5-min budget)
for MUL in native explicit; do for VAR in native case-split; do for SOLVER in z3 bitwuzla; do
    python3 scripts/redteam/phase2_theory_seahash/sat_calibration_raw_seahash.py \
        --rounds 1 --obs 8 --timeout-sec 300 --solver "$SOLVER" \
        --mul-encoding "$MUL" --var-shift-encoding "$VAR" \
        --json-report "tmp/attack/seahashstress/axis_c_raw_${SOLVER}_${MUL}_${VAR}.json"
done; done; done
```

### 5.3. mx3

```bash
# Axis A
python3 scripts/redteam/phase2_theory_mx3/lab_bias_mx3.py \
    --n-keys 65536 --key-sizes 32,256,1024 \
    --json-report tmp/attack/mx3stress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/phase2_theory_mx3/lab_struct_mx3.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/mx3stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/phase2_theory_mx3/lab_struct_mx3.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/mx3stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/phase2_theory_mx3/lab_struct_mx3.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/mx3stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/phase2_theory_mx3/lab_struct_mx3.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/mx3stress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/harness_bias_audit_mx3.sh

# Axis C — Z3 reaches Tier 3 in ~5 s on rounds = 1 obs = 8
python3 scripts/redteam/phase2_theory_mx3/sat_calibration_raw_mx3.py \
    --rounds 1 --obs 8 --timeout-sec 60 --solver z3 \
    --json-report tmp/attack/mx3stress/axis_c_raw_z3.json
# Axis C — Bitwuzla reaches Tier 3 in ~2 s on the same cell
python3 scripts/redteam/phase2_theory_mx3/sat_calibration_raw_mx3.py \
    --rounds 1 --obs 8 --timeout-sec 60 --solver bitwuzla \
    --json-report tmp/attack/mx3stress/axis_c_raw_bw.json
```

### 5.4. SipHash-1-3

```bash
# Axis A
python3 scripts/redteam/phase2_theory_siphash13/lab_bias_siphash13.py \
    --n-keys 65536 --key-sizes 32,256,1024 \
    --json-report tmp/attack/siphash13stress/axis_a_lab_bias.json

# Axis A'
python3 scripts/redteam/phase2_theory_siphash13/lab_struct_siphash13.py \
    --format json --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/siphash13stress/axis_a_struct_json_n65536_4096.json
python3 scripts/redteam/phase2_theory_siphash13/lab_struct_siphash13.py \
    --format json --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/siphash13stress/axis_a_struct_json_n4096_65536.json
python3 scripts/redteam/phase2_theory_siphash13/lab_struct_siphash13.py \
    --format html --n-instances 65536 --instance-size 4096 \
    --json-report tmp/attack/siphash13stress/axis_a_struct_html_n65536_4096.json
python3 scripts/redteam/phase2_theory_siphash13/lab_struct_siphash13.py \
    --format html --n-instances 4096 --instance-size 65536 \
    --json-report tmp/attack/siphash13stress/axis_a_struct_html_n4096_65536.json

# Axis B
bash scripts/redteam/harness_bias_audit_siphash13.sh

# Axis C — raw chain SAT KPA (rounds = 1 obs = 8, 5-min budget)
python3 scripts/redteam/phase2_theory_siphash13/sat_calibration_raw_siphash13.py \
    --rounds 1 --obs 8 --timeout-sec 300 --solver z3 \
    --json-report tmp/attack/siphash13stress/axis_c_raw_z3.json
python3 scripts/redteam/phase2_theory_siphash13/sat_calibration_raw_siphash13.py \
    --rounds 1 --obs 8 --timeout-sec 300 --solver bitwuzla \
    --json-report tmp/attack/siphash13stress/axis_c_raw_bw.json
```

### 5.5. Self-parity tests

Cross-check concrete vs Z3 symbolic for each primitive's chain-hash mirror:

```bash
python3 scripts/redteam/phase2_theory/chainhashes/_parity_test.py
python3 scripts/redteam/phase2_theory_t1ha1/t1ha1_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/phase2_theory_seahash/seahash_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/phase2_theory_mx3/mx3_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
python3 scripts/redteam/phase2_theory_siphash13/siphash13_chain_lo_concrete.py --rounds 1,2,4 --vectors 4
```
