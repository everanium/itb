# FNV-1a lo-lane SAT re-verification (v0.3.0 barrier)

Empirical re-verification of the v0.3.0 (Triple Ouroboros + always-on
48-bit Interlocked Barrier + 8-seed constellation) construction against
the FNV-1a lo-lane Full-KPA SAT attack from pre-v0.3.0 Phase 2g. That
Phase 2g attack recovered a functional dataSeed lo-lane compound key in
≈ 8 h single-core Bitwuzla against **Single Ouroboros with the barrier
disengaged**, yielding 83–85 % byte-level plaintext recovery on JSON /
HTML holdouts.

**Threat model — fresh nonces per message.** This track is orthogonal
to the nonce-reuse re-verification (see
`../nonce_reuse/README.md`). Every ciphertext here uses an independent
nonce (the fixed test nonce is a reproducibility knob, not a lab
assumption on the attacker). The v0.3.0 closure narrative for this
track is **multi-seed joint coupling** — every attacker-visible byte is
the sum of contributions from noiseSeed, lockSeed, dataSeed_i,
startSeed_i, so no per-chain observation channel exists.

## Files

- `run.sh` — one-shot runner that invokes `go test -run
  TestRedTeamBrokenFNV1a -v ./` from the repo root, then, if Bitwuzla
  is available, runs the Python SAT probe at the ITB_FNV1A_SAT_*
  environment-driven configuration and aggregates the emitted JSON
  records.
- `sat_probe.py` — Bitwuzla SAT harness. Encodes the naive-crib
  anchoring premise as a per-pixel disjunction over the 56 (np, r)
  tuples chained through the symbolic FNV-1a lo-lane; runs against
  both the Single Ouroboros / barrier-off control and the v0.3.0
  Triple / barrier ciphertext (per snake, over a fast-scan sample of
  candidate startPixels). See the module docstring for encoding
  detail and the maximum-peek attacker regime.
- `aggregate.py` — reads the emitted JSON records and prints a
  compact per-layer summary. Consumes only files under
  `~/scratch/redteam/fnv1a_sat/` — no test dependency.

## Probes (implemented as Go tests in `redteam_broken_fnv1a_sat_test.go`)

Each Go test emits one JSON record to `~/scratch/redteam/fnv1a_sat/`
for downstream aggregation.

- `TestRedTeamBrokenFNV1aCribKPA` — F1: attacker-realistic
  per-pixel achievable-set structure. Under FNV-1a's non-affine
  ChainHash no pixel-independent K exists, so the pre-v0.3.0 CRC128
  compound-K intersection filter yields zero cross-pixel
  intersection at every candidate shift.
- `TestRedTeamBrokenFNV1aCribKPATrueAnchor` — F2: lab-peek true
  anchor. Grants attacker true (np, r) per pixel via noiseSeed +
  dataSeed_i peek and counts how many crib channel bytes match the
  true dataHash prefix under the naive-crib alignment. Under barrier:
  match rate at chance floor for every candidate shift.
- `TestRedTeamBrokenFNV1aCribKPAControl` — F3: positive control.
  Single Ouroboros without barrier via `process128Cfg`, sp disclosed
  — the naive-crib SAT anchor recovers the true xor_mask56 at every
  crib pixel. Confirms the anchor logic is sensitive.
- `TestRedTeamBrokenFNV1aCribKPAStartPixelPeek` — F4: Layer 3
  scoped bonus with per-snake `sp_i` disclosed via
  `deriveStartPixel`. Reports channel matches at the disclosed sp
  versus the shift-averaged floor. Under barrier: the disclosed sp
  count is at the same floor as every other shift.
- `TestRedTeamBrokenFNV1aCribKPADisplacement` — F5: displacement
  fraction on the JSON crib. Repeats the invariant probe from
  `TestRedTeamBrokenBarrierDisplacement` (redteam_broken_test.go)
  on the exact same plaintext used by every F* probe.
- `TestRedTeamBrokenFNV1aCribKPAEmitCorpus` — F6: emits the Go /
  Python interface bundle (ciphertext + control + true seeds) under
  `~/scratch/redteam/fnv1a_sat/f6_corpus_bundle.json` for the Python
  SAT probe to consume.

## Attacker-realism scoping

Every F1 / F5 probe consumes attacker-visible inputs (ciphertext bytes,
the public nonce and dimension header, the fully-attacker-known JSON
crib) for its decision path. Lab peeks are tagged at each call site:

- `[lab-peek: true_seeds]` — F2 grants the attacker true noiseSeed
  + dataSeed_i values, deriving true (np, r) per pixel. Establishes
  the STRONGEST-ATTACKER upper bound. Under barrier the anchor still
  fails at chance floor — a definitive negative.
- `[lab-peek: sp_i]` — F4 grants the attacker per-snake startPixel
  via `startSeed_i.deriveStartPixel(nonce, snake_pixels)`. Combines
  with the F2 lab peek to place 5–6 of the 8 chains in the attacker's
  hands.
- `[lab-peek: barrier_split]` — F5 uses
  `splitForTriple48LockedCfg` with the true lockSeed to inspect the
  per-snake lane bytes for the displacement measurement.

Ground-truth seed values appear elsewhere only in terminal-stage
`[audit]` printouts, never in a decision path.

## Bitwuzla SAT probe scope

`sat_probe.py` is a compact adaptation of the pre-v0.3.0
`scripts/redteam/itb/theory/fnv1a/sat_harness_4round.py`. The full
Single-Ouroboros harness ran ≈ 8 h on 4 cribs + disclosed startPixel.
The v0.3.0 probe here targets an **isolated single-chain "strongest
attacker" upper bound**: the attacker is granted true (np, r) per pixel
(5 of 8 chains inverted for free) and only the single dataSeed_i lo
lane stays symbolic. If this UPPER-BOUND SAT returns UNSAT, the full
coupled-8-chain SAT (all 8 chains unknown + per-chunk interlock mask
triples symbolic) is trivially harder and also UNSAT.

Full symbolic 8-chain SAT is beyond a single-cycle scope; the
anchoring-level closure documented by F1 / F2 / F4 / F5 is the
load-bearing empirical evidence.

## Reproduction

```bash
# From the repo root:
./scripts/redteam/itb/fnv1a_sat/run.sh

# Or invoke the Go tests directly:
go test -tags redteam -run TestRedTeamBrokenFNV1a -v ./

# Then aggregate:
python3 scripts/redteam/itb/fnv1a_sat/aggregate.py

# Bitwuzla SAT probe (defaults 2 crib pixels, 600 s per instance,
# 4-candidate sp scan per snake):
python3 scripts/redteam/itb/fnv1a_sat/sat_probe.py \
    --n-crib-pixels 2 --timeout-sec 600 --regime true_npr

# Env-var knobs:
#   ITB_FNV1A_SAT_N        — crib pixels per SAT instance (default 2)
#   ITB_FNV1A_SAT_TIMEOUT  — solver timeout in seconds (default 600)
#   ITB_FNV1A_SAT_CAP      — candidate sp scan count per snake
#                            (default 8; run.sh defaults to 4)
```

Total wall-clock for the Go probes: ≈ 2 seconds on a workstation.
The Bitwuzla SAT probe scales with n_crib_pixels and the sp scan
count; at n = 2 pixels and cap = 4 sp candidates per snake, budget
≈ 15 minutes on a commodity workstation.

## Debug output

`~/scratch/redteam/fnv1a_sat/` lives outside the repository per the
CLAUDE.md working-tree layout. JSON records land there and stay local.
Override the parent directory via `REDTEAM_FNV1A_SAT_OUTPUT_DIR`.
