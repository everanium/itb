# Related-seed differential re-verification

Empirical re-verification of the archived Phase 2e finding
(CRC128 42.5M, FNV-1a 56.7M axis-hit ciphertext-XOR χ² on Single
Ouroboros with the overlay disengaged) against the shipped Triple
Ouroboros + always-on 48-bit Interlocked Barrier + 8 mandatory
seeds API. Primitives under test: **CRC128** and **FNV-1a** on all 8
seed roles (below-spec lab controls; each seed still gets an independent
random key). Nonce collision forced via the test-only `setBrokenTestNonce`
hook.

## Files

- `run.sh` — one-shot runner: invokes `go test -tags redteam -run TestRedTeamRelatedSeed
  -v ./` from the repo root, then aggregates the emitted JSON.
- `aggregate.py` — reads the emitted JSON records and prints a 4-D
  structural summary (axis dominance ranking, Δ pattern sensitivity,
  plaintext kind sensitivity, primitive contrast, positive-control
  drift vs the archived record). Consumes only files under
  `~/scratch/redteam/related_seed/` — no test dependencies.

## Probes (implemented as Go tests in `redteam_related_seed_test.go`)

Each Go test emits one JSON record to `~/scratch/redteam/related_seed/`.

- `TestRedTeamRelatedSeedControl` — **positive control**: reproduces
  the archived Phase 2e axis-hit (CRC128 42.5M / FNV-1a 56.7M) via
  `process128Cfg` (Single Ouroboros, no interlock overlay, no 3-snake
  split). Confirms the ported χ² probe is sensitive at the archived
  measurement angle and matches the archive numbers to within 0.3 %.
- `TestRedTeamRelatedSeedNoDeltaFloor` — **architectural floor**:
  two `Encrypt3x128Cfg` calls with IDENTICAL seeds under the same
  forced nonce. Measures the χ² floor produced by the barrier's
  independent per-encrypt CSPRNG draws (container background + payload
  fill + noise-bit at noisePos). Establishes the reference every
  matrix cell is compared against.
- `TestRedTeamRelatedSeedMatrix` — **8-axis Δ matrix**: 8 seed axes
  (noiseSeed / lockSeed / dataSeed{1,2,3} / startSeed{1,2,3}) × 3 Δ
  patterns (bit0 / bit_mid / bit_high) × 2 plaintext kinds (random /
  ascii) × 2 below-spec primitives (CRC128 / FNV-1a) = 96 cells,
  512 KiB plaintext each. Computes ciphertext-body XOR χ² per cell.

## Attacker-realism scoping

The related-seed differential is a **structural diffusion probe**, not
an attacker-realistic recovery path. A real attacker cannot force
1-bit seed deltas because `Encrypt3x128Cfg` draws every seed
independently through `NewSeed*`, and the shipped API rejects seed
pointer collisions. The lab-forced Δ is a probe INPUT designed to
measure whether the barrier absorbs perturbations at the archived
measurement angle.

Every probe consumes attacker-visible inputs (ciphertext bytes only)
for its decision path — the χ² statistic depends on nothing else. No
`dataSeed*` / `noiseSeed` / `lockSeed` components are read in any
decision path. Ground-truth Δ hex is recorded only in terminal-stage
JSON records for later cross-check, never in a decision path.

## Structural verdict

The barrier's related-seed diffusion property is **confined to
the lockSeed axis**:

- **lockSeed axis, both primitives**: χ² ≈ 200-635 across every Δ
  pattern and plaintext kind — inside the df=255 uniform band. A 1-bit
  Δ on lockSeed re-derives the interlock's per-chunk permutation
  entirely, avalanching the plaintext-byte-to-snake split and
  randomising every touched pixel byte's 7 data bits.
- **Every other seed axis** (noiseSeed / dataSeed_i / startSeed_i):
  χ² 19-56M range. **The no-Δ architectural floor** measured by
  `TestRedTeamRelatedSeedNoDeltaFloor` under identical seeds is
  CRC128 41.9M / FNV-1a 56.3M. The per-axis peak does NOT exceed the
  floor; Δ patterns that randomise the touched-snake data bits
  (bit0 / bit_mid) drop χ² BELOW the floor by diluting the noiseMask
  signal. No excess-over-floor signal on any non-lockSeed axis for
  either primitive.
- **Positive control**: the archived 42.5M / 56.7M axis-hit
  reproduced via `process128Cfg` (Single Ouroboros, no overlay) within
  0.3 %. The probe methodology matches the archived Phase 2e.

The archived Phase 2e "6.1M neutralised cluster" description
(architectural noisePos permutation signal, not primitive leak) has
its shipped analog in the CRC128 41.9M / FNV-1a 56.3M no-Δ floor. The
floor is primitive-conditional through noiseSeed's ChainHash shape
influencing noisePos derivation; it is not a primitive-attributable Δ
leak.

## Reproduction

```bash
# From the repo root:
./scripts/redteam/itb/related_seed/run.sh

# Or invoke the tests directly:
go test -tags redteam -run TestRedTeamRelatedSeed -v -timeout 1800s ./

# Then aggregate:
python3 scripts/redteam/itb/related_seed/aggregate.py
```

Total wall-clock across all probes: ~10 minutes on a workstation
(~9 min for the 96-cell matrix + ~40 s for the positive control +
~15 s for the no-Δ floor probe).

## Debug output

`~/scratch/redteam/related_seed/` lives outside the repository. JSON
records land there and stay local. Override the parent directory via
`REDTEAM_RELATED_SEED_OUTPUT_DIR`.
