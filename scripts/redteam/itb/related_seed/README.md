## ITB Related-Seed Differential Verification

Related-seed differential diffusion of the shipped Triple Ouroboros +
always-on 48-bit Interlocked Barrier + 8 mandatory seeds API, measured
as the ciphertext-XOR byte-histogram χ² of a pair of encrypts that
differ in one seed bit. Primitives under test: **CRC128** and **FNV-1a** on all 8
seed roles (below-spec lab controls; each seed still gets an independent
random key). Nonce collision forced via the test-only `setBrokenTestNonce`
hook.

## Files

- `run.sh` — one-shot runner: invokes `go test -tags redteam -run TestRedTeamRelatedSeed
  -v ./` from the repo root, then aggregates the emitted JSON.
- `aggregate.py` — reads the emitted JSON records and prints a 4-D
  structural summary (axis dominance ranking, Δ pattern sensitivity,
  plaintext kind sensitivity, primitive contrast, positive-control
  χ² against the no-Δ floor). Consumes only files under
  `~/scratch/redteam/related_seed/` — no test dependencies.

## Probes (implemented as Go tests in `redteam_related_seed_test.go`)

Each Go test emits one JSON record to `~/scratch/redteam/related_seed/`.

- `TestRedTeamRelatedSeedControl` — **positive control**: a data-axis
  bit_high Δ through `process128Cfg` (one region, no barrier, no
  3-region split) gives CRC128 42.5M / FNV-1a 42.6M. Confirms the χ²
  probe is sensitive where no barrier stands between the Δ and the wire.
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
measure whether the barrier absorbs perturbations.

Every probe consumes attacker-visible inputs (ciphertext bytes only)
for its decision path — the χ² statistic depends on nothing else. No
`dataSeed*` / `noiseSeed` / `lockSeed` components are read in any
decision path. Ground-truth Δ hex is recorded only in terminal-stage
JSON records for later cross-check, never in a decision path.

## Structural verdict

The barrier's related-seed diffusion property is **confined to
the lockSeed axis**:

- **lockSeed axis, both primitives**: χ² ≈ 300-800 across the Δ
  patterns the primitive carries into the masks and both plaintext
  kinds — within a few multiples of the df=255 uniform band top. A 1-bit
  Δ on lockSeed re-derives the interlock's per-chunk permutation
  entirely, avalanching the plaintext-byte-to-region split and
  randomising every touched pixel byte's 7 data bits. The bit_high
  pattern (top bit of the last component, the high word of the final
  ChainHash round) is a null Δ under FNV-1a on this axis: the flip
  survives `deriveInterLockSeed` at bit 127 and is cancelled when the
  `[K ‖ components]` cascade XORs the flipped component back in at its
  last round, so that cell sits at the no-Δ floor (42.2M), not above it.
  On the dataSeed_i / startSeed_i axes bit_high is a null Δ for both
  primitives (only `hLo` is consumed there; neither lab primitive
  carries a high-word change into the low word); on the noiseSeed axis
  the position mixes both words, so the same flip moves every noise
  position and lands below the floor.
- **Every other seed axis** (noiseSeed / dataSeed_i / startSeed_i):
  χ² 6-42M range. **The no-Δ architectural floor** measured by
  `TestRedTeamRelatedSeedNoDeltaFloor` under identical seeds is
  CRC128 42.2M / FNV-1a 42.2M. The per-axis peak does NOT exceed the
  floor; Δ patterns that randomise the touched-region data bits
  (bit0 / bit_mid) drop χ² BELOW the floor by diluting the noiseMask
  signal, and every noiseSeed cell sits below the floor because the Δ
  moves the noise position of every pixel. No excess-over-floor signal
  on any non-lockSeed axis for either primitive.
- **Positive control**: CRC128 42.5M / FNV-1a 42.6M via
  `process128Cfg` (one region, no barrier); the probe is sensitive.

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
