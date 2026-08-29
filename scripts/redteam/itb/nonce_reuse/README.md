# Nonce-Reuse adversarial re-verification (v0.3.0 barrier)

Empirical re-verification of the v0.3.0 (Triple Ouroboros + always-on
48-bit Interlocked Barrier + 8-seed constellation) construction under
forced nonce reuse. Primitive under test: **FNV-1a** on all 8 seed roles
(one below-spec lab primitive on every role; each seed still gets an
independent random key). Full KPA + nonce collision forced via the
test-only `setBrokenTestNonce` hook.

## Files

- `run.sh` — one-shot runner that invokes `go test -tags redteam -run
  TestRedTeamNonceReuse -v ./` from the repo root and copies the
  emitted JSON records under `~/scratch/redteam/nonce_reuse/` into a
  timestamped bundle for archival.
- `aggregate.py` — reads the emitted JSON records and prints a compact
  per-layer summary table. Consumes only files under
  `~/scratch/redteam/nonce_reuse/` — no test dependencies.

## Probes (implemented as Go tests in `redteam_nonce_reuse_test.go`)

Each Go test emits one JSON record to `~/scratch/redteam/nonce_reuse/`
for downstream aggregation.

- `TestRedTeamNonceReuseLayerAHistogram` — Layer A: byte-value chi-square
  / KL / byte-equal-rate on `C1 XOR C2` container bodies. Random /
  structured / near-identical plaintext pairs.
- `TestRedTeamNonceReuseLayerANaiveKPA` — Layer A': naive Crib-KPA
  constraint match assuming `snake_payload_byte == plaintext_byte`
  (i.e., ignoring the interlock). Reports max pixel-match count over
  candidate startPixels per snake.
- `TestRedTeamNonceReuseLayerBQuietChunk` — Layer B: with startPixel per
  snake granted as the single documented lab exception, measure per-pixel
  `(noisePos, rotation)` ambiguity on a near-identical plaintext pair.
- `TestRedTeamNonceReuseLayerBRandomPair` — Layer B random floor: same
  probe with random plaintext pair (no artificial quiet chunks).
- `TestRedTeamNonceReuseLayerBMaskOraclePeek` — Layer B': upper bound
  under startPixel-peek + mask-oracle-peek. Confirms the pre-v0.3.0
  demasker's Layer 1 succeeds at 100% precision IF the mask is revealed.
- `TestRedTeamNonceReuseLayerCFNVAlgebraic` — Layer C: attacker-realistic
  FNV-1a algebraic-recovery precondition. Zero pixels admit any (np, r)
  under the naive (no mask peek) constraint.
- `TestRedTeamNonceReuseLayerDMultiPair` — Layer D: N = 30 nonce-reuse
  ciphertexts, per-position distinct-byte-value distribution. Detects
  any deterministic residue across many pairs.
- `TestRedTeamNonceReuseCrossMessageDecrypt` — headline: given `C1, C2,
  P1, P2, C3`, recover bytes of `P3` under three regimes (attacker-
  realistic / startPixel peek / mask-oracle peek).
- `TestRedTeamNonceReuseSummaryDigest` — aggregates the per-probe JSON
  files into `summary_digest.json` for cross-track review.

## Attacker-realism scoping

Every probe consumes attacker-visible inputs (ciphertext bytes, the
public nonce and dimension header, the known Full-KPA plaintext pair)
for its decision path. Two narrowly-scoped lab peeks are permitted and
tagged at the call site:

- `[lab-peek: sp_i]` — Layer B / C probes grant the attacker the three
  snake `startPixel` values. This is the single documented "would it
  matter?" exception in the task brief.
- `[lab-peek: masks]` — the Layer B' `MaskOraclePeek` probe additionally
  reveals the per-chunk interlock mask triples. Results here are the
  UPPER BOUND — what the attack would achieve if a hypothetical
  primitive break revealed the `lockSeed`. Not attacker-realistic.

Ground-truth seed values appear only in terminal-stage `[audit]`
printouts, never in a decision path.

## Reproduction

```bash
# From the repo root:
./scripts/redteam/itb/nonce_reuse/run.sh

# Or invoke the tests directly:
go test -tags redteam -run TestRedTeamNonceReuse -v ./

# Then aggregate:
python3 scripts/redteam/itb/nonce_reuse/aggregate.py
```

Total wall-clock across all probes: ≈ 30 seconds on a workstation
(dominated by the Layer A histogram probe's 40 nonce-reuse-paired
encryptions).

## Debug output

`~/scratch/redteam/nonce_reuse/` lives outside the repository per the
CLAUDE.md working-tree layout. JSON records land there and stay local.
Override the parent directory via `REDTEAM_NONCE_REUSE_OUTPUT_DIR`.
