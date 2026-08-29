# Related-nonce differential re-verification

Empirical re-verification of the barrier's diffusion property against a
lab-forced 1-bit nonce Δ. Primitives under test: **CRC128** and
**FNV-1a** on all 8 seed roles (below-spec lab controls; each seed role
still gets an independent random key). Nonce Δ forced across the
compared encrypt pair via the test-only `setBrokenTestNonce` hook.

## Framing

A production attacker cannot force a 1-bit nonce delta: `generateNonceCfg`
draws every nonce from `crypto/rand` per Encrypt call, and the nonce is
never exposed to the caller as a controllable input. This is a
**structural diffusion probe** — the χ² measurement stresses the
barrier's diffusion property against a hypothetical nonce perturbation,
not any shipped-API attack path.

## Files

- `run.sh` — one-shot runner: invokes
  `go test -tags redteam -run TestRedTeamRelatedNonce -v ./` from the repo root, then
  aggregates the emitted JSON.
- `aggregate.py` — reads the emitted JSON records and prints a compact
  structural summary (Δ pattern ranking, plaintext-kind sensitivity,
  primitive contrast, excess-over-no-Δ-floor). Consumes only files under
  `~/scratch/redteam/related_nonce/` — no test dependencies.

## Probes (implemented as Go tests in `redteam_related_nonce_test.go`)

Each Go test emits one JSON record to `~/scratch/redteam/related_nonce/`.

- `TestRedTeamRelatedNonceNoDeltaFloor` — **architectural floor**: two
  `Encrypt3x128Cfg` calls with IDENTICAL seeds under the same forced
  nonce. Measures the χ² floor produced by the barrier's independent
  per-encrypt CSPRNG draws (container background + payload fill +
  noise-bit at each fixed `noisePos`). Reproduces Rank 2's floor within
  primitive-conditional noise.
- `TestRedTeamRelatedNonceMatrix` — **Δ matrix**: 6 nonce Δ patterns ×
  2 plaintext kinds (random / ASCII) × 2 below-spec primitives (CRC128 /
  FNV-1a) = 24 cells, 512 KiB plaintext each. Computes ciphertext-body
  XOR χ² per cell. Six Δ positions sample nonce byte-word structure:
  LSB of byte 0, MSB of byte 0, MSB of byte 7 (first 64-bit word
  boundary), LSB of byte 32 (middle-byte), LSB of byte 56 (start of
  last 64-bit word), MSB of byte 63 (top bit).

## Architectural derivation graph (code-trace)

The nonce is a shared input to FOUR distinct derivation paths, one per
each of the 8 shipped seed roles:

| Seed role  | Derivation           | Nonce buf layout             | Output consumed as |
|------------|----------------------|------------------------------|--------------------|
| noiseSeed  | `blockHash*(buf, p)` | `pixIdx (4 LE) \|\| nonce`   | per-pixel `noisePos = h.lo & 7` |
| dataSeed_i | `blockHash*(buf, p)` | `pixIdx (4 LE) \|\| nonce`   | per-pixel `dataRotation` + `channelXOR` per snake |
| startSeed_i| `ChainHash*(buf)`    | `0x02 \|\| nonce`            | `startPixel = h.lo % totalPixels` per snake |
| lockSeed   | `deriveInterLockSeed`| `0x02 \|\| nonce`            | full-width Interlocked Barrier per-chunk overlay key |

Every one of the 8 seeds consumes the nonce. A 1-bit nonce Δ perturbs
ALL 8 seed-derived outputs simultaneously — fundamentally different
from Rank 2's single-seed Δ. The lockSeed derivation slot is one of
eight nonce consumers, not a bottleneck; **nonce Δ SUPERSETS lockSeed
Δ** by also perturbing the other seven derivation slots.

## Attacker-realism scoping

The lab-forced nonce Δ is a probe INPUT designed to measure whether the
barrier absorbs perturbations at the archived measurement angle. Every
probe consumes attacker-visible inputs (ciphertext bytes only) for its
decision path — the χ² statistic depends on nothing else. No seed
components are read in any decision path. Ground-truth Δ hex is recorded
only in terminal-stage JSON records for later cross-check, never in a
decision path.

## Structural verdict

The barrier's related-nonce diffusion property is **full
absorption**:

- **CRC128 matrix (24 cells)**: χ² 242.4 – 283.3, mean 257.1. Every
  cell inside the df=255 uniform band (theoretical mean 255, one-sided
  3σ top ≈ 323). Δ_over_no-Δ-floor: -41.9M (four orders of magnitude
  below floor).
- **FNV-1a matrix (24 cells)**: χ² 217.2 – 263.4, mean 247.8. Every
  cell inside the df=255 uniform band. Δ_over_no-Δ-floor: -56.3M.
- **No-Δ floor reference (Rank 2 methodology)**: CRC128 41.90M,
  FNV-1a 56.28M — matches Rank 2's floor within 0.1 %.
- **Rank 2 lockSeed axis contrast**: CRC128 lockSeed-axis peak was 635,
  FNV-1a 550. Rank 3 nonce Δ is TIGHTER than the Rank 2 lockSeed axis
  (max 283 vs 635 CRC128, max 263 vs 550 FNV-1a) — consistent with the
  "SUPERSET" prediction that the additional 7 seed-derivation
  perturbations further randomise touched-pixel bytes on top of the
  lockSeed-routed interlock re-derivation.

Δ pattern sensitivity is negligible: max χ² across the six systematic
bit positions varies by 4-9 % within each primitive — none of
{bit_low, byte_msb, word_boundary, bit_mid, byte_high_lsb, bit_high}
is dominant. Plaintext-kind sensitivity is negligible as well: random
and ASCII plaintexts produce comparable χ² per primitive (mean 258 vs
256 CRC128, 252 vs 244 FNV-1a).

## Reproduction

```bash
# From the repo root:
./scripts/redteam/itb/related_nonce/run.sh

# Or invoke the tests directly:
go test -tags redteam -run TestRedTeamRelatedNonce -v -timeout 1800s ./

# Then aggregate:
python3 scripts/redteam/itb/related_nonce/aggregate.py
```

Total wall-clock across all probes: ~3 minutes on a workstation
(~2.5 min for the 24-cell matrix + ~15 s for the no-Δ floor probe).

## Debug output

`~/scratch/redteam/related_nonce/` lives outside the repository. JSON
records land there and stay local. Override the parent directory via
`REDTEAM_RELATED_NONCE_OUTPUT_DIR`.
