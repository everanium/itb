# Fresh-nonce near-identical distinguisher re-verification (v0.3.0 barrier)

Empirical re-verification of the v0.3.0 (Triple Ouroboros + always-on
48-bit Interlocked Barrier + 8-seed constellation) construction against
a **cross-message near-identical distinguisher under fresh nonces**.
Primitive under test: **FNV-1a** on all 8 seed roles (one below-spec
lab primitive on every role; each seed still gets an independent random
key). Attacker capability is shipped-API chosen-plaintext: submit two
plaintexts differing by a single-bit (or multi-bit) XOR delta, observe
the two ciphertexts, try to distinguish "near-identical plaintexts
encrypted under distinct fresh nonces" from "independent plaintexts
encrypted under distinct fresh nonces".

## Files

- `run.sh` — one-shot runner that invokes `go test -tags redteam -run
  TestRedTeamNearIdenticalFreshNonce -v ./` from the repo root and then
  runs `aggregate.py` on the emitted JSON record. Runtime ≈ 15–25 min
  wall-clock at the default sample size on an 8-core host.
- `aggregate.py` — reads the JSON record from
  `~/scratch/redteam/near_identical_fresh/` and prints a compact
  structural analysis table: per-cell byte-XOR chi² vs df=255 uniform,
  byte-equal floor ratios per category, and cross-category homogeneity
  chi² between the near-identical and independent-pair categories at
  every (size, delta position). Consumes only files under
  `~/scratch/redteam/near_identical_fresh/` — no test dependencies.

## Probe (implemented as one Go test in `redteam_near_identical_fresh_test.go`)

`TestRedTeamNearIdenticalFreshNonce` — the load-bearing cross-message
pair-distinguisher probe.

For each cell in a 4 × 6 × 2 matrix (plaintext sizes × delta positions
× categories):

- **Plaintext sizes**: 128 B, 512 B, 4 KB, 16 KB.
- **Delta positions** (attacker-chosen bit-flip position on `P2 = P1
  XOR delta_mask`):
    - `byte0_bit0` — LSB of the first plaintext byte
    - `byte0_bit7` — MSB of the first plaintext byte
    - `mid_bit3` — bit 3 of the middle plaintext byte
    - `end_bit0` — LSB of the last plaintext byte
    - `end_bit7` — MSB of the last plaintext byte
    - `spread_hw4` — 4-bit Hamming-weight delta at bytes 0, N/4, N/2,
      3N/4 (multi-bit distributed probe)
- **Categories**:
    - `near_identical` — `P2 = P1 XOR delta_mask` per the delta
      position above
    - `independent_control` — `P1` and `P2` drawn as independent
      uniform random of the same size

The probe samples N pairs per cell (default N = 80; override via
`ITB_NIF_N`), encrypts each side under an independent fresh CSPRNG
nonce via `Encrypt3x128Cfg` with the same 8 FNV-1a-keyed seeds, and
accumulates:

- the pooled 256-bin byte histogram of `body(C1) XOR body(C2)` per cell
- the byte-equal count (number of positions where `body(C1)[i] ==
  body(C2)[i]`) per cell
- the byte-XOR chi² vs df=255 uniform per cell
- the byte-equal floor ratio vs the 1/256 independent-stream floor per
  cell
- the two-sample homogeneity chi² between the near-identical and
  independent-pair aggregate histograms at every (size, delta) —
  df=255, one-sided 3σ band top ≈ 323

The JSON record emitted to
`~/scratch/redteam/near_identical_fresh/near_identical_fresh_matrix.json`
also includes the archival nonce-reuse
Layer A near-identical baseline at 512 B (~16.13× the 1/256 floor)
for a direct pre-v0.3.0 vs fresh-nonce contrast.

## Attacker-realism scoping

Every probe consumes attacker-visible inputs only:

- The plaintexts `(P1, P2)` are attacker-chosen (the delta position is
  the attacker's own probe).
- The wire bytes `(C1, C2)` are the shipped-API output of
  `Encrypt3x128Cfg` — the fresh nonce, dimension header, and container
  body are all public.
- No seed / nonce / mask / rotation / noise-position value is read in
  any decision path. The 8-seed component vectors are drawn from a
  deterministic PRNG for reproducibility; the values themselves are
  not consulted after the seeds are constructed.

No lab-only peek is invoked in this probe; every cell is measured
under strictly attacker-realistic inputs.

## Reproduction

```bash
# From the repo root:
./scripts/redteam/itb/near_identical_fresh/run.sh

# Or invoke the test directly:
go test -tags redteam -run TestRedTeamNearIdenticalFreshNonce -v -timeout 3600s ./

# Then aggregate:
python3 scripts/redteam/itb/near_identical_fresh/aggregate.py
```

Set `ITB_NIF_N` to a smaller value (e.g. `ITB_NIF_N=8`) for a
smoke-check run in ~2 min.

## Debug output

`~/scratch/redteam/near_identical_fresh/` lives outside the repository
per the CLAUDE.md working-tree layout. JSON records land there and
stay local. Override the parent directory via
`REDTEAM_NEAR_IDENTICAL_FRESH_OUTPUT_DIR`.

## Cross-reference

- The pre-v0.3.0 archival result on the same near-identical pair
  shape (Layer A histogram under **forced nonce reuse**) is in
  [`archive/REDTEAM-v0.2.md § Phase 2d`](../../../../archive/REDTEAM-v0.2.md)
  and the corresponding v0.3.0 nonce-reuse Layer A verdict in
  [`REDTEAM.md § Nonce reuse (lab-only)`](../../../../REDTEAM.md) —
  byte-equal rate `0.019`–`0.063` (`4.9×`–`16×` floor) at 128–512 B on
  the near-identical pair shape.
- The v0.3.0 fresh-nonce CPA single-message wire result (FNV-1a↔BLAKE3
  homogeneity on chosen-plaintext single messages) is in
  [`REDTEAM.md § Fresh-nonce CPA under FNV-1a on every seed role`](../../../../REDTEAM.md).
- This probe extends the fresh-nonce CPA closure to the
  cross-message pair-distinguisher surface — a distinct
  traffic-analysis capability the single-message wire test does not
  cover.
