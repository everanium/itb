# Fresh-nonce CPA broken-primitive re-verification (v0.3.0 barrier)

Empirical re-verification of the barrier's closure under a chosen-plaintext
attacker posture with fresh nonces, driving the below-spec **FNV-1a**
primitive on every one of the 8 mandatory seed roles. The load-bearing
observable is the two-sample byte-histogram homogeneity chi² between the
FNV-1a wire and a PRF-grade **BLAKE3** reference arm at every plaintext
kind.

## Framing (mandatory)

Two things distinguish this probe from the related-seed / related-nonce
diffusion probes:

1. **The attacker capability is real, not lab-forced.** Fresh-nonce
   chosen-plaintext is a shipped-API attacker posture — an attacker with
   an encryption oracle. The nonce is drawn from `crypto/rand` per call
   (the ordinary `generateNonceCfg` path; `setBrokenTestNonce` /
   `testNonceOverride` is NOT installed). The plaintext is entirely
   attacker-controlled.
2. **The primitive substitution is a lab hypothesis.** FNV-1a is a
   below-spec lab control that never enters the shipped registry. Keying
   FNV-1a onto all 8 seed roles simultaneously puts a fully invertible
   non-linear primitive at every derivation slot the barrier composes
   through. A production caller cannot reach this configuration — the
   registry rejects it.

The reference arm is BLAKE3 wrapped as a HashFunc128 (low 16 bytes of
the 32-byte keyed digest), driven through the same `Encrypt3x128Cfg`
entry point with the same 8-seed component vectors. Comparing the two
arms via a two-sample chi² homogeneity test at df=255 tests whether
FNV-1a's algebraic weakness surfaces at the barrier's CPA output — i.e.
whether an attacker who chooses plaintext can distinguish a wire
produced under FNV-1a from a wire produced under a PRF-grade primitive.

## Attack methodology

For each (primitive arm, plaintext kind) cell:

1. Fix one plaintext of `cpaPlaintextBytes = 512` bytes (deterministic
   per kind — the attacker fixes the plaintext, then queries the
   oracle).
2. Call `Encrypt3x128Cfg` `N` times (default N = 2000; override via
   `ITB_CPA_N`). Each call draws its own fresh CSPRNG nonce.
3. Accumulate the pooled 256-bin byte histogram of the container body
   across the N ciphertexts.

Per-cell statistics recorded:

- **Body chi² vs df=255 uniform** — Pearson chi² of the pooled body
  histogram against a uniform expectation. The container body is
  extracted with the same `bodyOfCT*` helper the related-seed /
  related-nonce probes use (the wire nonce + `W` + `H` dimension header
  is skipped so the well-known dimension-header signature does not
  dominate).
- **Mean pairwise byte-equal rate** — position-wise agreement fraction
  across successive ciphertext pairs (`ct[2k]` vs `ct[2k+1]` for k in
  `[0, N/2)`). For independent uniform streams the expected rate is
  1/256 ≈ 0.00391.
- **Two-sample homogeneity chi²** — computed once per plaintext kind
  across arms; df = 255 (256 bins, 2 samples). Under H0 (both arms
  drawn from the same distribution) the statistic follows χ²(df=255):
  mean 255, one-sided 3σ upper bound ≈ 323. A cell inside the uniform
  band means FNV-1a and BLAKE3 wires are indistinguishable at the
  tested sample size.

## Plaintext kinds (7 cells per arm)

Designed to surface any structural signal a chosen plaintext could
amplify:

| Kind | Content | Purpose |
|---|---|---|
| `zeros` | 512 zero bytes | trivial fixed low-Hamming-weight content |
| `fill_7f` | 512 × `0x7F` | high-Hamming-weight constant content; exercises the 7-bit channel packing |
| `single_bit_low` | zeros, bit 0 of byte 0 set | sparse sentinel at the payload start |
| `single_bit_mid` | zeros, bit 3 of byte 256 set | sparse sentinel at an interior chunk boundary |
| `structured_json` | public-schema JSON prefix + padding | crib-anchored attacker plaintext (JSON header pattern) |
| `structured_html` | HTML boilerplate prefix + padding | crib-anchored attacker plaintext (HTML `<!DOCTYPE ...>` pattern) |
| `random_control` | deterministic random 512 bytes | attacker-choice control with no structural signal to amplify |

Same plaintext bytes across arms per kind → the chi² homogeneity test
isolates the primitive-attributable arm difference.

## Files

- `run.sh` — one-shot runner: invokes `go test -tags redteam -run TestRedTeamCPABroken`
  from the repo root, then aggregates the emitted JSON.
- `aggregate.py` — reads the emitted JSON records and prints a compact
  structural summary (per-cell body chi², mean pairwise byte-equal rate,
  two-sample homogeneity chi², dominant plaintext kind ranking, null /
  signal verdict against the uniform band). Consumes only files under
  `~/scratch/redteam/cpa_broken/` — no test dependencies.

## Attacker-realism scoping

The chi² and byte-equal statistics are inherently attacker-visible:
every ingested byte is a public wire byte an attacker holding the
ciphertexts already has. No seed / nonce / mask / rotation /
noise-position value is read in any decision path. The 8-seed
component vectors are drawn from a deterministic PRNG so runs are
reproducible, but the vector values are not consulted after the seeds
are constructed. Ground-truth is present only in per-cell metadata
records for downstream cross-check; no metadata field enters a
decision.

The primitive-substitution axis (FNV-1a keyed onto all 8 seed roles) is
a lab hypothesis, not an attacker capability. The chosen-plaintext /
fresh-nonce capability itself is the shipped-API attacker posture; the
primitive substitution stresses whether closure holds when the
underlying hash is invertible non-linear rather than PRF-grade.

## Structural verdict

The v0.3.0 barrier's CPA closure under fresh nonces holds across the
primitive-substitution axis: FNV-1a keyed onto every seed role produces
a wire that is indistinguishable from a BLAKE3-keyed wire at the tested
sample size across every plaintext kind. The two-sample homogeneity chi²
lands inside the df=255 uniform band on every (kind) cell. Chosen
plaintext gives no observable handle on any of the 8 seed-derivation
slots because each Encrypt call redraws mask / noise / rotation /
startPixel per fresh nonce, and the barrier's Part 1 permutation moves
the chosen bytes to lane positions the attacker cannot pin.

Concrete per-cell numeric values are the output of `aggregate.py`
after `run.sh` (or the raw JSON at
`~/scratch/redteam/cpa_broken/cpa_broken_matrix.json`). The REDTEAM.md
"Broken-primitive stress" section carries the load-bearing verdict
table for this probe.

## Reproduction

```bash
# From the repo root:
./scripts/redteam/itb/cpa_broken/run.sh

# Or invoke the test directly:
go test -tags redteam -run TestRedTeamCPABroken -v -timeout 7200s ./

# Then aggregate:
python3 scripts/redteam/itb/cpa_broken/aggregate.py

# Reduce sample size for a quick smoke run:
ITB_CPA_N=200 ./scripts/redteam/itb/cpa_broken/run.sh
```

Wall-clock at the default N = 2000: ~25-30 minutes on a workstation
(28,000 encryptions total; FNV-1a's `math/big` state chain dominates
the runtime). Encrypt3x128Cfg parallelises across `runtime.NumCPU()`,
so wall time scales with cores.

## Debug output

`~/scratch/redteam/cpa_broken/` lives outside the repository per the
CLAUDE.md working-tree layout. JSON records land there and stay local.
Override the parent directory via `REDTEAM_CPA_BROKEN_OUTPUT_DIR`.
