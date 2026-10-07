## ITB Figures Computed Documentation

`figures` computes every deterministic figure the documentation publishes from the library itself and checks the documentation against the computed values, so a format or parameter change shows at once which published numbers went stale.

## What it computes

All figures are taken at the compiled-in defaults — `itb.DefaultNonceBits`, `itb.DefaultBarrierFill`, wrapper and parallax off — for 512 / 1024 / 2048-bit keys under both container floor sizing modes (Mode 1 per-region, Mode 2 per-container).

- **Measured through the public Single Message Encrypt API.** Container side and pixel count, the wire length (prefix + header + pixels; the prefix size and the header size are derived from the wire by the length identity, not assumed), the largest payload that still fits each floor container (bisection), the 512-bit Mode 2 container at a 1460-byte payload, the data-size rows at 1024-bit (1460 B, 10 KB, 16 KiB, 64 KiB, 1 / 4 / 16 / 64 MiB), the expansion range over 10 KB – 64 MiB, the largest accepted payload, the chunk header per nonce width, and the wrapper nonce per outer cipher.
- **Derived from exported constants.** `MinPixels` per key size, the per-pixel bit and configuration accounting, the ChainHash cascade depth per registry width, `DefaultChunkSize`, the birthday bounds at the default nonce width.
- **Formula figures**, each implemented once with the source section named at the computation site: ambiguity-dominance thresholds without CCA, noise barrier `2^(8P)`, encoding ambiguity `56^P` and `7^P`, configuration map `2^(62P)`, guaranteed DRBG residue `(2s + 1) × 7` and the residue at the exact pixel floor, classical and Grover brute-force bounds, the Landauer bound from `k_B T ln 2` at the CMB temperature, ratios against the key space and that bound, expansion ratios, and the Rank Barrier mask-space constants — `A = C(48, 16)`, `B = C(32, 16)`, `A · B`, `gcd(A, B)` with its factorisation, the PRF-preimage count per mask triple, and the bias cascade over a maximum-size message.

Container geometry depends on byte lengths alone, never on the primitive's output or the payload content, so the measurements are pinned to one registry primitive for reproducibility and hold for every other.

The expansion range is the maximum and minimum of wire / payload over the interval. The wire is constant across the payloads sharing one container side, so the maximum is found by walking the side boundaries upward from 10 KB by bisection until the ratio at a boundary falls 0.01 below the running maximum, and the minimum is bracketed between the ratio at 64 MiB and the side band just below it.

## Modes

```bash
go run ./tools/figures            # grouped tables of every figure
go run ./tools/figures -check     # verify the documentation; exit 1 on STALE / NOT FOUND
go run ./tools/figures -check -root /path/to/repo
```

Both modes run from the repository root by default; `-root` points elsewhere.

`-check` holds a registry of expectations: a file, a locator anchored on the prose or table text around the figure, and the exact spelling that site uses (`1,900 B`, `~2.6 KB`, `2^3,528`, `−62.7%`). It prints one line per expectation — `OK`, `STALE file:line expected vs found`, or `NOT FOUND` — and never edits a document. Figures the documentation restates many times (the mask-space cardinality, the gcd trap, the bias cascade) are swept across each file, and every occurrence must agree.

Only deterministic figures are covered. Timings, cycle counts and empirical χ² / KL / bias statistics are not computed.

## On STALE or NOT FOUND

- **STALE** — the document carries a figure the library no longer produces. Recompute the surrounding text from the table `figures` prints (the dependent figures — ratios, percentages, KB roundings, totals — move together), then re-run `-check`.
- **NOT FOUND** — the locator no longer matches the surrounding text, usually after a rewrite of the sentence or table row. Update the locator in `expectations.go` to the current text; the expected spelling stays with it.

The computation is the reference. A disagreement is resolved by correcting the document or the locator, not by adjusting the figure.

## Test

`go test ./tools/figures/...` runs both the computation and the check against the repository documentation, so `go test ./...` fails while any published figure is stale.
