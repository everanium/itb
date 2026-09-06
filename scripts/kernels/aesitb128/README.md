# AES-ITB-128 chain-absorb kernel generator

`gen_kernels.py` emits the 4-lane chain-absorb kernels of
`internal/aesitbasm/` — one `.s` file per (shape, tier):

- shapes: 13 / 20 / 36 / 68 bytes per lane (Interlocked Barrier PRF fill
  and the 128 / 256 / 512-bit nonce buf shapes)
- amd64 tiers: `aesni` (legacy-SSE XMM), `vex` (VEX-encoded XMM),
  `vaesavx2` (VAES YMM, two lanes per register), `avx512` (VAES ZMM, four
  lanes per register)
- arm64 tier: `neon` (AESE + AESMC, round constant folded into the next
  AESE key operand)

Twenty files in total: `aesitb_chain128_<shape>_<tier>_amd64.s` and
`aesitb_chain128_<shape>_neon_arm64.s`.

## Regenerate

```
python3 scripts/kernels/aesitb128/gen_kernels.py
```

The output directory is resolved relative to the script
(`../../../internal/aesitbasm/`). The generator is deterministic and takes
no inputs beyond its own source: the emitted files must match the
committed `.s` files byte for byte. Verify after any change to the
generator by re-running it and checking that `git diff --stat
internal/aesitbasm/` is empty (or, on an uncommitted tree, by diffing
against a copy taken before the run).

## Correctness invariant

Every kernel implements the construction documented in
`internal/aesitbasm/aesitbasm.go` and is pinned to the pure-Go reference
there by the in-package parity tests (`go test ./internal/aesitbasm/`,
every tier by direct call plus `ITB_FORCE_HASH_TIER` probes) and by the
root `aesitb_parity_test.go`. Round constants and the PKCS#7 pad vectors
are read from the Go side (`·RC`, `·pad4Tail`, `·pad13Tail`), so the
generator carries no numeric tables of its own.

## Fused ChainHash cascade kernels

`gen_fused_kernels.py` emits the fused-cascade kernels that evaluate the
whole `Seed128.ChainHash128` cascade in one call (see
`internal/aesitbasm/aesitbasm_fused.go`): 32 files,
`aesitb_fusedchain128_<shape>x4_<tier>_amd64.s` (tiers aesni / vex /
vaesavx2 / avx512), `aesitb_fusedchain128_<shape>x1_<tier>_amd64.s`
(tiers aesni / vex) and `aesitb_fusedchain128_<shape>x{1,4}_neon_arm64.s`.

```
python3 scripts/kernels/aesitb128/gen_fused_kernels.py
```

Same invariants as above: deterministic, no numeric tables of its own,
output must match the committed files byte for byte, and every kernel is
pinned to the pure-Go cascade by `go test ./internal/aesitbasm/` and to
the sequential `Seed128` loop by the root `aesitb_fused_parity_test.go`.
