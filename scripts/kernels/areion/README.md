# Areion-SoEM kernel generator

One deterministic generator emits every Areion-SoEM fused ChainHash
cascade kernel under `internal/areionasm/`. It takes no input beyond its
own source (the round constants are read from the Go side — `·AreionRC4x`
on amd64, `·AreionRCTable` on arm64 — and the SoEM domain-separation
constant from `·AreionSoEMDomainSep256`), and must reproduce the committed
`.s` files byte for byte. The generator accepts `--check`, which
regenerates in memory, compares against the committed files without
writing, and exits non-zero on any drift.

```
python3 scripts/kernels/areion/gen_fused_kernels.py --check
```

Run the generator without `--check` to (re)write its files; the output
directory is resolved relative to the script
(`../../../internal/areionasm/`). After any generator change, run the
`--check` form and confirm `git diff --stat internal/areionasm/` shows
only the intended kernels.

## Fused ChainHash cascade kernels — `gen_fused_kernels.py`

The kernels evaluate the whole `Seed256.ChainHash256` /
`Seed512.ChainHash512` cascade in one call (see
`internal/areionasm/areionasm_fused.go`):
`areion_fusedchain{256,512}_<shape>x4_<tier>_amd64.s` (tiers avx512 /
vaesavx2 / aesni), `areion_fusedchain{256,512}_<shape>x1_aesni_amd64.s`
(the single-lane kernel of every amd64 tier),
`areion_fusedchain{256,512}_<shape>x{1,4}_neon_arm64.s`, and the wide
kernels: `areion_fusedchain{256,512}_{20,36,68}x8_avx512_amd64.s`, the
eight-lane per-pixel kernels — two four-lane ZMM groups whose cascade
rounds are interleaved instruction by instruction, so twice the
independent `VAESENC` chains of a single lane group are in flight per
permutation — and the eight-lane Interlocked Barrier fill kernels
`areion_fusedchain256_13x8_avx512_amd64.s` (the batch-16 hook of width
256), `areion_fusedchain512_13x8_avx512_amd64.s` (the batch-32 hook of
width 512) and `areion_fusedchain{256,512}_13x8_neon_arm64.s`, with the
eight 13-byte fill blocks synthesised from `groupIdxBase` (in-register on
ZMM, into the frame on NEON). The YMM / XMM tiers run every fill hook as
four-lane kernel calls over Go-synthesised blocks, and the width-512
batch-16 hook runs that way on every tier. The module docstring of the
generator records the wide cells that are register-legal but not
emitted, with the measurement or the hook-width reason behind each.

Per cascade round the kernel re-keys the SoEM state from the previous
round's output XOR the component group (k2 = group ⊕ h; k1 is the fixed
key, constant across rounds) and re-absorbs the length-tagged message
chunk by chunk (24-byte chunks at width 256, 56 at width 512): per chunk
`state = P(state ⊕ k1) ⊕ P(state ⊕ k2 ⊕ D)` with the Areion permutation
`P` (10 rounds at width 256, 15 at width 512, both permutations
interleaved) and the domain-separation constant `D`. The message blocks
are data-invariant across rounds and are staged once per call; the
four-lane ZMM kernels keep them and both keys in registers, the wide ZMM
kernels read the blocks, the round constants and the domain constant as
memory operands and carry the feed-forward state in the permutation
registers between chunks, the YMM tier reads the blocks back as memory
operands (and, at width 512, keeps k2 in the frame), the XMM and NEON
tiers reload the blocks from the frame per chunk. The module docstring
of the generator lists the register plan of every tier.

## Store-to-load forwarding discipline (amd64)

The first eight message bytes of every lane are read as two 4-byte loads
behind the caller's 4-byte pixel-index store; every other message byte is
read at its natural width. Outputs are written as 16-byte stores — one per
state block per lane — on every tier, the width the Go side reads them
back with. Every wide kernel ends with `VZEROUPPER` before `RET`.

## Correctness invariant

Every kernel implements the cascade documented in
`internal/areionasm/areionasm_fused.go` and is pinned to the pure-Go
reference there (`ScalarFusedChain256` / `ScalarFusedChain512`, built on
`aes.AreionSoEM256` / `aes.AreionSoEM512`) by the in-package parity tests
(`go test ./internal/areionasm/`, every tier by direct call plus
`ITB_FORCE_HASH_TIER` / `ITB_FORCE_INTERLOCK_PRF_FILL_TIER` probes), by
the `hashes` package's known-answer vectors of the cascade
(`areion_cascade_kat_test.go`, produced under `-tags noitbasm`), and by
the cross-tier wire-parity tests. The generator changes how a kernel
reads its inputs and where it stages them, never what it computes.
