# BLAKE2b kernel generator

One deterministic generator emits every BLAKE2b fused ChainHash cascade
kernel under `hashes/internal/blake2basm/`. It takes no input beyond its
own source (the initialisation vector, the parameter blocks of both
digest widths, the block counters and the final flag are folded into
per-kernel read-only tables the generator computes), and must reproduce
the committed `.s` files byte for byte. The generator accepts `--check`,
which regenerates in memory, compares against the committed files
without writing, and exits non-zero on any drift.

```
python3 scripts/kernels/blake2b/gen_fused_kernels.py --check
```

Run the generator without `--check` to (re)write its files; the output
directory is resolved relative to the script
(`../../../hashes/internal/blake2basm/`). After any generator change, run
the `--check` form and confirm `git diff --stat hashes/internal/blake2basm/`
shows only the intended kernels.

## Fused ChainHash cascade kernels — `gen_fused_kernels.py`

The kernels evaluate the whole `Seed256.ChainHash256` /
`Seed512.ChainHash512` cascade in one call (see
`hashes/internal/blake2basm/blake2basm_fused.go`):
`blake2b_fusedchain{256,512}_<shape>x4_<tier>_amd64.s` (tiers avx512 /
avx2), `blake2b_fusedchain{256,512}_<shape>x4_neon_arm64.s`, and the
eight-lane ZMM kernels of the avx512 tier:
`blake2b_fusedchain{256,512}_{20,36,68}x8_avx512_amd64.s`, the per-pixel
kernels at the nonce-buf shapes, and the Interlocked Barrier fill kernels
`blake2b_fusedchain256_13x8_avx512_amd64.s` (the batch-16 hook of width
256) and `blake2b_fusedchain512_13x8_avx512_amd64.s` (the batch-32 hook of
width 512), with the eight 13-byte fill blocks synthesised in-register
from `groupIdxBase`. The avx2 and neon tiers run every fill hook as
four-lane kernel calls over Go-synthesised blocks, and the width-512
batch-16 hook runs that way on every tier. The single-lane entry points
of every tier run `blake2b_fusedchain{256,512}_<shape>x1_gpr_{amd64,arm64}.s`,
the general-purpose-register kernels: the compression state in
general-purpose registers (amd64 keeps fifteen of the sixteen words in
registers and one c word in a frame slot, which its G steps reach through
memory operands; arm64 keeps all sixteen), the message words as frame
slots, the rotates as `RORQ` / `ROR`.

Per cascade round the kernel runs one BLAKE2b compression per lane over
`key ‖ (data ⊕ seed)` — the fixed key, then data zero-padded to at least
the seed-injection width (32 bytes at width 256, 64 at width 512) with
the seed words XORed over the bytes after the key — with the seed of the
round being the component group XOR the previous round's output. Every
(width, shape) cell is one compression except width 512 at the 68-byte
shape, whose 132-byte input spans two blocks. The message words split
into the key words (broadcast from the key pointer), the seed-injected
words and the data-only words; the data words are staged once per call
into the frame, and the seed-injected words are rebuilt each round from
the staged data word, the component broadcast and the previous output —
one `VPTERNLOGQ` per word on the EVEX tier, a broadcast and two `VPXOR`
on the AVX2 tier, a `VDUP` and two `VEOR` on NEON. The compression state
is re-initialised each round from a read-only table that carries the IV,
the parameter block, the counter and the final flag of the block, so the
fold `h = h0 ⊕ v ⊕ v'` reads the same table. The module docstring of the
generator lists the register plan of every tier.

## Register budget

The 64-bit-lane state of BLAKE2b fills 16 registers at one qword lane per
pixel, and the 16 message words fill the other 16 of the EVEX register
file: the avx512 tier keeps state and words in YMM registers at four
lanes and in ZMM registers at eight lanes (the eight-pixel stride of the
width-256 / -512 pipelines and the fill kernels), 32 of 32 in both forms
with the seed-word rebuild and the fold as embedded-broadcast memory
operands. No sixteen-lane fill kernel exists: sixteen lanes would need two
ZMM registers per state word, the whole file, with the message words as
memory operands and no scratch — the port-bound outcome of that layout on
Areion-256 (0.93× / 0.99× / 0.99× of two eight-lane calls) makes it a
no-gain cell, and the generator carries no emitter for it. The avx2 tier has 16 YMM
registers: `Y0..Y14` hold `v[0..14]`, `Y15` is the ror63 temp, `v[15]`
lives in a frame slot with `v[12]` spilled around the two G functions that
touch `v[15]`, and the message words are frame slots read as memory
operands; the frame exceeds the NOSPLIT budget, so these kernels carry
the stack check. The NEON tier runs two lanes per pass over the same
16-register state with the words loaded pairwise from the frame.

## Store-to-load forwarding discipline (amd64)

The first eight message bytes of every lane are read as two 4-byte loads
behind the caller's 4-byte pixel-index store; every other message byte is
read at its natural width (8-, 5- or 4-byte tails as the shape dictates).
Outputs are written as 8-byte stores per word per lane. Every wide kernel
ends with `VZEROUPPER` before `RET`.

## Correctness invariant

Every kernel implements the cascade documented in
`hashes/internal/blake2basm/blake2basm_fused.go` and is pinned to the
pure-Go reference there (`ScalarFusedChain256` / `ScalarFusedChain512`,
built on `golang.org/x/crypto/blake2b`) by the in-package parity tests
(`go test ./hashes/internal/blake2basm/`, every tier by direct call plus
`ITB_FORCE_HASH_TIER` / `ITB_FORCE_INTERLOCK_PRF_FILL_TIER` probes), by
the `hashes` package's known-answer vectors of the cascade
(`blake2b_cascade_kat_test.go`, produced under `-tags noitbasm`), and by
the cross-tier wire-parity tests. The generator changes how a kernel
reads its inputs and where it stages them, never what it computes.
