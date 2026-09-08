# SipHash-2-4 kernel generator

One deterministic generator emits every SipHash-2-4 assembly kernel under
`hashes/internal/siphashasm/`. It takes no input beyond its own source,
reads no numeric tables of its own (the batch-16 lane-offset and
output-interleave tables are read from the Go side — `·laneIdx16`,
`·interleaveIdx16`; SipHash has no key schedule), and must reproduce the
committed `.s` files byte for byte. The generator accepts `--check`,
which regenerates in memory, compares against the committed files
without writing, and exits non-zero on any drift.

```
python3 scripts/kernels/siphash/gen_fused_kernels.py --check
```

Run the generator without `--check` to (re)write its files; the output
directory is resolved relative to the script
(`../../../hashes/internal/siphashasm/`). After any generator change, run
the `--check` form and confirm `git diff --stat hashes/internal/siphashasm/`
shows only the intended kernels.

## Fused ChainHash cascade kernels — `gen_fused_kernels.py`

The fused-cascade kernels that evaluate the whole `Seed128.ChainHash128`
cascade in one call (see `hashes/internal/siphashasm/siphashasm_fused.go`):
`siphash_fusedchain128_<shape>x4_<tier>_amd64.s` (tiers avx512 / avx2),
`siphash_fusedchain128_<shape>x1_gpr_amd64.s` (the single-lane kernel of
both amd64 tiers), `siphash_fusedchain128_<shape>x4_neon_arm64.s`,
`siphash_fusedchain128_<shape>x1_gpr_arm64.s`, and — at the three
nonce-buf shapes 20 / 36 / 68 only —
`siphash_fusedchain128_<shape>x8_avx512_amd64.s`, the eight-lane ZMM
kernels the pixel pipeline drives through its eight-pixel stride on
AVX-512F hosts: SipHash's four 64-bit state words fill a 512-bit
register at exactly eight lanes, so the eight-lane kernel runs the
four-lane instruction stream over twice the lanes. The eight-lane arm is
pinned to two calls of the four-lane EVEX kernel and to the pure-Go
cascade by the in-package parity tests, and disarmed by
`ITB_FORCE_CHAINHASH_X4=1`.

SipHash is keyed by the ChainHash seed pair alone, so every cascade
round re-keys the state from the previous round's output XOR the
component pair and re-absorbs the message words; what the kernels
amortise is the lane gather and word packing (once per call, with the
length tag folded into the tail word) and the `(lo, hi)` carry, which
never leaves the registers. Rotates are `VPROLQ` on the EVEX tier,
`VPSHUFD` / `VPSHUFB` / shift-or on the AVX2 tier (whose words are staged
in the frame and read back as `VPXOR` memory operands), `ROLQ` / `ROR`
in the GPR kernels, and `VSHL` + `VSRI` into an alternate register
(`VREV64` for the rotate by 32) on NEON. The module docstring of the
generator lists the register plan of every tier.

## Batch-16 Interlocked Barrier fill kernel — `gen_fused_kernels.py`

The same generator emits `siphash_fusedchain128_13x16_avx512_amd64.s`,
the 16-lane fused cascade kernel at the 13-byte shape that fills the
Interlocked Barrier PRF for 16 consecutive groups per call: the kernel
receives `groupIdxBase` and synthesises the two message words of every
lane in-register (`(idx << 8) | 0x03` and `(idx >> 56) | (13 << 56)`),
runs the cascade on two eight-lane groups with interleaved instruction
streams, and interleaves the `(lo, hi)` pairs through `·interleaveIdx16`
into four 64-byte stores in lane order. The AVX2 and NEON tiers carry
`siphash_fusedchain128_13x8_avx2_amd64.s` and
`siphash_fusedchain128_13x8_neon_arm64.s`, eight-lane fill kernels with
the same in-register block synthesis (lane offsets from `lane8<>` on
AVX2, from `·laneIdx16` on NEON) that the batch-16 arm calls twice; on
AVX2 the eight lanes run as two four-lane YMM groups with interleaved
instruction streams (15 of 16 registers, constants in RODATA and words
in the frame as `VPXOR` memory operands), on NEON as four two-lane
pairs (32 of 32 registers, constants `VDUP`'d on demand from GPRs and
the words reloaded through the rotate-alternate registers). Sixteen
lanes would need 16 YMM or 32 NEON registers of state alone, so eight
is the register ceiling of both tiers; the kernels are pinned to the
four-lane kernels of their tier and to the pure-Go reference by the
in-package parity tests.

## Store-to-load forwarding discipline (amd64)

Word 0 of every lane is read as two 4-byte loads behind the caller's
4-byte pixel-index store; the tail word is assembled from 4-byte
(20 / 36 / 68) or 4 + 1-byte (13) loads. The four- and eight-lane
kernels write their outputs as 16-byte stores after a qword unpack; the
batch-16 kernel writes 64-byte stores that the fill closure reads back
with 8-byte loads. Every wide kernel ends with `VZEROUPPER` before `RET`.

## Correctness invariant

Every kernel implements the construction documented in
`hashes/internal/siphashasm/siphashasm.go` and is pinned to the pure-Go
reference there by the in-package parity tests
(`go test ./hashes/internal/siphashasm/`, every tier by direct call plus
`ITB_FORCE_HASH_TIER` / `ITB_FORCE_INTERLOCK_PRF_FILL_TIER` probes), by
the `hashes` package's known-answer vectors of the cascade
(`siphash24_cascade_kat_test.go`, produced under `-tags noitbasm`), and by
the cross-tier wire-parity tests. The generator changes how a kernel
reads its inputs and where it stages them, never what it computes.
