# AES-ITB-128 kernel generators

One deterministic generator emits every AES-ITB-128 assembly kernel under
`internal/aesitbasm/`. It takes no input beyond its own source, reads
no numeric tables of its own (round constants, the PKCS#7 pad vectors, the
batch-16 absorb block and lane-offset table are read from the Go side —
`·RC`, `·pad4Tail`, `·pad13Tail`, `·absorb13Block`, `·laneIdxZ`), and must
reproduce the committed `.s` files byte for byte. The generator accepts
`--check`, which regenerates in memory, compares against the committed
files without writing, and exits non-zero on any drift.

```
python3 scripts/kernels/aesitb128/gen_fused_kernels.py --check
```

Run the generator without `--check` to (re)write its files; the output
directory is resolved relative to the script (`../../../internal/aesitbasm/`).
After any generator change, run the `--check` form and confirm
`git diff --stat internal/aesitbasm/` shows only the intended kernels.

## Fused ChainHash cascade kernels — `gen_fused_kernels.py`

The fused-cascade kernels that evaluate the whole `Seed128.ChainHash128`
cascade in one call (see `internal/aesitbasm/aesitbasm_fused.go`): 35
files, `aesitb_fusedchain128_<shape>x4_<tier>_amd64.s` (tiers aesni / vex /
vaesavx2 / avx512), `aesitb_fusedchain128_<shape>x1_<tier>_amd64.s` (tiers
aesni / vex), `aesitb_fusedchain128_<shape>x{1,4}_neon_arm64.s`, and — at
the three nonce-buf shapes 20 / 36 / 68 only —
`aesitb_fusedchain128_<shape>x8_avx512_amd64.s`, the eight-lane ZMM
kernels the pixel pipeline drives through its eight-pixel stride on
VAES + AVX-512 hosts: two four-lane state groups per call whose cascade
rounds are interleaved instruction by instruction, so the two independent
VAESENC chains overlap on the AES unit. The eight-lane arm is pinned to
two calls of the four-lane ZMM kernel and to the pure-Go cascade by the
in-package parity tests, and disarmed by `ITB_FORCE_CHAINHASH_X4=1`.

## Batch-16 Interlocked Barrier fill kernels — `gen_fused_kernels.py`

The same generator emits the 16-lane fused cascade kernels at the 13-byte
shape that fill the Interlocked Barrier PRF for 16 consecutive groups per
call: five files, `aesitb_fusedchain128_13x16_<tier>_amd64.s` (tiers
aesni / vex / vaesavx2 / avx512) and
`aesitb_fusedchain128_13x16_neon_arm64.s`. The kernels receive
`groupIdxBase` in a register and synthesise the 16 per-lane fill blocks
in-register, so the batch-16 path pays no per-lane pointer gather and no
store ahead of the call; every lane then runs the whole ChainHash cascade
over the caller's component slice (the prepended lock components of the
cascade fill), and with one pair the kernel is the plain chain-absorb of
the shape.

## Store-to-load forwarding discipline (amd64)

The amd64 kernels size every load to the store the Go call site leaves in
flight immediately ahead of the call, so the load forwards from the store
buffer instead of waiting for the store to commit — a failed forward
serialises consecutive kernel calls and costs more than the kernel itself:

- block 0 of the multi-block shapes follows the caller's 4-byte
  pixel-index store at offset 0 and is read as two 4-byte inserts plus an
  8-byte insert, never as one 16-byte load;
- the fused kernels stage the padded data blocks in registers on the wide
  tiers (with 32-byte stores read back by 32-byte loads for the blocks the
  YMM register file cannot hold), so no wide in-loop load spans a
  narrower staging store;
- the lane outputs are written as four 16-byte stores on every tier — the
  width the Go side reads them back with — rather than one 32- or 64-byte
  store.

The 13-byte Interlocked Barrier fill block is written byte-oriented (a
1-byte domain tag followed by an 8-byte group index) and read as an 8-, a
4- and a 1-byte insert; its stores sit far enough ahead of the kernel's
tail loads that the load shape there is not on the critical path.

Every wide kernel ends with `VZEROUPPER` before `RET`; the Go ABI wrapper
executes a legacy-SSE instruction after the return, and a dirty upper
state at that point costs an SSE/AVX transition assist per call.

## Correctness invariant

Every kernel implements the construction documented in
`internal/aesitbasm/aesitbasm.go` and is pinned to the pure-Go reference
there by the in-package parity tests (`go test ./internal/aesitbasm/`,
every tier by direct call plus `ITB_FORCE_HASH_TIER` /
`ITB_FORCE_INTERLOCK_PRF_FILL_TIER` probes), by the root
`aesitb_parity_test.go` / `aesitb_fused_parity_test.go`, and by the
cross-tier wire-parity tests. The generators change how a kernel reads its
inputs and where it stages them, never what it computes.
