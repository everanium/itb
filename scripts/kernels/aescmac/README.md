# AES-CMAC kernel generator

One deterministic generator emits every AES-CMAC assembly kernel under
`hashes/internal/aescmacasm/`. It takes no input beyond its own source,
reads no numeric tables of its own (the batch-16 absorb block and the ZMM
lane-offset table are read from the Go side — `·absorb13Block`,
`·laneIdxZ`; the round keys arrive expanded from `ExpandKeyAES128`), and
must reproduce the committed `.s` files byte for byte. The generator
accepts `--check`, which regenerates in memory, compares against the
committed files without writing, and exits non-zero on any drift.

```
python3 scripts/kernels/aescmac/gen_fused_kernels.py --check
```

Run the generator without `--check` to (re)write its files; the output
directory is resolved relative to the script
(`../../../hashes/internal/aescmacasm/`). After any generator change, run
the `--check` form and confirm `git diff --stat hashes/internal/aescmacasm/`
shows only the intended kernels.

## Fused ChainHash cascade kernels — `gen_fused_kernels.py`

The fused-cascade kernels that evaluate the whole `Seed128.ChainHash128`
cascade in one call (see `hashes/internal/aescmacasm/aescmacasm_fused.go`):
`aescmac_fusedchain128_<shape>x4_<tier>_amd64.s` (tiers aesni / vex /
vaesavx2 / avx512), `aescmac_fusedchain128_<shape>x1_<tier>_amd64.s` (tiers
aesni / vex), `aescmac_fusedchain128_<shape>x{1,4}_neon_arm64.s`, and — at
the three nonce-buf shapes 20 / 36 / 68 only —
`aescmac_fusedchain128_<shape>x8_avx512_amd64.s`, the eight-lane ZMM
kernels the pixel pipeline drives through its eight-pixel stride on
VAES + AVX-512 hosts: two four-lane state groups per call whose cascade
rounds are interleaved instruction by instruction. The eight-lane arm is
pinned to two calls of the four-lane ZMM kernel and to the pure-Go
cascade by the in-package parity tests, and disarmed by
`ITB_FORCE_CHAINHASH_X4=1`.

Every cascade round of every lane is one full AES-128 permutation per
zero-padded data block. The blocks are staged once with the first round
key folded in (block 0 also carries the length tag), so the loop body
runs nine `AESENC` under K1..K9 and one `AESENCLAST` under K10 per
block; the module docstring of the generator lists the round-key
residency of every tier, including the memory-operand keys of the
batch-16 XMM / YMM tiers where the register file cannot hold states,
eleven keys and blocks at once.

## Batch-16 Interlocked Barrier fill kernels — `gen_fused_kernels.py`

The same generator emits the 16-lane fused cascade kernels at the 13-byte
shape that fill the Interlocked Barrier PRF for 16 consecutive groups per
call: `aescmac_fusedchain128_13x16_<tier>_amd64.s` (tiers aesni / vex /
vaesavx2 / avx512) and `aescmac_fusedchain128_13x16_neon_arm64.s`. The
kernels receive `groupIdxBase` in a register and synthesise the 16
per-lane fill blocks in-register, so the batch-16 path pays no per-lane
pointer gather and no store ahead of the call; every lane then runs the
whole ChainHash cascade over the caller's component slice (the prepended
lock components of the cascade fill).

## Store-to-load forwarding discipline (amd64)

The amd64 kernels follow the AES-ITB-128 generator's load discipline
(`scripts/kernels/aesitb128/README.md`): block 0 of the multi-block
shapes is read as two 4-byte inserts plus an 8-byte insert behind the
caller's 4-byte pixel-index store, the wide tiers stage blocks in
registers or as same-width frame slots, and the lane outputs are written
as 16-byte stores. Every wide kernel ends with `VZEROUPPER` before `RET`.

## Correctness invariant

Every kernel implements the construction documented in
`hashes/internal/aescmacasm/aescmacasm.go` and is pinned to the pure-Go
reference there by the in-package parity tests
(`go test ./hashes/internal/aescmacasm/`, every tier by direct call plus
`ITB_FORCE_HASH_TIER` / `ITB_FORCE_INTERLOCK_PRF_FILL_TIER` probes), by
the `hashes` package's known-answer vectors of the cascade
(`aescmac_cascade_kat_test.go`, produced under `-tags noitbasm`), and by
the cross-tier wire-parity tests. The generator changes how a kernel
reads its inputs and where it stages them, never what it computes.

Independently of any reference, every kernel is held to the
input-entropy differential audit of `internal/kernelaudit`
(`hashes/internal/aescmacasm/aescmacasm_entropy*_test.go`, every tier by
direct call and the dispatchers under every dispatch state): every bit
of every lane buffer, component word, key byte and group index base
flipped alone changes the output — the flipped lane's and no other
lane's for a lane buffer, every lane's for a shared input — so an input
read at a narrower width than its buffer, a skipped component word or an
ignored key byte is caught where a reference sharing the defect would
not catch it, and the kernel must agree with the pure-Go cascade at the
baseline and after every flip. The `hashes` package runs the same audit
over the arms and the hooks of every shipped registry entry against the
sequential cascade of the entry's single arm
(`nonce_entropy_audit_test.go`).
