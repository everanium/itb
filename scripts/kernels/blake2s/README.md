# BLAKE2s kernel generator

One deterministic generator emits every BLAKE2s fused ChainHash cascade
kernel under `hashes/internal/blake2sasm/`. It takes no input beyond its
own source (the initialisation vector, the parameter block, the block
counters and the final flag are folded into per-kernel read-only tables
the generator computes), and must reproduce the committed `.s` files
byte for byte. The generator accepts `--check`, which regenerates in
memory, compares against the committed files without writing, and exits
non-zero on any drift.

```
python3 scripts/kernels/blake2s/gen_fused_kernels.py --check
```

Run the generator without `--check` to (re)write its files; the output
directory is resolved relative to the script
(`../../../hashes/internal/blake2sasm/`). After any generator change, run
the `--check` form and confirm `git diff --stat hashes/internal/blake2sasm/`
shows only the intended kernels.

## Fused ChainHash cascade kernels — `gen_fused_kernels.py`

The kernels evaluate the whole `Seed256.ChainHash256` cascade in one call
(see `hashes/internal/blake2sasm/blake2sasm_fused.go`):
`blake2s_fusedchain256_<shape>x4_<tier>_amd64.s` (tiers avx512 / avx2),
`blake2s_fusedchain256_<shape>x4_neon_arm64.s`, and the eight-lane YMM
kernels of the avx512 tier: `blake2s_fusedchain256_{20,36,68}x8_avx512_amd64.s`,
the per-pixel kernels at the nonce-buf shapes, and the Interlocked
Barrier fill kernel `blake2s_fusedchain256_13x8_avx512_amd64.s` (the
batch-16 hook), with the eight 13-byte fill blocks synthesised
in-register from `groupIdxBase`. The avx2 and neon tiers run the fill
hook as two four-lane kernel calls over Go-synthesised blocks. The
single-lane entry points of every tier run
`blake2s_fusedchain256_<shape>x1_gpr_{amd64,arm64}.s`, the
general-purpose-register kernels: the compression state in 32-bit
general-purpose registers (amd64 keeps fifteen of the sixteen words in
registers and one c word in a frame slot, which its G steps reach through
memory operands; arm64 keeps all sixteen), the message words as frame
slots, the rotates as `RORL` / `RORW`.

Per cascade round the kernel runs BLAKE2s per lane over
`key ‖ (data ⊕ seed)` — the 32-byte fixed key, then data zero-padded to
at least the 32-byte seed-injection width with the seed words XORed over
the bytes after the key — with the seed of the round being the component
group XOR the previous round's output. The 13- and 20-byte shapes are one
compression; the 36- and 68-byte shapes span two blocks. The message
words split into the key words (broadcast from the key pointer), the
seed-injected words and the data-only words; every 64-bit component and
output word straddles two 32-bit message words, low half first. The data
words are staged once per call into the frame, and the seed-injected
words are rebuilt each round from the staged data dword, the component
dword broadcast and the previous output — one `VPTERNLOGD` per word on
the EVEX tier, a broadcast and two `VPXOR` on the AVX2 tier, a `VDUP` and
two `VEOR` on NEON. The compression state is re-initialised each round
from a read-only table that carries the IV, the parameter block, the
counter and the final flag of the block, so the fold `h = h0 ⊕ v ⊕ v'`
reads the same table. The module docstring of the generator lists the
register plan of every tier.

## Register budget

The 32-bit-lane state of BLAKE2s fills 16 registers at one dword lane
per pixel, and the 16 message words fill the other 16 of the EVEX
register file: the avx512 tier keeps state and words in XMM registers at
four lanes and in YMM registers at eight lanes (the eight-pixel stride
of the width-256 pipeline and the fill kernel), 32 of 32 in both forms
with the seed-word rebuild and the fold as embedded-broadcast memory
operands. No sixteen-lane fill kernel exists: sixteen lanes would be the
ZMM form of the same plan, and the cell is waived — the batch-16 hook is
the widest fill rung of width 256. The avx2 tier has 16 XMM registers:
`X0..X14` hold `v[0..14]`, `X15` is the rotate temp, `v[15]` lives in a
frame slot with `v[12]` spilled around the two G functions that touch
`v[15]`, and the message words are frame slots read as memory operands;
every frame fits the NOSPLIT budget. The NEON tier holds the four dword
lanes of every state word in one register — one pass — with the words
loaded pairwise from the frame, one alternate register for the
shift-insert rotates and one byte mask for the rotate by 8.

## Store-to-load forwarding discipline (amd64)

Every message dword is read at its natural width (a 4-byte load, or the
1-byte tail of the 13-byte shape), so the first eight message bytes of a
lane are two 4-byte loads behind the caller's 4-byte pixel-index store.
Outputs are written as 4-byte stores per word per lane. Every wide kernel
ends with `VZEROUPPER` before `RET`.

## Correctness invariant

Every kernel implements the cascade documented in
`hashes/internal/blake2sasm/blake2sasm_fused.go` and is pinned to the
pure-Go reference there (`ScalarFusedChain256`, built on
`golang.org/x/crypto/blake2s`) by the in-package parity tests
(`go test ./hashes/internal/blake2sasm/`, every tier by direct call plus
`ITB_FORCE_HASH_TIER` / `ITB_FORCE_INTERLOCK_PRF_FILL_TIER` probes), by
the `hashes` package's known-answer vectors of the cascade
(`blake2s_cascade_kat_test.go`, produced under `-tags noitbasm`), and by
the cross-tier wire-parity tests. The generator changes how a kernel
reads its inputs and where it stages them, never what it computes.

Independently of any reference, every kernel is held to the
input-entropy differential audit of `internal/kernelaudit`
(`hashes/internal/blake2sasm/blake2sasm_entropy*_test.go`, every tier by
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
