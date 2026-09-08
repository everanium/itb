# ChaCha20 kernel generator

One deterministic generator emits every ChaCha20 fused ChainHash cascade
kernel under `hashes/internal/chacha20asm/`. It takes no input beyond its
own source (the "expand 32-byte k" constants and the block counter are
read-only tables the generator emits), and must reproduce the committed
`.s` files
byte for byte. The generator accepts `--check`, which regenerates in
memory, compares against the committed files without writing, and exits
non-zero on any drift.

```
python3 scripts/kernels/chacha20/gen_fused_kernels.py --check
```

Run the generator without `--check` to (re)write its files; the output
directory is resolved relative to the script
(`../../../hashes/internal/chacha20asm/`). After any generator change, run
the `--check` form and confirm `git diff --stat hashes/internal/chacha20asm/`
shows only the intended kernels.

## Fused ChainHash cascade kernels — `gen_fused_kernels.py`

The kernels evaluate the whole `Seed256.ChainHash256` cascade in one call
(see `hashes/internal/chacha20asm/chacha20asm_fused.go`):
`chacha20_fusedchain256_<shape>x4_<tier>_amd64.s` (tiers avx512 / avx2),
`chacha20_fusedchain256_<shape>x4_neon_arm64.s`, and the eight-lane YMM
kernels of the avx512 tier: `chacha20_fusedchain256_{20,36,68}x8_avx512_amd64.s`,
the per-pixel kernels at the nonce-buf shapes, and the Interlocked
Barrier fill kernel `chacha20_fusedchain256_13x8_avx512_amd64.s` (the
batch-16 hook), with the eight 13-byte fill blocks synthesised
in-register from `groupIdxBase`. The avx2 and neon tiers run the fill
hook as two four-lane kernel calls over Go-synthesised blocks. The
single-lane entry points of every tier run
`chacha20_fusedchain256_<shape>x1_gpr_{amd64,arm64}.s`, the
general-purpose-register kernels: the compression state in 32-bit
general-purpose registers (amd64 keeps fifteen of the sixteen words in
registers and one c word in a frame slot, which its G steps reach through
memory operands; arm64 keeps all sixteen), the message words as frame
slots, the rotates as `RORL` / `RORW`.

Per cascade round the kernel derives the ChaCha20 key per lane as the
32-byte fixed key XOR the seed — the seed of the round being the
component group XOR the previous round's output — and evaluates the
parent package's absorb: the 32-byte state `[LE64(len(data)) | 24-byte
data window]` XORed with the next 32 bytes of keystream after every
window. The keystream does not depend on the state, so the absorb is one
XOR of the data windows folded together with the length tag (the D
words, staged once per call into the frame) and the keystream halves the
shape consumes: the low half of block 0 at 13 / 20 bytes, both halves of
block 0 at 36 bytes, both halves of block 0 and the low half of block 1
at 68 bytes. Every 64-bit component and output word straddles two 32-bit
key words, low half first. The key words are rebuilt each round from the
fixed key dword, the component dword broadcast and the previous output —
a `VPBROADCASTD` and one `VPTERNLOGD` per word on the EVEX tier, two
broadcasts and two `VPXOR` on the AVX2 tier, a `VDUP` and two `VEOR` on
NEON — and every block starts from the constants, the key words, the
counter and the zero nonce; the initial state is added back after the
twenty rounds and the halves in use are XORed into the accumulator. The
module docstring of the generator lists the register plan of every tier.

## Register budget

The 32-bit-lane block state of ChaCha20 fills 16 registers at one dword
lane per pixel; the eight key words and the eight-word accumulator fill
the other 16 of the EVEX register file, with the constants and the
counter as embedded-broadcast memory operands: the avx512 tier keeps
the three sets in XMM registers at four lanes and in YMM registers at
eight lanes (the eight-pixel stride of the width-256 pipeline and the
fill kernel), 32 of 32 in both forms. No sixteen-lane fill kernel
exists: sixteen lanes would be the ZMM form of the same plan, and the
cell is waived — the batch-16 hook is the widest fill rung of width 256.
The avx2 tier has 16 XMM registers: `X0..X14` hold `v[0..14]`, `X15` is
the rotate temp, `v[15]` lives in a frame slot with `v[12]` spilled
around the two quarter rounds that touch `v[15]`, and the key words, the
accumulator and the replicated constants are memory operands; every
frame fits the NOSPLIT budget. The NEON tier holds the four dword lanes
of every state word in one register — one pass — with the key words in
eight more registers, one alternate register for the shift-insert
rotates, one byte mask for the rotate by 8 and the accumulator in the
frame.

## Store-to-load forwarding discipline (amd64)

Every data dword is read at its natural width (a 4-byte load, or the
1-byte tail of the 13-byte shape) and the windows are folded with
`XORL` at staging time, so the first eight data bytes of a lane are two
4-byte loads behind the caller's 4-byte pixel-index store. Outputs are
written as 4-byte stores per word per lane. Every wide kernel
ends with `VZEROUPPER` before `RET`.

## Correctness invariant

Every kernel implements the cascade documented in
`hashes/internal/chacha20asm/chacha20asm_fused.go` and is pinned to the
pure-Go reference there (`ScalarFusedChain256`, built on
`golang.org/x/crypto/chacha20`) by the in-package parity tests
(`go test ./hashes/internal/chacha20asm/`, every tier by direct call plus
`ITB_FORCE_HASH_TIER` / `ITB_FORCE_INTERLOCK_PRF_FILL_TIER` probes), by
the `hashes` package's known-answer vectors of the cascade
(`chacha20_cascade_kat_test.go`, produced under `-tags noitbasm`), and by
the cross-tier wire-parity tests. The generator changes how a kernel
reads its inputs and where it stages them, never what it computes.

Independently of any reference, every kernel is held to the
input-entropy differential audit of `internal/kernelaudit`
(`hashes/internal/chacha20asm/chacha20asm_entropy*_test.go`, every tier by
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
