## ITB ChaCha20 Kernels Generator

One deterministic generator emits every ChaCha20 fused ChainHash cascade
kernel under `hashes/internal/chacha20asm/`. It takes no input beyond its
own source (the "expand 32-byte k" constants are a read-only table the
generator emits), and must reproduce the committed
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
kernels of both amd64 tiers:
`chacha20_fusedchain256_{20,36,68}x8_{avx512,avx2}_amd64.s`, the
per-pixel kernels at the nonce-buf shapes, and the Interlocked Barrier
fill kernel `chacha20_fusedchain256_13x8_{avx512,avx2}_amd64.s` (the
batch-16 hook), with the eight 13-byte fill blocks synthesised
in-register from `groupIdxBase`. The neon tier runs the fill hook as
two four-lane kernel calls over Go-synthesised blocks. The
single-lane entry points of every tier run
`chacha20_fusedchain256_<shape>x1_gpr_{amd64,arm64}.s`, the
general-purpose-register kernels: the ChaCha20 block state in 32-bit
general-purpose registers (amd64 keeps fifteen of the sixteen words in
registers and one c word in a frame slot, which its quarter-round steps
reach through memory operands; arm64 keeps all sixteen), the key words
and the slot words as frame slots, the rotates as `ROLL` / `RORW`.

Per cascade round the kernel derives the ChaCha20 key per lane as the
32-byte fixed key XOR the seed — the seed of the round being the
component group XOR the previous round's output — and evaluates the
parent package's absorb: the HChaCha20 chain over the slot blocks of
the data. The data is encoded as 16-byte slot blocks of 15 data bytes
zero-padded plus a tag byte (`0x00` on every block but the last,
`0x80 | r` on the last block carrying `r` data bytes); every block
fills the four counter / nonce words 12..15 of the state `[σ | key |
block]`, twenty rounds run, and the permuted words 0..3 and 12..15 —
no feed-forward, the HChaCha20 convention — become the key of the next
block. The last key is the round's output, left in the state registers
0..3 and 12..15, and the next round rebuilds its key words from the
fixed key dword, the component dword broadcast and those output words —
a `VPBROADCASTD` and one `VPTERNLOGD` per word on the EVEX tier, two
broadcasts and two `VPXOR` on the AVX2 tier, a `VDUP` and two `VEOR` on
NEON. The slot words of every block are staged once per call into the
frame (the S words). Every 64-bit component and output word straddles
two 32-bit key words, low half first. The 13-byte fill block and the
20 / 36 / 68-byte nonce-buf shapes take 1 / 2 / 3 / 5 slot blocks per
cascade round. The module docstring of the generator lists the
register plan of every tier.

## Register budget

The 32-bit-lane block state of ChaCha20 fills 16 registers at one dword
lane per pixel and the eight key words of the cascade round fill eight
more, with the constants as embedded-broadcast memory operands: the
avx512 tier keeps both sets in XMM registers at four lanes and in YMM
registers at eight lanes (the eight-pixel stride of the width-256
pipeline and the fill kernel), 24 of 32 in both forms. The output of a
block is the key of the next, so no accumulator exists. No sixteen-lane
fill kernel exists: sixteen lanes would be the ZMM form of the same
plan, and the cell is waived — the batch-16 hook is the widest fill
rung of width 256. The avx2 tier has 16 registers at either width: `X0..X14` (`Y0..Y14` at the eight-lane YMM width) hold
`v[0..14]`, `X15` is the rotate temp, `v[15]` lives in a frame slot with
`v[12]` spilled around the two quarter rounds that touch `v[15]`, and
the key words, the slot words and the replicated constants are memory
operands; every four-lane frame fits the NOSPLIT budget. The eight-lane
kernels of the avx2 tier are the same plan on YMM registers — eight
dword lanes per register, one per pixel, the frame slots and memory
operands 32 bytes wide — so they carry the one spill of the four-lane
plan and no other; the shape-68 kernel (960-byte frame) carries the
stack check. The NEON tier holds the
four dword lanes of every state word in one register — one pass — with
the key words in eight more registers, one alternate register for the
shift-insert rotates and one byte mask for the rotate by 8.

## Store-to-load forwarding discipline (amd64)

Every slot word is read at its natural width — a 4-byte load for a
whole word, a 2-byte and a 1-byte load for three data bytes, a 2-byte
or 1-byte load for a shorter tail — at staging time, so the first slot
word of a lane is one 4-byte load behind the caller's 4-byte
pixel-index store. Outputs are written as 4-byte stores per word per
lane. Every wide kernel ends with `VZEROUPPER` before `RET`.

## Correctness invariant

Every kernel implements the cascade documented in
`hashes/internal/chacha20asm/chacha20asm_fused.go` and is pinned to the
pure-Go reference there (`ScalarFusedChain256`, built on the package's
own `HChaCha20` step, which the in-package tests pin to
`golang.org/x/crypto/chacha20.HChaCha20`, to the HChaCha20 vector of
draft-irtf-cfrg-xchacha § 2.2.1 and to the upstream block function)
by the in-package parity tests
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
