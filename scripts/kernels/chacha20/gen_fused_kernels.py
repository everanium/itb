#!/usr/bin/env python3
"""Emit the ChaCha20 fused ChainHash cascade kernels for hashes/internal/chacha20asm.

One file per (shape, lanes, tier). Width 256 only (ChaCha20 PRF: 32-byte
fixed key, four component words per cascade group, 32-byte output,
32-bit state words); shapes 13 / 20 / 36 / 68; lanes x4 (four data lanes
over one shared component slice, one dword lane per pixel), x8 (eight
lanes, the widened per-pixel hooks and the Interlocked Barrier fill) and
x1 (the single-lane general-purpose-register kernel of every tier);
amd64 tiers avx512 (EVEX XMM at four lanes, EVEX YMM at eight, VPROLD
rotates, VPTERNLOGD key-word rebuild, the constants as embedded-broadcast
memory operands) and avx2 (VEX XMM at four lanes, VEX YMM at eight,
synthesised rotates, the key words as memory operands); arm64 tier neon
(four dword lanes per register, one pass).

Both amd64 tiers carry the eight-lane YMM kernels — the same instruction
stream as the tier's four-lane kernel over twice the lanes, one dword
lane per pixel: the per-pixel kernels
chacha20_fusedchain256_{20,36,68}x8_{avx512,avx2}_amd64.s (eight lane
pointers, staged four at a time) and the Interlocked Barrier fill
kernel chacha20_fusedchain256_13x8_{avx512,avx2}_amd64.s (the batch-16
hook of width 256), with the eight 13-byte fill blocks
[0x03 | LE64(groupIdxBase+i) | 4×0x00] synthesised in-register from
groupIdxBase as the slot words (idx << 8) | 0x03, idx >> 24, idx >> 56
and the constant tag word 0x8D << 24 (the qword lane arithmetic on ZMM
narrowed to the dword lanes by VPMOVQD on avx512; on two YMM halves
narrowed by VPSHUFD + VPERMQ and joined by VINSERTI128 on avx2). The
neon tier runs the fill hook as two four-lane kernel calls over
Go-synthesised blocks. The
single-lane entry points of every tier run the general-purpose-register
kernels chacha20_fusedchain256_{13,20,36,68}x1_gpr_{amd64,arm64}.s: the
block state in 32-bit general-purpose registers, the key words and the
slot words as frame slots, the rotates as ROLL / RORW.

Cells that are not emitted, with the reason:
    13x16 avx512    sixteen dword lanes would be the ZMM form of the same
                    plan (24 of 32 registers); the cell is waived — the
                    batch-16 hook is the widest fill rung of width 256
    x8 neon         16 v × 2 V per word at eight lanes = 32 + the key
                    words, the rotate alternate and the byte-rotate mask
                    > 32 → spill; the four-lane kernel stays the top of
                    the neon tier

Cascade evaluated per lane (see chacha20asm_fused.go):
    h = 0
    for each component group g (4 words):
        seed = g ^ h
        h = ChaCha20-PRF(key ⊕ seed, data)
    out = h
which is Seed256.ChainHash over the parent package's ChaCha20 closure:
the fixed key XOR the seed words is the key of the first slot block, and
the data is absorbed through the HChaCha20 chain — the data encoded as
16-byte slot blocks of 15 data bytes zero-padded plus a tag byte (0x00
on every block but the last, 0x80 | r on the last block carrying r data
bytes), each block entering the state [σ | key | block] as the four
words 12..15, twenty rounds, and the permuted words 0..3 and 12..15 (no
feed-forward — the HChaCha20 convention) becoming the key of the next
block; the last key is the round's output. The slot words of every
block are staged once per call (the S words). Each cascade round
rebuilds the eight key words as K ⊕ component ⊕ h from the fixed key
dword, the component dword broadcast — each 64-bit component and output
word straddles two 32-bit key words, low half first — and the previous
round's output, which sits in the state registers 0..3 and 12..15 the
last block left behind.

Register plans:
    avx512 x4   X0..X15 the block state v[0..15], X16..X23 the key words
                of the cascade round; the constants are embedded-broadcast
                memory operands, the key-word rebuild is a VPBROADCASTD
                and one VPTERNLOGD per word against the output words in
                place — 24 of 32, no scratch register
    avx512 x8   the same plan on YMM registers (eight lanes), 24 of 32;
                every frame fits the NOSPLIT budget
    avx2 x4     X0..X14 v[0..14], X15 the rotate temp, v[15] in a frame
                slot with v[12] spilled around the two quarter rounds that
                touch v[15]; the key words, the slot words and the
                replicated constants are memory operands; rol16 / rol8 =
                VPSHUFB with byte masks, rol12 / rol7 = shift-shift-or
    avx2 x8     the same plan on YMM registers (eight dword lanes, one
                per pixel): Y0..Y14 v[0..14], Y15 the rotate temp, v[15]
                and the v[12] spill as 32-byte frame slots, the key words,
                slot words, replicated constants and byte masks as 32-byte
                memory operands — 16 of 16 with the one spill of the
                four-lane plan and no other; the shape-68 kernel (960-byte
                frame) carries the stack check
    neon x4     V0..V15 v[0..15] (four dword lanes per register, one
                pass), V16..V23 the key words, V24 the rotate alternate
                (VSHL + VSRI — the rotated word lands in the alternate
                register and the register roles swap; rol16 = VREV32 on
                16-bit elements, rol8 = VTBL against the byte mask in
                V25, both in place), V26 the temp; the block state is
                restored to its canonical registers after every block
    gpr amd64   v[0..15] in AX, BX, CX, DX, SI, DI, BP, R8..R11, R12..R15
                with v[11] — a c word, whose two quarter-round steps read
                or update it through one memory operand each — in a frame
                slot (15 of 15 usable registers), 32-bit operations; the
                key words, the slot words, the group counter and the
                component / key / output pointers in the frame
    gpr arm64   v[0..15] in R8..R17, R19..R24 (W-form operations); R0
                key, R1 components, R2 group counter, R4 output, R7 frame
                base, R5 / R6 the temps, R25 the constant table
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "hashes", "internal", "chacha20asm")
SHAPES = [13, 20, 36, 68]
AMD = "amd64 && !purego && !noitbasm"
ARM = "arm64 && !purego && !noitbasm"

SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
# Quarter-round order of one double round: four columns, then four
# diagonals.
QR_ORDER = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
            (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
DOUBLE_ROUNDS = 10
SLOT = 15        # data bytes per slot block
TAG_FINAL = 0x80  # tag bit of the final slot block
WORDS = 8        # output words (dwords) of the cascade
# The output words of a block — the key of the next — in state order.
OUT_WORDS = [0, 1, 2, 3, 12, 13, 14, 15]


# ------------------------------------------------------------- layout --

def nblocks(n):
    """The number of slot blocks of an n-byte input."""
    return max(1, (n + SLOT - 1) // SLOT)


def slot_words(n):
    """The slot words of every block as a list (per block) of four
    (d0, size, tag) entries: data bytes [d0, d0 + size) land in the word
    (size 0 for a zero word) and tag << 24 is ORed into word 3 of the
    final block."""
    m = nblocks(n)
    blocks = []
    for b in range(m):
        words = []
        for w in range(4):
            d0 = SLOT * b + 4 * w
            size = max(0, min(d0 + 4, SLOT * (b + 1), n) - d0)
            tag = 0
            if w == 3 and b == m - 1:
                tag = TAG_FINAL | (n - SLOT * (m - 1))
            words.append((d0, size, tag))
        blocks.append(words)
    return blocks


class Frame:
    def __init__(self, base=0):
        self.size = base
        self.slots = {}

    def alloc(self, key, size):
        off = self.size
        self.size += size
        self.slots[key] = off
        return off

    @property
    def aligned(self):
        return (self.size + 15) // 16 * 16


# ------------------------------------------------------- amd64 loads --

def load_slot_word_amd64(r, d0, size, tag, dst="R12", scratch="R13"):
    """Load one slot word of the lane at r into dst: the data bytes at
    their natural width (a dword, a word, a byte, or a word and a byte
    for three) and the tag byte of the final block."""
    out = []
    if size == 4:
        out.append(f"\tMOVL {d0}({r}), {dst}")
    elif size == 3:
        out.append(f"\tMOVWLZX {d0}({r}), {dst}")
        out.append(f"\tMOVBLZX {d0 + 2}({r}), {scratch}")
        out.append(f"\tSHLL $16, {scratch}")
        out.append(f"\tORL {scratch}, {dst}")
    elif size == 2:
        out.append(f"\tMOVWLZX {d0}({r}), {dst}")
    elif size == 1:
        out.append(f"\tMOVBLZX {d0}({r}), {dst}")
    elif tag:
        out.append(f"\tMOVL $0x{tag << 24:08x}, {dst}")
        return out
    else:
        raise ValueError((size, tag))
    if tag:
        out.append(f"\tORL $0x{tag << 24:08x}, {dst}")
    return out


LANE_REGS = ["R8", "R9", "R10", "R11"]


def stage_amd64(n, frame, lanes):
    """Stage the slot words of every block: S[b][w] holds the word of
    every lane (4 bytes per lane)."""
    lane_bytes = 4 * lanes
    blocks = slot_words(n)
    s = [[frame.alloc(("S", b, w), lane_bytes) for w in range(4)] for b in range(len(blocks))]
    lines = []
    for g in range(lanes // 4):
        if lanes == 8:
            lines.append("\tMOVQ dataPtrs+24(FP), DX")
            for i, r in enumerate(LANE_REGS):
                lines.append(f"\tMOVQ {8 * (4 * g + i)}(DX), {r}")
        for b, words in enumerate(blocks):
            for w, (d0, size, tag) in enumerate(words):
                for l, r in enumerate(LANE_REGS):
                    o = s[b][w] + 4 * (4 * g + l)
                    if size == 0 and not tag:
                        lines.append(f"\tMOVL $0, {o}(SP)")
                    else:
                        lines += load_slot_word_amd64(r, d0, size, tag)
                        lines.append(f"\tMOVL R12, {o}(SP)")
    if lanes == 8:
        lines.append("\tMOVQ out+32(FP), DX")
    return lines


# NOSPLIT_FRAME_MAX is the largest frame the kernels declare with
# NOSPLIT; the wider frames carry the stack-growth prologue instead.
NOSPLIT_FRAME_MAX = 736


def text_flags(frame):
    return "NOSPLIT, " if frame.aligned <= NOSPLIT_FRAME_MAX else ""


def prologue_amd64(x8):
    lines = ["\tMOVQ fixedKey+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX"]
    if not x8:
        lines.append("\tMOVQ dataPtrs+24(FP), DX")
        for i, r in enumerate(LANE_REGS):
            lines.append(f"\tMOVQ {8 * i}(DX), {r}")
    lines.append("\tMOVQ out+32(FP), DX")
    return lines


def header(build, n, lanes, tier_desc, fill=False):
    nb = nblocks(n)
    what = "fused ChainHash cascade kernel"
    if fill:
        what = "batch-16 Interlocked Barrier fill kernel"
    return f"""//go:build {build}

// {tier_desc} {what} for ChaCha20 at the
// {n}-byte shape, {lanes} lanes ({nb} slot block{'s' if nb > 1 else ''} per cascade round). The slot
// words are staged once per call and the key words rebuilt each round;
// see chacha20asm_fused.go for the construction and the in-package
// parity tests for the bit-exact pin against the pure-Go cascade.

#include "textflag.h"
"""


def const_tables(x8=False, replicate=1):
    """The constants: sigma[0..3], each replicated `replicate` times (the
    AVX2 tier reads full 16-byte operands)."""
    lines = []
    for i, c in enumerate(SIGMA):
        for r in range(replicate):
            lines.append(f"DATA sigma<>+{4 * (replicate * i + r)}(SB)/4, $0x{c:08x}")
    lines.append(f"GLOBL sigma<>(SB), RODATA|NOPTR, ${16 * replicate}")
    lines.append("")
    if x8:
        for i in range(8):
            lines.append(f"DATA laneIdx<>+{8 * i}(SB)/8, $0x{i:016x}")
        lines.append("GLOBL laneIdx<>(SB), RODATA|NOPTR, $64")
        lines.append("")
    return lines


# ------------------------------------------------------- EVEX family --

def evex_macros(p):
    qr = "\n".join([
        "#define CHACHA_QR(a, b, c, d) \\",
        "\tVPADDD b, a, a; \\",
        "\tVPXORD a, d, d; \\",
        "\tVPROLD $16, d, d; \\",
        "\tVPADDD d, c, c; \\",
        "\tVPXORD c, b, b; \\",
        "\tVPROLD $12, b, b; \\",
        "\tVPADDD b, a, a; \\",
        "\tVPXORD a, d, d; \\",
        "\tVPROLD $8, d, d; \\",
        "\tVPADDD d, c, c; \\",
        "\tVPXORD c, b, b; \\",
        "\tVPROLD $7, b, b",
    ])
    rows = [f"\tCHACHA_QR({p}{a}, {p}{b}, {p}{c}, {p}{d})" for a, b, c, d in QR_ORDER]
    dr = "#define CHACHA_DR \\\n" + "; \\\n".join(rows)
    return qr + "\n\n" + dr + "\n"


def evex_kernel(n, x8=False, fill=False):
    p = "Y" if x8 else "X"
    lanes = 8 if x8 else 4
    lane_bytes = 4 * lanes
    frame = Frame()
    build = []
    if fill:
        # One slot block: [0x03 | LE64(idx) | 4×0x00 | 0x00 0x00 | tag].
        s = [[frame.alloc(("S", 0, w), lane_bytes) for w in range(4)]]
        tag = TAG_FINAL | 13
        build += [
            "\tVPBROADCASTQ groupIdxBase+24(FP), Z0",
            "\tVPADDQ laneIdx<>(SB), Z0, Z0",
            "\tVPSLLQ $8, Z0, Z1",
            "\tMOVQ $3, R12",
            "\tVPBROADCASTQ R12, Z2",
            "\tVPORQ Z2, Z1, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {s[0][0]}(SP)",
            "\tVPSRLQ $24, Z0, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {s[0][1]}(SP)",
            "\tVPSRLQ $56, Z0, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {s[0][2]}(SP)",
            f"\tMOVQ $0x{tag << 24:08x}, R12",
            "\tVPBROADCASTD R12, Y1",
            f"\tVMOVDQU32 Y1, {s[0][3]}(SP)",
        ]
    else:
        build += stage_amd64(n, frame, lanes)
    mov = "VMOVDQU32"
    m = nblocks(n)

    def key(j):
        return f"{p}{16 + j}"

    def hreg(i):
        return f"{p}{OUT_WORDS[i]}"

    lines = [header(AMD, n, lanes, "AVX-512 " + ("YMM (eight lanes)" if x8 else "XMM (four lanes)"), fill=fill)]
    lines.append(evex_macros(p))
    kind = "groupIdxBase uint64, out *[8][4]uint64" if fill else f"dataPtrs *[{lanes}]*byte, out *[{lanes}][4]uint64"
    fn = f"chacha20FusedChain{n}x{lanes}Avx512Asm"
    lines.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, {kind})")
    lines.append(f"TEXT ·{fn}(SB), {text_flags(frame)}${frame.aligned}-40")
    lines += prologue_amd64(x8)
    lines.append("")
    lines += build
    lines.append("")
    for i in range(WORDS):
        lines.append(f"\tVPXORD {hreg(i)}, {hreg(i)}, {hreg(i)}")
    lines.append("")
    lines.append("loop:")
    # Key words: K ⊕ component dword ⊕ h dword (h in the output words).
    for j in range(8):
        lines.append(f"\tVPBROADCASTD {4 * j}(AX), {key(j)}")
        lines.append(f"\tVPTERNLOGD.BCST $0x96, {4 * j}(BX), {hreg(j)}, {key(j)}")
    for b in range(m):
        lines.append("")
        if b == 0:
            for j in range(8):
                lines.append(f"\tVMOVDQA32 {key(j)}, {p}{4 + j}")
        else:
            for j in range(8):
                lines.append(f"\tVMOVDQA32 {hreg(j)}, {p}{4 + j}")
        for i in range(4):
            lines.append(f"\tVPBROADCASTD sigma<>+{4 * i}(SB), {p}{i}")
        for w in range(4):
            lines.append(f"\t{mov} {frame.slots[('S', b, w)]}(SP), {p}{12 + w}")
        lines.append("")
        lines += ["\tCHACHA_DR"] * DOUBLE_ROUNDS
    lines.append("")
    lines.append("\tADDQ $32, BX")
    lines.append("\tDECQ CX")
    lines.append("\tJNZ loop")
    lines.append("")
    for i in range(WORDS):
        if x8:
            for q in range(2):
                lines.append(f"\tVEXTRACTI32X4 ${q}, {hreg(i)}, X4")
                for l in range(4):
                    lines.append(f"\tVPEXTRD ${l}, X4, {32 * (4 * q + l) + 4 * i}(DX)")
        else:
            for l in range(4):
                lines.append(f"\tVPEXTRD ${l}, {hreg(i)}, {32 * l + 4 * i}(DX)")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += const_tables(x8=fill)
    return "\n".join(lines)


# -------------------------------------------------------- AVX2 family --

def avx2_macros(p, lane_bytes):
    """The quarter round, the frame-slot offsets and the double round on
    the register prefix p (X at four lanes, Y at eight): the key words
    K(0..7) and the v[15] / v[12] slots are lane_bytes wide."""
    return f"""#define ROLD(x, n, rn, t) \\
\tVPSLLD n, x, t; \\
\tVPSRLD rn, x, x; \\
\tVPOR t, x, x

#define QR(a, b, c, d, t) \\
\tVPADDD b, a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFB rol16<>(SB), d, d; \\
\tVPADDD d, c, c; \\
\tVPXOR c, b, b; \\
\tROLD(b, $12, $20, t); \\
\tVPADDD b, a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFB rol8<>(SB), d, d; \\
\tVPADDD d, c, c; \\
\tVPXOR c, b, b; \\
\tROLD(b, $7, $25, t)

#define K(j)   (j*{lane_bytes})
#define V15    {8 * lane_bytes}
#define V12    {9 * lane_bytes}

#define DR \\
\tQR({p}0, {p}4, {p}8,  {p}12, {p}15); \\
\tQR({p}1, {p}5, {p}9,  {p}13, {p}15); \\
\tQR({p}2, {p}6, {p}10, {p}14, {p}15); \\
\tVMOVDQU {p}12, V12(SP); \\
\tVMOVDQU V15(SP), {p}15; \\
\tQR({p}3, {p}7, {p}11, {p}15, {p}12); \\
\tQR({p}0, {p}5, {p}10, {p}15, {p}12); \\
\tVMOVDQU {p}15, V15(SP); \\
\tVMOVDQU V12(SP), {p}12; \\
\tQR({p}1, {p}6, {p}11, {p}12, {p}15); \\
\tQR({p}2, {p}7, {p}8,  {p}13, {p}15); \\
\tQR({p}3, {p}4, {p}9,  {p}14, {p}15)
"""


def avx2_tables(lane_bytes):
    """The byte-rotate masks of VPSHUFB, one 16-byte pattern per 128-bit
    register half (lane_bytes 16 or 32)."""
    reps = lane_bytes // 16
    lines = []
    for name, lo, hi in (("rol16", "0x0504070601000302", "0x0d0c0f0e09080b0a"),
                         ("rol8", "0x0605040702010003", "0x0e0d0c0f0a09080b")):
        for r in range(reps):
            lines.append(f"DATA {name}<>+{16 * r}(SB)/8, ${lo}")
            lines.append(f"DATA {name}<>+{16 * r + 8}(SB)/8, ${hi}")
        lines.append(f"GLOBL {name}<>(SB), RODATA|NOPTR, ${lane_bytes}")
        lines.append("")
    return "\n".join(lines)


# The constants of the eight-lane fill kernel: the qword 3 in every lane
# (the tag byte 0x03 of the fill block) and the tag dword of its final
# slot word.
AVX2_FILL_TABLES = f"""DATA fillc<>+0(SB)/8, $3
DATA fillc<>+8(SB)/8, $3
DATA fillc<>+16(SB)/8, $3
DATA fillc<>+24(SB)/8, $3
DATA fillc<>+32(SB)/4, $0x{(TAG_FINAL | 13) << 24:08x}
GLOBL fillc<>(SB), RODATA|NOPTR, $48
"""


def avx2_fill_build(frame):
    """Synthesise the slot words of the eight 13-byte fill blocks on YMM
    registers: the lane indices as qwords (lanes 0..3 in Y1, 4..7 in
    Y2), each slot word as a qword shift of the index, narrowed to the
    dword lanes by VPSHUFD + VPERMQ per register half and joined by
    VINSERTI128 into one 32-byte slot store."""
    s = [frame.alloc(("S", 0, w), 32) for w in range(4)]
    lines = [
        "\tVPBROADCASTQ groupIdxBase+24(FP), Y0",
        "\tVPADDQ laneIdx<>+0(SB), Y0, Y1",
        "\tVPADDQ laneIdx<>+32(SB), Y0, Y2",
    ]

    def pack(off):
        return ["\tVPSHUFD $0x08, Y3, Y3", "\tVPERMQ $0x08, Y3, Y3",
                "\tVPSHUFD $0x08, Y4, Y4", "\tVPERMQ $0x08, Y4, Y4",
                "\tVINSERTI128 $1, X4, Y3, Y3", f"\tVMOVDQU Y3, {off}(SP)"]

    lines += ["\tVPSLLQ $8, Y1, Y3", "\tVPSLLQ $8, Y2, Y4",
              "\tVPOR fillc<>+0(SB), Y3, Y3", "\tVPOR fillc<>+0(SB), Y4, Y4"] + pack(s[0])
    lines += ["\tVPSRLQ $24, Y1, Y3", "\tVPSRLQ $24, Y2, Y4"] + pack(s[1])
    lines += ["\tVPSRLQ $56, Y1, Y3", "\tVPSRLQ $56, Y2, Y4"] + pack(s[2])
    lines += ["\tVPBROADCASTD fillc<>+32(SB), Y3", f"\tVMOVDQU Y3, {s[3]}(SP)"]
    return lines


def avx2_kernel(n, x8=False, fill=False):
    """The avx2 x4 (XMM) kernel, the x8 (YMM) per-pixel kernel, or the
    x8 (YMM) fill kernel at shape 13 (fill implies x8): one register
    plan, one dword lane per pixel, the register width following the
    lane count."""
    p = "Y" if x8 else "X"
    lanes = 8 if x8 else 4
    lane_bytes = 4 * lanes
    frame = Frame(10 * lane_bytes)  # K(0..7), V15, V12
    if fill:
        build = avx2_fill_build(frame)
    else:
        build = stage_amd64(n, frame, lanes)
    m = nblocks(n)
    lines = [header(AMD, n, lanes, "AVX2 " + ("YMM (eight lanes)" if x8 else "XMM (four lanes)"), fill=fill)]
    lines.append(avx2_macros(p, lane_bytes))
    kind = "groupIdxBase uint64, out *[8][4]uint64" if fill else f"dataPtrs *[{lanes}]*byte, out *[{lanes}][4]uint64"
    fn = f"chacha20FusedChain{n}x{lanes}Avx2Asm"
    lines.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, {kind})")
    lines.append(f"TEXT ·{fn}(SB), {text_flags(frame)}${frame.aligned}-40")
    lines += prologue_amd64(x8)
    lines.append("")
    lines += build
    lines.append("")
    # h = 0: the output words v[0..3], v[12..14] and the v[15] slot.
    for i in (0, 1, 2, 3, 12, 13, 14):
        lines.append(f"\tVPXOR {p}{i}, {p}{i}, {p}{i}")
    lines.append(f"\tVMOVDQU {p}0, V15(SP)")
    lines.append("")
    lines.append("loop:")
    # Key words: K ⊕ component dword ⊕ h dword; h[7] is the v[15] slot
    # and register 4 (dead between blocks) carries the component
    # broadcast.
    for j in range(8):
        lines.append(f"\tVPBROADCASTD {4 * j}(AX), {p}15")
        if j == 7:
            lines.append(f"\tVPXOR V15(SP), {p}15, {p}15")
        else:
            lines.append(f"\tVPXOR {p}{OUT_WORDS[j]}, {p}15, {p}15")
        lines.append(f"\tVPBROADCASTD {4 * j}(BX), {p}4")
        lines.append(f"\tVPXOR {p}4, {p}15, {p}15")
        lines.append(f"\tVMOVDQU {p}15, K({j})(SP)")
    for b in range(m):
        lines.append("")
        if b == 0:
            for j in range(8):
                lines.append(f"\tVMOVDQU K({j})(SP), {p}{4 + j}")
        else:
            for j in range(7):
                lines.append(f"\tVMOVDQA {p}{OUT_WORDS[j]}, {p}{4 + j}")
            lines.append(f"\tVMOVDQU V15(SP), {p}11")
        for i in range(4):
            lines.append(f"\tVMOVDQU sigma<>+{lane_bytes * i}(SB), {p}{i}")
        for w in range(3):
            lines.append(f"\tVMOVDQU {frame.slots[('S', b, w)]}(SP), {p}{12 + w}")
        lines.append(f"\tVMOVDQU {frame.slots[('S', b, 3)]}(SP), {p}15")
        lines.append(f"\tVMOVDQU {p}15, V15(SP)")
        lines.append("")
        lines += ["\tDR"] * DOUBLE_ROUNDS
    lines.append("")
    lines.append("\tADDQ $32, BX")
    lines.append("\tDECQ CX")
    lines.append("\tJNZ loop")
    lines.append("")
    lines.append(f"\tVMOVDQU V15(SP), {p}15")
    for i in range(WORDS):
        if x8:
            # X4 (a dead b word) is the extract temp of the upper half.
            for l in range(4):
                lines.append(f"\tVPEXTRD ${l}, X{OUT_WORDS[i]}, {32 * l + 4 * i}(DX)")
            lines.append(f"\tVEXTRACTI128 $1, Y{OUT_WORDS[i]}, X4")
            for l in range(4):
                lines.append(f"\tVPEXTRD ${l}, X4, {32 * (4 + l) + 4 * i}(DX)")
        else:
            for l in range(4):
                lines.append(f"\tVPEXTRD ${l}, X{OUT_WORDS[i]}, {32 * l + 4 * i}(DX)")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += const_tables(x8=fill, replicate=lanes)
    lines.append(avx2_tables(lane_bytes))
    if fill:
        lines.append(AVX2_FILL_TABLES)
    return "\n".join(lines)


# -------------------------------------------------------- NEON family --

ARM_LANE_REGS = ["R8", "R9", "R10", "R11"]


def load_slot_word_arm64(r, d0, size, tag, dst="R12", scratch="R13"):
    out = []
    if size == 4:
        out.append(f"\tMOVWU {d0}({r}), {dst}")
    elif size == 3:
        out.append(f"\tMOVHU {d0}({r}), {dst}")
        out.append(f"\tMOVBU {d0 + 2}({r}), {scratch}")
        out.append(f"\tORRW {scratch}<<16, {dst}, {dst}")
    elif size == 2:
        out.append(f"\tMOVHU {d0}({r}), {dst}")
    elif size == 1:
        out.append(f"\tMOVBU {d0}({r}), {dst}")
    elif tag:
        out.append(f"\tMOVW $0x{tag << 24:08x}, {dst}")
        return out
    else:
        raise ValueError((size, tag))
    if tag:
        out.append(f"\tMOVW $0x{tag << 24:08x}, {scratch}")
        out.append(f"\tORRW {scratch}, {dst}, {dst}")
    return out


def stage_arm64(n, frame, base="R7"):
    blocks = slot_words(n)
    s = [[frame.alloc(("S", b, w), 16) for w in range(4)] for b in range(len(blocks))]
    lines = []
    for b, words in enumerate(blocks):
        for w, (d0, size, tag) in enumerate(words):
            for l, r in enumerate(ARM_LANE_REGS):
                o = s[b][w] + 4 * l
                if size == 0 and not tag:
                    lines.append(f"\tMOVW ZR, {o}({base})")
                else:
                    lines += load_slot_word_arm64(r, d0, size, tag)
                    lines.append(f"\tMOVW R12, {o}({base})")
    return lines


class NeonRegs:
    def __init__(self):
        self.v = [f"V{i}" for i in range(16)]
        self.alt = "V24"

    def rot(self, idx, amount):
        src = self.v[idx]
        if amount == 16:
            return [f"\tVREV32 {src}.H8, {src}.H8"]
        if amount == 8:
            return [f"\tVTBL V25.B16, [{src}.B16], {src}.B16"]
        dst = self.alt
        out = [f"\tVSHL ${amount}, {src}.S4, {dst}.S4", f"\tVSRI ${32 - amount}, {src}.S4, {dst}.S4"]
        self.v[idx], self.alt = dst, src
        return out

    def restore(self, words):
        out = []
        pending = {i for i in words if self.v[i] != f"V{i}"}
        while pending:
            progress = False
            for i in sorted(pending):
                if not any(self.v[j] == f"V{i}" for j in pending if j != i):
                    out.append(f"\tVMOV {self.v[i]}.B16, V{i}.B16")
                    self.v[i] = f"V{i}"
                    pending.discard(i)
                    progress = True
                    break
            if not progress:
                i = min(pending)
                assert all(self.v[j] != "V24" for j in pending)
                out.append(f"\tVMOV {self.v[i]}.B16, V24.B16")
                self.v[i] = "V24"
        self.alt = "V24"
        return out


def neon_qr(regs, a, b, c, d):
    out = []
    v = regs.v
    out.append(f"\tVADD {v[b]}.S4, {v[a]}.S4, {v[a]}.S4")
    out.append(f"\tVEOR {v[a]}.B16, {v[d]}.B16, {v[d]}.B16")
    out += regs.rot(d, 16)
    v = regs.v
    out.append(f"\tVADD {v[d]}.S4, {v[c]}.S4, {v[c]}.S4")
    out.append(f"\tVEOR {v[c]}.B16, {v[b]}.B16, {v[b]}.B16")
    out += regs.rot(b, 12)
    v = regs.v
    out.append(f"\tVADD {v[b]}.S4, {v[a]}.S4, {v[a]}.S4")
    out.append(f"\tVEOR {v[a]}.B16, {v[d]}.B16, {v[d]}.B16")
    out += regs.rot(d, 8)
    v = regs.v
    out.append(f"\tVADD {v[d]}.S4, {v[c]}.S4, {v[c]}.S4")
    out.append(f"\tVEOR {v[c]}.B16, {v[b]}.B16, {v[b]}.B16")
    out += regs.rot(b, 7)
    return out


NEON_TABLES = """DATA rol8<>+0(SB)/8, $0x0605040702010003
DATA rol8<>+8(SB)/8, $0x0e0d0c0f0a09080b
GLOBL rol8<>(SB), RODATA|NOPTR, $16
"""


def neon_kernel(n):
    frame = Frame()
    o_off = [frame.alloc(("O", i), 16) for i in range(8)]
    build = stage_arm64(n, frame)
    m = nblocks(n)
    L = []
    emit = L.append
    emit(header(ARM, n, 4, "NEON (four lanes)"))
    fn = f"chacha20FusedChain{n}x4NeonAsm"
    emit(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)")
    emit(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    emit("\tMOVD fixedKey+0(FP), R0")
    emit("\tMOVD comps+8(FP), R1")
    emit("\tMOVD nGroups+16(FP), R2")
    emit("\tMOVD dataPtrs+24(FP), R3")
    for i, r in enumerate(ARM_LANE_REGS):
        emit(f"\tMOVD {8 * i}(R3), {r}")
    emit("\tMOVD out+32(FP), R3")
    emit(f"\tMOVD $frame-{frame.aligned}(SP), R7")
    emit("\tMOVD $rol8<>(SB), R12")
    emit("\tVLD1 (R12), [V25.B16]")
    emit("\tMOVD $sigma<>(SB), R25")
    emit("")
    for l in build:
        emit(l)
    emit("")
    for i in OUT_WORDS:
        emit(f"\tVEOR V{i}.B16, V{i}.B16, V{i}.B16")
    emit("")
    emit("loop:")
    # Key words: K ⊕ component dword ⊕ h dword (h in the output words).
    for j in range(8):
        emit(f"\tMOVWU {4 * j}(R0), R12")
        emit(f"\tMOVWU {4 * j}(R1), R13")
        emit("\tEORW R13, R12, R12")
        emit(f"\tVDUP R12, V{16 + j}.S4")
        emit(f"\tVEOR V{OUT_WORDS[j]}.B16, V{16 + j}.B16, V{16 + j}.B16")
    for b in range(m):
        regs = NeonRegs()
        emit("")
        if b == 0:
            for j in range(8):
                emit(f"\tVMOV V{16 + j}.B16, V{4 + j}.B16")
        else:
            for j in range(8):
                emit(f"\tVMOV V{OUT_WORDS[j]}.B16, V{4 + j}.B16")
        for i in range(4):
            emit(f"\tMOVWU {4 * i}(R25), R12")
            emit(f"\tVDUP R12, V{i}.S4")
        for w in range(4):
            emit(f"\tFMOVQ {frame.slots[('S', b, w)]}(R7), F{12 + w}")
        emit("")
        for _ in range(DOUBLE_ROUNDS):
            for a, bb, c, d in QR_ORDER:
                for l in neon_qr(regs, a, bb, c, d):
                    emit(l)
        emit("")
        for l in regs.restore(range(16)):
            emit(l)
    emit("")
    emit("\tADD $32, R1, R1")
    emit("\tSUB $1, R2, R2")
    emit("\tCBNZ R2, loop")
    emit("")
    for i in range(WORDS):
        emit(f"\tFMOVQ F{OUT_WORDS[i]}, {o_off[i]}(R7)")
    for i in range(WORDS):
        for l in range(4):
            emit(f"\tMOVWU {o_off[i] + 4 * l}(R7), R12")
            emit(f"\tMOVW R12, {32 * l + 4 * i}(R3)")
    emit("")
    emit("\tRET")
    emit("")
    L += const_tables()
    emit(NEON_TABLES)
    return "\n".join(L)


# ---------------------------------------------------------- GPR x1 --

GPR_REGS_AMD64 = ["AX", "BX", "CX", "DX", "SI", "DI", "BP", "R8", "R9", "R10", "R11", None, "R12", "R13", "R14", "R15"]
GPR_REGS_ARM64 = ["R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R19", "R20", "R21", "R22", "R23", "R24"]


def gpr_header(build, n, tier_desc):
    nb = nblocks(n)
    return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for ChaCha20 at the
// {n}-byte shape, 1 lane ({nb} slot block{'s' if nb > 1 else ''} per cascade round). The slot
// words are staged once per call and the key words rebuilt each round;
// see chacha20asm_fused.go for the construction and the in-package
// parity tests for the bit-exact pin against the pure-Go cascade.

#include "textflag.h"
"""


def gpr_kernel_amd64(n):
    frame = Frame()
    k_off = [frame.alloc(("K", j), 4) for j in range(8)]
    blocks = slot_words(n)
    m = len(blocks)
    s_off = [[frame.alloc(("S", b, w), 4) for w in range(4)] for b in range(m)]
    spill = frame.alloc("v11", 4)
    if frame.size % 8:
        frame.alloc("pad", 4)
    cnt = frame.alloc("cnt", 8)
    cmp = frame.alloc("comps", 8)
    outp = frame.alloc("out", 8)
    keyp = frame.alloc("key", 8)
    R = GPR_REGS_AMD64

    def v(i):
        return R[i] if R[i] is not None else f"{spill}(SP)"

    L = [gpr_header(AMD, n, "amd64 general-purpose-register")]
    fn = f"chacha20FusedChain{n}x1GprAsm"
    L.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)")
    L.append(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    L += ["\tMOVQ fixedKey+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX",
          "\tMOVQ data+24(FP), DX", "\tMOVQ out+32(FP), DI",
          f"\tMOVQ BX, {cmp}(SP)", f"\tMOVQ CX, {cnt}(SP)", f"\tMOVQ DI, {outp}(SP)", f"\tMOVQ AX, {keyp}(SP)", ""]
    for b, words in enumerate(blocks):
        for w, (d0, size, tag) in enumerate(words):
            if size == 0 and not tag:
                L.append(f"\tMOVL $0, {s_off[b][w]}(SP)")
            else:
                L += load_slot_word_amd64("DX", d0, size, tag) + [f"\tMOVL R12, {s_off[b][w]}(SP)"]
    for i in OUT_WORDS:
        L.append(f"\tXORL {R[i]}, {R[i]}")
    L += ["", "loop:"]
    # Key words: K ⊕ component dword ⊕ h dword (h in the output words;
    # the b words v[4..10] are dead between rounds and serve as scratch).
    L += [f"\tMOVQ {cmp}(SP), R9", f"\tMOVQ {keyp}(SP), R11"]
    for j in range(8):
        L += [f"\tMOVL {4 * j}(R11), R10", f"\tXORL {4 * j}(R9), R10", f"\tXORL {R[OUT_WORDS[j]]}, R10",
              f"\tMOVL R10, {k_off[j]}(SP)"]
    L += ["\tADDQ $32, R9", f"\tMOVQ R9, {cmp}(SP)"]
    for b in range(m):
        L.append("")
        if b == 0:
            for j in range(8):
                if R[4 + j] is None:
                    L += [f"\tMOVL {k_off[j]}(SP), R12", f"\tMOVL R12, {spill}(SP)"]
                else:
                    L.append(f"\tMOVL {k_off[j]}(SP), {R[4 + j]}")
        else:
            for j in range(8):
                if R[4 + j] is None:
                    L.append(f"\tMOVL {R[OUT_WORDS[j]]}, {spill}(SP)")
                else:
                    L.append(f"\tMOVL {R[OUT_WORDS[j]]}, {R[4 + j]}")
        for i in range(4):
            L.append(f"\tMOVL $0x{SIGMA[i]:08x}, {R[i]}")
        for w in range(4):
            L.append(f"\tMOVL {s_off[b][w]}(SP), {R[12 + w]}")
        L.append("")
        for _ in range(DOUBLE_ROUNDS):
            for a, bb, c, d in QR_ORDER:
                L += [f"\tADDL {v(bb)}, {v(a)}", f"\tXORL {v(a)}, {v(d)}", f"\tROLL $16, {v(d)}",
                      f"\tADDL {v(d)}, {v(c)}", f"\tXORL {v(c)}, {v(bb)}", f"\tROLL $12, {v(bb)}",
                      f"\tADDL {v(bb)}, {v(a)}", f"\tXORL {v(a)}, {v(d)}", f"\tROLL $8, {v(d)}",
                      f"\tADDL {v(d)}, {v(c)}", f"\tXORL {v(c)}, {v(bb)}", f"\tROLL $7, {v(bb)}"]
    L += ["", f"\tDECQ {cnt}(SP)", "\tJNZ loop", "", f"\tMOVQ {outp}(SP), R9"]
    for i in range(WORDS):
        L.append(f"\tMOVL {R[OUT_WORDS[i]]}, {4 * i}(R9)")
    L += ["\tRET", ""]
    return "\n".join(L)


def gpr_kernel_arm64(n):
    frame = Frame()
    k_off = [frame.alloc(("K", j), 4) for j in range(8)]
    blocks = slot_words(n)
    m = len(blocks)
    s_off = [[frame.alloc(("S", b, w), 4) for w in range(4)] for b in range(m)]
    R = GPR_REGS_ARM64
    L = [gpr_header(ARM, n, "ARM64 general-purpose-register")]
    fn = f"chacha20FusedChain{n}x1GprAsm"
    L.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)")
    L.append(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    L += ["\tMOVD fixedKey+0(FP), R0", "\tMOVD comps+8(FP), R1", "\tMOVD nGroups+16(FP), R2",
          "\tMOVD data+24(FP), R3", "\tMOVD out+32(FP), R4", f"\tMOVD $frame-{frame.aligned}(SP), R7",
          "\tMOVD $sigma<>(SB), R25", ""]
    for b, words in enumerate(blocks):
        for w, (d0, size, tag) in enumerate(words):
            if size == 0 and not tag:
                L.append(f"\tMOVW ZR, {s_off[b][w]}(R7)")
            else:
                L += load_slot_word_arm64("R3", d0, size, tag, "R5", "R6") + [f"\tMOVW R5, {s_off[b][w]}(R7)"]
    for i in OUT_WORDS:
        L.append(f"\tMOVW ZR, {R[i]}")
    L += ["", "loop:"]
    for j in range(8):
        L += [f"\tMOVWU {4 * j}(R0), R5", f"\tMOVWU {4 * j}(R1), R6", "\tEORW R6, R5, R5",
              f"\tEORW {R[OUT_WORDS[j]]}, R5, R5", f"\tMOVW R5, {k_off[j]}(R7)"]
    L.append("\tADD $32, R1, R1")
    for b in range(m):
        L.append("")
        if b == 0:
            for j in range(8):
                L.append(f"\tMOVWU {k_off[j]}(R7), {R[4 + j]}")
        else:
            for j in range(8):
                L.append(f"\tMOVWU {R[OUT_WORDS[j]]}, {R[4 + j]}")
        for i in range(4):
            L.append(f"\tMOVWU {4 * i}(R25), {R[i]}")
        for w in range(4):
            L.append(f"\tMOVWU {s_off[b][w]}(R7), {R[12 + w]}")
        L.append("")
        for _ in range(DOUBLE_ROUNDS):
            for a, bb, c, d in QR_ORDER:
                va, vb, vc, vd = R[a], R[bb], R[c], R[d]
                L += [f"\tADDW {vb}, {va}, {va}", f"\tEORW {va}, {vd}, {vd}", f"\tRORW $16, {vd}, {vd}",
                      f"\tADDW {vd}, {vc}, {vc}", f"\tEORW {vc}, {vb}, {vb}", f"\tRORW $20, {vb}, {vb}",
                      f"\tADDW {vb}, {va}, {va}", f"\tEORW {va}, {vd}, {vd}", f"\tRORW $24, {vd}, {vd}",
                      f"\tADDW {vd}, {vc}, {vc}", f"\tEORW {vc}, {vb}, {vb}", f"\tRORW $25, {vb}, {vb}"]
    L += ["", "\tSUB $1, R2, R2", "\tCBNZ R2, loop", ""]
    for i in range(WORDS):
        L.append(f"\tMOVW {R[OUT_WORDS[i]]}, {4 * i}(R4)")
    L += ["\tRET", ""]
    L += const_tables()
    return "\n".join(L)


# ------------------------------------------------------------- driver --

def render_all():
    files = {}
    for n in SHAPES:
        files[f"chacha20_fusedchain256_{n}x4_avx512_amd64.s"] = evex_kernel(n) + "\n"
        files[f"chacha20_fusedchain256_{n}x4_avx2_amd64.s"] = avx2_kernel(n) + "\n"
        files[f"chacha20_fusedchain256_{n}x4_neon_arm64.s"] = neon_kernel(n) + "\n"
        files[f"chacha20_fusedchain256_{n}x1_gpr_amd64.s"] = gpr_kernel_amd64(n)
        files[f"chacha20_fusedchain256_{n}x1_gpr_arm64.s"] = gpr_kernel_arm64(n)
    for n in (20, 36, 68):
        files[f"chacha20_fusedchain256_{n}x8_avx512_amd64.s"] = evex_kernel(n, x8=True) + "\n"
        files[f"chacha20_fusedchain256_{n}x8_avx2_amd64.s"] = avx2_kernel(n, x8=True) + "\n"
    files["chacha20_fusedchain256_13x8_avx512_amd64.s"] = evex_kernel(13, x8=True, fill=True) + "\n"
    files["chacha20_fusedchain256_13x8_avx2_amd64.s"] = avx2_kernel(13, x8=True, fill=True) + "\n"
    return files


def main(argv):
    check = "--check" in argv
    unknown = [a for a in argv if a != "--check"]
    if unknown:
        raise SystemExit(f"gen_fused_kernels.py: unknown argument(s) {unknown}; known: --check")
    files = render_all()
    drift = 0
    for name, text in sorted(files.items()):
        path = os.path.join(OUT, name)
        if check:
            try:
                with open(path) as f:
                    cur = f.read()
            except FileNotFoundError:
                cur = None
            if cur != text:
                print(f"drift: {name}")
                drift += 1
        else:
            with open(path, "w") as f:
                f.write(text)
    if check:
        print(f"{len(files)} files, {drift} drift")
        return 1 if drift else 0
    print(f"wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
