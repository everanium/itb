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
memory operands) and avx2 (VEX XMM, synthesised rotates, the key words
and the state accumulator as memory operands); arm64 tier neon (four
dword lanes per register, one pass).

The avx512 tier carries the eight-lane YMM kernels — the same instruction
stream as the four-lane EVEX kernel over twice the lanes, one dword lane
per pixel: the per-pixel kernels chacha20_fusedchain256_{20,36,68}x8_avx512_amd64.s
(eight lane pointers, staged four at a time) and the Interlocked Barrier
fill kernel chacha20_fusedchain256_13x8_avx512_amd64.s (the batch-16 hook
of width 256), with the eight 13-byte fill blocks
[0x03 | LE64(groupIdxBase+i) | 4×0x00] synthesised in-register from
groupIdxBase as the three data dwords (idx << 8) | 0x03, idx >> 24 and
idx >> 56 (the qword lane arithmetic on ZMM, narrowed to the dword lanes
by VPMOVQD). The avx2 and neon tiers run the fill hook as two four-lane
kernel calls over Go-synthesised blocks. The single-lane entry points of
every tier run the general-purpose-register kernels
chacha20_fusedchain256_{13,20,36,68}x1_gpr_{amd64,arm64}.s: the block
state in 32-bit general-purpose registers, the key words and the state
accumulator as frame slots, the rotates as ROLL / RORW.

Cells that are not emitted, with the reason:
    13x16 avx512    sixteen dword lanes would be the ZMM form of the same
                    plan (32 of 32 registers); the cell is waived — the
                    batch-16 hook is the widest fill rung of width 256
    x8 avx2         16 v × 2 XMM per word at eight lanes = 32 > 16 → spill;
                    the four-lane kernel stays the top of the avx2 tier
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
the fixed key XOR the seed words is the ChaCha20 key, the nonce is zero,
and the 32-byte state [LE64(len(data)) | 24-byte data window] absorbs
the data 24 bytes at a time, each window XORed into the state followed
by an XOR with the next 32 bytes of keystream. The keystream never
depends on the state, so the absorb reduces to one XOR of the data
windows folded together with the length tag (the D words, staged once
per call) and the keystream halves the shape consumes: the low half of
block 0 (13 / 20 bytes), both halves of block 0 (36 bytes), both halves
of block 0 and the low half of block 1 (68 bytes). Each cascade round
rebuilds the eight key words as K ⊕ component ⊕ h from the fixed key
dword, the component dword broadcast — each 64-bit component and output
word straddles two 32-bit key words, low half first — and the previous
round's output, then runs one ChaCha20 block per counter value: the
state from the "expand 32-byte k" constants, the key words, the counter
and the zero nonce, twenty rounds, the initial state added back.

Register plans:
    avx512 x4   X0..X15 the block state v[0..15], X16..X23 the key words,
                X24..X31 the state accumulator S; the constants and the
                counter are embedded-broadcast memory operands, the
                key-word rebuild is a VPBROADCASTD and one VPTERNLOGD
                per word — 32 of 32, no scratch register
    avx512 x8   the same plan on YMM registers (eight lanes), 32 of 32;
                every frame fits the NOSPLIT budget
    avx2 x4     X0..X14 v[0..14], X15 the rotate temp, v[15] in a frame
                slot with v[12] spilled around the two quarter rounds that
                touch v[15]; the key words, the accumulator and the
                replicated constants are memory operands; rol16 / rol8 =
                VPSHUFB with byte masks, rol12 / rol7 = shift-shift-or
    neon x4     V0..V15 v[0..15] (four dword lanes per register, one
                pass), V16..V23 the key words, V24 the rotate alternate
                (VSHL + VSRI — the rotated word lands in the alternate
                register and the register roles swap; rol16 = VREV32 on
                16-bit elements, rol8 = VTBL against the byte mask in
                V25, both in place), V26 / V27 the accumulator temps; the
                accumulator lives in the frame; the block state is
                restored to its canonical registers before the initial
                state is added back
    gpr amd64   v[0..15] in AX, BX, CX, DX, SI, DI, BP, R8..R11, R12..R15
                with v[11] — a c word, whose two quarter-round steps read
                or update it through one memory operand each — in a frame
                slot (15 of 15 usable registers), 32-bit operations; the
                key words, the accumulator, the data words, the group
                counter and the component / key / output pointers in the
                frame; the accumulator is updated with memory-destination
                XORL
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
WINDOW = 24   # data window bytes per absorb step
WORDS = 8     # output words (dwords) of the cascade


# ------------------------------------------------------------- layout --

def data_words(n):
    """The six data words (state words 2..7) as lists of (d0, size)
    fragments to XOR together: window j contributes data bytes
    [24j + 4(w-2), +4) ∩ [0, n) to word w."""
    words = {w: [] for w in range(2, 8)}
    off = 0
    while off < n or off == 0:
        for w in range(2, 8):
            d0 = off + 4 * (w - 2)
            size = max(0, min(d0 + 4, n) - d0)
            if size > 0:
                words[w].append((d0, size))
        off += WINDOW
        if off >= n:
            break
    return words


def halves(n):
    """The keystream halves the shape consumes, as (block, half)."""
    steps = max(1, (n + WINDOW - 1) // WINDOW)
    return [(j // 2, j % 2) for j in range(steps)]


def nblocks(n):
    return max(b for b, _ in halves(n)) + 1


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

def load_word_amd64(r, d0, size, dst="R12"):
    if size == 4:
        return [f"\tMOVL {d0}({r}), {dst}"]
    if size == 1:
        return [f"\tMOVBLZX {d0}({r}), {dst}"]
    raise ValueError(size)


def load_data_word_amd64(r, frags, dst="R12", scratch="R13"):
    """XOR the fragments of one data word of the lane at r into dst."""
    out = []
    for i, (d0, size) in enumerate(frags):
        if i == 0:
            out += load_word_amd64(r, d0, size, dst)
        else:
            out += load_word_amd64(r, d0, size, scratch)
            out.append(f"\tXORL {scratch}, {dst}")
    return out


LANE_REGS = ["R8", "R9", "R10", "R11"]


def stage_amd64(n, frame, lanes):
    """Stage the D words: D0 = len(data), D1 = 0, D2..D7 the folded data
    windows of every lane (4 bytes per lane per word)."""
    lane_bytes = 4 * lanes
    words = data_words(n)
    d = [frame.alloc(("D", w), lane_bytes) for w in range(8)]
    lines = []
    for l in range(lanes):
        lines.append(f"\tMOVL ${n}, {d[0] + 4 * l}(SP)")
        lines.append(f"\tMOVL $0, {d[1] + 4 * l}(SP)")
    for g in range(lanes // 4):
        if lanes == 8:
            lines.append("\tMOVQ dataPtrs+24(FP), DX")
            for i, r in enumerate(LANE_REGS):
                lines.append(f"\tMOVQ {8 * (4 * g + i)}(DX), {r}")
        for w in range(2, 8):
            for l, r in enumerate(LANE_REGS):
                o = d[w] + 4 * (4 * g + l)
                if not words[w]:
                    lines.append(f"\tMOVL $0, {o}(SP)")
                else:
                    lines += load_data_word_amd64(r, words[w])
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
// {n}-byte shape, {lanes} lanes ({nb} keystream block{'s' if nb > 1 else ''} per cascade round). The data
// words are staged once per call and the key words rebuilt each round;
// see chacha20asm_fused.go for the construction and the in-package
// parity tests for the bit-exact pin against the pure-Go cascade.

#include "textflag.h"
"""


def const_tables(x8=False, replicate=1):
    """The constants: sigma[0..3] and the counter 1, each replicated
    `replicate` times (the AVX2 tier reads full 16-byte operands)."""
    lines = []
    for i, c in enumerate(SIGMA):
        for r in range(replicate):
            lines.append(f"DATA sigma<>+{4 * (replicate * i + r)}(SB)/4, $0x{c:08x}")
    lines.append(f"GLOBL sigma<>(SB), RODATA|NOPTR, ${16 * replicate}")
    lines.append("")
    for r in range(replicate):
        lines.append(f"DATA one<>+{4 * r}(SB)/4, $0x00000001")
    lines.append(f"GLOBL one<>(SB), RODATA|NOPTR, ${4 * replicate}")
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
        d = [frame.alloc(("D", w), lane_bytes) for w in range(8)]
        build += [
            "\tVPBROADCASTQ groupIdxBase+24(FP), Z0",
            "\tVPADDQ laneIdx<>(SB), Z0, Z0",
            "\tVPSLLQ $8, Z0, Z1",
            "\tMOVQ $3, R12",
            "\tVPBROADCASTQ R12, Z2",
            "\tVPORQ Z2, Z1, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {d[2]}(SP)",
            "\tVPSRLQ $24, Z0, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {d[3]}(SP)",
            "\tVPSRLQ $56, Z0, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {d[4]}(SP)",
            f"\tMOVQ ${n}, R12",
            "\tVPBROADCASTD R12, Y1",
            f"\tVMOVDQU32 Y1, {d[0]}(SP)",
            "\tVPXORD Y2, Y2, Y2",
        ]
        build += [f"\tVMOVDQU32 Y2, {d[w]}(SP)" for w in (1, 5, 6, 7)]
    else:
        build += stage_amd64(n, frame, lanes)
    mov = "VMOVDQU32"

    def key(j):
        return f"{p}{16 + j}"

    def acc(i):
        return f"{p}{24 + i}"

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
        lines.append(f"\tVPXORD {acc(i)}, {acc(i)}, {acc(i)}")
    lines.append("")
    lines.append("loop:")
    # Key words: K ⊕ component dword ⊕ h dword (h in the accumulator).
    for j in range(8):
        lines.append(f"\tVPBROADCASTD {4 * j}(AX), {key(j)}")
        lines.append(f"\tVPTERNLOGD.BCST $0x96, {4 * j}(BX), {acc(j)}, {key(j)}")
    for i in range(WORDS):
        lines.append(f"\t{mov} {frame.slots[('D', i)]}(SP), {acc(i)}")
    for b in range(nblocks(n)):
        lines.append("")
        for i in range(4):
            lines.append(f"\tVPBROADCASTD sigma<>+{4 * i}(SB), {p}{i}")
        for j in range(8):
            lines.append(f"\tVMOVDQA32 {key(j)}, {p}{4 + j}")
        if b == 0:
            lines.append(f"\tVPXORD {p}12, {p}12, {p}12")
        else:
            lines.append(f"\tVPBROADCASTD one<>(SB), {p}12")
        for i in (13, 14, 15):
            lines.append(f"\tVPXORD {p}{i}, {p}{i}, {p}{i}")
        lines.append("")
        lines += ["\tCHACHA_DR"] * DOUBLE_ROUNDS
        lines.append("")
        used = [h for bb, h in halves(n) if bb == b]
        for i in range(16):
            if i // 8 not in used:
                continue
            if i < 4:
                lines.append(f"\tVPADDD.BCST sigma<>+{4 * i}(SB), {p}{i}, {p}{i}")
            elif i < 12:
                lines.append(f"\tVPADDD {key(i - 4)}, {p}{i}, {p}{i}")
            elif i == 12 and b > 0:
                lines.append(f"\tVPADDD.BCST one<>(SB), {p}{i}, {p}{i}")
        for h in used:
            for i in range(8):
                lines.append(f"\tVPXORD {p}{8 * h + i}, {acc(i)}, {acc(i)}")
    lines.append("")
    lines.append("\tADDQ $32, BX")
    lines.append("\tDECQ CX")
    lines.append("\tJNZ loop")
    lines.append("")
    for i in range(WORDS):
        if x8:
            for q in range(2):
                lines.append(f"\tVEXTRACTI32X4 ${q}, {acc(i)}, X0")
                for l in range(4):
                    lines.append(f"\tVPEXTRD ${l}, X0, {32 * (4 * q + l) + 4 * i}(DX)")
        else:
            # The accumulator moves to a VEX-encodable register for the
            # extraction; the state is dead after the loop.
            lines.append(f"\tVMOVDQA32 X{24 + i}, X{i}")
            for l in range(4):
                lines.append(f"\tVPEXTRD ${l}, X{i}, {32 * l + 4 * i}(DX)")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += const_tables(x8=fill)
    return "\n".join(lines)


# -------------------------------------------------------- AVX2 family --

AVX2_MACROS = """#define ROLD(x, n, rn, t) \\
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

#define K(j)   (j*16)
#define S(i)   (128 + i*16)
#define V15    256
#define V12    272

#define DR \\
\tQR(X0, X4, X8,  X12, X15); \\
\tQR(X1, X5, X9,  X13, X15); \\
\tQR(X2, X6, X10, X14, X15); \\
\tVMOVDQU X12, V12(SP); \\
\tVMOVDQU V15(SP), X15; \\
\tQR(X3, X7, X11, X15, X12); \\
\tQR(X0, X5, X10, X15, X12); \\
\tVMOVDQU X15, V15(SP); \\
\tVMOVDQU V12(SP), X12; \\
\tQR(X1, X6, X11, X12, X15); \\
\tQR(X2, X7, X8,  X13, X15); \\
\tQR(X3, X4, X9,  X14, X15)
"""

AVX2_TABLES = """DATA rol16<>+0(SB)/8, $0x0504070601000302
DATA rol16<>+8(SB)/8, $0x0d0c0f0e09080b0a
GLOBL rol16<>(SB), RODATA|NOPTR, $16

DATA rol8<>+0(SB)/8, $0x0605040702010003
DATA rol8<>+8(SB)/8, $0x0e0d0c0f0a09080b
GLOBL rol8<>(SB), RODATA|NOPTR, $16
"""


def avx2_kernel(n):
    frame = Frame(288)  # K(0..7), S(0..7), V15, V12
    build = stage_amd64(n, frame, 4)
    lines = [header(AMD, n, 4, "AVX2 XMM (four lanes)")]
    lines.append(AVX2_MACROS)
    fn = f"chacha20FusedChain{n}x4Avx2Asm"
    lines.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)")
    lines.append(f"TEXT ·{fn}(SB), {text_flags(frame)}${frame.aligned}-40")
    lines += prologue_amd64(False)
    lines.append("")
    lines += build
    lines.append("")
    lines.append("\tVPXOR X15, X15, X15")
    for i in range(WORDS):
        lines.append(f"\tVMOVDQU X15, S({i})(SP)")
    lines.append("")
    lines.append("loop:")
    for j in range(8):
        lines.append(f"\tVPBROADCASTD {4 * j}(AX), X15")
        lines.append(f"\tVPXOR S({j})(SP), X15, X15")
        lines.append(f"\tVPBROADCASTD {4 * j}(BX), X0")
        lines.append(f"\tVPXOR X0, X15, X15")
        lines.append(f"\tVMOVDQU X15, K({j})(SP)")
    for i in range(WORDS):
        lines.append(f"\tVMOVDQU {frame.slots[('D', i)]}(SP), X15")
        lines.append(f"\tVMOVDQU X15, S({i})(SP)")
    for b in range(nblocks(n)):
        lines.append("")
        for i in range(4):
            lines.append(f"\tVMOVDQU sigma<>+{16 * i}(SB), X{i}")
        for j in range(8):
            lines.append(f"\tVMOVDQU K({j})(SP), X{4 + j}")
        if b == 0:
            lines.append("\tVPXOR X12, X12, X12")
        else:
            lines.append("\tVMOVDQU one<>(SB), X12")
        lines.append("\tVPXOR X13, X13, X13")
        lines.append("\tVPXOR X14, X14, X14")
        lines.append("\tVPXOR X15, X15, X15")
        lines.append("\tVMOVDQU X15, V15(SP)")
        lines.append("")
        lines += ["\tDR"] * DOUBLE_ROUNDS
        lines.append("")
        lines.append("\tVMOVDQU V15(SP), X15")
        used = [h for bb, h in halves(n) if bb == b]
        for i in range(16):
            if i // 8 not in used:
                continue
            if i < 4:
                lines.append(f"\tVPADDD sigma<>+{16 * i}(SB), X{i}, X{i}")
            elif i < 12:
                lines.append(f"\tVPADDD K({i - 4})(SP), X{i}, X{i}")
            elif i == 12 and b > 0:
                lines.append(f"\tVPADDD one<>(SB), X{i}, X{i}")
        for h in used:
            for i in range(8):
                lines.append(f"\tVPXOR S({i})(SP), X{8 * h + i}, X{8 * h + i}")
                lines.append(f"\tVMOVDQU X{8 * h + i}, S({i})(SP)")
    lines.append("")
    lines.append("\tADDQ $32, BX")
    lines.append("\tDECQ CX")
    lines.append("\tJNZ loop")
    lines.append("")
    for i in range(WORDS):
        lines.append(f"\tVMOVDQU S({i})(SP), X{i}")
        for l in range(4):
            lines.append(f"\tVPEXTRD ${l}, X{i}, {32 * l + 4 * i}(DX)")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += const_tables(replicate=4)
    lines.append(AVX2_TABLES)
    return "\n".join(lines)


# -------------------------------------------------------- NEON family --

ARM_LANE_REGS = ["R8", "R9", "R10", "R11"]


def load_word_arm64(r, d0, size, dst="R12"):
    if size == 4:
        return [f"\tMOVWU {d0}({r}), {dst}"]
    if size == 1:
        return [f"\tMOVBU {d0}({r}), {dst}"]
    raise ValueError(size)


def load_data_word_arm64(r, frags, dst="R12", scratch="R13"):
    out = []
    for i, (d0, size) in enumerate(frags):
        if i == 0:
            out += load_word_arm64(r, d0, size, dst)
        else:
            out += load_word_arm64(r, d0, size, scratch)
            out.append(f"\tEORW {scratch}, {dst}, {dst}")
    return out


def stage_arm64(n, frame, base="R7"):
    words = data_words(n)
    d = [frame.alloc(("D", w), 16) for w in range(8)]
    lines = [f"\tMOVW ${n}, R12"]
    for l in range(4):
        lines.append(f"\tMOVW R12, {d[0] + 4 * l}({base})")
        lines.append(f"\tMOVW ZR, {d[1] + 4 * l}({base})")
    for w in range(2, 8):
        for l, r in enumerate(ARM_LANE_REGS):
            if not words[w]:
                lines.append(f"\tMOVW ZR, {d[w] + 4 * l}({base})")
            else:
                lines += load_data_word_arm64(r, words[w])
                lines.append(f"\tMOVW R12, {d[w] + 4 * l}({base})")
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
    s_off = [frame.alloc(("S", i), 16) for i in range(8)]
    build = stage_arm64(n, frame)
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
    for i in range(WORDS):
        emit(f"\tMOVD ZR, {s_off[i]}(R7)")
        emit(f"\tMOVD ZR, {s_off[i] + 8}(R7)")
    emit("")
    emit("loop:")
    # Key words: K ⊕ component dword ⊕ h dword (h in the accumulator).
    for j in range(8):
        emit(f"\tMOVWU {4 * j}(R0), R12")
        emit(f"\tMOVWU {4 * j}(R1), R13")
        emit("\tEORW R13, R12, R12")
        emit(f"\tVDUP R12, V{16 + j}.S4")
        emit(f"\tFMOVQ {s_off[j]}(R7), F26")
        emit(f"\tVEOR V26.B16, V{16 + j}.B16, V{16 + j}.B16")
    for i in range(WORDS):
        emit(f"\tFMOVQ {frame.slots[('D', i)]}(R7), F26")
        emit(f"\tFMOVQ F26, {s_off[i]}(R7)")
    for b in range(nblocks(n)):
        regs = NeonRegs()
        emit("")
        for i in range(4):
            emit(f"\tMOVWU {4 * i}(R25), R12")
            emit(f"\tVDUP R12, V{i}.S4")
        for j in range(8):
            emit(f"\tVMOV V{16 + j}.B16, V{4 + j}.B16")
        if b == 0:
            emit("\tVEOR V12.B16, V12.B16, V12.B16")
        else:
            emit("\tMOVW $1, R12")
            emit("\tVDUP R12, V12.S4")
        for i in (13, 14, 15):
            emit(f"\tVEOR V{i}.B16, V{i}.B16, V{i}.B16")
        emit("")
        for _ in range(DOUBLE_ROUNDS):
            for a, bb, c, d in QR_ORDER:
                for l in neon_qr(regs, a, bb, c, d):
                    emit(l)
        emit("")
        for l in regs.restore(range(16)):
            emit(l)
        used = [h for bb, h in halves(n) if bb == b]
        for i in range(16):
            if i // 8 not in used:
                continue
            if i < 4:
                emit(f"\tMOVWU {4 * i}(R25), R12")
                emit("\tVDUP R12, V26.S4")
                emit(f"\tVADD V26.S4, V{i}.S4, V{i}.S4")
            elif i < 12:
                emit(f"\tVADD V{16 + i - 4}.S4, V{i}.S4, V{i}.S4")
            elif i == 12 and b > 0:
                emit("\tMOVW $1, R12")
                emit("\tVDUP R12, V26.S4")
                emit(f"\tVADD V26.S4, V{i}.S4, V{i}.S4")
        for h in used:
            for i in range(8):
                emit(f"\tFMOVQ {s_off[i]}(R7), F26")
                emit(f"\tVEOR V{8 * h + i}.B16, V26.B16, V26.B16")
                emit(f"\tFMOVQ F26, {s_off[i]}(R7)")
    emit("")
    emit("\tADD $32, R1, R1")
    emit("\tSUB $1, R2, R2")
    emit("\tCBNZ R2, loop")
    emit("")
    for i in range(WORDS):
        for l in range(4):
            emit(f"\tMOVWU {s_off[i] + 4 * l}(R7), R12")
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
// {n}-byte shape, 1 lane ({nb} keystream block{'s' if nb > 1 else ''} per cascade round). The data
// words are staged once per call and the key words rebuilt each round;
// see chacha20asm_fused.go for the construction and the in-package
// parity tests for the bit-exact pin against the pure-Go cascade.

#include "textflag.h"
"""


def gpr_kernel_amd64(n):
    frame = Frame()
    k_off = [frame.alloc(("K", j), 4) for j in range(8)]
    s_off = [frame.alloc(("S", i), 4) for i in range(8)]
    d_off = [frame.alloc(("D", w), 4) for w in range(8)]
    spill = frame.alloc("v11", 4)
    frame.alloc("pad", 4)
    cnt = frame.alloc("cnt", 8)
    cmp = frame.alloc("comps", 8)
    outp = frame.alloc("out", 8)
    keyp = frame.alloc("key", 8)
    words = data_words(n)
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
    L += [f"\tMOVL ${n}, {d_off[0]}(SP)", f"\tMOVL $0, {d_off[1]}(SP)"]
    for w in range(2, 8):
        if not words[w]:
            L.append(f"\tMOVL $0, {d_off[w]}(SP)")
        else:
            L += load_data_word_amd64("DX", words[w]) + [f"\tMOVL R12, {d_off[w]}(SP)"]
    L += [f"\tMOVL $0, {s_off[i]}(SP)" for i in range(8)]
    L += ["", "loop:"]
    # Key words: K ⊕ component dword ⊕ h dword (h in the accumulator).
    L += [f"\tMOVQ {cmp}(SP), R9", f"\tMOVQ {keyp}(SP), R11"]
    for j in range(8):
        L += [f"\tMOVL {4 * j}(R11), R10", f"\tXORL {4 * j}(R9), R10", f"\tXORL {s_off[j]}(SP), R10",
              f"\tMOVL R10, {k_off[j]}(SP)"]
    L += ["\tADDQ $32, R9", f"\tMOVQ R9, {cmp}(SP)"]
    for i in range(8):
        L += [f"\tMOVL {d_off[i]}(SP), R10", f"\tMOVL R10, {s_off[i]}(SP)"]
    for b in range(nblocks(n)):
        L.append("")
        for i in range(4):
            L.append(f"\tMOVL $0x{SIGMA[i]:08x}, {R[i]}")
        for j in range(8):
            if R[4 + j] is None:
                L += [f"\tMOVL {k_off[j]}(SP), R12", f"\tMOVL R12, {spill}(SP)"]
            else:
                L.append(f"\tMOVL {k_off[j]}(SP), {R[4 + j]}")
        L.append(f"\tMOVL ${b}, {R[12]}")
        for i in (13, 14, 15):
            L.append(f"\tXORL {R[i]}, {R[i]}")
        L.append("")
        for _ in range(DOUBLE_ROUNDS):
            for a, bb, c, d in QR_ORDER:
                L += [f"\tADDL {v(bb)}, {v(a)}", f"\tXORL {v(a)}, {v(d)}", f"\tROLL $16, {v(d)}",
                      f"\tADDL {v(d)}, {v(c)}", f"\tXORL {v(c)}, {v(bb)}", f"\tROLL $12, {v(bb)}",
                      f"\tADDL {v(bb)}, {v(a)}", f"\tXORL {v(a)}, {v(d)}", f"\tROLL $8, {v(d)}",
                      f"\tADDL {v(d)}, {v(c)}", f"\tXORL {v(c)}, {v(bb)}", f"\tROLL $7, {v(bb)}"]
        L.append("")
        used = [h for bb, h in halves(n) if bb == b]
        for i in range(16):
            if i // 8 not in used or R[i] is None:
                continue
            if i < 4:
                L.append(f"\tADDL $0x{SIGMA[i]:08x}, {R[i]}")
            elif i < 12:
                L.append(f"\tADDL {k_off[i - 4]}(SP), {R[i]}")
            elif i == 12 and b > 0:
                L.append(f"\tADDL ${b}, {R[i]}")
        for h in used:
            for i in range(8):
                if R[8 * h + i] is None:
                    # The spilled c word: added back through v[0]'s
                    # register, consumed by the low half already.
                    L += [f"\tMOVL {spill}(SP), AX", f"\tADDL {k_off[8 * h + i - 4]}(SP), AX",
                          f"\tXORL AX, {s_off[i]}(SP)"]
                else:
                    L.append(f"\tXORL {R[8 * h + i]}, {s_off[i]}(SP)")
    L += ["", f"\tDECQ {cnt}(SP)", "\tJNZ loop", "", f"\tMOVQ {outp}(SP), R9"]
    for i in range(WORDS):
        L += [f"\tMOVL {s_off[i]}(SP), R10", f"\tMOVL R10, {4 * i}(R9)"]
    L += ["\tRET", ""]
    return "\n".join(L)


def gpr_kernel_arm64(n):
    frame = Frame()
    k_off = [frame.alloc(("K", j), 4) for j in range(8)]
    s_off = [frame.alloc(("S", i), 4) for i in range(8)]
    d_off = [frame.alloc(("D", w), 4) for w in range(8)]
    words = data_words(n)
    R = GPR_REGS_ARM64
    L = [gpr_header(ARM, n, "ARM64 general-purpose-register")]
    fn = f"chacha20FusedChain{n}x1GprAsm"
    L.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)")
    L.append(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    L += ["\tMOVD fixedKey+0(FP), R0", "\tMOVD comps+8(FP), R1", "\tMOVD nGroups+16(FP), R2",
          "\tMOVD data+24(FP), R3", "\tMOVD out+32(FP), R4", f"\tMOVD $frame-{frame.aligned}(SP), R7",
          "\tMOVD $sigma<>(SB), R25", ""]
    L += [f"\tMOVW ${n}, R5", f"\tMOVW R5, {d_off[0]}(R7)", f"\tMOVW ZR, {d_off[1]}(R7)"]
    for w in range(2, 8):
        if not words[w]:
            L.append(f"\tMOVW ZR, {d_off[w]}(R7)")
        else:
            L += load_data_word_arm64("R3", words[w], "R5", "R6") + [f"\tMOVW R5, {d_off[w]}(R7)"]
    L += [f"\tMOVW ZR, {s_off[i]}(R7)" for i in range(8)]
    L += ["", "loop:"]
    for j in range(8):
        L += [f"\tMOVWU {4 * j}(R0), R5", f"\tMOVWU {4 * j}(R1), R6", "\tEORW R6, R5, R5",
              f"\tMOVWU {s_off[j]}(R7), R6", "\tEORW R6, R5, R5", f"\tMOVW R5, {k_off[j]}(R7)"]
    L.append("\tADD $32, R1, R1")
    for i in range(8):
        L += [f"\tMOVWU {d_off[i]}(R7), R5", f"\tMOVW R5, {s_off[i]}(R7)"]
    for b in range(nblocks(n)):
        L.append("")
        for i in range(4):
            L.append(f"\tMOVWU {4 * i}(R25), {R[i]}")
        for j in range(8):
            L.append(f"\tMOVWU {k_off[j]}(R7), {R[4 + j]}")
        L.append(f"\tMOVW ${b}, {R[12]}")
        for i in (13, 14, 15):
            L.append(f"\tMOVW $0, {R[i]}")
        L.append("")
        for _ in range(DOUBLE_ROUNDS):
            for a, bb, c, d in QR_ORDER:
                va, vb, vc, vd = R[a], R[bb], R[c], R[d]
                L += [f"\tADDW {vb}, {va}, {va}", f"\tEORW {va}, {vd}, {vd}", f"\tRORW $16, {vd}, {vd}",
                      f"\tADDW {vd}, {vc}, {vc}", f"\tEORW {vc}, {vb}, {vb}", f"\tRORW $20, {vb}, {vb}",
                      f"\tADDW {vb}, {va}, {va}", f"\tEORW {va}, {vd}, {vd}", f"\tRORW $24, {vd}, {vd}",
                      f"\tADDW {vd}, {vc}, {vc}", f"\tEORW {vc}, {vb}, {vb}", f"\tRORW $25, {vb}, {vb}"]
        L.append("")
        used = [h for bb, h in halves(n) if bb == b]
        for i in range(16):
            if i // 8 not in used:
                continue
            if i < 4:
                L += [f"\tMOVWU {4 * i}(R25), R5", f"\tADDW R5, {R[i]}, {R[i]}"]
            elif i < 12:
                L += [f"\tMOVWU {k_off[i - 4]}(R7), R5", f"\tADDW R5, {R[i]}, {R[i]}"]
            elif i == 12 and b > 0:
                L.append(f"\tADDW ${b}, {R[i]}, {R[i]}")
        for h in used:
            for i in range(8):
                L += [f"\tMOVWU {s_off[i]}(R7), R5", f"\tEORW {R[8 * h + i]}, R5, R5", f"\tMOVW R5, {s_off[i]}(R7)"]
    L += ["", "\tSUB $1, R2, R2", "\tCBNZ R2, loop", ""]
    for i in range(WORDS):
        L += [f"\tMOVWU {s_off[i]}(R7), R5", f"\tMOVW R5, {4 * i}(R4)"]
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
    files["chacha20_fusedchain256_13x8_avx512_amd64.s"] = evex_kernel(13, x8=True, fill=True) + "\n"
    return files


def main(argv):
    check = "--check" in argv
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
