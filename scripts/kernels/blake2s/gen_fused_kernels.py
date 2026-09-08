#!/usr/bin/env python3
"""Emit the BLAKE2s fused ChainHash cascade kernels for hashes/internal/blake2sasm.

One file per (shape, lanes, tier). Width 256 only (BLAKE2s: 32-byte fixed
key, four component words per cascade group, 32-byte output, 32-bit state
words); shapes 13 / 20 / 36 / 68; lanes x4 (four data lanes over one shared
component slice, one dword lane per pixel), x8 (eight lanes, the widened
per-pixel hooks and the Interlocked Barrier fill) and x1 (the single-lane
general-purpose-register kernel of every tier); amd64 tiers avx512 (EVEX
XMM at four lanes, EVEX YMM at eight, VPRORD rotates, VPTERNLOGD folds)
and avx2 (VEX XMM, synthesised rotates, the message words as memory
operands); arm64 tier neon (four dword lanes per register, one pass).

The avx512 tier carries the eight-lane YMM kernels — the same instruction
stream as the four-lane EVEX kernel over twice the lanes, one dword lane
per pixel: the per-pixel kernels blake2s_fusedchain256_{20,36,68}x8_avx512_amd64.s
(eight lane pointers, staged four at a time) and the Interlocked Barrier
fill kernel blake2s_fusedchain256_13x8_avx512_amd64.s (the batch-16 hook of
width 256), with the eight 13-byte fill blocks
[0x03 | LE64(groupIdxBase+i) | 4×0x00] synthesised in-register from
groupIdxBase as the three data dwords (idx << 8) | 0x03, idx >> 24 and
idx >> 56 (the qword lane arithmetic on ZMM, narrowed to the dword lanes
by VPMOVQD). The avx2 and neon tiers run the fill hook as two four-lane
kernel calls over Go-synthesised blocks. The single-lane entry points of
every tier run the general-purpose-register kernels
blake2s_fusedchain256_{13,20,36,68}x1_gpr_{amd64,arm64}.s: the compression
state in 32-bit general-purpose registers, the message words as frame
slots, the rotates as RORL / RORW.

Cells that are not emitted, with the reason:
    13x16 avx512    sixteen dword lanes would be the ZMM form of the same
                    plan (32 of 32 registers); the cell is waived — the
                    batch-16 hook is the widest fill rung of width 256
    x8 avx2         16 v × 2 XMM per word at eight lanes = 32 > 16 → spill;
                    the four-lane kernel stays the top of the avx2 tier
    x8 neon         16 v × 2 V per word at eight lanes = 32 + the rotate
                    alternate, the byte-rotate mask and the word loads >
                    32 → spill; the four-lane kernel stays the top of the
                    neon tier

Cascade evaluated per lane (see blake2sasm_fused.go):
    h = 0
    for each component group g (4 words):
        seed = g ^ h
        h = BLAKE2s(key ‖ (data ⊕ seed))
    out = h
which is Seed256.ChainHash over the parent package's BLAKE2s prefix-MAC
closure: the fixed key, then data zero-padded to at least the 32-byte
seed-injection width with the seed words XORed over the bytes after the
key, hashed by BLAKE2s-256. The 13- and 20-byte shapes are one BLAKE2s
compression (a 64-byte input); the 36- and 68-byte shapes span two blocks
(t = 64 then t = 68 / 100, final). The message words are the key words
(broadcast from the key pointer), the seed-injected words and the
data-only words; the data words are staged once per call from the lane
pointers into the frame, and each cascade round rebuilds the seed-injected
words as D ⊕ component ⊕ h from the staged data dword, the component
dword broadcast — each 64-bit component and output word straddles two
32-bit message words, low half first — and the previous round's output:
one VPTERNLOGD per word on the EVEX tier. The compression state is
re-initialised each round from a per-kernel table holding IV, the
parameter block, t and the final flag.

Register plans:
    avx512 x4   X0..X15 the compression state v[0..15], X16..X31 the
                message words m[0..15]; the fold h = h0 ⊕ v ⊕ v' and the
                seed-word rebuild are VPTERNLOGD with embedded-broadcast
                memory operands, so no scratch register is needed
    avx512 x8   the same plan on YMM registers (eight lanes): Y0..Y15 the
                state, Y16..Y31 the message words, 32 of 32 with the
                seed-word rebuild and the fold as VPTERNLOGD
                embedded-broadcast memory operands; the shape-68 kernel
                (800-byte frame) carries the stack check
    avx2 x4     X0..X14 v[0..14], X15 the rotate temp, v[15] in a frame
                slot with v[12] spilled around the two G functions that
                touch v[15]; the message words are frame slots read as
                memory operands; ror16 / ror8 = VPSHUFB with byte masks,
                ror12 / ror7 = shift-shift-or; every frame fits the
                NOSPLIT budget
    neon x4     V0..V15 v[0..15] (four dword lanes per register, one
                pass); the message words in the frame, loaded pairwise
                into V16 / V17; V18 the rotate alternate (VSHL + VSRI —
                the rotated word lands in the alternate register and the
                register roles swap; ror16 = VREV32 on 16-bit elements,
                ror8 = VTBL against the byte mask in V19, both in place);
                the fold restores the rotated words to their canonical
                registers through the free alternate; the state-init
                tables are read-only data (R6 the table base)
    gpr amd64   v[0..15] in AX, BX, CX, DX, SI, DI, BP, R8..R11, R12..R15
                with v[11] — a c word, whose two G steps read or update
                it through one memory operand each — in a frame slot
                (15 of 15 usable registers), 32-bit operations
                throughout; the message words, the group counter, the
                component / key / output pointers in the frame; the
                fold's h0 constants pass through the just-folded v[8+i]
                register; R9 / R10 / R11 / R12 are the loop-top temps
                while only h = v[0..7] is live
    gpr arm64   v[0..15] in R8..R17, R19..R24 (W-form operations); R0
                key, R1 components, R2 group counter, R4 output, R7 frame
                base, R5 / R6 the message-word loads of every G, R25 the
                state-init table
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "hashes", "internal", "blake2sasm")
SHAPES = [13, 20, 36, 68]
AMD = "amd64 && !purego && !noitbasm"
ARM = "arm64 && !purego && !noitbasm"

IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
PARAM = 0x01010020  # digest length 32, fanout 1, depth 1
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]
ROUNDS = SIGMA
# G function order of one round: four columns, then four diagonals.
G_ORDER = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
MASK32 = (1 << 32) - 1
KEY = 32      # fixed key bytes, the message prefix
INJECT = 32   # seed-injection width
BLOCK = 64
WORDS = 8     # output words (dwords) of the cascade


# ------------------------------------------------------------- layout --

def layout(n):
    """Blocks of the shape cell. Each block is a dict with the 16 message
    words — ('key', k), ('seed', k, d0, size), ('data', d0, size) or
    ('zero',) — the counter t and the final flag. A seed word k (0..7) is
    the k-th dword after the key: data bytes [d0, d0+size), component
    dword k (the low half of component k/2 for even k, the high half for
    odd k) and output dword k."""
    total = KEY + max(n, INJECT)
    nblocks = (total + BLOCK - 1) // BLOCK
    blocks = []
    for b in range(nblocks):
        words = []
        for w in range(16):
            off = BLOCK * b + 4 * w
            if off >= total:
                words.append(("zero",))
            elif off < KEY:
                words.append(("key", off // 4))
            else:
                d0 = off - KEY
                size = max(0, min(d0 + 4, n) - d0)
                if d0 < INJECT:
                    words.append(("seed", d0 // 4, d0, size))
                elif size > 0:
                    words.append(("data", d0, size))
                else:
                    words.append(("zero",))
        blocks.append({"words": words, "t": min(total, BLOCK * (b + 1)), "final": b == nblocks - 1})
    return blocks


def init_table(block):
    """The 16 state words a compression of this block starts from: h0 (IV
    with the parameter block folded into h0[0]) and IV with t and the
    final flag folded in."""
    v = list(IV) + list(IV)
    v[0] ^= PARAM
    v[12] ^= block["t"]
    if block["final"]:
        v[14] ^= MASK32
    return v


def seed_words(block):
    return [(w, e) for w, e in enumerate(block["words"]) if e[0] == "seed"]


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
    """Load the data bytes [d0, d0+size) of the lane at pointer r into dst,
    zero-extended; every word is one load at its natural width."""
    if size == 4:
        return [f"\tMOVL {d0}({r}), {dst}"]
    if size == 1:
        return [f"\tMOVBLZX {d0}({r}), {dst}"]
    raise ValueError(size)


LANE_REGS = ["R8", "R9", "R10", "R11"]


def stage_amd64(blocks, frame, lane_bytes=16):
    """Stage the per-lane data words of every block into the frame (one
    slot of 4 bytes per lane per word): the D slots of the seed words
    (zero when the word carries no data) and the data-only words."""
    lines = []
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                key, d0, size = ("D", e[1]), e[2], e[3]
            elif e[0] == "data":
                key, d0, size = ("T", b, w), e[1], e[2]
            else:
                continue
            base = frame.alloc(key, lane_bytes)
            for l, r in enumerate(LANE_REGS):
                if size == 0:
                    lines.append(f"\tMOVL $0, {base + 4 * l}(SP)")
                else:
                    lines += load_word_amd64(r, d0, size)
                    lines.append(f"\tMOVL R12, {base + 4 * l}(SP)")
    return lines


def stage_amd64_x8(blocks, frame):
    """Stage the per-lane data words of eight lanes (32-byte slots):
    lanes 0..3 then 4..7, each group loading its four lane pointers into
    R8..R11 (dead after its stores)."""
    lines = []
    keys = []
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                keys.append((("D", e[1]), e[2], e[3]))
            elif e[0] == "data":
                keys.append((("T", b, w), e[1], e[2]))
    for key, _, _ in keys:
        frame.alloc(key, 32)
    for g in range(2):
        lines.append("\tMOVQ dataPtrs+24(FP), DX")
        for i, r in enumerate(LANE_REGS):
            lines.append(f"\tMOVQ {8 * (4 * g + i)}(DX), {r}")
        for key, d0, size in keys:
            base = frame.slots[key]
            for l, r in enumerate(LANE_REGS):
                o = base + 4 * (4 * g + l)
                if size == 0:
                    lines.append(f"\tMOVL $0, {o}(SP)")
                else:
                    lines += load_word_amd64(r, d0, size)
                    lines.append(f"\tMOVL R12, {o}(SP)")
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
    nb = len(layout(n))
    what = "fused ChainHash cascade kernel"
    if fill:
        what = "batch-16 Interlocked Barrier fill kernel"
    return f"""//go:build {build}

// {tier_desc} {what} for BLAKE2s at the
// {n}-byte shape, {lanes} lanes ({nb} compression{'s' if nb > 1 else ''} per cascade round). The data
// words are staged once per call and the seed-injected words rebuilt
// each round; see blake2sasm_fused.go for the construction and the
// in-package parity tests for the bit-exact pin against the pure-Go
// cascade.

#include "textflag.h"
"""


def tables(blocks, x8=False):
    lines = []
    for b, block in enumerate(blocks):
        v = init_table(block)
        for k in range(16):
            lines.append(f"DATA tab{b}<>+{4 * k}(SB)/4, $0x{v[k]:08x}")
        lines.append(f"GLOBL tab{b}<>(SB), RODATA|NOPTR, $64")
        lines.append("")
    if x8:
        for i in range(8):
            lines.append(f"DATA laneIdx<>+{8 * i}(SB)/8, $0x{i:016x}")
        lines.append("GLOBL laneIdx<>(SB), RODATA|NOPTR, $64")
        lines.append("")
    return lines


# ------------------------------------------------------- EVEX family --

def evex_macros(p):
    """The G function and the round on the register prefix p (X or Y)."""
    g = "\n".join([
        "#define BLAKE2S_G(a, b, c, d, mx, my) \\",
        "\tVPADDD b, a, a; \\",
        "\tVPADDD mx, a, a; \\",
        "\tVPXORD a, d, d; \\",
        "\tVPRORD $16, d, d; \\",
        "\tVPADDD d, c, c; \\",
        "\tVPXORD c, b, b; \\",
        "\tVPRORD $12, b, b; \\",
        "\tVPADDD b, a, a; \\",
        "\tVPADDD my, a, a; \\",
        "\tVPXORD a, d, d; \\",
        "\tVPRORD $8, d, d; \\",
        "\tVPADDD d, c, c; \\",
        "\tVPXORD c, b, b; \\",
        "\tVPRORD $7, b, b",
    ])
    rows = []
    for gi, (a, b, c, d) in enumerate(G_ORDER):
        rows.append(f"\tBLAKE2S_G({p}{a}, {p}{b}, {p}{c}, {p}{d}, s{2 * gi}, s{2 * gi + 1})")
    r = "#define BLAKE2S_ROUND(" + ", ".join(f"s{i}" for i in range(16)) + ") \\\n" + "; \\\n".join(rows)
    return g + "\n\n" + r + "\n"


def evex_rounds(p):
    return [f"\tBLAKE2S_ROUND({', '.join(f'{p}{16 + s}' for s in sigma)})" for sigma in ROUNDS]


def evex_kernel(n, x8=False, fill=False):
    """The avx512 x4 (XMM) kernel, the x8 (YMM) per-pixel kernel, or the
    x8 (YMM) fill kernel at shape 13 (fill implies x8)."""
    p = "Y" if x8 else "X"
    lanes = 8 if x8 else 4
    lane_bytes = 4 * lanes
    blocks = layout(n)
    nb = len(blocks)
    frame = Frame()
    build = []
    if fill:
        # Synthesised fill blocks: D0 = (idx << 8) | 0x03, D1 = idx >> 24,
        # D2 = idx >> 56, the remaining seed-injected words zero. The
        # qword lane arithmetic runs on ZMM and VPMOVQD narrows each lane
        # to its dword.
        d = [frame.alloc(("D", k), lane_bytes) for k in range(8)]
        build += [
            "\tVPBROADCASTQ groupIdxBase+24(FP), Z0",
            "\tVPADDQ laneIdx<>(SB), Z0, Z0",
            "\tVPSLLQ $8, Z0, Z1",
            "\tMOVQ $3, R12",
            "\tVPBROADCASTQ R12, Z2",
            "\tVPORQ Z2, Z1, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {d[0]}(SP)",
            "\tVPSRLQ $24, Z0, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {d[1]}(SP)",
            "\tVPSRLQ $56, Z0, Z1",
            "\tVPMOVQD Z1, Y1",
            f"\tVMOVDQU32 Y1, {d[2]}(SP)",
            "\tVPXORD Y2, Y2, Y2",
        ]
        build += [f"\tVMOVDQU32 Y2, {d[k]}(SP)" for k in range(3, 8)]
    elif x8:
        build += stage_amd64_x8(blocks, frame)
    else:
        build += stage_amd64(blocks, frame, lane_bytes)
    if nb > 1:
        for i in range(8):
            frame.alloc(("H", i), lane_bytes)
    mov = "VMOVDQU32"

    def m(w):
        return f"{p}{16 + w}"

    def load_words(b, with_key):
        """Set the round-invariant message registers of block b."""
        out = []
        for w, e in enumerate(blocks[b]["words"]):
            if e[0] == "key":
                if with_key:
                    out.append(f"\tVPBROADCASTD {4 * e[1]}(AX), {m(w)}")
            elif e[0] == "data":
                out.append(f"\t{mov} {frame.slots[('T', b, w)]}(SP), {m(w)}")
            elif e[0] == "zero":
                out.append(f"\tVPXORD {m(w)}, {m(w)}, {m(w)}")
        return out

    lines = []
    lines.append(header(AMD, n, lanes, "AVX-512 " + ("YMM (eight lanes)" if x8 else "XMM (four lanes)"), fill=fill))
    lines.append(evex_macros(p))
    if fill:
        kind = "groupIdxBase uint64, out *[8][4]uint64"
    else:
        kind = f"dataPtrs *[{lanes}]*byte, out *[{lanes}][4]uint64"
    fn = f"blake2sFusedChain{n}x{lanes}Avx512Asm"
    lines.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, {kind})")
    lines.append(f"TEXT ·{fn}(SB), {text_flags(frame)}${frame.aligned}-40")
    lines += prologue_amd64(x8)
    lines.append("")
    lines += build
    lines.append("")
    if nb == 1:
        lines += load_words(0, True)
    for i in range(WORDS):
        lines.append(f"\tVPXORD {p}{i}, {p}{i}, {p}{i}")
    lines.append("")
    lines.append("loop:")
    # Seed-injected words of block 0: D ⊕ component dword ⊕ h dword.
    for w, e in seed_words(blocks[0]):
        k = e[1]
        lines.append(f"\t{mov} {frame.slots[('D', k)]}(SP), {m(w)}")
        lines.append(f"\tVPTERNLOGD.BCST $0x96, {4 * k}(BX), {p}{k}, {m(w)}")
    if nb > 1:
        lines += load_words(0, True)
    for b, block in enumerate(blocks):
        lines.append("")
        if b > 0:
            for i in range(8):
                lines.append(f"\t{mov} {p}{i}, {frame.slots[('H', i)]}(SP)")
            lines += load_words(b, False)
        for k in range(0 if b == 0 else 8, 16):
            lines.append(f"\tVPBROADCASTD tab{b}<>+{4 * k}(SB), {p}{k}")
        lines.append("")
        lines += evex_rounds(p)
        lines.append("")
        last = b == nb - 1
        for i in range(8):
            if nb > 1 and last:
                lines.append(f"\tVPTERNLOGD $0x96, {frame.slots[('H', i)]}(SP), {p}{8 + i}, {p}{i}")
            else:
                lines.append(f"\tVPTERNLOGD.BCST $0x96, tab{b}<>+{4 * i}(SB), {p}{8 + i}, {p}{i}")
    lines.append("")
    lines.append("\tADDQ $32, BX")
    lines.append("\tDECQ CX")
    lines.append("\tJNZ loop")
    lines.append("")
    for i in range(WORDS):
        if x8:
            for q in range(2):
                lines.append(f"\tVEXTRACTI32X4 ${q}, Y{i}, X16")
                for l in range(4):
                    lines.append(f"\tVPEXTRD ${l}, X16, {32 * (4 * q + l) + 4 * i}(DX)")
        else:
            for l in range(4):
                lines.append(f"\tVPEXTRD ${l}, X{i}, {32 * l + 4 * i}(DX)")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += tables(blocks, fill)
    return "\n".join(lines)


# -------------------------------------------------------- AVX2 family --

AVX2_MACROS = """#define RORD(x, n, ln, t) \\
\tVPSRLD n, x, t; \\
\tVPSLLD ln, x, x; \\
\tVPOR t, x, x

#define GA(a, b, c, d, mx, my, t) \\
\tVPADDD b, a, a; \\
\tVPADDD mx(SP), a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFB ror16<>(SB), d, d; \\
\tVPADDD d, c, c; \\
\tVPXOR c, b, b; \\
\tRORD(b, $12, $20, t); \\
\tVPADDD b, a, a; \\
\tVPADDD my(SP), a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFB ror8<>(SB), d, d; \\
\tVPADDD d, c, c; \\
\tVPXOR c, b, b; \\
\tRORD(b, $7, $25, t)

#define M(i)   (i*16)
#define V15    256
#define V12    272

#define ROUND(s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15) \\
\tGA(X0, X4, X8,  X12, M(s0),  M(s1),  X15); \\
\tGA(X1, X5, X9,  X13, M(s2),  M(s3),  X15); \\
\tGA(X2, X6, X10, X14, M(s4),  M(s5),  X15); \\
\tVMOVDQU X12, V12(SP); \\
\tVMOVDQU V15(SP), X15; \\
\tGA(X3, X7, X11, X15, M(s6),  M(s7),  X12); \\
\tGA(X0, X5, X10, X15, M(s8),  M(s9),  X12); \\
\tVMOVDQU X15, V15(SP); \\
\tVMOVDQU V12(SP), X12; \\
\tGA(X1, X6, X11, X12, M(s10), M(s11), X15); \\
\tGA(X2, X7, X8,  X13, M(s12), M(s13), X15); \\
\tGA(X3, X4, X9,  X14, M(s14), M(s15), X15)
"""

AVX2_TABLES = """DATA ror16<>+0(SB)/8, $0x0504070601000302
DATA ror16<>+8(SB)/8, $0x0d0c0f0e09080b0a
GLOBL ror16<>(SB), RODATA|NOPTR, $16

DATA ror8<>+0(SB)/8, $0x0407060500030201
DATA ror8<>+8(SB)/8, $0x0c0f0e0d080b0a09
GLOBL ror8<>(SB), RODATA|NOPTR, $16
"""


def avx2_rounds():
    return [f"\tROUND({','.join(str(s) for s in sigma)})" for sigma in ROUNDS]


def avx2_kernel(n):
    blocks = layout(n)
    nb = len(blocks)
    frame = Frame(288)  # M(0..15), V15, V12
    build = stage_amd64(blocks, frame, 16)
    if nb > 1:
        for i in range(8):
            frame.alloc(("H", i), 16)

    def slot(w):
        return f"M({w})"

    def load_words(b, with_key):
        out = []
        for w, e in enumerate(blocks[b]["words"]):
            if e[0] == "key":
                if with_key:
                    out.append(f"\tVPBROADCASTD {4 * e[1]}(AX), X15")
                    out.append(f"\tVMOVDQU X15, {slot(w)}(SP)")
            elif e[0] == "data":
                out.append(f"\tVMOVDQU {frame.slots[('T', b, w)]}(SP), X15")
                out.append(f"\tVMOVDQU X15, {slot(w)}(SP)")
            elif e[0] == "zero":
                out.append("\tVPXOR X15, X15, X15")
                out.append(f"\tVMOVDQU X15, {slot(w)}(SP)")
        return out

    tmp2 = "X8"  # free between the fold and the state init
    lines = []
    lines.append(header(AMD, n, 4, "AVX2 XMM (four lanes)"))
    lines.append(AVX2_MACROS)
    fn = f"blake2sFusedChain{n}x4Avx2Asm"
    lines.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)")
    lines.append(f"TEXT ·{fn}(SB), {text_flags(frame)}${frame.aligned}-40")
    lines += prologue_amd64(False)
    lines.append("")
    lines += build
    lines.append("")
    if nb == 1:
        lines += load_words(0, True)
    for i in range(WORDS):
        lines.append(f"\tVPXOR X{i}, X{i}, X{i}")
    lines.append("")
    lines.append("loop:")
    for w, e in seed_words(blocks[0]):
        k = e[1]
        lines.append(f"\tVMOVDQU {frame.slots[('D', k)]}(SP), X15")
        lines.append(f"\tVPXOR X{k}, X15, X15")
        lines.append(f"\tVPBROADCASTD {4 * k}(BX), {tmp2}")
        lines.append(f"\tVPXOR {tmp2}, X15, X15")
        lines.append(f"\tVMOVDQU X15, {slot(w)}(SP)")
    if nb > 1:
        lines += load_words(0, True)
    for b, block in enumerate(blocks):
        lines.append("")
        if b > 0:
            for i in range(8):
                lines.append(f"\tVMOVDQU X{i}, {frame.slots[('H', i)]}(SP)")
            lines += load_words(b, False)
        for k in range(0 if b == 0 else 8, 15):
            lines.append(f"\tVPBROADCASTD tab{b}<>+{4 * k}(SB), X{k}")
        lines.append(f"\tVPBROADCASTD tab{b}<>+60(SB), X15")
        lines.append("\tVMOVDQU X15, V15(SP)")
        lines.append("")
        lines += avx2_rounds()
        lines.append("")
        last = b == nb - 1
        for i in range(8):
            if i == 7:
                lines.append("\tVPXOR V15(SP), X7, X7")
            else:
                lines.append(f"\tVPXOR X{8 + i}, X{i}, X{i}")
            if nb > 1 and last:
                lines.append(f"\tVPXOR {frame.slots[('H', i)]}(SP), X{i}, X{i}")
            else:
                lines.append(f"\tVPBROADCASTD tab{b}<>+{4 * i}(SB), X15")
                lines.append(f"\tVPXOR X15, X{i}, X{i}")
    lines.append("")
    lines.append("\tADDQ $32, BX")
    lines.append("\tDECQ CX")
    lines.append("\tJNZ loop")
    lines.append("")
    for i in range(WORDS):
        for l in range(4):
            lines.append(f"\tVPEXTRD ${l}, X{i}, {32 * l + 4 * i}(DX)")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += tables(blocks)
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


def stage_arm64(blocks, frame, base="R7"):
    """Stage the per-lane data words as in stage_amd64 (four lanes, 4 bytes
    each, so one 16-byte slot per word) through the frame base register."""
    lines = []
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                key, d0, size = ("D", e[1]), e[2], e[3]
            elif e[0] == "data":
                key, d0, size = ("T", b, w), e[1], e[2]
            else:
                continue
            off = frame.alloc(key, 16)
            for l, r in enumerate(ARM_LANE_REGS):
                if size == 0:
                    lines.append(f"\tMOVW ZR, {off + 4 * l}({base})")
                else:
                    lines += load_word_arm64(r, d0, size)
                    lines.append(f"\tMOVW R12, {off + 4 * l}({base})")
    return lines


class NeonRegs:
    """Tracks which physical register holds each state word; a shift-insert
    rotate writes into the alternate register and swaps the roles, the
    byte-granular rotates run in place."""

    def __init__(self):
        self.v = [f"V{i}" for i in range(16)]
        self.alt = "V18"

    def rot(self, idx, amount):
        src = self.v[idx]
        if amount == 16:
            return [f"\tVREV32 {src}.H8, {src}.H8"]
        if amount == 8:
            return [f"\tVTBL V19.B16, [{src}.B16], {src}.B16"]
        dst = self.alt
        out = [f"\tVSHL ${32 - amount}, {src}.S4, {dst}.S4", f"\tVSRI ${amount}, {src}.S4, {dst}.S4"]
        self.v[idx], self.alt = dst, src
        return out

    def restore(self, words):
        """Move the given words back to their canonical registers, using
        the registers no listed word occupies as temporaries, so no move
        overwrites a word that is still to be moved."""
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
                # A cycle among the pending words: every one of them
                # occupies another's canonical register, so the alternate
                # is free; park the first pending word there.
                i = min(pending)
                assert all(self.v[j] != "V18" for j in pending)
                out.append(f"\tVMOV {self.v[i]}.B16, V18.B16")
                self.v[i] = "V18"
        self.alt = "V18"
        return out


def neon_g(regs, a, b, c, d, mx, my):
    """One G function; mx / my are the frame offsets of the two message
    words (loaded into V16 / V17)."""
    out = [f"\tFMOVQ {mx}(R7), F16", f"\tFMOVQ {my}(R7), F17"]
    v = regs.v
    out.append(f"\tVADD {v[b]}.S4, {v[a]}.S4, {v[a]}.S4")
    out.append(f"\tVADD V16.S4, {v[a]}.S4, {v[a]}.S4")
    out.append(f"\tVEOR {v[a]}.B16, {v[d]}.B16, {v[d]}.B16")
    out += regs.rot(d, 16)
    v = regs.v
    out.append(f"\tVADD {v[d]}.S4, {v[c]}.S4, {v[c]}.S4")
    out.append(f"\tVEOR {v[c]}.B16, {v[b]}.B16, {v[b]}.B16")
    out += regs.rot(b, 12)
    v = regs.v
    out.append(f"\tVADD {v[b]}.S4, {v[a]}.S4, {v[a]}.S4")
    out.append(f"\tVADD V17.S4, {v[a]}.S4, {v[a]}.S4")
    out.append(f"\tVEOR {v[a]}.B16, {v[d]}.B16, {v[d]}.B16")
    out += regs.rot(d, 8)
    v = regs.v
    out.append(f"\tVADD {v[d]}.S4, {v[c]}.S4, {v[c]}.S4")
    out.append(f"\tVEOR {v[c]}.B16, {v[b]}.B16, {v[b]}.B16")
    out += regs.rot(b, 7)
    return out


NEON_TABLES = """DATA ror8<>+0(SB)/8, $0x0407060500030201
DATA ror8<>+8(SB)/8, $0x0c0f0e0d080b0a09
GLOBL ror8<>(SB), RODATA|NOPTR, $16
"""


def neon_kernel(n):
    """NEON x4 kernel: four dword lanes per 128-bit register, one pass. The
    message words are frame slots; the state lives in V0..V15 with V18 as
    the rotate alternate, V19 the ror8 byte mask and V16 / V17 the word
    loads."""
    blocks = layout(n)
    nb = len(blocks)
    frame = Frame()
    m_off = [frame.alloc(("M", w), 16) for w in range(16)]
    build = stage_arm64(blocks, frame)
    h_off = [frame.alloc(("H", i), 16) for i in range(8)] if nb > 1 else []
    out_lines = []

    def emit(s):
        out_lines.append(s)

    emit(header(ARM, n, 4, "NEON (four lanes)"))
    fn = f"blake2sFusedChain{n}x4NeonAsm"
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
    emit("\tMOVD $ror8<>(SB), R12")
    emit("\tVLD1 (R12), [V19.B16]")
    emit("")
    for l in build:
        emit(l)
    emit("")
    # Round-invariant words of block 0.
    for w, e in enumerate(blocks[0]["words"]):
        if e[0] == "key":
            emit(f"\tMOVWU {4 * e[1]}(R0), R12")
            emit("\tVDUP R12, V16.S4")
            emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
        elif e[0] == "data":
            emit(f"\tFMOVQ {frame.slots[('T', 0, w)]}(R7), F16")
            emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
        elif e[0] == "zero":
            emit(f"\tMOVD ZR, {m_off[w]}(R7)")
            emit(f"\tMOVD ZR, {m_off[w] + 8}(R7)")
    for i in range(WORDS):
        emit(f"\tVEOR V{i}.B16, V{i}.B16, V{i}.B16")
    emit("")
    emit("loop:")
    # Seed-injected words: D ⊕ component dword ⊕ h dword (h in V0..V7).
    for w, e in seed_words(blocks[0]):
        k = e[1]
        emit(f"\tFMOVQ {frame.slots[('D', k)]}(R7), F16")
        emit(f"\tMOVWU {4 * k}(R1), R12")
        emit("\tVDUP R12, V17.S4")
        emit("\tVEOR V16.B16, V17.B16, V16.B16")
        emit(f"\tVEOR V{k}.B16, V16.B16, V16.B16")
        emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
    if nb > 1:
        for w, e in enumerate(blocks[0]["words"]):
            if e[0] == "key":
                emit(f"\tMOVWU {4 * e[1]}(R0), R12")
                emit("\tVDUP R12, V16.S4")
                emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
    for b, block in enumerate(blocks):
        regs = NeonRegs()
        emit("")
        if b > 0:
            for i in range(8):
                emit(f"\tFMOVQ F{i}, {h_off[i]}(R7)")
            for w, e in enumerate(block["words"]):
                if e[0] == "data":
                    emit(f"\tFMOVQ {frame.slots[('T', b, w)]}(R7), F16")
                    emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
                elif e[0] == "zero":
                    emit(f"\tMOVD ZR, {m_off[w]}(R7)")
                    emit(f"\tMOVD ZR, {m_off[w] + 8}(R7)")
        emit(f"\tMOVD $tab{b}<>(SB), R6")
        for k in range(0 if b == 0 else 8, 16):
            emit(f"\tMOVWU {4 * k}(R6), R12")
            emit(f"\tVDUP R12, V{k}.S4")
        emit("")
        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                for l in neon_g(regs, a, bb, c, d, m_off[sigma[2 * gi]], m_off[sigma[2 * gi + 1]]):
                    emit(l)
        emit("")
        last = b == nb - 1
        v = regs.v
        # Fold in place: h_i = h0_i ⊕ v_i ⊕ v_{i+8}, then move the rotated
        # b words back to V4..V7.
        for i in range(8):
            emit(f"\tVEOR {v[8 + i]}.B16, {v[i]}.B16, {v[i]}.B16")
            if nb > 1 and last:
                emit(f"\tFMOVQ {h_off[i]}(R7), F16")
            else:
                emit(f"\tMOVWU {4 * i}(R6), R12")
                emit("\tVDUP R12, V16.S4")
            emit(f"\tVEOR V16.B16, {v[i]}.B16, {v[i]}.B16")
        for l in regs.restore(range(8)):
            emit(l)
    emit("")
    emit("\tADD $32, R1, R1")
    emit("\tSUB $1, R2, R2")
    emit("\tCBNZ R2, loop")
    emit("")
    for i in range(WORDS):
        for l in range(4):
            emit(f"\tVMOV V{i}.S[{l}], R12")
            emit(f"\tMOVW R12, {32 * l + 4 * i}(R3)")
    emit("")
    emit("\tRET")
    emit("")
    for l in tables(blocks):
        emit(l)
    emit(NEON_TABLES)
    return "\n".join(out_lines)


# ---------------------------------------------------------- GPR x1 --
#
# The single-lane kernels run the cascade in general-purpose registers
# with 32-bit operations: the compression state v[0..15] in registers (on
# amd64 fifteen of them, v[11] — a c word, the role whose two G steps
# read or update it through one memory operand each — in a frame slot),
# the message words as frame slots (amd64: memory operands of ADDL;
# arm64: MOVWU into two temps per G), the rotates as RORL / RORW. They
# serve the single-lane tail of every tier and the single arm.

GPR_REGS_AMD64 = ["AX", "BX", "CX", "DX", "SI", "DI", "BP", "R8", "R9", "R10", "R11", None, "R12", "R13", "R14", "R15"]
GPR_SPILL_AMD64 = 11
GPR_REGS_ARM64 = ["R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R19", "R20", "R21", "R22", "R23", "R24"]


def gpr_header(build, n, tier_desc):
    nb = len(layout(n))
    return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for BLAKE2s at the
// {n}-byte shape, 1 lane ({nb} compression{'s' if nb > 1 else ''} per cascade round). The data
// words are staged once per call and the seed-injected words rebuilt
// each round; see blake2sasm_fused.go for the construction and the
// in-package parity tests for the bit-exact pin against the pure-Go
// cascade.

#include "textflag.h"
"""


def gpr_kernel_amd64(n):
    blocks = layout(n)
    nb = len(blocks)
    frame = Frame()
    m_off = [frame.alloc(("M", w), 4) for w in range(16)]
    spill = frame.alloc("v11", 4)
    frame.alloc("pad", 4)
    cnt = frame.alloc("cnt", 8)
    cmp = frame.alloc("comps", 8)
    outp = frame.alloc("out", 8)
    keyp = frame.alloc("key", 8)
    d_off = {}
    t_off = {}
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                d_off[e[1]] = (frame.alloc(("D", e[1]), 4), e[2], e[3])
            elif e[0] == "data":
                t_off[(b, w)] = (frame.alloc(("T", b, w), 4), e[1], e[2])
    h_off = [frame.alloc(("H", i), 4) for i in range(8)] if nb > 1 else []
    R = GPR_REGS_AMD64

    def v(i):
        return R[i] if R[i] is not None else f"{spill}(SP)"

    L = [gpr_header(AMD, n, "amd64 general-purpose-register")]
    fn = f"blake2sFusedChain{n}x1GprAsm"
    L.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)")
    L.append(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    L += ["\tMOVQ fixedKey+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX",
          "\tMOVQ data+24(FP), DX", "\tMOVQ out+32(FP), DI",
          f"\tMOVQ BX, {cmp}(SP)", f"\tMOVQ CX, {cnt}(SP)", f"\tMOVQ DI, {outp}(SP)", f"\tMOVQ AX, {keyp}(SP)", ""]
    # Stage the data words (D slots of the seed words, T slots of the
    # data-only words) and the key words of block 0 into their m slots.
    for k in sorted(d_off):
        off, d0, size = d_off[k]
        if size == 0:
            L.append(f"\tMOVL $0, {off}(SP)")
        else:
            L += load_word_amd64("DX", d0, size) + [f"\tMOVL R12, {off}(SP)"]
    for (b, w), (off, d0, size) in sorted(t_off.items()):
        L += load_word_amd64("DX", d0, size) + [f"\tMOVL R12, {off}(SP)"]

    def load_words(b, with_key, key="AX"):
        out = []
        for w, e in enumerate(blocks[b]["words"]):
            if e[0] == "key":
                if with_key:
                    out += [f"\tMOVL {4 * e[1]}({key}), R12", f"\tMOVL R12, {m_off[w]}(SP)"]
            elif e[0] == "data":
                out += [f"\tMOVL {t_off[(b, w)][0]}(SP), R12", f"\tMOVL R12, {m_off[w]}(SP)"]
            elif e[0] == "zero":
                out.append(f"\tMOVL $0, {m_off[w]}(SP)")
        return out

    L += load_words(0, True)
    L += [f"\tXORL {R[i]}, {R[i]}" for i in range(8)]
    L += ["", "loop:"]
    # Seed-injected words: D ⊕ component dword ⊕ h dword (h in v[0..7]).
    L.append(f"\tMOVQ {cmp}(SP), R9")
    for w, e in seed_words(blocks[0]):
        k = e[1]
        L += [f"\tMOVL {d_off[k][0]}(SP), R10", f"\tXORL {4 * k}(R9), R10", f"\tXORL {R[k]}, R10",
              f"\tMOVL R10, {m_off[w]}(SP)"]
    L += ["\tADDQ $32, R9", f"\tMOVQ R9, {cmp}(SP)"]
    if nb > 1:
        # Block 1 overwrote the message slots: restore block 0's
        # round-invariant words (the key pointer through v[10]'s
        # register, dead at the loop top).
        L += [f"\tMOVQ {keyp}(SP), R11"] + load_words(0, True, key="R11")
    for b, block in enumerate(blocks):
        tab = init_table(block)
        L.append("")
        if b > 0:
            L += [f"\tMOVL {R[i]}, {h_off[i]}(SP)" for i in range(8)]
            L += load_words(b, False)
        for k in range(0 if b == 0 else 8, 16):
            if R[k] is None:
                L += [f"\tMOVL $0x{tab[k]:08x}, R12", f"\tMOVL R12, {spill}(SP)"]
            else:
                L.append(f"\tMOVL $0x{tab[k]:08x}, {R[k]}")
        L.append("")
        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                mx, my = f"{m_off[sigma[2 * gi]]}(SP)", f"{m_off[sigma[2 * gi + 1]]}(SP)"
                L += [f"\tADDL {v(bb)}, {v(a)}", f"\tADDL {mx}, {v(a)}", f"\tXORL {v(a)}, {v(d)}", f"\tRORL $16, {v(d)}",
                      f"\tADDL {v(d)}, {v(c)}", f"\tXORL {v(c)}, {v(bb)}", f"\tRORL $12, {v(bb)}",
                      f"\tADDL {v(bb)}, {v(a)}", f"\tADDL {my}, {v(a)}", f"\tXORL {v(a)}, {v(d)}", f"\tRORL $8, {v(d)}",
                      f"\tADDL {v(d)}, {v(c)}", f"\tXORL {v(c)}, {v(bb)}", f"\tRORL $7, {v(bb)}"]
        L.append("")
        last = b == nb - 1
        for i in range(8):
            L.append(f"\tXORL {v(8 + i)}, {R[i]}")
            if nb > 1 and last:
                L.append(f"\tXORL {h_off[i]}(SP), {R[i]}")
            else:
                tmp = R[8 + i] if R[8 + i] is not None else R[8 + i - 1]
                L += [f"\tMOVL $0x{tab[i]:08x}, {tmp}", f"\tXORL {tmp}, {R[i]}"]
    L += ["", f"\tDECQ {cnt}(SP)", "\tJNZ loop", "", f"\tMOVQ {outp}(SP), R9"]
    L += [f"\tMOVL {R[i]}, {4 * i}(R9)" for i in range(WORDS)]
    L += ["\tRET", ""]
    return "\n".join(L)


def gpr_kernel_arm64(n):
    blocks = layout(n)
    nb = len(blocks)
    frame = Frame()
    m_off = [frame.alloc(("M", w), 4) for w in range(16)]
    d_off = {}
    t_off = {}
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                d_off[e[1]] = (frame.alloc(("D", e[1]), 4), e[2], e[3])
            elif e[0] == "data":
                t_off[(b, w)] = (frame.alloc(("T", b, w), 4), e[1], e[2])
    h_off = [frame.alloc(("H", i), 4) for i in range(8)] if nb > 1 else []
    R = GPR_REGS_ARM64

    L = [gpr_header(ARM, n, "ARM64 general-purpose-register")]
    fn = f"blake2sFusedChain{n}x1GprAsm"
    L.append(f"// func {fn}(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)")
    L.append(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    L += ["\tMOVD fixedKey+0(FP), R0", "\tMOVD comps+8(FP), R1", "\tMOVD nGroups+16(FP), R2",
          "\tMOVD data+24(FP), R3", "\tMOVD out+32(FP), R4", f"\tMOVD $frame-{frame.aligned}(SP), R7", ""]
    for k in sorted(d_off):
        off, d0, size = d_off[k]
        if size == 0:
            L.append(f"\tMOVW ZR, {off}(R7)")
        else:
            L += load_word_arm64("R3", d0, size, "R5") + [f"\tMOVW R5, {off}(R7)"]
    for (b, w), (off, d0, size) in sorted(t_off.items()):
        L += load_word_arm64("R3", d0, size, "R5") + [f"\tMOVW R5, {off}(R7)"]

    def load_words(b, with_key):
        out = []
        for w, e in enumerate(blocks[b]["words"]):
            if e[0] == "key":
                if with_key:
                    out += [f"\tMOVWU {4 * e[1]}(R0), R5", f"\tMOVW R5, {m_off[w]}(R7)"]
            elif e[0] == "data":
                out += [f"\tMOVWU {t_off[(b, w)][0]}(R7), R5", f"\tMOVW R5, {m_off[w]}(R7)"]
            elif e[0] == "zero":
                out.append(f"\tMOVW ZR, {m_off[w]}(R7)")
        return out

    L += load_words(0, True)
    L += [f"\tMOVW $0, {R[i]}" for i in range(8)]
    L += ["", "loop:"]
    for w, e in seed_words(blocks[0]):
        k = e[1]
        L += [f"\tMOVWU {d_off[k][0]}(R7), R5", f"\tMOVWU {4 * k}(R1), R6", "\tEORW R6, R5, R5",
              f"\tEORW {R[k]}, R5, R5", f"\tMOVW R5, {m_off[w]}(R7)"]
    L.append("\tADD $32, R1, R1")
    if nb > 1:
        L += load_words(0, True)
    for b, block in enumerate(blocks):
        L.append("")
        if b > 0:
            L += [f"\tMOVW {R[i]}, {h_off[i]}(R7)" for i in range(8)]
            L += load_words(b, False)
        L.append(f"\tMOVD $tab{b}<>(SB), R25")
        for k in range(0 if b == 0 else 8, 16):
            L.append(f"\tMOVWU {4 * k}(R25), {R[k]}")
        L.append("")
        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                mx, my = m_off[sigma[2 * gi]], m_off[sigma[2 * gi + 1]]
                va, vb, vc, vd = R[a], R[bb], R[c], R[d]
                L += [f"\tMOVWU {mx}(R7), R5", f"\tMOVWU {my}(R7), R6",
                      f"\tADDW {vb}, {va}, {va}", f"\tADDW R5, {va}, {va}", f"\tEORW {va}, {vd}, {vd}", f"\tRORW $16, {vd}, {vd}",
                      f"\tADDW {vd}, {vc}, {vc}", f"\tEORW {vc}, {vb}, {vb}", f"\tRORW $12, {vb}, {vb}",
                      f"\tADDW {vb}, {va}, {va}", f"\tADDW R6, {va}, {va}", f"\tEORW {va}, {vd}, {vd}", f"\tRORW $8, {vd}, {vd}",
                      f"\tADDW {vd}, {vc}, {vc}", f"\tEORW {vc}, {vb}, {vb}", f"\tRORW $7, {vb}, {vb}"]
        L.append("")
        last = b == nb - 1
        for i in range(8):
            L.append(f"\tEORW {R[8 + i]}, {R[i]}, {R[i]}")
            if nb > 1 and last:
                L.append(f"\tMOVWU {h_off[i]}(R7), R5")
            else:
                L.append(f"\tMOVWU {4 * i}(R25), R5")
            L.append(f"\tEORW R5, {R[i]}, {R[i]}")
    L += ["", "\tSUB $1, R2, R2", "\tCBNZ R2, loop", ""]
    L += [f"\tMOVW {R[i]}, {4 * i}(R4)" for i in range(WORDS)]
    L += ["\tRET", ""]
    L += tables(blocks)
    return "\n".join(L)


# ------------------------------------------------------------- driver --

def render_all():
    files = {}
    for n in SHAPES:
        files[f"blake2s_fusedchain256_{n}x4_avx512_amd64.s"] = evex_kernel(n) + "\n"
        files[f"blake2s_fusedchain256_{n}x4_avx2_amd64.s"] = avx2_kernel(n) + "\n"
        files[f"blake2s_fusedchain256_{n}x4_neon_arm64.s"] = neon_kernel(n) + "\n"
        files[f"blake2s_fusedchain256_{n}x1_gpr_amd64.s"] = gpr_kernel_amd64(n)
        files[f"blake2s_fusedchain256_{n}x1_gpr_arm64.s"] = gpr_kernel_arm64(n)
    for n in (20, 36, 68):
        files[f"blake2s_fusedchain256_{n}x8_avx512_amd64.s"] = evex_kernel(n, x8=True) + "\n"
    files["blake2s_fusedchain256_13x8_avx512_amd64.s"] = evex_kernel(13, x8=True, fill=True) + "\n"
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
