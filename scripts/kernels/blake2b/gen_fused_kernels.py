#!/usr/bin/env python3
"""Emit the BLAKE2b fused ChainHash cascade kernels for hashes/internal/blake2basm.

One file per (width, shape, lanes, tier). Widths 256 (BLAKE2b-256: 32-byte
fixed key, four component words per cascade group, 32-byte output) and 512
(BLAKE2b-512: 64-byte key, eight words per group, 64-byte output); shapes
13 / 20 / 36 / 68; lanes x4 (four data lanes over one shared component
slice) and x1 (the single-lane general-purpose-register kernel of every
tier); amd64 tiers avx512 (EVEX YMM, one qword lane per pixel, VPRORQ
rotates, VPTERNLOGQ folds) and avx2 (VEX YMM, synthesised rotates, the
message words as memory operands); arm64 tier neon (two lanes per pass,
two passes).

The avx512 tier additionally carries the eight-lane ZMM kernels — the
same instruction stream as the four-lane EVEX kernel over twice the
lanes, one qword lane per pixel: the per-pixel kernels
blake2b_fusedchain{256,512}_{20,36,68}x8_avx512_amd64.s (eight lane
pointers, staged four at a time) and the Interlocked Barrier fill
kernels blake2b_fusedchain256_13x8_avx512_amd64.s (the batch-16 hook of
width 256) and blake2b_fusedchain512_13x8_avx512_amd64.s (the batch-32
hook of width 512), with the eight 13-byte fill blocks
[0x03 | LE64(groupIdxBase+i) | 4×0x00] synthesised in-register from
groupIdxBase as the two data words (idx << 8) | 0x03 and idx >> 56. The
avx2 and neon tiers run every fill hook as four-lane kernel calls over
Go-synthesised blocks, and the width-512 batch-16 hook runs that way on
every tier. The single-lane entry points of every tier run the
general-purpose-register kernels
blake2b_fusedchain{256,512}_{13,20,36,68}x1_gpr_{amd64,arm64}.s: the
compression state in general-purpose registers, the message words as
frame slots, the rotates as RORQ / ROR.

Cells that are not emitted, with the reason:
    13x16 avx512 (both widths)  16 v × 2 ZMM per word at sixteen lanes = 32
                                = 32 with the message words as memory
                                operands and no scratch; the port-bound
                                outcome of the same layout on Areion-256
                                (0.93x / 0.99x / 0.99x of two eight-lane
                                calls on an i7-11700K) makes a wider
                                BLAKE2b fill kernel a no-gain cell → not
                                emitted
    x8 avx2 (both widths)       16 v × 2 YMM per word at eight lanes = 32
                                > 16 → spill; the four-lane kernel stays
                                the top of the avx2 tier
    x8 neon (both widths)       16 v × 4 V per word at eight lanes = 64 >
                                32 → spill; the four-lane kernel stays the
                                top of the neon tier

Cascade evaluated per lane (see blake2basm_fused.go):
    h = 0
    for each component group g (4 words at width 256, 8 at 512):
        seed = g ^ h
        h = BLAKE2b-W(key ‖ (data ⊕ seed))
    out = h
which is Seed{256,512}.ChainHash over the parent package's BLAKE2b
prefix-MAC closure: the fixed key, then data zero-padded to at least the
seed-injection width (32 / 64 bytes) with the seed words XORed over the
bytes after the key, hashed by BLAKE2b with the digest-length parameter
of the width. Every (width, shape) cell is one BLAKE2b compression
except width 512 at the 68-byte shape, whose 132-byte input spans two
blocks (t = 128 then t = 132, final). The message words are the key
words (broadcast from the key pointer), the seed-injected words and the
data-only words; the data words are staged once per call from the lane
pointers into the frame (data[0:8] as two 4-byte loads, matching the
caller's 4-byte pixel-index store so store-to-load forwarding succeeds),
and each cascade round rebuilds the seed-injected words as
D ⊕ component ⊕ h from the staged data word, the component broadcast and
the previous round's output — one VPTERNLOGQ per word on the EVEX tier.
The compression state is re-initialised each round from a per-kernel
table holding IV, the parameter block, t and the final flag.

Register plans:
    avx512 x4   Y0..Y15 the compression state v[0..15], Y16..Y31 the
                message words m[0..15]; the fold h = h0 ⊕ v ⊕ v' and the
                seed-word rebuild are VPTERNLOGQ with embedded-broadcast
                memory operands, so no scratch register is needed
    avx512 x8   the same plan on ZMM registers (eight lanes): Z0..Z15 the
                state, Z16..Z31 the message words, 32 of 32 with the
                seed-word rebuild and the fold as VPTERNLOGQ
                embedded-broadcast memory operands; the shape-68 kernels
                (576- / 1088-byte frames) carry the stack check
    avx2 x4     Y0..Y14 v[0..14], Y15 the ror63 temp, v[15] in a frame
                slot with v[12] spilled around the two G functions that
                touch v[15]; the message words are frame slots read as
                memory operands; ror32 = VPSHUFD, ror24 / ror16 = VPSHUFB
                with byte masks, ror63 = shift-or; the frame exceeds the
                NOSPLIT budget, so these kernels carry the stack check
    neon x4     V0..V15 v[0..15], one pass body looped over the lane
                pairs (0,1) and (2,3) (R19 / R20 the per-pass slot and
                output bases, R21 the pass counter); the message words in
                the frame, loaded pairwise into V16/V17; V18 the
                rotate alternate (VSHL + VSRI, the rotate by 32 as VREV64
                on 32-bit elements) — the rotated word lands in the
                alternate register and the register roles swap; the
                state-init tables are read-only data (R6 the table base)
    gpr amd64   v[0..15] in AX, BX, CX, DX, SI, DI, BP, R8..R11, R12..R15
                with v[11] — a c word, whose two G steps read or update
                it through one memory operand each — in a frame slot
                (15 of 15 usable registers); the message words, the
                group counter, the component / key / output pointers in
                the frame; the fold's h0 constants pass through the just-
                folded v[8+i] register; R9 / R10 / R11 / R12 are the
                loop-top temps while only h = v[0..7] is live
    gpr arm64   v[0..15] in R8..R17, R19..R24; R0 key, R1 components, R2
                group counter, R4 output, R7 frame base, R5 / R6 the
                message-word loads of every G, R25 the state-init table
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "hashes", "internal", "blake2basm")
SHAPES = [13, 20, 36, 68]
AMD = "amd64 && !purego && !noitbasm"
ARM = "arm64 && !purego && !noitbasm"

IV = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]
PARAM = {256: 0x01010020, 512: 0x01010040}  # digest length, fanout 1, depth 1
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
ROUNDS = SIGMA + SIGMA[:2]
# G function order of one round: four columns, then four diagonals.
G_ORDER = [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]
MASK64 = (1 << 64) - 1


# ------------------------------------------------------------- layout --

def layout(width, n):
    """Blocks of the (width, shape) cell. Each block is a dict with the 16
    message words — ('key', k), ('seed', i, d0, size), ('data', d0, size)
    or ('zero',) — the counter t and the final flag."""
    key = width // 8
    inject = key
    total = key + max(n, inject)
    nblocks = (total + 127) // 128
    blocks = []
    for b in range(nblocks):
        words = []
        for w in range(16):
            off = 128 * b + 8 * w
            if off >= total:
                words.append(("zero",))
            elif off < key:
                words.append(("key", off // 8))
            else:
                d0 = off - key
                size = max(0, min(d0 + 8, n) - d0)
                if d0 < inject:
                    words.append(("seed", d0 // 8, d0, size))
                elif size > 0:
                    words.append(("data", d0, size))
                else:
                    words.append(("zero",))
        blocks.append({"words": words, "t": min(total, 128 * (b + 1)), "final": b == nblocks - 1})
    return blocks


def init_table(width, block):
    """The 16 state words a compression of this block starts from: h0 (IV
    with the parameter block folded into h0[0]) and IV with t and the
    final flag folded in."""
    v = list(IV) + list(IV)
    v[0] ^= PARAM[width]
    v[12] ^= block["t"]
    if block["final"]:
        v[14] ^= MASK64
    return v


def seed_words(block):
    return [(w, e) for w, e in enumerate(block["words"]) if e[0] == "seed"]


def data_words(block):
    return [(w, e) for w, e in enumerate(block["words"]) if e[0] == "data"]


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

def load_word_amd64(r, d0, size, dst="R12", scratch="R13"):
    """Load the data bytes [d0, d0+size) of the lane at pointer r into dst,
    zero-extended. data[0:8] goes as two 4-byte loads."""
    if size == 8 and d0 == 0:
        return [f"\tMOVL 0({r}), {dst}", f"\tMOVL 4({r}), {scratch}", f"\tSHLQ $32, {scratch}", f"\tORQ {scratch}, {dst}"]
    if size == 8:
        return [f"\tMOVQ {d0}({r}), {dst}"]
    if size == 5:
        return [f"\tMOVL {d0}({r}), {dst}", f"\tMOVBLZX {d0 + 4}({r}), {scratch}", f"\tSHLQ $32, {scratch}",
                f"\tORQ {scratch}, {dst}"]
    if size == 4:
        return [f"\tMOVL {d0}({r}), {dst}"]
    raise ValueError(size)


LANE_REGS = ["R8", "R9", "R10", "R11"]


def stage_amd64(blocks, frame, lane_bytes=32):
    """Stage the per-lane data words of every block into the frame (one
    slot of 8 bytes per lane per word): the D slots of the seed words
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
                    lines.append(f"\tMOVQ $0, {base + 8 * l}(SP)")
                else:
                    lines += load_word_amd64(r, d0, size)
                    lines.append(f"\tMOVQ R12, {base + 8 * l}(SP)")
    return lines


def stage_amd64_x8(blocks, frame):
    """Stage the per-lane data words of eight lanes (64-byte slots):
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
        frame.alloc(key, 64)
    for g in range(2):
        lines.append("\tMOVQ dataPtrs+24(FP), DX")
        for i, r in enumerate(LANE_REGS):
            lines.append(f"\tMOVQ {8 * (4 * g + i)}(DX), {r}")
        for key, d0, size in keys:
            base = frame.slots[key]
            for l, r in enumerate(LANE_REGS):
                o = base + 8 * (4 * g + l)
                if size == 0:
                    lines.append(f"\tMOVQ $0, {o}(SP)")
                else:
                    lines += load_word_amd64(r, d0, size)
                    lines.append(f"\tMOVQ R12, {o}(SP)")
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


def header(build, width, n, lanes, tier_desc, fill=False):
    nb = len(layout(width, n))
    what = "fused ChainHash cascade kernel"
    if fill:
        what = f"batch-{16 if width == 256 else 32} Interlocked Barrier fill kernel"
    return f"""//go:build {build}

// {tier_desc} {what} for BLAKE2b-{width} at the
// {n}-byte shape, {lanes} lanes ({nb} compression{'s' if nb > 1 else ''} per cascade round). The data
// words are staged once per call and the seed-injected words rebuilt
// each round; see blake2basm_fused.go for the construction and the
// in-package parity tests for the bit-exact pin against the pure-Go
// cascade.

#include "textflag.h"
"""


def tables(width, blocks, x8=False):
    lines = []
    for b, block in enumerate(blocks):
        v = init_table(width, block)
        for k in range(16):
            lines.append(f"DATA tab{b}<>+{8 * k}(SB)/8, $0x{v[k]:016x}")
        lines.append(f"GLOBL tab{b}<>(SB), RODATA|NOPTR, $128")
        lines.append("")
    if x8:
        for i in range(8):
            lines.append(f"DATA laneIdx<>+{8 * i}(SB)/8, $0x{i:016x}")
        lines.append("GLOBL laneIdx<>(SB), RODATA|NOPTR, $64")
        lines.append("")
    return lines


# ------------------------------------------------------- EVEX family --

def evex_macros(p):
    """The G function and the round on the register prefix p (Y or Z)."""
    g = "\n".join([
        "#define BLAKE2B_G(a, b, c, d, mx, my) \\",
        "\tVPADDQ b, a, a; \\",
        "\tVPADDQ mx, a, a; \\",
        "\tVPXORQ a, d, d; \\",
        "\tVPRORQ $32, d, d; \\",
        "\tVPADDQ d, c, c; \\",
        "\tVPXORQ c, b, b; \\",
        "\tVPRORQ $24, b, b; \\",
        "\tVPADDQ b, a, a; \\",
        "\tVPADDQ my, a, a; \\",
        "\tVPXORQ a, d, d; \\",
        "\tVPRORQ $16, d, d; \\",
        "\tVPADDQ d, c, c; \\",
        "\tVPXORQ c, b, b; \\",
        "\tVPRORQ $63, b, b",
    ])
    rows = []
    for gi, (a, b, c, d) in enumerate(G_ORDER):
        rows.append(f"\tBLAKE2B_G({p}{a}, {p}{b}, {p}{c}, {p}{d}, s{2 * gi}, s{2 * gi + 1})")
    r = "#define BLAKE2B_ROUND(" + ", ".join(f"s{i}" for i in range(16)) + ") \\\n" + "; \\\n".join(rows)
    return g + "\n\n" + r + "\n"


def evex_rounds(p):
    return [f"\tBLAKE2B_ROUND({', '.join(f'{p}{16 + s}' for s in sigma)})" for sigma in ROUNDS]


def evex_kernel(width, n, x8=False, fill=False):
    """The avx512 x4 (YMM) kernel, the x8 (ZMM) per-pixel kernel, or the
    x8 (ZMM) fill kernel at shape 13 (fill implies x8)."""
    p = "Z" if x8 else "Y"
    lanes = 8 if x8 else 4
    lane_bytes = 8 * lanes
    words = width // 64
    blocks = layout(width, n)
    nb = len(blocks)
    frame = Frame()
    build = []
    if fill:
        # Synthesised fill blocks: D0 = (idx << 8) | 0x03, D1 = idx >> 56,
        # the remaining seed-injected words zero.
        d = [frame.alloc(("D", i), lane_bytes) for i in range(words)]
        build += [
            "\tVPBROADCASTQ groupIdxBase+24(FP), Z0",
            "\tVPADDQ laneIdx<>(SB), Z0, Z0",
            "\tVPSLLQ $8, Z0, Z1",
            "\tMOVQ $3, R12",
            "\tVPBROADCASTQ R12, Z2",
            "\tVPORQ Z2, Z1, Z1",
            f"\tVMOVDQU64 Z1, {d[0]}(SP)",
            "\tVPSRLQ $56, Z0, Z1",
            f"\tVMOVDQU64 Z1, {d[1]}(SP)",
            "\tVPXORQ Z2, Z2, Z2",
        ]
        build += [f"\tVMOVDQU64 Z2, {d[i]}(SP)" for i in range(2, words)]
    elif x8:
        build += stage_amd64_x8(blocks, frame)
    else:
        build += stage_amd64(blocks, frame, lane_bytes)
    if nb > 1:
        for i in range(8):
            frame.alloc(("H", i), lane_bytes)
    mov = "VMOVDQU64"

    def m(w):
        return f"{p}{16 + w}"

    def load_words(b, with_key):
        """Set the round-invariant message registers of block b."""
        out = []
        for w, e in enumerate(blocks[b]["words"]):
            if e[0] == "key":
                if with_key:
                    out.append(f"\tVPBROADCASTQ {8 * e[1]}(AX), {m(w)}")
            elif e[0] == "data":
                out.append(f"\t{mov} {frame.slots[('T', b, w)]}(SP), {m(w)}")
            elif e[0] == "zero":
                out.append(f"\tVPXORQ {m(w)}, {m(w)}, {m(w)}")
        return out

    lines = []
    lines.append(header(AMD, width, n, lanes, "AVX-512 " + ("ZMM (eight lanes)" if x8 else "YMM (four lanes)"), fill=fill))
    lines.append(evex_macros(p))
    if fill:
        kind = f"groupIdxBase uint64, out *[8][{words}]uint64"
    else:
        kind = f"dataPtrs *[{lanes}]*byte, out *[{lanes}][{words}]uint64"
    fn = f"blake2b{width}FusedChain{n}x{lanes}Avx512Asm"
    lines.append(f"// func {fn}(fixedKey *[{width // 8}]byte, comps *uint64, nGroups int, {kind})")
    lines.append(f"TEXT ·{fn}(SB), {text_flags(frame)}${frame.aligned}-40")
    lines += prologue_amd64(x8)
    lines.append("")
    lines += build
    lines.append("")
    if nb == 1:
        lines += load_words(0, True)
    for i in range(words):
        lines.append(f"\tVPXORQ {p}{i}, {p}{i}, {p}{i}")
    lines.append("")
    lines.append("loop:")
    # Seed-injected words of block 0: D ⊕ component ⊕ h.
    for w, e in seed_words(blocks[0]):
        i = e[1]
        lines.append(f"\t{mov} {frame.slots[('D', i)]}(SP), {m(w)}")
        lines.append(f"\tVPTERNLOGQ.BCST $0x96, {8 * i}(BX), {p}{i}, {m(w)}")
    if nb > 1:
        lines += load_words(0, True)
    for b, block in enumerate(blocks):
        lines.append("")
        if b > 0:
            for i in range(8):
                lines.append(f"\t{mov} {p}{i}, {frame.slots[('H', i)]}(SP)")
            lines += load_words(b, False)
        for k in range(0 if b == 0 else 8, 16):
            lines.append(f"\tVPBROADCASTQ tab{b}<>+{8 * k}(SB), {p}{k}")
        lines.append("")
        lines += evex_rounds(p)
        lines.append("")
        last = b == nb - 1
        nf = words if last else 8
        for i in range(nf):
            if nb > 1 and last:
                lines.append(f"\tVPTERNLOGQ $0x96, {frame.slots[('H', i)]}(SP), {p}{8 + i}, {p}{i}")
            else:
                lines.append(f"\tVPTERNLOGQ.BCST $0x96, tab{b}<>+{8 * i}(SB), {p}{8 + i}, {p}{i}")
    lines.append("")
    lines.append(f"\tADDQ ${8 * words}, BX")
    lines.append("\tDECQ CX")
    lines.append("\tJNZ loop")
    lines.append("")
    stride = 8 * words
    for i in range(words):
        for q in range(lanes // 2):
            lines.append(f"\tVEXTRACTI64X2 ${q}, {p}{i}, X16")
            lines.append(f"\tVPEXTRQ $0, X16, {stride * (2 * q) + 8 * i}(DX)")
            lines.append(f"\tVPEXTRQ $1, X16, {stride * (2 * q + 1) + 8 * i}(DX)")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += tables(width, blocks, fill)
    return "\n".join(lines)


# -------------------------------------------------------- AVX2 family --

AVX2_MACROS = """#define ROR63(b, t) \\
\tVPSRLQ $63, b, t; \\
\tVPADDQ b, b, b; \\
\tVPOR t, b, b

#define GA(a, b, c, d, mx, my, t) \\
\tVPADDQ b, a, a; \\
\tVPADDQ mx(SP), a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFD $0xB1, d, d; \\
\tVPADDQ d, c, c; \\
\tVPXOR c, b, b; \\
\tVPSHUFB ror24<>(SB), b, b; \\
\tVPADDQ b, a, a; \\
\tVPADDQ my(SP), a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFB ror16<>(SB), d, d; \\
\tVPADDQ d, c, c; \\
\tVPXOR c, b, b; \\
\tROR63(b, t)

#define M(i)   (i*32)
#define V15    512
#define V12    544

#define ROUND(s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15) \\
\tGA(Y0, Y4, Y8,  Y12, M(s0),  M(s1),  Y15); \\
\tGA(Y1, Y5, Y9,  Y13, M(s2),  M(s3),  Y15); \\
\tGA(Y2, Y6, Y10, Y14, M(s4),  M(s5),  Y15); \\
\tVMOVDQU Y12, V12(SP); \\
\tVMOVDQU V15(SP), Y15; \\
\tGA(Y3, Y7, Y11, Y15, M(s6),  M(s7),  Y12); \\
\tGA(Y0, Y5, Y10, Y15, M(s8),  M(s9),  Y12); \\
\tVMOVDQU Y15, V15(SP); \\
\tVMOVDQU V12(SP), Y12; \\
\tGA(Y1, Y6, Y11, Y12, M(s10), M(s11), Y15); \\
\tGA(Y2, Y7, Y8,  Y13, M(s12), M(s13), Y15); \\
\tGA(Y3, Y4, Y9,  Y14, M(s14), M(s15), Y15)
"""

AVX2_TABLES = """DATA ror24<>+0(SB)/8,  $0x0201000706050403
DATA ror24<>+8(SB)/8,  $0x0a09080f0e0d0c0b
DATA ror24<>+16(SB)/8, $0x0201000706050403
DATA ror24<>+24(SB)/8, $0x0a09080f0e0d0c0b
GLOBL ror24<>(SB), RODATA|NOPTR, $32

DATA ror16<>+0(SB)/8,  $0x0100070605040302
DATA ror16<>+8(SB)/8,  $0x09080f0e0d0c0b0a
DATA ror16<>+16(SB)/8, $0x0100070605040302
DATA ror16<>+24(SB)/8, $0x09080f0e0d0c0b0a
GLOBL ror16<>(SB), RODATA|NOPTR, $32
"""


def avx2_rounds():
    return [f"\tROUND({','.join(str(s) for s in sigma)})" for sigma in ROUNDS]


def avx2_kernel(width, n):
    words = width // 64
    blocks = layout(width, n)
    nb = len(blocks)
    frame = Frame(576)  # M(0..15), V15, V12
    build = stage_amd64(blocks, frame, 32)
    if nb > 1:
        for i in range(8):
            frame.alloc(("H", i), 32)

    def slot(w):
        return f"M({w})"

    def load_words(b, with_key):
        out = []
        for w, e in enumerate(blocks[b]["words"]):
            if e[0] == "key":
                if with_key:
                    out.append(f"\tVPBROADCASTQ {8 * e[1]}(AX), Y15")
                    out.append(f"\tVMOVDQU Y15, {slot(w)}(SP)")
            elif e[0] == "data":
                out.append(f"\tVMOVDQU {frame.slots[('T', b, w)]}(SP), Y15")
                out.append(f"\tVMOVDQU Y15, {slot(w)}(SP)")
            elif e[0] == "zero":
                out.append("\tVPXOR Y15, Y15, Y15")
                out.append(f"\tVMOVDQU Y15, {slot(w)}(SP)")
        return out

    tmp2 = f"Y{words}"  # free between the fold and the state init
    lines = []
    lines.append(header(AMD, width, n, 4, "AVX2 YMM (four lanes)"))
    lines.append(AVX2_MACROS)
    fn = f"blake2b{width}FusedChain{n}x4Avx2Asm"
    lines.append(f"// func {fn}(fixedKey *[{width // 8}]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][{words}]uint64)")
    # The frame (sixteen 32-byte word slots, the v[15] / v[12] slots, the
    # staged data words and, for the two-block cell, the saved h) exceeds
    # the NOSPLIT budget, so the kernel carries the stack check.
    lines.append(f"TEXT ·{fn}(SB), ${frame.aligned}-40")
    lines += prologue_amd64(False)
    lines.append("")
    lines += build
    lines.append("")
    if nb == 1:
        lines += load_words(0, True)
    for i in range(words):
        lines.append(f"\tVPXOR Y{i}, Y{i}, Y{i}")
    lines.append("")
    lines.append("loop:")
    for w, e in seed_words(blocks[0]):
        i = e[1]
        lines.append(f"\tVMOVDQU {frame.slots[('D', i)]}(SP), Y15")
        lines.append(f"\tVPXOR Y{i}, Y15, Y15")
        lines.append(f"\tVPBROADCASTQ {8 * i}(BX), {tmp2}")
        lines.append(f"\tVPXOR {tmp2}, Y15, Y15")
        lines.append(f"\tVMOVDQU Y15, {slot(w)}(SP)")
    if nb > 1:
        lines += load_words(0, True)
    for b, block in enumerate(blocks):
        lines.append("")
        if b > 0:
            for i in range(8):
                lines.append(f"\tVMOVDQU Y{i}, {frame.slots[('H', i)]}(SP)")
            lines += load_words(b, False)
        for k in range(0 if b == 0 else 8, 15):
            lines.append(f"\tVPBROADCASTQ tab{b}<>+{8 * k}(SB), Y{k}")
        lines.append(f"\tVPBROADCASTQ tab{b}<>+120(SB), Y15")
        lines.append("\tVMOVDQU Y15, V15(SP)")
        lines.append("")
        lines += avx2_rounds()
        lines.append("")
        last = b == nb - 1
        nf = words if last else 8
        for i in range(nf):
            if i == 7:
                lines.append("\tVPXOR V15(SP), Y7, Y7")
            else:
                lines.append(f"\tVPXOR Y{8 + i}, Y{i}, Y{i}")
            if nb > 1 and last:
                lines.append(f"\tVPXOR {frame.slots[('H', i)]}(SP), Y{i}, Y{i}")
            else:
                lines.append(f"\tVPBROADCASTQ tab{b}<>+{8 * i}(SB), Y15")
                lines.append(f"\tVPXOR Y15, Y{i}, Y{i}")
    lines.append("")
    lines.append(f"\tADDQ ${8 * words}, BX")
    lines.append("\tDECQ CX")
    lines.append("\tJNZ loop")
    lines.append("")
    stride = 8 * words
    for i in range(words):
        for q in range(2):
            lines.append(f"\tVEXTRACTI128 ${q}, Y{i}, X15")
            lines.append(f"\tVPEXTRQ $0, X15, {stride * (2 * q) + 8 * i}(DX)")
            lines.append(f"\tVPEXTRQ $1, X15, {stride * (2 * q + 1) + 8 * i}(DX)")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += tables(width, blocks)
    lines.append(AVX2_TABLES)
    return "\n".join(lines)


# -------------------------------------------------------- NEON family --

ARM_LANE_REGS = ["R8", "R9", "R10", "R11"]


def load_word_arm64(r, d0, size, dst="R12", scratch="R13"):
    if size == 8 and d0 == 0:
        return [f"\tMOVWU 0({r}), {dst}", f"\tMOVWU 4({r}), {scratch}", f"\tORR {scratch}<<32, {dst}, {dst}"]
    if size == 8:
        return [f"\tMOVD {d0}({r}), {dst}"]
    if size == 5:
        return [f"\tMOVWU {d0}({r}), {dst}", f"\tMOVBU {d0 + 4}({r}), {scratch}", f"\tORR {scratch}<<32, {dst}, {dst}"]
    if size == 4:
        return [f"\tMOVWU {d0}({r}), {dst}"]
    raise ValueError(size)


def stage_arm64(blocks, frame, base="R7"):
    """Stage the per-lane data words as in stage_amd64 (four lanes, 8 bytes
    each, so one 32-byte slot per word) through the frame base register."""
    lines = []
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                key, d0, size = ("D", e[1]), e[2], e[3]
            elif e[0] == "data":
                key, d0, size = ("T", b, w), e[1], e[2]
            else:
                continue
            off = frame.alloc(key, 32)
            for l, r in enumerate(ARM_LANE_REGS):
                if size == 0:
                    lines.append(f"\tMOVD ZR, {off + 8 * l}({base})")
                else:
                    lines += load_word_arm64(r, d0, size)
                    lines.append(f"\tMOVD R12, {off + 8 * l}({base})")
    return lines


class NeonRegs:
    """Tracks which physical register holds each state word; a rotate
    writes into the alternate register and swaps the roles."""

    def __init__(self):
        self.v = [f"V{i}" for i in range(16)]
        self.alt = "V18"

    def rot(self, idx, amount):
        src, dst = self.v[idx], self.alt
        if amount == 32:
            return [f"\tVREV64 {src}.S4, {src}.S4"]
        out = [f"\tVSHL ${64 - amount}, {src}.D2, {dst}.D2", f"\tVSRI ${amount}, {src}.D2, {dst}.D2"]
        self.v[idx], self.alt = dst, src
        return out


def neon_g(regs, a, b, c, d, mx, my):
    """One G function; mx / my are the frame offsets of the two message words
    of the current half (loaded into V16 / V17)."""
    out = [f"\tFMOVQ {mx}(R7), F16", f"\tFMOVQ {my}(R7), F17"]
    v = regs.v
    out.append(f"\tVADD {v[b]}.D2, {v[a]}.D2, {v[a]}.D2")
    out.append(f"\tVADD V16.D2, {v[a]}.D2, {v[a]}.D2")
    out.append(f"\tVEOR {v[a]}.B16, {v[d]}.B16, {v[d]}.B16")
    out += regs.rot(d, 32)
    v = regs.v
    out.append(f"\tVADD {v[d]}.D2, {v[c]}.D2, {v[c]}.D2")
    out.append(f"\tVEOR {v[c]}.B16, {v[b]}.B16, {v[b]}.B16")
    out += regs.rot(b, 24)
    v = regs.v
    out.append(f"\tVADD {v[b]}.D2, {v[a]}.D2, {v[a]}.D2")
    out.append(f"\tVADD V17.D2, {v[a]}.D2, {v[a]}.D2")
    out.append(f"\tVEOR {v[a]}.B16, {v[d]}.B16, {v[d]}.B16")
    out += regs.rot(d, 16)
    v = regs.v
    out.append(f"\tVADD {v[d]}.D2, {v[c]}.D2, {v[c]}.D2")
    out.append(f"\tVEOR {v[c]}.B16, {v[b]}.B16, {v[b]}.B16")
    out += regs.rot(b, 63)
    return out


def neon_kernel(width, n):
    """NEON x4 kernel: two lanes per pass (one qword lane per 128-bit
    register), one pass body looped over the lane pairs (0,1) and (2,3)
    with R19 walking the per-pair halves of the staged slots and R20 the
    output rows. The message words of the current pass are frame slots;
    the state lives in V0..V15 with V18 as the rotate alternate and
    V16 / V17 the word loads."""
    words = width // 64
    blocks = layout(width, n)
    nb = len(blocks)
    frame = Frame()
    m_off = [frame.alloc(("M", w), 16) for w in range(16)]
    build = stage_arm64(blocks, frame)
    h_off = [frame.alloc(("H", i), 16) for i in range(8)] if nb > 1 else []
    out_lines = []

    def emit(s):
        out_lines.append(s)

    emit(header(ARM, width, n, 4, "NEON (two lanes per pass, two passes)"))
    fn = f"blake2b{width}FusedChain{n}x4NeonAsm"
    emit(f"// func {fn}(fixedKey *[{width // 8}]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][{words}]uint64)")
    emit(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    emit("\tMOVD fixedKey+0(FP), R0")
    emit("\tMOVD comps+8(FP), R1")
    emit("\tMOVD nGroups+16(FP), R2")
    emit("\tMOVD dataPtrs+24(FP), R3")
    for i, r in enumerate(ARM_LANE_REGS):
        emit(f"\tMOVD {8 * i}(R3), {r}")
    emit("\tMOVD out+32(FP), R3")
    emit(f"\tMOVD $frame-{frame.aligned}(SP), R7")
    emit("")
    for l in build:
        emit(l)
    emit("")
    # Two passes over the lane pairs (0,1) and (2,3): R19 walks the
    # per-pair 16-byte half of every staged slot, R20 the output rows.
    emit("\tMOVD R7, R19")
    emit("\tMOVD R3, R20")
    emit("\tMOVD $2, R21")
    emit("")
    emit("pass:")
    emit("\tMOVD R1, R4")  # component pointer of this pass
    emit("\tMOVD R2, R5")  # group counter
    # Round-invariant words of block 0.
    for w, e in enumerate(blocks[0]["words"]):
        if e[0] == "key":
            emit(f"\tMOVD {8 * e[1]}(R0), R12")
            emit(f"\tMOVD R12, {m_off[w]}(R7)")
            emit(f"\tMOVD R12, {m_off[w] + 8}(R7)")
        elif e[0] == "data":
            emit(f"\tFMOVQ {frame.slots[('T', 0, w)]}(R19), F16")
            emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
        elif e[0] == "zero":
            emit(f"\tMOVD ZR, {m_off[w]}(R7)")
            emit(f"\tMOVD ZR, {m_off[w] + 8}(R7)")
    for i in range(words):
        emit(f"\tVEOR V{i}.B16, V{i}.B16, V{i}.B16")
    emit("")
    emit("loop:")
    # Seed-injected words: D ⊕ component ⊕ h (h in V0..V{words-1}).
    for w, e in seed_words(blocks[0]):
        i = e[1]
        emit(f"\tFMOVQ {frame.slots[('D', i)]}(R19), F16")
        emit(f"\tMOVD {8 * i}(R4), R12")
        emit("\tVDUP R12, V17.D2")
        emit("\tVEOR V16.B16, V17.B16, V16.B16")
        emit(f"\tVEOR V{i}.B16, V16.B16, V16.B16")
        emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
    if nb > 1:
        for w, e in enumerate(blocks[0]["words"]):
            if e[0] == "key":
                emit(f"\tMOVD {8 * e[1]}(R0), R12")
                emit(f"\tMOVD R12, {m_off[w]}(R7)")
                emit(f"\tMOVD R12, {m_off[w] + 8}(R7)")
    for b, block in enumerate(blocks):
        regs = NeonRegs()
        emit("")
        if b > 0:
            for i in range(8):
                emit(f"\tFMOVQ F{i}, {h_off[i]}(R7)")
            for w, e in enumerate(block["words"]):
                if e[0] == "data":
                    emit(f"\tFMOVQ {frame.slots[('T', b, w)]}(R19), F16")
                    emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
                elif e[0] == "zero":
                    emit(f"\tMOVD ZR, {m_off[w]}(R7)")
                    emit(f"\tMOVD ZR, {m_off[w] + 8}(R7)")
        emit(f"\tMOVD $tab{b}<>(SB), R6")
        for k in range(0 if b == 0 else 8, 16):
            emit(f"\tMOVD {8 * k}(R6), R12")
            emit(f"\tVDUP R12, V{k}.D2")
        emit("")
        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                for l in neon_g(regs, a, bb, c, d, m_off[sigma[2 * gi]], m_off[sigma[2 * gi + 1]]):
                    emit(l)
        emit("")
        last = b == nb - 1
        nf = words if last else 8
        v = regs.v
        # Fold into V0..V7 physical registers: h_i = h0_i ⊕ v_i ⊕ v_{i+8}.
        for i in range(nf):
            emit(f"\tVEOR {v[8 + i]}.B16, {v[i]}.B16, {v[i]}.B16")
            if nb > 1 and last:
                emit(f"\tFMOVQ {h_off[i]}(R7), F16")
            else:
                emit(f"\tMOVD {8 * i}(R6), R12")
                emit("\tVDUP R12, V16.D2")
            emit(f"\tVEOR V16.B16, {v[i]}.B16, {v[i]}.B16")
            if v[i] != f"V{i}":
                emit(f"\tVMOV {v[i]}.B16, V{i}.B16")
    emit("")
    emit(f"\tADD ${8 * words}, R4, R4")
    emit("\tSUB $1, R5, R5")
    emit("\tCBNZ R5, loop")
    emit("")
    stride = 8 * words
    for i in range(words):
        emit(f"\tVMOV V{i}.D[0], R12")
        emit(f"\tMOVD R12, {8 * i}(R20)")
        emit(f"\tVMOV V{i}.D[1], R12")
        emit(f"\tMOVD R12, {stride + 8 * i}(R20)")
    emit("")
    emit("\tADD $16, R19, R19")
    emit(f"\tADD ${2 * stride}, R20, R20")
    emit("\tSUB $1, R21, R21")
    emit("\tCBNZ R21, pass")
    emit("")
    emit("\tRET")
    emit("")
    for l in tables(width, blocks):
        emit(l)
    return "\n".join(out_lines)


# ---------------------------------------------------------- GPR x1 --
#
# The single-lane kernels run the cascade in general-purpose registers:
# the compression state v[0..15] in registers (on amd64 fifteen of them,
# v[11] — a c word, the role whose two G steps read or update it through
# one memory operand each — in a frame slot), the message words as frame
# slots (amd64: memory operands of ADDQ; arm64: MOVD into two temps per
# G), the rotates as RORQ / ROR. They serve the single-lane tail of every
# tier and the single arm.

GPR_REGS_AMD64 = ["AX", "BX", "CX", "DX", "SI", "DI", "BP", "R8", "R9", "R10", "R11", None, "R12", "R13", "R14", "R15"]
GPR_SPILL_AMD64 = 11
GPR_REGS_ARM64 = ["R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R19", "R20", "R21", "R22", "R23", "R24"]


def gpr_header(build, width, n, tier_desc):
    nb = len(layout(width, n))
    return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for BLAKE2b-{width} at the
// {n}-byte shape, 1 lane ({nb} compression{'s' if nb > 1 else ''} per cascade round). The data
// words are staged once per call and the seed-injected words rebuilt
// each round; see blake2basm_fused.go for the construction and the
// in-package parity tests for the bit-exact pin against the pure-Go
// cascade.

#include "textflag.h"
"""


def gpr_kernel_amd64(width, n):
    words = width // 64
    blocks = layout(width, n)
    nb = len(blocks)
    frame = Frame()
    m_off = [frame.alloc(("M", w), 8) for w in range(16)]
    spill = frame.alloc("v11", 8)
    cnt = frame.alloc("cnt", 8)
    cmp = frame.alloc("comps", 8)
    outp = frame.alloc("out", 8)
    keyp = frame.alloc("key", 8)
    d_off = {}
    t_off = {}
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                d_off[e[1]] = (frame.alloc(("D", e[1]), 8), e[2], e[3])
            elif e[0] == "data":
                t_off[(b, w)] = (frame.alloc(("T", b, w), 8), e[1], e[2])
    h_off = [frame.alloc(("H", i), 8) for i in range(8)] if nb > 1 else []
    R = GPR_REGS_AMD64

    def v(i):
        return R[i] if R[i] is not None else f"{spill}(SP)"

    L = [gpr_header(AMD, width, n, "amd64 general-purpose-register")]
    fn = f"blake2b{width}FusedChain{n}x1GprAsm"
    L.append(f"// func {fn}(fixedKey *[{width // 8}]byte, comps *uint64, nGroups int, data *byte, out *[{words}]uint64)")
    L.append(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    L += ["\tMOVQ fixedKey+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX",
          "\tMOVQ data+24(FP), DX", "\tMOVQ out+32(FP), DI",
          f"\tMOVQ BX, {cmp}(SP)", f"\tMOVQ CX, {cnt}(SP)", f"\tMOVQ DI, {outp}(SP)", f"\tMOVQ AX, {keyp}(SP)", ""]
    # Stage the data words (D slots of the seed words, T slots of the
    # data-only words) and the key words of block 0 into their m slots.
    for i in sorted(d_off):
        off, d0, size = d_off[i]
        if size == 0:
            L.append(f"\tMOVQ $0, {off}(SP)")
        else:
            L += load_word_amd64("DX", d0, size) + [f"\tMOVQ R12, {off}(SP)"]
    for (b, w), (off, d0, size) in sorted(t_off.items()):
        L += load_word_amd64("DX", d0, size) + [f"\tMOVQ R12, {off}(SP)"]

    def load_words(b, with_key, key="AX"):
        out = []
        for w, e in enumerate(blocks[b]["words"]):
            if e[0] == "key":
                if with_key:
                    out += [f"\tMOVQ {8 * e[1]}({key}), R12", f"\tMOVQ R12, {m_off[w]}(SP)"]
            elif e[0] == "data":
                out += [f"\tMOVQ {t_off[(b, w)][0]}(SP), R12", f"\tMOVQ R12, {m_off[w]}(SP)"]
            elif e[0] == "zero":
                out.append(f"\tMOVQ $0, {m_off[w]}(SP)")
        return out

    L += load_words(0, True)
    L += [f"\tXORQ {R[i]}, {R[i]}" for i in range(8)]
    L += ["", "loop:"]
    # Seed-injected words: D ⊕ component ⊕ h (h in v[0..words-1]).
    L.append(f"\tMOVQ {cmp}(SP), R9")
    for w, e in seed_words(blocks[0]):
        i = e[1]
        L += [f"\tMOVQ {d_off[i][0]}(SP), R10", f"\tXORQ {8 * i}(R9), R10", f"\tXORQ {R[i]}, R10",
              f"\tMOVQ R10, {m_off[w]}(SP)"]
    L += [f"\tADDQ ${8 * words}, R9", f"\tMOVQ R9, {cmp}(SP)"]
    if nb > 1:
        # Block 1 overwrote the message slots: restore block 0's
        # round-invariant words (the key pointer through v[10]'s
        # register, dead at the loop top).
        L += [f"\tMOVQ {keyp}(SP), R11"] + load_words(0, True, key="R11")
    for b, block in enumerate(blocks):
        tab = init_table(width, block)
        L.append("")
        if b > 0:
            L += [f"\tMOVQ {R[i]}, {h_off[i]}(SP)" for i in range(8)]
            L += load_words(b, False)
        for k in range(0 if b == 0 else 8, 16):
            if R[k] is None:
                L += [f"\tMOVQ $0x{tab[k]:016x}, R12", f"\tMOVQ R12, {spill}(SP)"]
            else:
                L.append(f"\tMOVQ $0x{tab[k]:016x}, {R[k]}")
        L.append("")
        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                mx, my = f"{m_off[sigma[2 * gi]]}(SP)", f"{m_off[sigma[2 * gi + 1]]}(SP)"
                L += [f"\tADDQ {v(bb)}, {v(a)}", f"\tADDQ {mx}, {v(a)}", f"\tXORQ {v(a)}, {v(d)}", f"\tRORQ $32, {v(d)}",
                      f"\tADDQ {v(d)}, {v(c)}", f"\tXORQ {v(c)}, {v(bb)}", f"\tRORQ $24, {v(bb)}",
                      f"\tADDQ {v(bb)}, {v(a)}", f"\tADDQ {my}, {v(a)}", f"\tXORQ {v(a)}, {v(d)}", f"\tRORQ $16, {v(d)}",
                      f"\tADDQ {v(d)}, {v(c)}", f"\tXORQ {v(c)}, {v(bb)}", f"\tRORQ $63, {v(bb)}"]
        L.append("")
        last = b == nb - 1
        nf = words if last else 8
        for i in range(nf):
            L.append(f"\tXORQ {v(8 + i)}, {R[i]}")
            if nb > 1 and last:
                L.append(f"\tXORQ {h_off[i]}(SP), {R[i]}")
            else:
                tmp = R[8 + i] if R[8 + i] is not None else R[8 + i - 1]
                L += [f"\tMOVQ $0x{tab[i]:016x}, {tmp}", f"\tXORQ {tmp}, {R[i]}"]
    L += ["", f"\tDECQ {cnt}(SP)", "\tJNZ loop", "", f"\tMOVQ {outp}(SP), R9"]
    L += [f"\tMOVQ {R[i]}, {8 * i}(R9)" for i in range(words)]
    L += ["\tRET", ""]
    return "\n".join(L)


def gpr_kernel_arm64(width, n):
    words = width // 64
    blocks = layout(width, n)
    nb = len(blocks)
    frame = Frame()
    m_off = [frame.alloc(("M", w), 8) for w in range(16)]
    d_off = {}
    t_off = {}
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                d_off[e[1]] = (frame.alloc(("D", e[1]), 8), e[2], e[3])
            elif e[0] == "data":
                t_off[(b, w)] = (frame.alloc(("T", b, w), 8), e[1], e[2])
    h_off = [frame.alloc(("H", i), 8) for i in range(8)] if nb > 1 else []
    R = GPR_REGS_ARM64

    L = [gpr_header(ARM, width, n, "ARM64 general-purpose-register")]
    fn = f"blake2b{width}FusedChain{n}x1GprAsm"
    L.append(f"// func {fn}(fixedKey *[{width // 8}]byte, comps *uint64, nGroups int, data *byte, out *[{words}]uint64)")
    L.append(f"TEXT ·{fn}(SB), NOSPLIT, ${frame.aligned}-40")
    L += ["\tMOVD fixedKey+0(FP), R0", "\tMOVD comps+8(FP), R1", "\tMOVD nGroups+16(FP), R2",
          "\tMOVD data+24(FP), R3", "\tMOVD out+32(FP), R4", f"\tMOVD $frame-{frame.aligned}(SP), R7", ""]
    for i in sorted(d_off):
        off, d0, size = d_off[i]
        if size == 0:
            L.append(f"\tMOVD ZR, {off}(R7)")
        else:
            L += load_word_arm64("R3", d0, size, "R5", "R6") + [f"\tMOVD R5, {off}(R7)"]
    for (b, w), (off, d0, size) in sorted(t_off.items()):
        L += load_word_arm64("R3", d0, size, "R5", "R6") + [f"\tMOVD R5, {off}(R7)"]

    def load_words(b, with_key):
        out = []
        for w, e in enumerate(blocks[b]["words"]):
            if e[0] == "key":
                if with_key:
                    out += [f"\tMOVD {8 * e[1]}(R0), R5", f"\tMOVD R5, {m_off[w]}(R7)"]
            elif e[0] == "data":
                out += [f"\tMOVD {t_off[(b, w)][0]}(R7), R5", f"\tMOVD R5, {m_off[w]}(R7)"]
            elif e[0] == "zero":
                out.append(f"\tMOVD ZR, {m_off[w]}(R7)")
        return out

    L += load_words(0, True)
    L += [f"\tMOVD $0, {R[i]}" for i in range(8)]
    L += ["", "loop:"]
    for w, e in seed_words(blocks[0]):
        i = e[1]
        L += [f"\tMOVD {d_off[i][0]}(R7), R5", f"\tMOVD {8 * i}(R1), R6", f"\tEOR R6, R5, R5",
              f"\tEOR {R[i]}, R5, R5", f"\tMOVD R5, {m_off[w]}(R7)"]
    L.append(f"\tADD ${8 * words}, R1, R1")
    if nb > 1:
        L += load_words(0, True)
    for b, block in enumerate(blocks):
        L.append("")
        if b > 0:
            L += [f"\tMOVD {R[i]}, {h_off[i]}(R7)" for i in range(8)]
            L += load_words(b, False)
        L.append(f"\tMOVD $tab{b}<>(SB), R25")
        for k in range(0 if b == 0 else 8, 16):
            L.append(f"\tMOVD {8 * k}(R25), {R[k]}")
        L.append("")
        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                mx, my = m_off[sigma[2 * gi]], m_off[sigma[2 * gi + 1]]
                va, vb, vc, vd = R[a], R[bb], R[c], R[d]
                L += [f"\tMOVD {mx}(R7), R5", f"\tMOVD {my}(R7), R6",
                      f"\tADD {vb}, {va}, {va}", f"\tADD R5, {va}, {va}", f"\tEOR {va}, {vd}, {vd}", f"\tROR $32, {vd}, {vd}",
                      f"\tADD {vd}, {vc}, {vc}", f"\tEOR {vc}, {vb}, {vb}", f"\tROR $24, {vb}, {vb}",
                      f"\tADD {vb}, {va}, {va}", f"\tADD R6, {va}, {va}", f"\tEOR {va}, {vd}, {vd}", f"\tROR $16, {vd}, {vd}",
                      f"\tADD {vd}, {vc}, {vc}", f"\tEOR {vc}, {vb}, {vb}", f"\tROR $63, {vb}, {vb}"]
        L.append("")
        last = b == nb - 1
        nf = words if last else 8
        for i in range(nf):
            L.append(f"\tEOR {R[8 + i]}, {R[i]}, {R[i]}")
            if nb > 1 and last:
                L.append(f"\tMOVD {h_off[i]}(R7), R5")
            else:
                L.append(f"\tMOVD {8 * i}(R25), R5")
            L.append(f"\tEOR R5, {R[i]}, {R[i]}")
    L += ["", "\tSUB $1, R2, R2", "\tCBNZ R2, loop", ""]
    L += [f"\tMOVD {R[i]}, {8 * i}(R4)" for i in range(words)]
    L += ["\tRET", ""]
    L += tables(width, blocks)
    return "\n".join(L)


# ------------------------------------------------------------- driver --

def render_all():
    files = {}
    for width in (256, 512):
        for n in SHAPES:
            files[f"blake2b_fusedchain{width}_{n}x4_avx512_amd64.s"] = evex_kernel(width, n) + "\n"
            files[f"blake2b_fusedchain{width}_{n}x4_avx2_amd64.s"] = avx2_kernel(width, n) + "\n"
            files[f"blake2b_fusedchain{width}_{n}x4_neon_arm64.s"] = neon_kernel(width, n)
    for width in (256, 512):
        for n in (20, 36, 68):
            files[f"blake2b_fusedchain{width}_{n}x8_avx512_amd64.s"] = evex_kernel(width, n, x8=True) + "\n"
    files["blake2b_fusedchain256_13x8_avx512_amd64.s"] = evex_kernel(256, 13, x8=True, fill=True) + "\n"
    files["blake2b_fusedchain512_13x8_avx512_amd64.s"] = evex_kernel(512, 13, x8=True, fill=True) + "\n"
    for width in (256, 512):
        for n in SHAPES:
            files[f"blake2b_fusedchain{width}_{n}x1_gpr_amd64.s"] = gpr_kernel_amd64(width, n)
            files[f"blake2b_fusedchain{width}_{n}x1_gpr_arm64.s"] = gpr_kernel_arm64(width, n)
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
