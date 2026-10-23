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
[0x03 | LE64(groupIdxBase+i) | LE32(v)] synthesised in-register from
groupIdxBase and the per-message interlock-nonce fold v (a uint32, the
little-endian image of bytes 9..12 of every fill block) as the two data
words (idx << 8) | 0x03 and (idx >> 56) | (v << 8): idx >> 56 occupies
bits 0..7 of the second word and v << 8 bits 8..39, so the fold is one
broadcast ORed into the idx >> 56 vector before its frame store. The
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
data-only words; zero-padded message words are elided from the G steps,
and seed words beyond the input length omit the data-slot XOR. The data
words are staged once per call from the lane pointers into the frame
(data[0:8] as two 4-byte loads, matching the caller's 4-byte pixel-index
store so store-to-load forwarding succeeds), and each cascade round
rebuilds the seed-injected words as D ⊕ component ⊕ h (or component ⊕ h
when D is zero) from the staged data word, the component broadcast and
the previous round's output. The compression state is re-initialised
each round from a per-kernel table holding IV, the parameter block, t
and the final flag.

Register plans:
    avx512 x4   Y0..Y15 the compression state v[0..15], Y16..Y31 the
                message words m[0..15] (and, in the two-block cell,
                Y24..Y31 the saved chaining value H[0..7] across block 1
                while Y16..Y23 retain key[0..7] for the whole call);
                the fold h = h0 ⊕ v ⊕ v' and the seed-word rebuild are
                VPTERNLOGQ / VPXORQ with embedded-broadcast memory
                operands, so no scratch register is needed
    avx512 x8   the same plan on ZMM registers (eight lanes): Z0..Z15 the
                state, Z16..Z31 the message words and saved chaining
                value; every frame fits the NOSPLIT budget
    avx2 x4     Y0..Y14 v[0..14], Y15 the ror63 temp, v[15] in a frame
                slot with v[12] spilled around the two G functions that
                touch v[15]; the non-zero message words are frame slots
                read as memory operands; ror32 = VPSHUFD, ror24 / ror16
                = VPSHUFB with byte masks, ror63 = shift-or
    neon x4     V0..V15 v[0..15], one pass body looped over the lane
                pairs (0,1) and (2,3) (R19 / R20 the per-pass slot and
                output bases, R21 the pass counter); at width 256 all
                non-zero message words stay in registers (V19..V22 the
                key, V23..V26 the seed words, V27..V31 the data words);
                at width 512 V19..V26 hold the key, V27..V31 hold
                seed[0..4], and seed[5..7] use frame slots loaded into
                V16 / V17 (with block 1's single data word at shape 68
                held in V16); V18 the rotate alternate (VSHL + VSRI, the
                rotate by 32 as VREV64 on 32-bit elements); the
                state-init tables are read-only data (R6 the table base)
    gpr amd64   v[0..15] in AX, BX, CX, DX, SI, DI, BP, R8..R11, R12..R15
                with v[11] — a c word, whose two G steps read or update
                it through one memory operand each — in a frame slot
                (15 of 15 usable registers); the non-zero message words,
                the group counter, the component / output pointers in
                the frame; the fold's h0 constants pass through the just-
                folded v[8+i] register; R9 / R10 are the loop-top temps
                while only h = v[0..7] is live
    gpr arm64   v[0..15] in R8..R17, R19..R24; R0 key, R1 components, R2
                group counter, R4 output, R7 frame base, R5 / R6 the
                message-word loads of every G (the key words read through
                R0, the others from the frame), R25 the state-init table

Frame contents: the staged data words (public) and, on the tiers whose
register file cannot hold all message words, the key words and the
seed-injected words, plus the state words a plan spills (the avx2
v[15] / v[12] slots, the gpr amd64 v[11] slot) and the chaining value
of the two-block cell (on the non-EVEX tiers). Every slot or register
that held a key word, a seed-injected word or state is overwritten with
zeros before the kernel returns.
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


def secret_message_words(blocks):
    """Message words of block 0 that carry the key or a seed-injected word:
    their frame slots hold secret-derived values."""
    return sorted({w for w, e in enumerate(blocks[0]["words"]) if e[0] in ("key", "seed")})


def seed_message_words(blocks):
    """Message words of block 0 that carry a seed-injected word."""
    return sorted({w for w, e in enumerate(blocks[0]["words"]) if e[0] == "seed"})


def wipe_amd64(offsets, width, zero):
    """Zero stores over frame slots of the given byte width; zero names a
    register of that width already holding zero (unused for 8-byte slots)."""
    if width == 8:
        return [f"\tMOVQ $0, {o}(SP)" for o in offsets]
    evex = width == 64 or int(zero[1:]) >= 16
    mov = "VMOVDQU64" if evex else "VMOVDQU"
    return [f"\t{mov} {zero}, {o}(SP)" for o in offsets]


def wipe_arm64(offsets, width, base="R7"):
    """Zero stores over frame slots of the given byte width (8 or 16)
    through the frame base register; 16-byte slots go through F16 = 0."""
    if not offsets:
        return []
    if width == 8:
        return [f"\tMOVD ZR, {o}({base})" for o in offsets]
    return ["\tVEOR V16.B16, V16.B16, V16.B16"] + [f"\tFMOVQ F16, {o}({base})" for o in offsets]


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
    """Stage the per-lane non-zero data words of every block into the frame
    (one slot of 8 bytes per lane per word): the non-zero D slots of the
    seed words and the data-only words."""
    lines = []
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                if e[3] == 0:
                    continue
                key, d0, size = ("D", e[1]), e[2], e[3]
            elif e[0] == "data":
                key, d0, size = ("T", b, w), e[1], e[2]
            else:
                continue
            base = frame.slots[key] if key in frame.slots else frame.alloc(key, lane_bytes)
            for l, r in enumerate(LANE_REGS):
                lines += load_word_amd64(r, d0, size)
                lines.append(f"\tMOVQ R12, {base + 8 * l}(SP)")
    return lines


def stage_amd64_x8(blocks, frame):
    """Stage the per-lane non-zero data words of eight lanes (64-byte slots):
    lanes 0..3 then 4..7, each group loading its four lane pointers into
    R8..R11 (dead after its stores)."""
    lines = []
    keys = []
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed" and e[3] > 0:
                keys.append((("D", e[1]), e[2], e[3]))
            elif e[0] == "data":
                keys.append((("T", b, w), e[1], e[2]))
    for key, _, _ in keys:
        if key not in frame.slots:
            frame.alloc(key, 64)
    for g in range(2):
        lines.append("\tMOVQ dataPtrs+24(FP), DX")
        for i, r in enumerate(LANE_REGS):
            lines.append(f"\tMOVQ {8 * (4 * g + i)}(DX), {r}")
        for key, d0, size in keys:
            base = frame.slots[key]
            for l, r in enumerate(LANE_REGS):
                o = base + 8 * (4 * g + l)
                lines += load_word_amd64(r, d0, size)
                lines.append(f"\tMOVQ R12, {o}(SP)")
    lines.append("\tMOVQ out+32(FP), DX")
    return lines


# NOSPLIT_FRAME_MAX is the largest frame the kernels declare with
# NOSPLIT; the wider frames carry the stack-growth prologue instead.
NOSPLIT_FRAME_MAX = 728


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

EVEX_G_DEFS = {
    "BLAKE2B_G": [
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
    ],
    "BLAKE2B_GX": [
        "#define BLAKE2B_GX(a, b, c, d, mx) \\",
        "\tVPADDQ b, a, a; \\",
        "\tVPADDQ mx, a, a; \\",
        "\tVPXORQ a, d, d; \\",
        "\tVPRORQ $32, d, d; \\",
        "\tVPADDQ d, c, c; \\",
        "\tVPXORQ c, b, b; \\",
        "\tVPRORQ $24, b, b; \\",
        "\tVPADDQ b, a, a; \\",
        "\tVPXORQ a, d, d; \\",
        "\tVPRORQ $16, d, d; \\",
        "\tVPADDQ d, c, c; \\",
        "\tVPXORQ c, b, b; \\",
        "\tVPRORQ $63, b, b",
    ],
    "BLAKE2B_GY": [
        "#define BLAKE2B_GY(a, b, c, d, my) \\",
        "\tVPADDQ b, a, a; \\",
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
    ],
    "BLAKE2B_GZ": [
        "#define BLAKE2B_GZ(a, b, c, d) \\",
        "\tVPADDQ b, a, a; \\",
        "\tVPXORQ a, d, d; \\",
        "\tVPRORQ $32, d, d; \\",
        "\tVPADDQ d, c, c; \\",
        "\tVPXORQ c, b, b; \\",
        "\tVPRORQ $24, b, b; \\",
        "\tVPADDQ b, a, a; \\",
        "\tVPXORQ a, d, d; \\",
        "\tVPRORQ $16, d, d; \\",
        "\tVPADDQ d, c, c; \\",
        "\tVPXORQ c, b, b; \\",
        "\tVPRORQ $63, b, b",
    ],
}


def evex_rounds(p, mops, used):
    """Emit the 12 rounds of one block given mops[0..15] (each a register /
    memory operand string or None for an elided zero word)."""
    if all(mops[w] is not None for w in range(16)):
        used.add("BLAKE2B_G")
        used.add("BLAKE2B_ROUND")
        return [f"\tBLAKE2B_ROUND({', '.join(mops[s] for s in sigma)})" for sigma in ROUNDS]
    out = []
    for sigma in ROUNDS:
        for gi, (a, b, c, d) in enumerate(G_ORDER):
            mx, my = mops[sigma[2 * gi]], mops[sigma[2 * gi + 1]]
            ra, rb, rc, rd = f"{p}{a}", f"{p}{b}", f"{p}{c}", f"{p}{d}"
            if mx is not None and my is not None:
                used.add("BLAKE2B_G")
                out.append(f"\tBLAKE2B_G({ra}, {rb}, {rc}, {rd}, {mx}, {my})")
            elif mx is not None:
                used.add("BLAKE2B_GX")
                out.append(f"\tBLAKE2B_GX({ra}, {rb}, {rc}, {rd}, {mx})")
            elif my is not None:
                used.add("BLAKE2B_GY")
                out.append(f"\tBLAKE2B_GY({ra}, {rb}, {rc}, {rd}, {my})")
            else:
                used.add("BLAKE2B_GZ")
                out.append(f"\tBLAKE2B_GZ({ra}, {rb}, {rc}, {rd})")
    return out


def evex_macros(p, used):
    """Emit the G-function and round macros referenced by used."""
    parts = []
    for name in ("BLAKE2B_G", "BLAKE2B_GX", "BLAKE2B_GY", "BLAKE2B_GZ"):
        if name in used:
            parts.append("\n".join(EVEX_G_DEFS[name]))
    if "BLAKE2B_ROUND" in used:
        rows = [f"\tBLAKE2B_G({p}{a}, {p}{b}, {p}{c}, {p}{d}, s{2 * gi}, s{2 * gi + 1})"
                for gi, (a, b, c, d) in enumerate(G_ORDER)]
        parts.append("#define BLAKE2B_ROUND(" + ", ".join(f"s{i}" for i in range(16)) + ") \\\n" + "; \\\n".join(rows))
    return "\n\n".join(parts) + "\n"


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
        # Synthesised fill blocks: D0 = (idx << 8) | 0x03,
        # D1 = (idx >> 56) | (v << 8), the remaining seed-injected words
        # identically zero (no frame slots allocated).
        d = [frame.alloc(("D", i), lane_bytes) for i in range(2)]
        build += [
            "\t// Fill blocks [0x03 | LE64(groupIdxBase+i) | LE32(v)] as the data",
            "\t// words D0 = (idx << 8) | 0x03 and D1 = (idx >> 56) | (v << 8).",
            "\tVPBROADCASTQ groupIdxBase+24(FP), Z0",
            "\tVPADDQ laneIdx<>(SB), Z0, Z0",
            "\tVPSLLQ $8, Z0, Z1",
            "\tMOVQ $3, R12",
            "\tVPBROADCASTQ R12, Z2",
            "\tVPORQ Z2, Z1, Z1",
            f"\tVMOVDQU64 Z1, {d[0]}(SP)",
            "\tMOVL v+40(FP), R12",
            "\tSHLQ $8, R12",
            "\tVPBROADCASTQ R12, Z2",
            "\tVPSRLQ $56, Z0, Z1",
            "\tVPORQ Z2, Z1, Z1",
            f"\tVMOVDQU64 Z1, {d[1]}(SP)",
        ]
    elif x8:
        build += stage_amd64_x8(blocks, frame)
    else:
        build += stage_amd64(blocks, frame, lane_bytes)
    mov = "VMOVDQU64"

    def m(w):
        return f"{p}{16 + w}"

    # Round-invariant message registers of block 0 (key words in 16..23
    # and data words of 1-block shapes): never clobbered inside the loop.
    pre_loop = []
    for w, e in enumerate(blocks[0]["words"]):
        if e[0] == "key":
            pre_loop.append(f"\tVPBROADCASTQ {8 * e[1]}(AX), {m(w)}")
        elif e[0] == "data":
            pre_loop.append(f"\t{mov} {frame.slots[('T', 0, w)]}(SP), {m(w)}")

    used_macros = set()
    block_rounds = []
    for b, block in enumerate(blocks):
        mops = []
        for w, e in enumerate(block["words"]):
            if e[0] == "zero":
                mops.append(None)
            elif b > 0 and e[0] == "data":
                mops.append(f"{frame.slots[('T', b, w)]}(SP)")
            else:
                mops.append(m(w))
        block_rounds.append(evex_rounds(p, mops, used_macros))

    lines = []
    lines.append(header(AMD, width, n, lanes, "AVX-512 " + ("ZMM (eight lanes)" if x8 else "YMM (four lanes)"), fill=fill))
    lines.append(evex_macros(p, used_macros))
    if fill:
        kind = f"groupIdxBase uint64, out *[8][{words}]uint64, v uint32"
        argsize = 44
    else:
        kind = f"dataPtrs *[{lanes}]*byte, out *[{lanes}][{words}]uint64"
        argsize = 40
    fn = f"blake2b{width}FusedChain{n}x{lanes}Avx512Asm"
    lines.append(f"// func {fn}(fixedKey *[{width // 8}]byte, comps *uint64, nGroups int, {kind})")
    lines.append(f"TEXT ·{fn}(SB), {text_flags(frame)}${frame.aligned}-{argsize}")
    lines += prologue_amd64(x8)
    lines.append("")
    lines += build
    lines.append("")
    lines += pre_loop
    for i in range(words):
        lines.append(f"\tVPXORQ {p}{i}, {p}{i}, {p}{i}")
    lines.append("")
    lines.append("loop:")
    # Seed-injected words of block 0: D ⊕ component ⊕ h (or component ⊕ h when D = 0).
    for w, e in seed_words(blocks[0]):
        i, size = e[1], e[3]
        if size == 0:
            lines.append(f"\tVPXORQ.BCST {8 * i}(BX), {p}{i}, {m(w)}")
        else:
            lines.append(f"\t{mov} {frame.slots[('D', i)]}(SP), {m(w)}")
            lines.append(f"\tVPTERNLOGQ.BCST $0x96, {8 * i}(BX), {p}{i}, {m(w)}")
    for b, block in enumerate(blocks):
        lines.append("")
        if b > 0:
            # Save chaining value H[0..7] into dead seed registers m(8..15).
            for i in range(8):
                lines.append(f"\tVMOVDQA64 {p}{i}, {m(8 + i)}")
        for k in range(0 if b == 0 else 8, 16):
            lines.append(f"\tVPBROADCASTQ tab{b}<>+{8 * k}(SB), {p}{k}")
        lines.append("")
        lines += block_rounds[b]
        lines.append("")
        last = b == nb - 1
        nf = words if last else 8
        for i in range(nf):
            if nb > 1 and last:
                lines.append(f"\tVPTERNLOGQ $0x96, {p}{8 + i}, {m(8 + i)}, {p}{i}")
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
    for w in range(32):
        lines.append(f"\tVPXORD X{w}, X{w}, X{w}")
    lines += wipe_amd64(range(0, frame.aligned, lane_bytes), lane_bytes, f"{p}16")
    for reg in (["AX", "BX", "CX", "DX", "R12"] if fill else ["AX", "BX", "CX", "DX", "R8", "R9", "R10", "R11", "R12", "R13"]):
        lines.append(f"\tXORQ {reg}, {reg}")
    lines.append("\tVZEROUPPER")
    lines.append("\tRET")
    lines.append("")
    lines += tables(width, blocks, fill)
    return "\n".join(lines)


# -------------------------------------------------------- AVX2 family --

AVX2_G_DEFS = {
    "GA": """#define GA(a, b, c, d, mx, my, t) \\
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
\tROR63(b, t)""",
    "GAX": """#define GAX(a, b, c, d, mx, t) \\
\tVPADDQ b, a, a; \\
\tVPADDQ mx(SP), a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFD $0xB1, d, d; \\
\tVPADDQ d, c, c; \\
\tVPXOR c, b, b; \\
\tVPSHUFB ror24<>(SB), b, b; \\
\tVPADDQ b, a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFB ror16<>(SB), d, d; \\
\tVPADDQ d, c, c; \\
\tVPXOR c, b, b; \\
\tROR63(b, t)""",
    "GAY": """#define GAY(a, b, c, d, my, t) \\
\tVPADDQ b, a, a; \\
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
\tROR63(b, t)""",
    "GAZ": """#define GAZ(a, b, c, d, t) \\
\tVPADDQ b, a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFD $0xB1, d, d; \\
\tVPADDQ d, c, c; \\
\tVPXOR c, b, b; \\
\tVPSHUFB ror24<>(SB), b, b; \\
\tVPADDQ b, a, a; \\
\tVPXOR a, d, d; \\
\tVPSHUFB ror16<>(SB), d, d; \\
\tVPADDQ d, c, c; \\
\tVPXOR c, b, b; \\
\tROR63(b, t)""",
}

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


def avx2_g_call(a, b, c, d, mx, my, t, used):
    rd = "Y15" if d == 15 else f"Y{d}"
    if mx is not None and my is not None:
        used.add("GA")
        return f"\tGA(Y{a}, Y{b}, Y{c}, {rd}, {mx}, {my}, {t})"
    if mx is not None:
        used.add("GAX")
        return f"\tGAX(Y{a}, Y{b}, Y{c}, {rd}, {mx}, {t})"
    if my is not None:
        used.add("GAY")
        return f"\tGAY(Y{a}, Y{b}, Y{c}, {rd}, {my}, {t})"
    used.add("GAZ")
    return f"\tGAZ(Y{a}, Y{b}, Y{c}, {rd}, {t})"


def avx2_rounds(mops, used):
    if all(mops[w] == f"M({w})" for w in range(16)):
        used.add("GA")
        used.add("ROUND")
        return [f"\tROUND({','.join(str(s) for s in sigma)})" for sigma in ROUNDS]
    out = []
    for sigma in ROUNDS:
        for gi in range(3):
            a, b, c, d = G_ORDER[gi]
            out.append(avx2_g_call(a, b, c, d, mops[sigma[2 * gi]], mops[sigma[2 * gi + 1]], "Y15", used))
        out.append("\tVMOVDQU Y12, V12(SP)")
        out.append("\tVMOVDQU V15(SP), Y15")
        for gi in (3, 4):
            a, b, c, d = G_ORDER[gi]
            out.append(avx2_g_call(a, b, c, d, mops[sigma[2 * gi]], mops[sigma[2 * gi + 1]], "Y12", used))
        out.append("\tVMOVDQU Y15, V15(SP)")
        out.append("\tVMOVDQU V12(SP), Y12")
        for gi in range(5, 8):
            a, b, c, d = G_ORDER[gi]
            out.append(avx2_g_call(a, b, c, d, mops[sigma[2 * gi]], mops[sigma[2 * gi + 1]], "Y15", used))
    return out


def avx2_macros(n_m, used):
    parts = [
        "#define ROR63(b, t) \\\n\tVPSRLQ $63, b, t; \\\n\tVPADDQ b, b, b; \\\n\tVPOR t, b, b"
    ]
    for name in ("GA", "GAX", "GAY", "GAZ"):
        if name in used:
            parts.append(AVX2_G_DEFS[name])
    parts.append(f"#define M(i)   (i*32)\n#define V15    {32 * n_m}\n#define V12    {32 * (n_m + 1)}")
    if "ROUND" in used:
        parts.append("""#define ROUND(s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15) \\
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
\tGA(Y3, Y4, Y9,  Y14, M(s14), M(s15), Y15)""")
    return "\n\n".join(parts) + "\n"


def avx2_kernel(width, n):
    words = width // 64
    blocks = layout(width, n)
    nb = len(blocks)
    n_m = sum(1 for e in blocks[0]["words"] if e[0] != "zero")
    frame = Frame((n_m + 2) * 32)  # M(0..n_m-1), V15, V12
    # Stage block 0's data-only words straight into their M(w) slots.
    for w, e in enumerate(blocks[0]["words"]):
        if e[0] == "data":
            frame.slots[("T", 0, w)] = 32 * w
    build = stage_amd64(blocks, frame, 32)
    if nb > 1:
        for i in range(8):
            frame.alloc(("H", i), 32)

    def slot(w):
        return f"M({w})"

    # Key words of block 0 live in M(0..words-1) and are never overwritten
    # by block 1 (which reads its data words from their own T slots).
    pre_loop = []
    for w, e in enumerate(blocks[0]["words"]):
        if e[0] == "key":
            pre_loop.append(f"\tVPBROADCASTQ {8 * e[1]}(AX), Y15")
            pre_loop.append(f"\tVMOVDQU Y15, {slot(w)}(SP)")

    used_macros = set()
    block_rounds = []
    for b, block in enumerate(blocks):
        mops = []
        for w, e in enumerate(block["words"]):
            if e[0] == "zero":
                mops.append(None)
            elif b > 0:
                mops.append(str(frame.slots[("T", b, w)]))
            else:
                mops.append(slot(w))
        block_rounds.append(avx2_rounds(mops, used_macros))

    tmp2 = f"Y{words}"  # free between the fold and the state init
    lines = []
    lines.append(header(AMD, width, n, 4, "AVX2 YMM (four lanes)"))
    lines.append(avx2_macros(n_m, used_macros))
    fn = f"blake2b{width}FusedChain{n}x4Avx2Asm"
    lines.append(f"// func {fn}(fixedKey *[{width // 8}]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][{words}]uint64)")
    lines.append(f"TEXT ·{fn}(SB), {text_flags(frame)}${frame.aligned}-40")
    lines += prologue_amd64(False)
    lines.append("")
    lines += build
    lines.append("")
    lines += pre_loop
    for i in range(words):
        lines.append(f"\tVPXOR Y{i}, Y{i}, Y{i}")
    lines.append("")
    lines.append("loop:")
    for w, e in seed_words(blocks[0]):
        i, size = e[1], e[3]
        if size == 0:
            lines.append(f"\tVPBROADCASTQ {8 * i}(BX), Y15")
            lines.append(f"\tVPXOR Y{i}, Y15, Y15")
            lines.append(f"\tVMOVDQU Y15, {slot(w)}(SP)")
        else:
            lines.append(f"\tVMOVDQU {frame.slots[('D', i)]}(SP), Y15")
            lines.append(f"\tVPXOR Y{i}, Y15, Y15")
            lines.append(f"\tVPBROADCASTQ {8 * i}(BX), {tmp2}")
            lines.append(f"\tVPXOR {tmp2}, Y15, Y15")
            lines.append(f"\tVMOVDQU Y15, {slot(w)}(SP)")
    for b, block in enumerate(blocks):
        lines.append("")
        if b > 0:
            for i in range(8):
                lines.append(f"\tVMOVDQU Y{i}, {frame.slots[('H', i)]}(SP)")
        for k in range(0 if b == 0 else 8, 15):
            lines.append(f"\tVPBROADCASTQ tab{b}<>+{8 * k}(SB), Y{k}")
        lines.append(f"\tVPBROADCASTQ tab{b}<>+120(SB), Y15")
        lines.append("\tVMOVDQU Y15, V15(SP)")
        lines.append("")
        lines += block_rounds[b]
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
    for w in range(16):
        lines.append(f"\tVPXOR Y{w}, Y{w}, Y{w}")
    lines += wipe_amd64(range(0, frame.aligned, 32), 32, "Y15")
    for reg in ["AX", "BX", "CX", "DX", "R8", "R9", "R10", "R11", "R12", "R13"]:
        lines.append(f"\tXORQ {reg}, {reg}")
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
    """Stage the per-lane non-zero data words as in stage_amd64 (four lanes,
    8 bytes each, so one 32-byte slot per word) through the frame base
    register."""
    lines = []
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed":
                if e[3] == 0:
                    continue
                key, d0, size = ("D", e[1]), e[2], e[3]
            elif e[0] == "data":
                key, d0, size = ("T", b, w), e[1], e[2]
            else:
                continue
            off = frame.alloc(key, 32)
            for l, r in enumerate(ARM_LANE_REGS):
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
    """One G function; mx / my are the two message words of the current
    half: a frame offset (loaded into V16 / V17), the name of the vector
    register a word is resident in, or None for an elided zero word."""
    out = []
    ops = []
    for m, tmp in ((mx, 16), (my, 17)):
        if m is None or isinstance(m, str):
            ops.append(m)
        else:
            out.append(f"\tFMOVQ {m}(R7), F{tmp}")
            ops.append(f"V{tmp}")
    v = regs.v
    out.append(f"\tVADD {v[b]}.D2, {v[a]}.D2, {v[a]}.D2")
    if ops[0] is not None:
        out.append(f"\tVADD {ops[0]}.D2, {v[a]}.D2, {v[a]}.D2")
    out.append(f"\tVEOR {v[a]}.B16, {v[d]}.B16, {v[d]}.B16")
    out += regs.rot(d, 32)
    v = regs.v
    out.append(f"\tVADD {v[d]}.D2, {v[c]}.D2, {v[c]}.D2")
    out.append(f"\tVEOR {v[c]}.B16, {v[b]}.B16, {v[b]}.B16")
    out += regs.rot(b, 24)
    v = regs.v
    out.append(f"\tVADD {v[b]}.D2, {v[a]}.D2, {v[a]}.D2")
    if ops[1] is not None:
        out.append(f"\tVADD {ops[1]}.D2, {v[a]}.D2, {v[a]}.D2")
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
    output rows. The key words are loaded once per call straight from the
    key pointer into V19.. (VLD1R); V23..V31 (width 256) or V27..V31
    (width 512) hold seed and data words in registers so only seed[5..7]
    at width 512 require frame message slots. All secret registers and
    slots are zeroed before return."""
    words = width // 64
    blocks = layout(width, n)
    nb = len(blocks)
    frame = Frame()
    nkey = width // 64
    # V19..V31 hold up to 13 message words of block 0 (w = 0..12):
    # at width 256 all non-zero words (w = 0..12) fit in V19..V31;
    # at width 512 w = 0..12 (key[0..7] and seed[0..4]) fit in V19..V31
    # and only w = 13..15 (seed[5..7]) use frame slots.
    m_reg = {w: f"V{19 + w}" for w, e in enumerate(blocks[0]["words"]) if e[0] != "zero" and 19 + w <= 31}
    m_off = [frame.alloc(("M", w), 16) if blocks[0]["words"][w][0] != "zero" and w not in m_reg else None for w in range(16)]
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
    # Key words k = 0..nkey-1 resident in V19.. for the whole call.
    emit("\tMOVD R0, R12")
    for k in range(nkey):
        emit(f"\tVLD1R.P 8(R12), [V{19 + k}.D2]")
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
    # Data words of block 0 into their resident registers V27..V31.
    for w, e in enumerate(blocks[0]["words"]):
        if e[0] == "data":
            emit(f"\tFMOVQ {frame.slots[('T', 0, w)]}(R19), F{19 + w}")
    for i in range(words):
        emit(f"\tVEOR V{i}.B16, V{i}.B16, V{i}.B16")
    emit("")
    emit("loop:")
    # Seed-injected words: D ⊕ component ⊕ h (h in V0..V{words-1}).
    for w, e in seed_words(blocks[0]):
        i, size = e[1], e[3]
        if w in m_reg:
            vr = m_reg[w]
            fr = f"F{vr[1:]}"
            if size == 0:
                emit(f"\tMOVD {8 * i}(R4), R12")
                emit(f"\tVDUP R12, {vr}.D2")
                emit(f"\tVEOR V{i}.B16, {vr}.B16, {vr}.B16")
            else:
                emit(f"\tFMOVQ {frame.slots[('D', i)]}(R19), {fr}")
                emit(f"\tMOVD {8 * i}(R4), R12")
                emit("\tVDUP R12, V17.D2")
                emit(f"\tVEOR V17.B16, {vr}.B16, {vr}.B16")
                emit(f"\tVEOR V{i}.B16, {vr}.B16, {vr}.B16")
        else:
            if size == 0:
                emit(f"\tMOVD {8 * i}(R4), R12")
                emit("\tVDUP R12, V16.D2")
                emit(f"\tVEOR V{i}.B16, V16.B16, V16.B16")
                emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
            else:
                emit(f"\tFMOVQ {frame.slots[('D', i)]}(R19), F16")
                emit(f"\tMOVD {8 * i}(R4), R12")
                emit("\tVDUP R12, V17.D2")
                emit("\tVEOR V16.B16, V17.B16, V16.B16")
                emit(f"\tVEOR V{i}.B16, V16.B16, V16.B16")
                emit(f"\tFMOVQ F16, {m_off[w]}(R7)")
    for b, block in enumerate(blocks):
        regs = NeonRegs()

        def mop(w, b=b, block=block):
            e = block["words"][w]
            if e[0] == "zero":
                return None
            if b > 0:
                return "V16"
            return m_reg[w] if w in m_reg else m_off[w]

        emit("")
        if b > 0:
            for i in range(8):
                emit(f"\tFMOVQ F{i}, {h_off[i]}(R7)")
            emit(f"\tFMOVQ {frame.slots[('T', b, 0)]}(R19), F16")
        emit(f"\tMOVD $tab{b}<>(SB), R6")
        for k in range(0 if b == 0 else 8, 16):
            emit(f"\tMOVD {8 * k}(R6), R12")
            emit(f"\tVDUP R12, V{k}.D2")
        emit("")
        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                for l in neon_g(regs, a, bb, c, d, mop(sigma[2 * gi]), mop(sigma[2 * gi + 1])):
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
    for r in range(32):
        emit(f"\tVEOR V{r}.B16, V{r}.B16, V{r}.B16")
    for o in range(0, frame.aligned, 16):
        emit(f"\tFMOVQ F16, {o}(R7)")
    for reg in ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R19", "R20", "R21"]:
        emit(f"\tMOVD ZR, {reg}")
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
    m_off = [frame.alloc(("M", w), 8) if blocks[0]["words"][w][0] != "zero" else None for w in range(16)]
    spill = frame.alloc("v11", 8)
    cnt = frame.alloc("cnt", 8)
    cmp = frame.alloc("comps", 8)
    outp = frame.alloc("out", 8)
    d_off = {}
    t_off = {}
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed" and e[3] > 0:
                d_off[e[1]] = (frame.alloc(("D", e[1]), 8), e[2], e[3])
            elif e[0] == "data":
                if b == 0:
                    t_off[(b, w)] = (m_off[w], e[1], e[2])
                else:
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
          f"\tMOVQ BX, {cmp}(SP)", f"\tMOVQ CX, {cnt}(SP)", f"\tMOVQ DI, {outp}(SP)", ""]
    # Stage the non-zero D slots of the seed words, the data-only words
    # (directly into M(w) for block 0, into T(1, w) for block 1), and the
    # key words of block 0 once before the cascade loop.
    for i in sorted(d_off):
        off, d0, size = d_off[i]
        L += load_word_amd64("DX", d0, size) + [f"\tMOVQ R12, {off}(SP)"]
    for (b, w), (off, d0, size) in sorted(t_off.items()):
        L += load_word_amd64("DX", d0, size) + [f"\tMOVQ R12, {off}(SP)"]
    for w, e in enumerate(blocks[0]["words"]):
        if e[0] == "key":
            L += [f"\tMOVQ {8 * e[1]}(AX), R12", f"\tMOVQ R12, {m_off[w]}(SP)"]
    L += [f"\tXORQ {R[i]}, {R[i]}" for i in range(8)]
    L += ["", "loop:"]
    # Seed-injected words: D ⊕ component ⊕ h (h in v[0..words-1]).
    L.append(f"\tMOVQ {cmp}(SP), R9")
    for w, e in seed_words(blocks[0]):
        i, size = e[1], e[3]
        if size == 0:
            L += [f"\tMOVQ {8 * i}(R9), R10", f"\tXORQ {R[i]}, R10", f"\tMOVQ R10, {m_off[w]}(SP)"]
        else:
            L += [f"\tMOVQ {d_off[i][0]}(SP), R10", f"\tXORQ {8 * i}(R9), R10", f"\tXORQ {R[i]}, R10",
                  f"\tMOVQ R10, {m_off[w]}(SP)"]
    L += [f"\tADDQ ${8 * words}, R9", f"\tMOVQ R9, {cmp}(SP)"]
    for b, block in enumerate(blocks):
        tab = init_table(width, block)
        L.append("")
        if b > 0:
            L += [f"\tMOVQ {R[i]}, {h_off[i]}(SP)" for i in range(8)]
        for k in range(0 if b == 0 else 8, 16):
            if R[k] is None:
                L += [f"\tMOVQ $0x{tab[k]:016x}, R12", f"\tMOVQ R12, {spill}(SP)"]
            else:
                L.append(f"\tMOVQ $0x{tab[k]:016x}, {R[k]}")
        L.append("")

        def mop(w, b=b, block=block):
            e = block["words"][w]
            if e[0] == "zero":
                return None
            if b > 0:
                return f"{t_off[(b, w)][0]}(SP)"
            return f"{m_off[w]}(SP)"

        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                mx, my = mop(sigma[2 * gi]), mop(sigma[2 * gi + 1])
                L.append(f"\tADDQ {v(bb)}, {v(a)}")
                if mx is not None:
                    L.append(f"\tADDQ {mx}, {v(a)}")
                L += [f"\tXORQ {v(a)}, {v(d)}", f"\tRORQ $32, {v(d)}",
                      f"\tADDQ {v(d)}, {v(c)}", f"\tXORQ {v(c)}, {v(bb)}", f"\tRORQ $24, {v(bb)}",
                      f"\tADDQ {v(bb)}, {v(a)}"]
                if my is not None:
                    L.append(f"\tADDQ {my}, {v(a)}")
                L += [f"\tXORQ {v(a)}, {v(d)}", f"\tRORQ $16, {v(d)}",
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
    L += wipe_amd64(range(0, frame.aligned, 8), 8, None)
    for reg in ["AX", "BX", "CX", "DX", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]:
        L.append(f"\tXORQ {reg}, {reg}")
    L += ["\tRET", ""]
    return "\n".join(L)


def gpr_kernel_arm64(width, n):
    words = width // 64
    blocks = layout(width, n)
    nb = len(blocks)
    frame = Frame()
    m_off = [frame.alloc(("M", w), 8) if blocks[0]["words"][w][0] in ("seed", "data") else None for w in range(16)]
    d_off = {}
    t_off = {}
    for b, block in enumerate(blocks):
        for w, e in enumerate(block["words"]):
            if e[0] == "seed" and e[3] > 0:
                d_off[e[1]] = (frame.alloc(("D", e[1]), 8), e[2], e[3])
            elif e[0] == "data":
                if b == 0:
                    t_off[(b, w)] = (m_off[w], e[1], e[2])
                else:
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
        L += load_word_arm64("R3", d0, size, "R5", "R6") + [f"\tMOVD R5, {off}(R7)"]
    for (b, w), (off, d0, size) in sorted(t_off.items()):
        L += load_word_arm64("R3", d0, size, "R5", "R6") + [f"\tMOVD R5, {off}(R7)"]

    def mload(b, w, dst):
        e = blocks[b]["words"][w]
        if e[0] == "zero":
            return None
        if e[0] == "key":
            return f"\tMOVD {8 * e[1]}(R0), {dst}"
        if b > 0:
            return f"\tMOVD {t_off[(b, w)][0]}(R7), {dst}"
        return f"\tMOVD {m_off[w]}(R7), {dst}"

    L += [f"\tMOVD $0, {R[i]}" for i in range(8)]
    L += ["", "loop:"]
    for w, e in seed_words(blocks[0]):
        i, size = e[1], e[3]
        if size == 0:
            L += [f"\tMOVD {8 * i}(R1), R5", f"\tEOR {R[i]}, R5, R5", f"\tMOVD R5, {m_off[w]}(R7)"]
        else:
            L += [f"\tMOVD {d_off[i][0]}(R7), R5", f"\tMOVD {8 * i}(R1), R6", f"\tEOR R6, R5, R5",
                  f"\tEOR {R[i]}, R5, R5", f"\tMOVD R5, {m_off[w]}(R7)"]
    L.append(f"\tADD ${8 * words}, R1, R1")
    for b, block in enumerate(blocks):
        L.append("")
        if b > 0:
            L += [f"\tMOVD {R[i]}, {h_off[i]}(R7)" for i in range(8)]
        L.append(f"\tMOVD $tab{b}<>(SB), R25")
        for k in range(0 if b == 0 else 8, 16):
            L.append(f"\tMOVD {8 * k}(R25), {R[k]}")
        L.append("")
        for sigma in ROUNDS:
            for gi, (a, bb, c, d) in enumerate(G_ORDER):
                va, vb, vc, vd = R[a], R[bb], R[c], R[d]
                lx = mload(b, sigma[2 * gi], "R5")
                ly = mload(b, sigma[2 * gi + 1], "R6")
                if lx is not None:
                    L.append(lx)
                if ly is not None:
                    L.append(ly)
                L.append(f"\tADD {vb}, {va}, {va}")
                if lx is not None:
                    L.append(f"\tADD R5, {va}, {va}")
                L += [f"\tEOR {va}, {vd}, {vd}", f"\tROR $32, {vd}, {vd}",
                      f"\tADD {vd}, {vc}, {vc}", f"\tEOR {vc}, {vb}, {vb}", f"\tROR $24, {vb}, {vb}",
                      f"\tADD {vb}, {va}, {va}"]
                if ly is not None:
                    L.append(f"\tADD R6, {va}, {va}")
                L += [f"\tEOR {va}, {vd}, {vd}", f"\tROR $16, {vd}, {vd}",
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
    L += wipe_arm64(range(0, frame.aligned, 8), 8)
    for reg in ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"] + R + ["R25"]:
        L.append(f"\tMOVD ZR, {reg}")
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
    files["blake2b_fusedchain256_13x4_avx512_amd64.s"] += '\n// func dumpSIMDRegs(dst *[88]uint64, avx512 bool)\nTEXT ·dumpSIMDRegs(SB), NOSPLIT, $0-9\n\tMOVQ dst+0(FP), AX\n\tMOVQ CX, 512(AX)\n\tMOVQ DX, 520(AX)\n\tMOVQ SI, 528(AX)\n\tMOVQ DI, 536(AX)\n\tMOVQ R8, 544(AX)\n\tMOVQ R9, 552(AX)\n\tMOVQ R10, 560(AX)\n\tMOVQ R11, 568(AX)\n\tMOVQ R12, 576(AX)\n\tMOVQ R13, 584(AX)\n\tMOVQ R15, 592(AX)\n\tMOVOU X0, 0(AX)\n\tMOVOU X1, 16(AX)\n\tMOVOU X2, 32(AX)\n\tMOVOU X3, 48(AX)\n\tMOVOU X4, 64(AX)\n\tMOVOU X5, 80(AX)\n\tMOVOU X6, 96(AX)\n\tMOVOU X7, 112(AX)\n\tMOVOU X8, 128(AX)\n\tMOVOU X9, 144(AX)\n\tMOVOU X10, 160(AX)\n\tMOVOU X11, 176(AX)\n\tMOVOU X12, 192(AX)\n\tMOVOU X13, 208(AX)\n\tMOVOU X14, 224(AX)\n\tMOVOU X15, 240(AX)\n\tMOVBLZX avx512+8(FP), CX\n\tTESTQ CX, CX\n\tJZ dumpDone\n\tVMOVDQU64 X16, 256(AX)\n\tVMOVDQU64 X17, 272(AX)\n\tVMOVDQU64 X18, 288(AX)\n\tVMOVDQU64 X19, 304(AX)\n\tVMOVDQU64 X20, 320(AX)\n\tVMOVDQU64 X21, 336(AX)\n\tVMOVDQU64 X22, 352(AX)\n\tVMOVDQU64 X23, 368(AX)\n\tVMOVDQU64 X24, 384(AX)\n\tVMOVDQU64 X25, 400(AX)\n\tVMOVDQU64 X26, 416(AX)\n\tVMOVDQU64 X27, 432(AX)\n\tVMOVDQU64 X28, 448(AX)\n\tVMOVDQU64 X29, 464(AX)\n\tVMOVDQU64 X30, 480(AX)\n\tVMOVDQU64 X31, 496(AX)\ndumpDone:\n\tPXOR X2, X2\n\tXORQ R12, R12\n\tXORQ AX, AX\n\tXORQ CX, CX\n\tRET\n\n// func dirtySIMDRegForTest(masked uint64)\nTEXT ·dirtySIMDRegForTest(SB), NOSPLIT, $0-8\n\tMOVQ masked+0(FP), R12\n\tMOVQ $0x5555555555555555, AX\n\tXORQ AX, R12\n\tMOVQ R12, X2\n\tXORQ AX, AX\n\tRET\n'
    files["blake2b_fusedchain256_13x4_neon_arm64.s"] += '\n// func dumpSIMDRegs(dst *[88]uint64, avx512 bool)\nTEXT ·dumpSIMDRegs(SB), NOSPLIT, $0-9\n\tMOVD dst+0(FP), R0\n\tMOVD R1, 512(R0)\n\tMOVD R2, 520(R0)\n\tMOVD R3, 528(R0)\n\tMOVD R4, 536(R0)\n\tMOVD R5, 544(R0)\n\tMOVD R6, 552(R0)\n\tMOVD R7, 560(R0)\n\tMOVD R8, 568(R0)\n\tMOVD R9, 576(R0)\n\tMOVD R10, 584(R0)\n\tMOVD R11, 592(R0)\n\tMOVD R12, 600(R0)\n\tMOVD R13, 608(R0)\n\tMOVD R14, 616(R0)\n\tMOVD R15, 624(R0)\n\tMOVD R16, 632(R0)\n\tMOVD R17, 640(R0)\n\tMOVD R19, 648(R0)\n\tMOVD R20, 656(R0)\n\tMOVD R21, 664(R0)\n\tMOVD R22, 672(R0)\n\tMOVD R23, 680(R0)\n\tMOVD R24, 688(R0)\n\tMOVD R25, 696(R0)\n\tVST1.P [V0.B16, V1.B16, V2.B16, V3.B16], 64(R0)\n\tVST1.P [V4.B16, V5.B16, V6.B16, V7.B16], 64(R0)\n\tVST1.P [V8.B16, V9.B16, V10.B16, V11.B16], 64(R0)\n\tVST1.P [V12.B16, V13.B16, V14.B16, V15.B16], 64(R0)\n\tVST1.P [V16.B16, V17.B16, V18.B16, V19.B16], 64(R0)\n\tVST1.P [V20.B16, V21.B16, V22.B16, V23.B16], 64(R0)\n\tVST1.P [V24.B16, V25.B16, V26.B16, V27.B16], 64(R0)\n\tVST1 [V28.B16, V29.B16, V30.B16, V31.B16], (R0)\n\tVEOR V2.B16, V2.B16, V2.B16\n\tMOVD ZR, R12\n\tMOVD ZR, R0\n\tRET\n\n// func dirtySIMDRegForTest(masked uint64)\nTEXT ·dirtySIMDRegForTest(SB), NOSPLIT, $0-8\n\tMOVD masked+0(FP), R12\n\tMOVD $0x5555555555555555, R0\n\tEOR R0, R12, R12\n\tVMOV R12, V2.D[0]\n\tMOVD ZR, R0\n\tRET\n'
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
