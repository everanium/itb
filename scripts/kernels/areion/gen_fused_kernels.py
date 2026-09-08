#!/usr/bin/env python3
"""Emit the Areion-SoEM fused ChainHash cascade kernels for internal/areionasm.

One file per (width, shape, lanes, tier). Widths 256 (Areion-SoEM-256:
two 16-byte state blocks, 24-byte absorb chunk, 32-byte fixed key, four
component words per cascade group) and 512 (four blocks, 56-byte chunk,
64-byte fixed key, eight words per group); shapes 13 / 20 / 36 / 68;
lanes x4 (four data lanes over one shared component slice) and x1; amd64
tiers avx512 (VAES on ZMM, four lanes per register), vaesavx2 (VAES on
YMM, two lanes per pass, two passes) and aesni (legacy-SSE AES-NI on XMM,
two lanes per pass at width 256, one lane per pass at width 512, the
single-lane arm of both tiers); arm64 tier neon (ARM Crypto Extension,
two lanes per pass at width 256, one at width 512).

The avx512 tier additionally carries areion_fusedchain256_13x8_avx512_amd64.s,
the batch-16 Interlocked Barrier fill kernel of width 256: eight lanes in
two ZMM groups whose cascade rounds are interleaved instruction by
instruction (four independent VAESENC chains per permutation instead of
the two a single lane group exposes), with the eight 13-byte fill blocks
[0x03 | LE64(groupIdxBase+i) | 4×0x00] synthesised in-register from
groupIdxBase. Width 512 has no dedicated fill kernel: its batch-16 hook
covers four groups per call, exactly the x4 kernel over Go-synthesised
blocks, and so do the YMM / XMM / NEON tiers of width 256.

Cascade evaluated per lane (see areionasm_fused.go):
    h = 0
    for each component group g (4 words at width 256, 8 at 512):
        k2 = LE(g) ^ h                         # seed of this round
        state = S0                             # [LE64(len) | data[0:chunk] | 0…]
        for each absorb chunk c:
            if c > 0: state ^= X_c             # [0(8) | data chunk c | 0…]
            s1 = state ^ K1                    # K1 = fixed key
            s2 = state ^ k2 ^ D                # D = 0x01 in byte 0
            state = P(s1) ^ P(s2)              # Areion permutation, SoEM
        h = state
    out = h
which is Seed{256,512}.ChainHash over the root package's Areion-SoEM
chain-absorb closure: the length-tagged first chunk, the XOR absorb of
every further chunk, and the (single, batched) arms' fixed-key ‖ seed
SoEM keying, with the seed re-derived from the previous round's output
XOR the component group. The message blocks S0 / X_c are data-invariant
across cascade rounds and are staged once per call (GPR stores into the
frame, then one vector load per block); the tiers with register room keep
them in registers, the others read them back as memory operands. The
domain-separation constant D is folded into k2's first block once per
group. The SoEM keys K1 / k2 never leave registers on the ZMM tier; the
YMM width-512 and XMM tiers hold k2 in the frame.

Load shapes follow the stores the Go call sites leave in flight: the
caller writes a 4-byte pixel index at offset 0 of every lane buffer
immediately before the call, so data[0:8] is staged as two 4-byte loads.
Outputs are written as 16-byte stores (one per state block per lane) on
every tier, the width the Go side reads them back with.

Register plans:
    zmm 256 x4    Z0/Z1 s1, Z4/Z5 s2, Z2/Z6 temps, Z3 zero, Z8/Z9 K1,
                  Z10/Z11 k2, Z12 D, Z13 scratch, Z14/Z15 state, Z16..Z25
                  RC[0..9], Z26.. staged blocks (S0, X1, X2)
    zmm 256 x8    group A: Z0/Z1 s1, Z4/Z5 s2, Z2/Z6 temps, Z10/Z11 k2,
                  Z14/Z15 state, Z24/Z25 S0; group B: Z16/Z17, Z20/Z21,
                  Z18/Z22, Z26/Z27, Z30/Z31, Z28/Z29; shared Z3 zero,
                  Z8/Z9 K1, Z12 D, Z7 / Z13 / Z19 / Z23 scratch; RC as
                  memory operands
    zmm 512 x4    Z0..Z3 s1, Z8..Z11 s2, Z4/Z5/Z12/Z13 temps, Z6 zero, Z7
                  scratch, Z14..Z17 state, Z18..Z21 K1, Z22..Z25 k2,
                  Z26..Z31 staged blocks; RC and D as memory operands
    ymm 256 x4    Y0/Y1 s1, Y2/Y3 s2, Y4/Y5 temps, Y6 zero, Y7 scratch,
                  Y8/Y9 state, Y10/Y11 K1, Y12 D, Y13/Y14 k2; RC and the
                  staged blocks as memory operands
    ymm 512 x4    Y0..Y3 s1 and state, Y8..Y11 s2, Y4/Y5/Y12/Y13 temps,
                  Y6 zero, Y7 scratch; K1 broadcast from the key pointer,
                  k2 in the frame, RC / D / staged blocks as memory operands
    xmm 256       X0..X3 lane A (s1 a/b, s2 a/b), X4..X7 lane B, X8..X11
                  temps, X12 zero, X13 RC, X14/X15 K1; k2 in the frame
                  (x4) or X6/X7 (x1); staged blocks reloaded from the frame
    xmm 512       X0..X3 s1, X4..X7 s2, X8..X11 temps, X12 zero, X13 RC,
                  X14/X15 scratch; K1 from the key pointer, k2 in the frame
    neon 256      V0..V3 lane A, V4..V7 lane B, V8..V11 temps, V12 zero,
                  V13 RC, V14/V15 K1, V16..V19 k2, V20..V23 S0, V24..V27
                  X1, V28..V31 X2
    neon 512      V0..V3 s1, V4..V7 s2, V8..V11 temps, V12 zero, V13 RC,
                  V14..V17 K1, V18..V21 k2, V22..V25 S0, V26/V27 X1
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "internal", "areionasm")
SHAPES = [13, 20, 36, 68]
AMD = "amd64 && !purego && !noitbasm"
ARM = "arm64 && !purego && !noitbasm"
WIDTHS = {
    256: dict(nb=2, chunk=24, key=32, rounds=10, words=4),
    512: dict(nb=4, chunk=56, key=64, rounds=15, words=8),
}
RC = "·AreionRC4x"
DSEP = "·AreionSoEMDomainSep256"


# ---------------------------------------------------------------- layout --

def chunk_maps(width, n):
    """Byte maps of every absorb chunk: chunk 0 is the initial state, the
    others the XOR patterns. Each chunk is a list of nb blocks; each block
    a list of 16 entries ('len',) / ('zero',) / ('data', i)."""
    w = WIDTHS[width]
    chunks, off, c = [], 0, 0
    while True:
        blocks = []
        for b in range(w["nb"]):
            m = []
            for s in range(16 * b, 16 * b + 16):
                if s < 8:
                    m.append(("len",) if c == 0 else ("zero",))
                else:
                    d = off + (s - 8)
                    if s - 8 < w["chunk"] and d < n:
                        m.append(("data", d))
                    else:
                        m.append(("zero",))
            blocks.append(m)
        chunks.append(blocks)
        off += w["chunk"]
        c += 1
        if off >= n:
            break
    return chunks


def nonzero(m):
    return any(e[0] != "zero" for e in m)


def runs(m):
    """Split a block map into runs (kind, slot offset, length, data start)."""
    out, i = [], 0
    while i < 16:
        k = m[i][0]
        j = i + 1
        while j < 16 and m[j][0] == k and (k != "data" or m[j][1] == m[j - 1][1] + 1):
            j += 1
        out.append((k, i, j - i, m[i][1] if k == "data" else None))
        i = j
    return out


class Frame:
    def __init__(self):
        self.size = 0
        self.slots = {}

    def alloc(self, key, size):
        off = self.size
        self.size += size
        self.slots[key] = off
        return off

    @property
    def aligned(self):
        return (self.size + 15) // 16 * 16


def pieces(length, d, split_head):
    """Greedy 8/4/2/1-byte pieces; the first eight data bytes go as 4-byte
    pieces so the caller's 4-byte pixel-index store forwards."""
    out = []
    while length > 0:
        if split_head and d is not None and d < 8:
            sz = min(4, 8 - d, length)
            sz = 4 if sz >= 4 else (2 if sz >= 2 else 1)
        else:
            sz = 8 if length >= 8 else (4 if length >= 4 else (2 if length >= 2 else 1))
        out.append(sz)
        length -= sz
        if d is not None:
            d += sz
    return out


# --------------------------------------------------------- amd64 staging --

AMD_LOAD = {8: "MOVQ", 4: "MOVL", 2: "MOVWLZX", 1: "MOVBLZX"}
AMD_STORE = {8: "MOVQ", 4: "MOVL", 2: "MOVW", 1: "MOVB"}


def stage_amd64(width, n, lanes, lane_regs, frame, tmp="R12"):
    """Stage every non-zero block of every chunk into the frame in SoA
    layout (block slot = 16 * lanes bytes, lane l at +16*l)."""
    lines = []
    for c, blocks in enumerate(chunk_maps(width, n)):
        for b, m in enumerate(blocks):
            if not nonzero(m):
                continue
            base = frame.alloc((c, b), 16 * lanes)
            for l in range(lanes):
                r = lane_regs[l]
                o = base + 16 * l
                for kind, so, ln, d in runs(m):
                    if kind == "len":
                        lines.append(f"\tMOVQ ${n}, {o + so}(SP)")
                    elif kind == "zero":
                        p = so
                        for sz in pieces(ln, None, False):
                            lines.append(f"\t{AMD_STORE[sz]} $0, {o + p}(SP)")
                            p += sz
                    else:
                        p, dd = so, d
                        for sz in pieces(ln, d, True):
                            lines.append(f"\t{AMD_LOAD[sz]} {dd}({r}), {tmp}")
                            lines.append(f"\t{AMD_STORE[sz]} {tmp}, {o + p}(SP)")
                            p += sz
                            dd += sz
    return lines


def prologue_amd64(lanes, ptr_kind):
    lines = ["\tMOVQ fixedKey+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX"]
    if ptr_kind == "x4":
        lines.append("\tMOVQ dataPtrs+24(FP), DX")
        for i, r in enumerate(["R8", "R9", "R10", "R11"]):
            lines.append(f"\tMOVQ {8 * i}(DX), {r}")
    elif ptr_kind == "x1":
        lines.append("\tMOVQ data+24(FP), R8")
    lines.append("\tMOVQ out+32(FP), DX")
    return lines


def header(build, width, n, lanes, tier_desc, fill=False):
    w = WIDTHS[width]
    nch = len(chunk_maps(width, n))
    what = "batch-16 Interlocked Barrier fill kernel" if fill else "fused ChainHash cascade kernel"
    return f"""//go:build {build}

// {tier_desc} {what} for Areion-SoEM-{width} at the
// {n}-byte shape, {lanes} lane{'s' if lanes > 1 else ''} ({nch} absorb chunk{'s' if nch > 1 else ''}, {nch} SoEM evaluation{'s' if nch > 1 else ''} —
// {2 * nch} {w['rounds']}-round Areion-{width} permutations — per cascade round). The message
// blocks are staged once per call; see areionasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"
"""


# ------------------------------------------------------------- zmm 256 --

def zmm256_round(s1a, s1b, s2a, s2b, rc, ta="Z2", tb="Z6", zero="Z3"):
    return [f"\tVMOVDQA64 {s1a}, {ta}", f"\tVMOVDQA64 {s2a}, {tb}",
            f"\tVAESENC {rc}, {ta}, {ta}", f"\tVAESENC {rc}, {tb}, {tb}",
            f"\tVAESENC {s1b}, {ta}, {ta}", f"\tVAESENC {s2b}, {tb}, {tb}",
            f"\tVAESENCLAST {zero}, {s1a}, {s1a}", f"\tVAESENCLAST {zero}, {s2a}, {s2a}",
            f"\tVMOVDQA64 {ta}, {s1b}", f"\tVMOVDQA64 {tb}, {s2b}"]


def zmm256_perm(s1, s2, rc_of):
    lines = []
    for r in range(10):
        a, b = (0, 1) if r % 2 == 0 else (1, 0)
        lines += zmm256_round(s1[a], s1[b], s2[a], s2[b], rc_of(r))
    return lines


def zmm256_x4(n):
    frame = Frame()
    lines = header(AMD, 256, n, 4, "AVX-512 + VAES ZMM (four lanes per register)")
    body = prologue_amd64(4, "x4")
    body += stage_amd64(256, n, 4, ["R8", "R9", "R10", "R11"], frame)
    body += ["\tVPXORD Z3, Z3, Z3", "\tVBROADCASTI32X4 0(AX), Z8", "\tVBROADCASTI32X4 16(AX), Z9",
             f"\tVMOVDQU64 {DSEP}(SB), Z12"]
    body += [f"\tVMOVDQU64 {RC}+{64 * r}(SB), Z{16 + r}" for r in range(10)]
    chunks = chunk_maps(256, n)
    reg = {}
    nxt = 26
    for c, blocks in enumerate(chunks):
        for b, m in enumerate(blocks):
            if nonzero(m):
                reg[(c, b)] = f"Z{nxt}"
                body.append(f"\tVMOVDQU64 {frame.slots[(c, b)]}(SP), Z{nxt}")
                nxt += 1
    body += ["\tVPXORD Z14, Z14, Z14", "\tVPXORD Z15, Z15, Z15", "", "loop:"]
    body += ["\tVBROADCASTI32X4 0(BX), Z13", "\tVPXORD Z13, Z14, Z10", "\tVPXORD Z12, Z10, Z10",
             "\tVBROADCASTI32X4 16(BX), Z13", "\tVPXORD Z13, Z15, Z11", "\tADDQ $32, BX"]
    st = ["Z14", "Z15"]
    k1 = ["Z8", "Z9"]
    k2 = ["Z10", "Z11"]
    s1 = ["Z0", "Z1"]
    s2 = ["Z4", "Z5"]
    for c, blocks in enumerate(chunks):
        if c == 0:
            for b in range(2):
                src = reg.get((0, b))
                if src is None:
                    body += [f"\tVMOVDQA64 {k1[b]}, {s1[b]}", f"\tVMOVDQA64 {k2[b]}, {s2[b]}"]
                else:
                    body += [f"\tVPXORD {k1[b]}, {src}, {s1[b]}", f"\tVPXORD {k2[b]}, {src}, {s2[b]}"]
        else:
            for b in range(2):
                if (c, b) in reg:
                    body.append(f"\tVPXORD {reg[(c, b)]}, {st[b]}, {st[b]}")
            for b in range(2):
                body += [f"\tVPXORD {k1[b]}, {st[b]}, {s1[b]}", f"\tVPXORD {k2[b]}, {st[b]}, {s2[b]}"]
        body += zmm256_perm(s1, s2, lambda r: f"Z{16 + r}")
        body += [f"\tVPXORD {s2[b]}, {s1[b]}, {st[b]}" for b in range(2)]
    body += ["\tDECQ CX", "\tJNZ loop", ""]
    for l in range(4):
        body += [f"\tVEXTRACTI64X2 ${l}, Z14, {32 * l}(DX)", f"\tVEXTRACTI64X2 ${l}, Z15, {32 * l + 16}(DX)"]
    body += ["\tVZEROUPPER", "\tRET"]
    sig = f"// func areion256FusedChain{n}x4Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)"
    return lines + f"\n{sig}\nTEXT ·areion256FusedChain{n}x4Avx512Asm(SB), NOSPLIT, ${frame.aligned}-40\n" + "\n".join(body) + "\n"


def zmm256_x8():
    """Batch-16 fill kernel of width 256: eight lanes in two interleaved
    ZMM groups, blocks synthesised in-register."""
    lines = header(AMD, 256, 13, 8, "AVX-512 + VAES ZMM (two interleaved four-lane groups)", fill=True)
    lines += """
// areionFill13<>: per-group lane index offsets in the low qword of each
// 128-bit lane slot (group A lanes 0..3, group B lanes 4..7), the 13-byte
// length tag and the 0x03 domain tag as qword vectors.
DATA areionFill13<>+0x000(SB)/8, $0
DATA areionFill13<>+0x008(SB)/8, $0
DATA areionFill13<>+0x010(SB)/8, $1
DATA areionFill13<>+0x018(SB)/8, $0
DATA areionFill13<>+0x020(SB)/8, $2
DATA areionFill13<>+0x028(SB)/8, $0
DATA areionFill13<>+0x030(SB)/8, $3
DATA areionFill13<>+0x038(SB)/8, $0
DATA areionFill13<>+0x040(SB)/8, $4
DATA areionFill13<>+0x048(SB)/8, $0
DATA areionFill13<>+0x050(SB)/8, $5
DATA areionFill13<>+0x058(SB)/8, $0
DATA areionFill13<>+0x060(SB)/8, $6
DATA areionFill13<>+0x068(SB)/8, $0
DATA areionFill13<>+0x070(SB)/8, $7
DATA areionFill13<>+0x078(SB)/8, $0
"""
    for i in range(8):
        lines += f"DATA areionFill13<>+0x{0x80 + 8 * i:03x}(SB)/8, $13\n"
    for i in range(8):
        lines += f"DATA areionFill13<>+0x{0xC0 + 8 * i:03x}(SB)/8, $3\n"
    lines += "GLOBL areionFill13<>(SB), RODATA|NOPTR, $256\n"
    body = ["\tMOVQ fixedKey+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX", "\tMOVQ out+32(FP), DX"]
    body += ["\tVPXORD Z3, Z3, Z3", "\tVBROADCASTI32X4 0(AX), Z8", "\tVBROADCASTI32X4 16(AX), Z9",
             f"\tVMOVDQU64 {DSEP}(SB), Z12",
             "\tVPBROADCASTQ groupIdxBase+24(FP), Z13",
             "\tVMOVDQU64 areionFill13<>+128(SB), Z19",
             "\tVPADDQ areionFill13<>+0(SB), Z13, Z7",
             "\tVPADDQ areionFill13<>+64(SB), Z13, Z23",
             "\tVPSLLQ $8, Z7, Z24", "\tVPORQ areionFill13<>+192(SB), Z24, Z24", "\tVPUNPCKLQDQ Z24, Z19, Z24",
             "\tVPSRLQ $56, Z7, Z25", "\tVPUNPCKLQDQ Z3, Z25, Z25",
             "\tVPSLLQ $8, Z23, Z28", "\tVPORQ areionFill13<>+192(SB), Z28, Z28", "\tVPUNPCKLQDQ Z28, Z19, Z28",
             "\tVPSRLQ $56, Z23, Z29", "\tVPUNPCKLQDQ Z3, Z29, Z29",
             "\tVPXORD Z14, Z14, Z14", "\tVPXORD Z15, Z15, Z15", "\tVPXORD Z30, Z30, Z30", "\tVPXORD Z31, Z31, Z31",
             "", "loop:"]
    body += ["\tVBROADCASTI32X4 0(BX), Z13", "\tVPXORD Z13, Z14, Z10", "\tVPXORD Z12, Z10, Z10",
             "\tVPXORD Z13, Z30, Z26", "\tVPXORD Z12, Z26, Z26",
             "\tVBROADCASTI32X4 16(BX), Z13", "\tVPXORD Z13, Z15, Z11", "\tVPXORD Z13, Z31, Z27",
             "\tADDQ $32, BX"]
    body += ["\tVPXORD Z8, Z24, Z0", "\tVPXORD Z8, Z28, Z16", "\tVPXORD Z9, Z25, Z1", "\tVPXORD Z9, Z29, Z17",
             "\tVPXORD Z10, Z24, Z4", "\tVPXORD Z26, Z28, Z20", "\tVPXORD Z11, Z25, Z5", "\tVPXORD Z27, Z29, Z21"]
    for r in range(10):
        a, b = (0, 1) if r % 2 == 0 else (1, 0)
        ra = zmm256_round(["Z0", "Z1"][a], ["Z0", "Z1"][b], ["Z4", "Z5"][a], ["Z4", "Z5"][b], f"{RC}+{64 * r}(SB)")
        rb = zmm256_round(["Z16", "Z17"][a], ["Z16", "Z17"][b], ["Z20", "Z21"][a], ["Z20", "Z21"][b],
                          f"{RC}+{64 * r}(SB)", ta="Z18", tb="Z22")
        for x, y in zip(ra, rb):
            body += [x, y]
    body += ["\tVPXORD Z4, Z0, Z14", "\tVPXORD Z20, Z16, Z30", "\tVPXORD Z5, Z1, Z15", "\tVPXORD Z21, Z17, Z31"]
    body += ["\tDECQ CX", "\tJNZ loop", ""]
    for l in range(4):
        body += [f"\tVEXTRACTI64X2 ${l}, Z14, {32 * l}(DX)", f"\tVEXTRACTI64X2 ${l}, Z15, {32 * l + 16}(DX)"]
    for l in range(4):
        body += [f"\tVEXTRACTI64X2 ${l}, Z30, {128 + 32 * l}(DX)", f"\tVEXTRACTI64X2 ${l}, Z31, {128 + 32 * l + 16}(DX)"]
    body += ["\tVZEROUPPER", "\tRET"]
    sig = "// func areion256FusedChain13x8Avx512Asm(fixedKey *[32]byte, comps *uint64, nGroups int, groupIdxBase uint64, out *[8][4]uint64)"
    return lines + f"\n{sig}\nTEXT ·areion256FusedChain13x8Avx512Asm(SB), NOSPLIT, $0-40\n" + "\n".join(body) + "\n"


# ------------------------------------------------------------- zmm 512 --

def zmm512_round(s1, s2, rc, zero="Z6", t=("Z4", "Z5", "Z12", "Z13")):
    a, b, c, d = s1
    e, f, g, h = s2
    return [f"\tVMOVDQA64 {a}, {t[0]}", f"\tVMOVDQA64 {e}, {t[2]}",
            f"\tVAESENC {zero}, {t[0]}, {t[0]}", f"\tVAESENC {zero}, {t[2]}, {t[2]}",
            f"\tVPXORD {t[0]}, {b}, {b}", f"\tVPXORD {t[2]}, {f}, {f}",
            f"\tVMOVDQA64 {c}, {t[1]}", f"\tVMOVDQA64 {g}, {t[3]}",
            f"\tVAESENC {zero}, {t[1]}, {t[1]}", f"\tVAESENC {zero}, {t[3]}, {t[3]}",
            f"\tVPXORD {t[1]}, {d}, {d}", f"\tVPXORD {t[3]}, {h}, {h}",
            f"\tVAESENCLAST {zero}, {a}, {a}", f"\tVAESENCLAST {zero}, {e}, {e}",
            f"\tVAESENCLAST {rc}, {c}, {c}", f"\tVAESENCLAST {rc}, {g}, {g}",
            f"\tVAESENC {zero}, {c}, {c}", f"\tVAESENC {zero}, {g}, {g}"]


def roles(regs, r):
    return [regs[(r + i) % 4] for i in range(4)]


def zmm512_perm(s1, s2):
    lines = []
    for r in range(15):
        lines += zmm512_round(roles(s1, r), roles(s2, r), f"{RC}+{64 * r}(SB)")
    return lines


ROT = [3, 0, 1, 2]  # output block b comes from permutation register ROT[b]


def zmm512_x4(n):
    frame = Frame()
    lines = header(AMD, 512, n, 4, "AVX-512 + VAES ZMM (four lanes per register)")
    body = prologue_amd64(4, "x4")
    body += stage_amd64(512, n, 4, ["R8", "R9", "R10", "R11"], frame)
    body += ["\tVPXORD Z6, Z6, Z6"] + [f"\tVBROADCASTI32X4 {16 * b}(AX), Z{18 + b}" for b in range(4)]
    chunks = chunk_maps(512, n)
    reg = {}
    nxt = 26
    for c, blocks in enumerate(chunks):
        for b, m in enumerate(blocks):
            if nonzero(m):
                reg[(c, b)] = f"Z{nxt}"
                body.append(f"\tVMOVDQU64 {frame.slots[(c, b)]}(SP), Z{nxt}")
                nxt += 1
    st = [f"Z{14 + b}" for b in range(4)]
    k1 = [f"Z{18 + b}" for b in range(4)]
    k2 = [f"Z{22 + b}" for b in range(4)]
    s1 = [f"Z{b}" for b in range(4)]
    s2 = [f"Z{8 + b}" for b in range(4)]
    body += [f"\tVPXORD {s}, {s}, {s}" for s in st] + ["", "loop:"]
    for b in range(4):
        body += [f"\tVBROADCASTI32X4 {16 * b}(BX), Z7", f"\tVPXORD Z7, {st[b]}, {k2[b]}"]
        if b == 0:
            body.append(f"\tVPXORD {DSEP}(SB), {k2[0]}, {k2[0]}")
    body.append("\tADDQ $64, BX")
    for c, blocks in enumerate(chunks):
        if c == 0:
            for b in range(4):
                src = reg.get((0, b))
                if src is None:
                    body += [f"\tVMOVDQA64 {k1[b]}, {s1[b]}", f"\tVMOVDQA64 {k2[b]}, {s2[b]}"]
                else:
                    body += [f"\tVPXORD {k1[b]}, {src}, {s1[b]}", f"\tVPXORD {k2[b]}, {src}, {s2[b]}"]
        else:
            for b in range(4):
                if (c, b) in reg:
                    body.append(f"\tVPXORD {reg[(c, b)]}, {st[b]}, {st[b]}")
            for b in range(4):
                body += [f"\tVPXORD {k1[b]}, {st[b]}, {s1[b]}", f"\tVPXORD {k2[b]}, {st[b]}, {s2[b]}"]
        body += zmm512_perm(s1, s2)
        body += [f"\tVPXORD {s2[ROT[b]]}, {s1[ROT[b]]}, {st[b]}" for b in range(4)]
    body += ["\tDECQ CX", "\tJNZ loop", ""]
    for l in range(4):
        body += [f"\tVEXTRACTI64X2 ${l}, {st[b]}, {64 * l + 16 * b}(DX)" for b in range(4)]
    body += ["\tVZEROUPPER", "\tRET"]
    sig = f"// func areion512FusedChain{n}x4Avx512Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)"
    return lines + f"\n{sig}\nTEXT ·areion512FusedChain{n}x4Avx512Asm(SB), NOSPLIT, ${frame.aligned}-40\n" + "\n".join(body) + "\n"


# ------------------------------------------------------------- ymm 256 --

def ymm256_round(s1a, s1b, s2a, s2b, r):
    rc = f"{RC}+{64 * r}(SB)"
    return [f"\tVAESENC {rc}, {s1a}, Y4", f"\tVAESENC {rc}, {s2a}, Y5",
            f"\tVAESENC {s1b}, Y4, Y4", f"\tVAESENC {s2b}, Y5, Y5",
            f"\tVAESENCLAST Y6, {s1a}, {s1a}", f"\tVAESENCLAST Y6, {s2a}, {s2a}",
            f"\tVMOVDQA Y4, {s1b}", f"\tVMOVDQA Y5, {s2b}"]


def ymm256_x4(n):
    frame = Frame()
    lines = header(AMD, 256, n, 4, "AVX2 + VAES YMM (two lanes per pass, two passes)")
    body = prologue_amd64(4, "x4")
    body += stage_amd64(256, n, 4, ["R8", "R9", "R10", "R11"], frame)
    body += ["\tVPXOR Y6, Y6, Y6", "\tVBROADCASTI128 0(AX), Y10", "\tVBROADCASTI128 16(AX), Y11",
             f"\tVMOVDQU {DSEP}(SB), Y12"]
    chunks = chunk_maps(256, n)
    for p in range(2):
        body += ["", f"\t// pass {p}: lanes {2 * p}, {2 * p + 1}",
                 "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX",
                 "\tVPXOR Y8, Y8, Y8", "\tVPXOR Y9, Y9, Y9", "", f"loop{p}:"]
        body += ["\tVBROADCASTI128 0(BX), Y7", "\tVPXOR Y7, Y8, Y13", "\tVPXOR Y12, Y13, Y13",
                 "\tVBROADCASTI128 16(BX), Y7", "\tVPXOR Y7, Y9, Y14", "\tADDQ $32, BX"]
        st, k1, k2, s1, s2 = ["Y8", "Y9"], ["Y10", "Y11"], ["Y13", "Y14"], ["Y0", "Y1"], ["Y2", "Y3"]
        for c, blocks in enumerate(chunks):
            if c == 0:
                for b in range(2):
                    if (0, b) in frame.slots:
                        o = frame.slots[(0, b)] + 32 * p
                        body += [f"\tVPXOR {o}(SP), {k1[b]}, {s1[b]}", f"\tVPXOR {o}(SP), {k2[b]}, {s2[b]}"]
                    else:
                        body += [f"\tVMOVDQA {k1[b]}, {s1[b]}", f"\tVMOVDQA {k2[b]}, {s2[b]}"]
            else:
                for b in range(2):
                    if (c, b) in frame.slots:
                        body.append(f"\tVPXOR {frame.slots[(c, b)] + 32 * p}(SP), {st[b]}, {st[b]}")
                for b in range(2):
                    body += [f"\tVPXOR {k1[b]}, {st[b]}, {s1[b]}", f"\tVPXOR {k2[b]}, {st[b]}, {s2[b]}"]
            for r in range(10):
                a, b = (0, 1) if r % 2 == 0 else (1, 0)
                body += ymm256_round(s1[a], s1[b], s2[a], s2[b], r)
            body += [f"\tVPXOR {s2[b]}, {s1[b]}, {st[b]}" for b in range(2)]
        body += ["\tDECQ CX", f"\tJNZ loop{p}"]
        body += [f"\tVEXTRACTI128 $0, Y8, {64 * p}(DX)", f"\tVEXTRACTI128 $0, Y9, {64 * p + 16}(DX)",
                 f"\tVEXTRACTI128 $1, Y8, {64 * p + 32}(DX)", f"\tVEXTRACTI128 $1, Y9, {64 * p + 48}(DX)"]
    body += ["\tVZEROUPPER", "\tRET"]
    sig = f"// func areion256FusedChain{n}x4VaesAvx2Asm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)"
    return lines + f"\n{sig}\nTEXT ·areion256FusedChain{n}x4VaesAvx2Asm(SB), NOSPLIT, ${frame.aligned}-40\n" + "\n".join(body) + "\n"


# ------------------------------------------------------------- ymm 512 --

def ymm512_round(s1, s2, r, zero="Y6", t=("Y4", "Y5", "Y12", "Y13")):
    rc = f"{RC}+{64 * r}(SB)"
    a, b, c, d = s1
    e, f, g, h = s2
    return [f"\tVMOVDQA {a}, {t[0]}", f"\tVMOVDQA {e}, {t[2]}",
            f"\tVAESENC {zero}, {t[0]}, {t[0]}", f"\tVAESENC {zero}, {t[2]}, {t[2]}",
            f"\tVPXOR {t[0]}, {b}, {b}", f"\tVPXOR {t[2]}, {f}, {f}",
            f"\tVMOVDQA {c}, {t[1]}", f"\tVMOVDQA {g}, {t[3]}",
            f"\tVAESENC {zero}, {t[1]}, {t[1]}", f"\tVAESENC {zero}, {t[3]}, {t[3]}",
            f"\tVPXOR {t[1]}, {d}, {d}", f"\tVPXOR {t[3]}, {h}, {h}",
            f"\tVAESENCLAST {zero}, {a}, {a}", f"\tVAESENCLAST {zero}, {e}, {e}",
            f"\tVAESENCLAST {rc}, {c}, {c}", f"\tVAESENCLAST {rc}, {g}, {g}",
            f"\tVAESENC {zero}, {c}, {c}", f"\tVAESENC {zero}, {g}, {g}"]


def ymm512_x4(n):
    frame = Frame()
    lines = header(AMD, 512, n, 4, "AVX2 + VAES YMM (two lanes per pass, two passes)")
    body = prologue_amd64(4, "x4")
    body += stage_amd64(512, n, 4, ["R8", "R9", "R10", "R11"], frame)
    k2off = frame.alloc("k2", 128)
    body += ["\tVPXOR Y6, Y6, Y6"]
    chunks = chunk_maps(512, n)
    s1 = [f"Y{b}" for b in range(4)]
    s2 = [f"Y{8 + b}" for b in range(4)]
    for p in range(2):
        body += ["", f"\t// pass {p}: lanes {2 * p}, {2 * p + 1}",
                 "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX"]
        body += [f"\tVPXOR {s}, {s}, {s}" for s in s1] + ["", f"loop{p}:"]
        for b in range(4):
            body += [f"\tVBROADCASTI128 {16 * b}(BX), Y7", f"\tVPXOR Y7, {s1[b]}, Y7"]
            if b == 0:
                body.append(f"\tVPXOR {DSEP}(SB), Y7, Y7")
            body.append(f"\tVMOVDQU Y7, {k2off + 32 * b}(SP)")
        body.append("\tADDQ $64, BX")
        for c, blocks in enumerate(chunks):
            if c == 0:
                for b in range(4):
                    k2 = f"{k2off + 32 * b}(SP)"
                    body.append(f"\tVBROADCASTI128 {16 * b}(AX), Y7")
                    if (0, b) in frame.slots:
                        o = frame.slots[(0, b)] + 32 * p
                        body += [f"\tVMOVDQU {o}(SP), {s2[b]}", f"\tVPXOR {k2}, {s2[b]}, {s2[b]}",
                                 f"\tVPXOR {o}(SP), Y7, {s1[b]}"]
                    else:
                        body += [f"\tVMOVDQU {k2}, {s2[b]}", f"\tVMOVDQA Y7, {s1[b]}"]
            else:
                for b in range(4):
                    if (c, b) in frame.slots:
                        body.append(f"\tVPXOR {frame.slots[(c, b)] + 32 * p}(SP), {s1[b]}, {s1[b]}")
                for b in range(4):
                    body += [f"\tVPXOR {k2off + 32 * b}(SP), {s1[b]}, {s2[b]}",
                             f"\tVBROADCASTI128 {16 * b}(AX), Y7", f"\tVPXOR Y7, {s1[b]}, {s1[b]}"]
            for r in range(15):
                body += ymm512_round(roles(s1, r), roles(s2, r), r)
            # state = rotate(s1 ^ s2) into Y0..Y3
            body += ["\tVPXOR Y11, Y3, Y12", "\tVPXOR Y8, Y0, Y13", "\tVPXOR Y9, Y1, Y4", "\tVPXOR Y10, Y2, Y5",
                     "\tVMOVDQA Y12, Y0", "\tVMOVDQA Y13, Y1", "\tVMOVDQA Y4, Y2", "\tVMOVDQA Y5, Y3"]
        body += ["\tDECQ CX", f"\tJNZ loop{p}"]
        for b in range(4):
            body += [f"\tVEXTRACTI128 $0, {s1[b]}, {128 * p + 16 * b}(DX)",
                     f"\tVEXTRACTI128 $1, {s1[b]}, {128 * p + 64 + 16 * b}(DX)"]
    body += ["\tVZEROUPPER", "\tRET"]
    sig = f"// func areion512FusedChain{n}x4VaesAvx2Asm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)"
    return lines + f"\n{sig}\nTEXT ·areion512FusedChain{n}x4VaesAvx2Asm(SB), NOSPLIT, ${frame.aligned}-40\n" + "\n".join(body) + "\n"


# ------------------------------------------------------------- xmm 256 --

def xmm256_round(chains, r):
    """chains: list of (a, b) register pairs; temps X8.. in order."""
    lines = [f"\tMOVOU {RC}+{64 * r}(SB), X13"]
    for i, (a, b) in enumerate(chains):
        lines.append(f"\tMOVOU {a}, X{8 + i}")
    for i in range(len(chains)):
        lines.append(f"\tAESENC X13, X{8 + i}")
    for i, (a, b) in enumerate(chains):
        lines.append(f"\tAESENC {b}, X{8 + i}")
    for a, b in chains:
        lines.append(f"\tAESENCLAST X12, {a}")
    for i, (a, b) in enumerate(chains):
        lines.append(f"\tMOVOU X{8 + i}, {b}")
    return lines


def xmm256_perm(states):
    """states: list of (s1a, s1b, s2a, s2b) per lane."""
    lines = []
    for r in range(10):
        chains = []
        for s1a, s1b, s2a, s2b in states:
            if r % 2 == 0:
                chains += [(s1a, s1b), (s2a, s2b)]
            else:
                chains += [(s1b, s1a), (s2b, s2a)]
        lines += xmm256_round(chains, r)
    return lines


def xmm256(n, lanes):
    frame = Frame()
    tier = "AES-NI XMM (two lanes per pass, two passes)" if lanes == 4 else "AES-NI XMM (single lane)"
    lines = header(AMD, 256, n, lanes, tier)
    body = prologue_amd64(lanes, "x4" if lanes == 4 else "x1")
    body += stage_amd64(256, n, lanes, ["R8", "R9", "R10", "R11"][:lanes], frame)
    chunks = chunk_maps(256, n)
    body += ["\tMOVOU 0(AX), X14", "\tMOVOU 16(AX), X15", "\tPXOR X12, X12"]
    if lanes == 4:
        k2off = frame.alloc("k2", 64)
        lane_regs = [("X0", "X1", "X2", "X3"), ("X4", "X5", "X6", "X7")]
        passes = 2
    else:
        lane_regs = [("X0", "X1", "X2", "X3")]
        passes = 1
    for p in range(passes):
        body += ["", f"\t// pass {p}", "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX"]
        for s1a, s1b, _, _ in lane_regs:
            body += [f"\tPXOR {s1a}, {s1a}", f"\tPXOR {s1b}, {s1b}"]
        body += ["", f"loop{p}:"]
        # k2 = comps ^ h (D folded into block 0)
        body.append(f"\tMOVOU {DSEP}(SB), X10")
        for li, (s1a, s1b, s2a, s2b) in enumerate(lane_regs):
            h = [s1a, s1b]
            for b in range(2):
                body += [f"\tMOVOU {16 * b}(BX), X8", f"\tPXOR {h[b]}, X8"]
                if b == 0:
                    body.append("\tPXOR X10, X8")
                if lanes == 4:
                    body.append(f"\tMOVOU X8, {k2off + 32 * li + 16 * b}(SP)")
                else:
                    body.append(f"\tMOVOU X8, X{6 + b}")
        body.append("\tADDQ $32, BX")
        for c, blocks in enumerate(chunks):
            for li, (s1a, s1b, s2a, s2b) in enumerate(lane_regs):
                lane = 2 * p + li
                st, s1, s2 = [s1a, s1b], [s1a, s1b], [s2a, s2b]
                k1 = ["X14", "X15"]
                for b in range(2):
                    k2 = f"{k2off + 32 * li + 16 * b}(SP)" if lanes == 4 else f"X{6 + b}"
                    if c == 0:
                        if (0, b) in frame.slots:
                            o = frame.slots[(0, b)] + 16 * lane
                            body += [f"\tMOVOU {o}(SP), {s1[b]}", f"\tMOVOU {s1[b]}, {s2[b]}", f"\tPXOR {k1[b]}, {s1[b]}"]
                            if lanes == 4:
                                body += [f"\tMOVOU {k2}, X8", f"\tPXOR X8, {s2[b]}"]
                            else:
                                body.append(f"\tPXOR {k2}, {s2[b]}")
                        else:
                            body.append(f"\tMOVOU {k1[b]}, {s1[b]}")
                            body.append(f"\tMOVOU {k2}, {s2[b]}")
                    else:
                        if (c, b) in frame.slots:
                            body += [f"\tMOVOU {frame.slots[(c, b)] + 16 * lane}(SP), X8", f"\tPXOR X8, {st[b]}"]
                        if lanes == 4:
                            body += [f"\tMOVOU {k2}, {s2[b]}", f"\tPXOR {st[b]}, {s2[b]}"]
                        else:
                            body += [f"\tMOVOU {st[b]}, {s2[b]}", f"\tPXOR {k2}, {s2[b]}"]
                        body.append(f"\tPXOR {k1[b]}, {s1[b]}")
            body += xmm256_perm(lane_regs)
            for s1a, s1b, s2a, s2b in lane_regs:
                body += [f"\tPXOR {s2a}, {s1a}", f"\tPXOR {s2b}, {s1b}"]
        body += ["\tDECQ CX", f"\tJNZ loop{p}"]
        for li, (s1a, s1b, _, _) in enumerate(lane_regs):
            lane = 2 * p + li
            body += [f"\tMOVOU {s1a}, {32 * lane}(DX)", f"\tMOVOU {s1b}, {32 * lane + 16}(DX)"]
    body.append("\tRET")
    if lanes == 4:
        sig = f"// func areion256FusedChain{n}x4AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)"
        name = f"areion256FusedChain{n}x4AesNiAsm"
    else:
        sig = f"// func areion256FusedChain{n}x1AesNiAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)"
        name = f"areion256FusedChain{n}x1AesNiAsm"
    return lines + f"\n{sig}\nTEXT ·{name}(SB), NOSPLIT, ${frame.aligned}-40\n" + "\n".join(body) + "\n"


# ------------------------------------------------------------- xmm 512 --

def xmm512_round(s1, s2, r):
    a, b, c, d = s1
    e, f, g, h = s2
    return [f"\tMOVOU {RC}+{64 * r}(SB), X13",
            f"\tMOVOU {a}, X8", f"\tMOVOU {e}, X10", f"\tAESENC X12, X8", f"\tAESENC X12, X10",
            f"\tPXOR X8, {b}", f"\tPXOR X10, {f}",
            f"\tMOVOU {c}, X9", f"\tMOVOU {g}, X11", f"\tAESENC X12, X9", f"\tAESENC X12, X11",
            f"\tPXOR X9, {d}", f"\tPXOR X11, {h}",
            f"\tAESENCLAST X12, {a}", f"\tAESENCLAST X12, {e}",
            f"\tAESENCLAST X13, {c}", f"\tAESENCLAST X13, {g}",
            f"\tAESENC X12, {c}", f"\tAESENC X12, {g}"]


def xmm512(n, lanes):
    frame = Frame()
    tier = "AES-NI XMM (one lane per pass, four passes)" if lanes == 4 else "AES-NI XMM (single lane)"
    lines = header(AMD, 512, n, lanes, tier)
    body = prologue_amd64(lanes, "x4" if lanes == 4 else "x1")
    body += stage_amd64(512, n, lanes, ["R8", "R9", "R10", "R11"][:lanes], frame)
    k2off = frame.alloc("k2", 64)
    chunks = chunk_maps(512, n)
    body += ["\tPXOR X12, X12"]
    s1 = [f"X{b}" for b in range(4)]
    s2 = [f"X{4 + b}" for b in range(4)]
    for p in range(lanes):
        body += ["", f"\t// pass {p}: lane {p}", "\tMOVQ comps+8(FP), BX", "\tMOVQ nGroups+16(FP), CX"]
        body += [f"\tPXOR {s}, {s}" for s in s1] + ["", f"loop{p}:"]
        body.append(f"\tMOVOU {DSEP}(SB), X15")
        for b in range(4):
            body += [f"\tMOVOU {16 * b}(BX), X14", f"\tPXOR {s1[b]}, X14"]
            if b == 0:
                body.append("\tPXOR X15, X14")
            body.append(f"\tMOVOU X14, {k2off + 16 * b}(SP)")
        body.append("\tADDQ $64, BX")
        for c, blocks in enumerate(chunks):
            for b in range(4):
                k2 = f"{k2off + 16 * b}(SP)"
                if c == 0:
                    body.append(f"\tMOVOU {16 * b}(AX), X14")
                    if (0, b) in frame.slots:
                        o = frame.slots[(0, b)] + 16 * p
                        body += [f"\tMOVOU {o}(SP), {s1[b]}", f"\tMOVOU {s1[b]}, {s2[b]}", f"\tPXOR X14, {s1[b]}",
                                 f"\tMOVOU {k2}, X15", f"\tPXOR X15, {s2[b]}"]
                    else:
                        body += [f"\tMOVOU X14, {s1[b]}", f"\tMOVOU {k2}, {s2[b]}"]
                else:
                    if (c, b) in frame.slots:
                        body += [f"\tMOVOU {frame.slots[(c, b)] + 16 * p}(SP), X14", f"\tPXOR X14, {s1[b]}"]
                    body += [f"\tMOVOU {k2}, {s2[b]}", f"\tPXOR {s1[b]}, {s2[b]}",
                             f"\tMOVOU {16 * b}(AX), X14", f"\tPXOR X14, {s1[b]}"]
            for r in range(15):
                body += xmm512_round(roles(s1, r), roles(s2, r), r)
            # state = rotate(s1 ^ s2) into X0..X3
            body += ["\tPXOR X7, X3", "\tPXOR X4, X0", "\tPXOR X5, X1", "\tPXOR X6, X2",
                     "\tMOVOU X3, X8", "\tMOVOU X2, X3", "\tMOVOU X1, X2", "\tMOVOU X0, X1", "\tMOVOU X8, X0"]
        body += ["\tDECQ CX", f"\tJNZ loop{p}"]
        body += [f"\tMOVOU {s1[b]}, {64 * p + 16 * b}(DX)" for b in range(4)]
    body.append("\tRET")
    if lanes == 4:
        sig = f"// func areion512FusedChain{n}x4AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)"
        name = f"areion512FusedChain{n}x4AesNiAsm"
    else:
        sig = f"// func areion512FusedChain{n}x1AesNiAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)"
        name = f"areion512FusedChain{n}x1AesNiAsm"
    return lines + f"\n{sig}\nTEXT ·{name}(SB), NOSPLIT, ${frame.aligned}-40\n" + "\n".join(body) + "\n"


# ---------------------------------------------------------------- neon --

ARM_LOAD = {8: "MOVD", 4: "MOVWU", 2: "MOVHU", 1: "MOVBU"}
ARM_STORE = {8: "MOVD", 4: "MOVW", 2: "MOVH", 1: "MOVB"}


def stage_arm64(width, n, lanes, lane_regs, frame, base="R7", tmp="R12"):
    lines = []
    for c, blocks in enumerate(chunk_maps(width, n)):
        for b, m in enumerate(blocks):
            if not nonzero(m):
                continue
            slot = frame.alloc((c, b), 16 * lanes)
            for l in range(lanes):
                r = lane_regs[l]
                o = slot + 16 * l
                for kind, so, ln, d in runs(m):
                    if kind == "len":
                        lines += [f"\tMOVD ${n}, {tmp}", f"\tMOVD {tmp}, {o + so}({base})"]
                    elif kind == "zero":
                        p = so
                        for sz in pieces(ln, None, False):
                            lines.append(f"\t{ARM_STORE[sz]} ZR, {o + p}({base})")
                            p += sz
                    else:
                        p, dd = so, d
                        for sz in pieces(ln, d, True):
                            lines.append(f"\t{ARM_LOAD[sz]} {dd}({r}), {tmp}")
                            lines.append(f"\t{ARM_STORE[sz]} {tmp}, {o + p}({base})")
                            p += sz
                            dd += sz
    return lines


def neon256_round(chains, r, zero="V12", rc="V13", t0=8):
    """chains: (a, b) pairs; temps V{t0}.. ; rc register already loaded."""
    lines = []
    for i, (a, b) in enumerate(chains):
        lines.append(f"\tVMOV {a}.B16, V{t0 + i}.B16")
    for i in range(len(chains)):
        lines.append(f"\tAESE {zero}.B16, V{t0 + i}.B16")
    for i in range(len(chains)):
        lines.append(f"\tAESMC V{t0 + i}.B16, V{t0 + i}.B16")
    for i in range(len(chains)):
        lines.append(f"\tAESE {rc}.B16, V{t0 + i}.B16")
    for i in range(len(chains)):
        lines.append(f"\tAESMC V{t0 + i}.B16, V{t0 + i}.B16")
    for i, (a, b) in enumerate(chains):
        lines.append(f"\tVEOR {b}.B16, V{t0 + i}.B16, V{t0 + i}.B16")
    for a, b in chains:
        lines.append(f"\tAESE {zero}.B16, {a}.B16")
    for i, (a, b) in enumerate(chains):
        lines.append(f"\tVMOV V{t0 + i}.B16, {b}.B16")
    return lines


def neon256_perm(states):
    lines = ["\tMOVD $·AreionRCTable(SB), R5"]
    for r in range(10):
        lines.append("\tVLD1.P 16(R5), [V13.B16]")
        chains = []
        for s1a, s1b, s2a, s2b in states:
            if r % 2 == 0:
                chains += [(s1a, s1b), (s2a, s2b)]
            else:
                chains += [(s1b, s1a), (s2b, s2a)]
        lines += neon256_round(chains, r)
    return lines


def neon_prologue(ptr_kind):
    lines = ["\tMOVD fixedKey+0(FP), R0", "\tMOVD comps+8(FP), R1", "\tMOVD nGroups+16(FP), R2"]
    if ptr_kind == "x4":
        lines.append("\tMOVD dataPtrs+24(FP), R3")
        for i, r in enumerate(["R8", "R9", "R10", "R11"]):
            lines.append(f"\tMOVD {8 * i}(R3), {r}")
    else:
        lines.append("\tMOVD data+24(FP), R8")
    lines.append("\tMOVD out+32(FP), R4")
    return lines


def neon256(n, lanes):
    frame = Frame()
    tier = "NEON + ARM Crypto Extension (two lanes per pass, two passes)" if lanes == 4 else "NEON + ARM Crypto Extension (single lane)"
    lines = header(ARM, 256, n, lanes, tier)
    body = neon_prologue("x4" if lanes == 4 else "x1")
    chunks = chunk_maps(256, n)
    # frame: staging + D slot
    body_stage = stage_arm64(256, n, lanes, ["R8", "R9", "R10", "R11"][:lanes], frame)
    doff = frame.alloc("d", 16)
    body.append(f"\tMOVD $frame-{frame.aligned}(SP), R7")
    body += body_stage
    body += ["\tMOVD $1, R12", f"\tMOVD R12, {doff}(R7)", f"\tMOVD ZR, {doff + 8}(R7)"]
    body += ["\tVEOR V12.B16, V12.B16, V12.B16", "\tVLD1 (R0), [V14.B16, V15.B16]"]
    lane_regs = [("V0", "V1", "V2", "V3"), ("V4", "V5", "V6", "V7")] if lanes == 4 else [("V0", "V1", "V2", "V3")]
    k2 = [("V16", "V17"), ("V18", "V19")]
    passes = 2 if lanes == 4 else 1
    for p in range(passes):
        body += ["", f"\t// pass {p}"]
        # staged blocks into V20.. per lane of this pass
        reg = {}
        nxt = 20
        for c, blocks in enumerate(chunks):
            for b in range(2):
                if (c, b) in frame.slots:
                    for li in range(len(lane_regs)):
                        lane = 2 * p + li
                        body += [f"\tADD ${frame.slots[(c, b)] + 16 * lane}, R7, R6", f"\tVLD1 (R6), [V{nxt}.B16]"]
                        reg[(c, b, li)] = f"V{nxt}"
                        nxt += 1
        body += ["\tMOVD comps+8(FP), R1", "\tMOVD nGroups+16(FP), R2"]
        for s1a, s1b, _, _ in lane_regs:
            body += [f"\tVEOR {s1a}.B16, {s1a}.B16, {s1a}.B16", f"\tVEOR {s1b}.B16, {s1b}.B16, {s1b}.B16"]
        body += ["", f"loop{p}:"]
        body += ["\tVLD1.P 32(R1), [V8.B16, V9.B16]", f"\tADD ${doff}, R7, R6", "\tVLD1 (R6), [V10.B16]"]
        for li, (s1a, s1b, _, _) in enumerate(lane_regs):
            body += [f"\tVEOR {s1a}.B16, V8.B16, {k2[li][0]}.B16", f"\tVEOR V10.B16, {k2[li][0]}.B16, {k2[li][0]}.B16",
                     f"\tVEOR {s1b}.B16, V9.B16, {k2[li][1]}.B16"]
        for c, blocks in enumerate(chunks):
            for li, (s1a, s1b, s2a, s2b) in enumerate(lane_regs):
                st, s1, s2 = [s1a, s1b], [s1a, s1b], [s2a, s2b]
                k1 = ["V14", "V15"]
                for b in range(2):
                    if c == 0:
                        src = reg.get((0, b, li))
                        if src is None:
                            body += [f"\tVMOV {k1[b]}.B16, {s1[b]}.B16", f"\tVMOV {k2[li][b]}.B16, {s2[b]}.B16"]
                        else:
                            body += [f"\tVEOR {k2[li][b]}.B16, {src}.B16, {s2[b]}.B16", f"\tVEOR {k1[b]}.B16, {src}.B16, {s1[b]}.B16"]
                    else:
                        if (c, b, li) in reg:
                            body.append(f"\tVEOR {reg[(c, b, li)]}.B16, {st[b]}.B16, {st[b]}.B16")
                        body += [f"\tVEOR {k2[li][b]}.B16, {st[b]}.B16, {s2[b]}.B16", f"\tVEOR {k1[b]}.B16, {st[b]}.B16, {s1[b]}.B16"]
            body += neon256_perm(lane_regs)
            for s1a, s1b, s2a, s2b in lane_regs:
                body += [f"\tVEOR {s2a}.B16, {s1a}.B16, {s1a}.B16", f"\tVEOR {s2b}.B16, {s1b}.B16, {s1b}.B16"]
        body += ["\tSUBS $1, R2, R2", f"\tBNE loop{p}"]
        for li, (s1a, s1b, _, _) in enumerate(lane_regs):
            lane = 2 * p + li
            body += [f"\tADD ${32 * lane}, R4, R6", f"\tVST1 [{s1a}.B16, {s1b}.B16], (R6)"]
    body.append("\tRET")
    if lanes == 4:
        sig = f"// func areion256FusedChain{n}x4NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][4]uint64)"
        name = f"areion256FusedChain{n}x4NeonAsm"
    else:
        sig = f"// func areion256FusedChain{n}x1NeonAsm(fixedKey *[32]byte, comps *uint64, nGroups int, data *byte, out *[4]uint64)"
        name = f"areion256FusedChain{n}x1NeonAsm"
    return lines + f"\n{sig}\nTEXT ·{name}(SB), NOSPLIT, ${frame.aligned}-40\n" + "\n".join(body) + "\n"


def neon512_round(s1, s2, zero="V12", rc="V13"):
    a, b, c, d = s1
    e, f, g, h = s2
    return [f"\tVMOV {a}.B16, V8.B16", f"\tVMOV {e}.B16, V10.B16",
            f"\tAESE {zero}.B16, V8.B16", f"\tAESE {zero}.B16, V10.B16",
            "\tAESMC V8.B16, V8.B16", "\tAESMC V10.B16, V10.B16",
            f"\tVEOR V8.B16, {b}.B16, {b}.B16", f"\tVEOR V10.B16, {f}.B16, {f}.B16",
            f"\tVMOV {c}.B16, V9.B16", f"\tVMOV {g}.B16, V11.B16",
            f"\tAESE {zero}.B16, V9.B16", f"\tAESE {zero}.B16, V11.B16",
            "\tAESMC V9.B16, V9.B16", "\tAESMC V11.B16, V11.B16",
            f"\tVEOR V9.B16, {d}.B16, {d}.B16", f"\tVEOR V11.B16, {h}.B16, {h}.B16",
            f"\tAESE {zero}.B16, {a}.B16", f"\tAESE {zero}.B16, {e}.B16",
            f"\tAESE {zero}.B16, {c}.B16", f"\tAESE {zero}.B16, {g}.B16",
            f"\tAESE {rc}.B16, {c}.B16", f"\tAESE {rc}.B16, {g}.B16",
            f"\tAESMC {c}.B16, {c}.B16", f"\tAESMC {g}.B16, {g}.B16"]


def neon512(n, lanes):
    frame = Frame()
    tier = "NEON + ARM Crypto Extension (one lane per pass, four passes)" if lanes == 4 else "NEON + ARM Crypto Extension (single lane)"
    lines = header(ARM, 512, n, lanes, tier)
    body = neon_prologue("x4" if lanes == 4 else "x1")
    chunks = chunk_maps(512, n)
    body_stage = stage_arm64(512, n, lanes, ["R8", "R9", "R10", "R11"][:lanes], frame)
    doff = frame.alloc("d", 16)
    body.append(f"\tMOVD $frame-{frame.aligned}(SP), R7")
    body += body_stage
    body += ["\tMOVD $1, R12", f"\tMOVD R12, {doff}(R7)", f"\tMOVD ZR, {doff + 8}(R7)"]
    body += ["\tVEOR V12.B16, V12.B16, V12.B16", "\tVLD1 (R0), [V14.B16, V15.B16, V16.B16, V17.B16]"]
    s1 = [f"V{b}" for b in range(4)]
    s2 = [f"V{4 + b}" for b in range(4)]
    k1 = [f"V{14 + b}" for b in range(4)]
    k2 = [f"V{18 + b}" for b in range(4)]
    for p in range(lanes):
        body += ["", f"\t// pass {p}: lane {p}"]
        reg = {}
        nxt = 22
        for c, blocks in enumerate(chunks):
            for b in range(4):
                if (c, b) in frame.slots:
                    body += [f"\tADD ${frame.slots[(c, b)] + 16 * p}, R7, R6", f"\tVLD1 (R6), [V{nxt}.B16]"]
                    reg[(c, b)] = f"V{nxt}"
                    nxt += 1
        body += ["\tMOVD comps+8(FP), R1", "\tMOVD nGroups+16(FP), R2"]
        body += [f"\tVEOR {s}.B16, {s}.B16, {s}.B16" for s in s1] + ["", f"loop{p}:"]
        body += ["\tVLD1.P 64(R1), [V8.B16, V9.B16, V10.B16, V11.B16]", f"\tADD ${doff}, R7, R6", "\tVLD1 (R6), [V13.B16]"]
        for b in range(4):
            body.append(f"\tVEOR {s1[b]}.B16, V{8 + b}.B16, {k2[b]}.B16")
        body.append(f"\tVEOR V13.B16, {k2[0]}.B16, {k2[0]}.B16")
        for c, blocks in enumerate(chunks):
            for b in range(4):
                if c == 0:
                    src = reg.get((0, b))
                    if src is None:
                        body += [f"\tVMOV {k1[b]}.B16, {s1[b]}.B16", f"\tVMOV {k2[b]}.B16, {s2[b]}.B16"]
                    else:
                        body += [f"\tVEOR {k2[b]}.B16, {src}.B16, {s2[b]}.B16", f"\tVEOR {k1[b]}.B16, {src}.B16, {s1[b]}.B16"]
                else:
                    if (c, b) in reg:
                        body.append(f"\tVEOR {reg[(c, b)]}.B16, {s1[b]}.B16, {s1[b]}.B16")
                    body += [f"\tVEOR {k2[b]}.B16, {s1[b]}.B16, {s2[b]}.B16", f"\tVEOR {k1[b]}.B16, {s1[b]}.B16, {s1[b]}.B16"]
            body.append("\tMOVD $·AreionRCTable(SB), R5")
            for r in range(15):
                body.append("\tVLD1.P 16(R5), [V13.B16]")
                body += neon512_round(roles(s1, r), roles(s2, r))
            # state = rotate(s1 ^ s2) into V0..V3
            body += ["\tVEOR V7.B16, V3.B16, V8.B16", "\tVEOR V4.B16, V0.B16, V9.B16",
                     "\tVEOR V5.B16, V1.B16, V10.B16", "\tVEOR V6.B16, V2.B16, V11.B16",
                     "\tVMOV V8.B16, V0.B16", "\tVMOV V9.B16, V1.B16", "\tVMOV V10.B16, V2.B16", "\tVMOV V11.B16, V3.B16"]
        body += ["\tSUBS $1, R2, R2", f"\tBNE loop{p}"]
        body += [f"\tADD ${64 * p}, R4, R6", "\tVST1 [V0.B16, V1.B16, V2.B16, V3.B16], (R6)"]
    body.append("\tRET")
    if lanes == 4:
        sig = f"// func areion512FusedChain{n}x4NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, dataPtrs *[4]*byte, out *[4][8]uint64)"
        name = f"areion512FusedChain{n}x4NeonAsm"
    else:
        sig = f"// func areion512FusedChain{n}x1NeonAsm(fixedKey *[64]byte, comps *uint64, nGroups int, data *byte, out *[8]uint64)"
        name = f"areion512FusedChain{n}x1NeonAsm"
    return lines + f"\n{sig}\nTEXT ·{name}(SB), NOSPLIT, ${frame.aligned}-40\n" + "\n".join(body) + "\n"


# ------------------------------------------------------------ render --

def render_all():
    files = {}
    for n in SHAPES:
        files[f"areion_fusedchain256_{n}x4_avx512_amd64.s"] = zmm256_x4(n)
        files[f"areion_fusedchain256_{n}x4_vaesavx2_amd64.s"] = ymm256_x4(n)
        files[f"areion_fusedchain256_{n}x4_aesni_amd64.s"] = xmm256(n, 4)
        files[f"areion_fusedchain256_{n}x1_aesni_amd64.s"] = xmm256(n, 1)
        files[f"areion_fusedchain512_{n}x4_avx512_amd64.s"] = zmm512_x4(n)
        files[f"areion_fusedchain512_{n}x4_vaesavx2_amd64.s"] = ymm512_x4(n)
        files[f"areion_fusedchain512_{n}x4_aesni_amd64.s"] = xmm512(n, 4)
        files[f"areion_fusedchain512_{n}x1_aesni_amd64.s"] = xmm512(n, 1)
        files[f"areion_fusedchain256_{n}x4_neon_arm64.s"] = neon256(n, 4)
        files[f"areion_fusedchain256_{n}x1_neon_arm64.s"] = neon256(n, 1)
        files[f"areion_fusedchain512_{n}x4_neon_arm64.s"] = neon512(n, 4)
        files[f"areion_fusedchain512_{n}x1_neon_arm64.s"] = neon512(n, 1)
    files["areion_fusedchain256_13x8_avx512_amd64.s"] = zmm256_x8()
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
