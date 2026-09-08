#!/usr/bin/env python3
"""Emit the SipHash-2-4 fused ChainHash cascade kernels for hashes/internal/siphashasm.

One file per (shape, lanes, tier). Shapes 13/20/36/68 (message words 2/3/5/9);
lanes x4 (four data lanes over one shared component slice) and x1 (single
lane); amd64 tiers avx512 (EVEX YMM, VPROLQ rotates) and avx2 (VEX YMM,
synthesised rotates) for x4, one GPR kernel for x1 (reached under any
selected assembly tier); arm64 tiers neon for x4 and gpr for x1.

The avx512 tier additionally carries an x8 variant at the three nonce-buf
shapes 20/36/68 (siphash_fusedchain128_<shape>x8_avx512_amd64.s): eight
lanes in ZMM registers, one qword per lane — SipHash's 64-bit state words
fill a 512-bit register at exactly eight lanes, so the x8 kernel runs the
same instruction stream as the x4 kernel over twice the lanes.

A third family, x16 at shape 13 only, is the Interlocked Barrier PRF fill
kernel (siphash_fusedchain128_13x16_avx512_amd64.s): the kernel receives
groupIdxBase in the frame and synthesises the 16 per-lane fill blocks
in-register — [0x03 | LE64(groupIdxBase+i) | 4×0x00] for lane i — as the
two message words m0 = (idx << 8) | 0x03 and m1 = (idx >> 56) | (13 << 56),
then runs the cascade on two eight-lane groups whose instruction streams
are interleaved. The avx2 and neon tiers have no x16 kernel: the Go
dispatcher synthesises the blocks and runs four x4 calls.

Cascade evaluated per lane (see siphashasm_fused.go):
    (lo, hi) = (0, 0)
    for each component pair (c0, c1):
        k0 = c0 ^ lo; k1 = c1 ^ hi
        v0 = k0 ^ C0; v1 = k1 ^ (C1 ^ 0xee); v2 = k0 ^ C2; v3 = k1 ^ C3
        for each message word m: v3 ^= m; SipRound; SipRound; v0 ^= m
        v2 ^= 0xee; SipRound × 4; lo = v0 ^ v1 ^ v2 ^ v3
        v1 ^= 0xdd; SipRound × 4; hi = v0 ^ v1 ^ v2 ^ v3
    out = (lo, hi)
The message words are the little-endian 8-byte words of the input; the
last word carries the remaining 4 (20 / 36 / 68) or 5 (13) bytes with the
input length in its top byte, exactly as SipHash-128 (dchest/siphash
Hash128) pads. The words are round-invariant and are packed once per call
(word 0 through two 4-byte loads, matching the caller's 4-byte pixel-index
store so store-to-load forwarding succeeds); the per-pair key is the
previous pair's output XOR the component pair, so the whole cascade is
register-resident.

Register plans:
    avx512 x4   Y0..Y3 state, Y4/Y5 k0/k1, Y6/Y7 lo/hi, Y8..Y13 the six
                constants, Y14/Y15 the pair broadcasts, Y16.. the words
    avx512 x8   the same plan on ZMM registers
    avx512 x16  Z0..Z3 / Z4..Z7 the two groups' states, Z8..Z11 lo/hi,
                Z12..Z15 the synthesised words, Z16..Z21 constants,
                Z22/Z23 pair broadcasts, Z24..Z27 k0/k1, Z28..Z31 scratch
    avx2 x4     Y0..Y3 state, Y4/Y6 k0/k1, Y5 rotate scratch, Y7/Y8 lo/hi,
                Y9..Y14 constants, Y15 pair broadcast; the words are staged
                once into the frame as 32-byte slots and read back as VPXOR
                memory operands
    gpr x1      R8..R11 state, R12/R13 lo/hi, AX/SI k0/k1, R14 the tail
                word, word 0 in the frame, R15 scratch
    neon x4     lanes (0,1) and (2,3) in two register halves: V0/V1 v0,
                V2/V3 v1 (alternate V16/V17), V4/V5 v2, V6/V7 v3 (alternate
                V18/V19); V8..V11 lo/hi, V12..V15 k0/k1, V20..V25 constants,
                V26/V27 pair broadcasts, V28/V29 the current word; the words
                are staged once into the frame and walked with VLD1.P. The
                64-bit rotates run as VSHL + VSRI into the alternate register
                (rotate by 32 as VREV64 on 32-bit elements).
    gpr arm64   R8..R11 state, R12/R13 lo/hi, R14/R15 k0/k1, R19 tail word,
                R24 word 0, R20..R23 constants, R16 scratch
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "hashes", "internal", "siphashasm")
SHAPES = [13, 20, 36, 68]
X8_SHAPES = [20, 36, 68]
AMD = "amd64 && !purego && !noitbasm"
ARM = "arm64 && !purego && !noitbasm"

C0 = 0x736f6d6570736575
C1EE = 0x646f72616e646f83  # C1 ^ 0xee, the SipHash-128 v1 init
C2 = 0x6c7967656e657261
C3 = 0x7465646279746573
CONSTS = [C0, C1EE, C2, C3, 0xEE, 0xDD]
CONST_NAMES = ["C0", "C1 ^ 0xee", "C2", "C3", "0xee", "0xdd"]


def words(n):
    """Message words of an n-byte input: full 8-byte words plus the padded tail."""
    return (n + 8) // 8


def tail_bytes(n):
    return n - 8 * (words(n) - 1)


def tag(n):
    return n << 56


def header(shape, lanes, tier_desc, build):
    nw = words(shape)
    return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for SipHash-2-4-128 at the
// {shape}-byte shape, {lanes} lane{'s' if lanes > 1 else ''} ({nw} message words, {2 * nw + 8} SipRounds per cascade
// round). The words are packed once and every cascade round re-keys the
// state from the previous round's output; see siphashasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"
"""


# ---------------------------------------------------------------- amd64 word loads

def gpr_word(shape, w, r, dst, scratch):
    """Load raw message word w of the lane at pointer r into dst (tag not applied)."""
    nw = words(shape)
    off = 8 * w
    if w == 0:
        return [f"\tMOVL 0({r}), {dst}", f"\tMOVL 4({r}), {scratch}", f"\tSHLQ $32, {scratch}", f"\tORQ {scratch}, {dst}"]
    if w == nw - 1:
        if tail_bytes(shape) == 5:
            return [f"\tMOVL {off}({r}), {dst}", f"\tMOVBLZX {off + 4}({r}), {scratch}", f"\tSHLQ $32, {scratch}",
                    f"\tORQ {scratch}, {dst}"]
        return [f"\tMOVL {off}({r}), {dst}"]
    return [f"\tMOVQ {off}({r}), {dst}"]


# ---------------------------------------------------------------- EVEX (avx512) family

def evex_round(states, P):
    """One SipRound on every (v0, v1, v2, v3) tuple in states, instruction-interleaved."""
    ops = [
        lambda s: f"VPADDQ {s[1]}, {s[0]}, {s[0]}",
        lambda s: f"VPROLQ $13, {s[1]}, {s[1]}",
        lambda s: f"VPXORQ {s[0]}, {s[1]}, {s[1]}",
        lambda s: f"VPROLQ $32, {s[0]}, {s[0]}",
        lambda s: f"VPADDQ {s[3]}, {s[2]}, {s[2]}",
        lambda s: f"VPROLQ $16, {s[3]}, {s[3]}",
        lambda s: f"VPXORQ {s[2]}, {s[3]}, {s[3]}",
        lambda s: f"VPADDQ {s[3]}, {s[0]}, {s[0]}",
        lambda s: f"VPROLQ $21, {s[3]}, {s[3]}",
        lambda s: f"VPXORQ {s[0]}, {s[3]}, {s[3]}",
        lambda s: f"VPADDQ {s[1]}, {s[2]}, {s[2]}",
        lambda s: f"VPROLQ $17, {s[1]}, {s[1]}",
        lambda s: f"VPXORQ {s[2]}, {s[1]}, {s[1]}",
        lambda s: f"VPROLQ $32, {s[2]}, {s[2]}",
    ]
    return ["\t" + "; ".join(op(s) for s in states) for op in ops]


def evex_consts(P, base):
    """Broadcast the six constants into P(base)..P(base+5)."""
    L = []
    for i, c in enumerate(CONSTS):
        L += [f"\tMOVQ ${c:#x}, R12", f"\tVPBROADCASTQ R12, {P}{base + i}"]
    return L


def evex_pack_words(shape, regs, P, wbase, scratch2):
    """Pack the message words of the lanes at regs into P(wbase+w); lane pairs
    are inserted 128 bits at a time."""
    nw = words(shape)
    L = []
    for w in range(nw):
        dst = f"{P}{wbase + w}"
        for p in range(0, len(regs), 2):
            x = f"X{wbase + w}" if p == 0 else "X4"
            L += gpr_word(shape, w, regs[p], "R12", scratch2)
            L.append(f"\tVMOVQ R12, {x}")
            L += gpr_word(shape, w, regs[p + 1], "R12", scratch2)
            L.append(f"\tVPINSRQ $1, R12, {x}, {x}")
            if p > 0:
                L.append(f"\tVINSERTI64X2 ${p // 2}, X4, {dst}, {dst}")
        if w == nw - 1:
            L += [f"\tMOVQ ${tag(shape):#x}, R12", f"\tVPBROADCASTQ R12, {P}4", f"\tVPXORQ {P}4, {dst}, {dst}"]
    return L


def evex_body(shape, P, wbase):
    """The cascade loop on one state group: Y/Z0..3 state, 4/5 k0/k1, 6/7 lo/hi,
    8..13 constants, 14/15 pair broadcasts, words at wbase."""
    nw = words(shape)
    S = [(f"{P}0", f"{P}1", f"{P}2", f"{P}3")]
    L = [f"\tVPXORQ {P}6, {P}6, {P}6", f"\tVPXORQ {P}7, {P}7, {P}7", "", "loop:",
         f"\tVPBROADCASTQ 0(BX), {P}14", f"\tVPBROADCASTQ 8(BX), {P}15",
         f"\tVPXORQ {P}6, {P}14, {P}4", f"\tVPXORQ {P}7, {P}15, {P}5",
         f"\tVPXORQ {P}8, {P}4, {P}0", f"\tVPXORQ {P}9, {P}5, {P}1", f"\tVPXORQ {P}10, {P}4, {P}2", f"\tVPXORQ {P}11, {P}5, {P}3"]
    for w in range(nw):
        L.append(f"\tVPXORQ {P}{wbase + w}, {P}3, {P}3")
        L += evex_round(S, P) + evex_round(S, P)
        L.append(f"\tVPXORQ {P}{wbase + w}, {P}0, {P}0")
    L.append(f"\tVPXORQ {P}12, {P}2, {P}2")
    for _ in range(4):
        L += evex_round(S, P)
    L += [f"\tVPXORQ {P}1, {P}0, {P}6", f"\tVPTERNLOGQ $0x96, {P}3, {P}2, {P}6", f"\tVPXORQ {P}13, {P}1, {P}1"]
    for _ in range(4):
        L += evex_round(S, P)
    L += [f"\tVPXORQ {P}1, {P}0, {P}7", f"\tVPTERNLOGQ $0x96, {P}3, {P}2, {P}7",
          "\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", ""]
    return L


def evex_x4(shape):
    regs = ["R8", "R9", "R10", "R11"]
    L = [f"// func sipHash24FusedChain{shape}x4Avx512Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)",
         f"TEXT ·sipHash24FusedChain{shape}x4Avx512Asm(SB), NOSPLIT, $0-32",
         "\tMOVQ comps+0(FP), BX", "\tMOVQ nPairs+8(FP), CX", "\tMOVQ dataPtrs+16(FP), DX", "\tMOVQ out+24(FP), DI",
         "\tMOVQ 0(DX), R8", "\tMOVQ 8(DX), R9", "\tMOVQ 16(DX), R10", "\tMOVQ 24(DX), R11", ""]
    L += evex_pack_words(shape, regs, "Y", 16, "R13")
    L.append("")
    L += evex_consts("Y", 8)
    L += evex_body(shape, "Y", 16)
    L += ["\tVPUNPCKLQDQ Y7, Y6, Y4", "\tVPUNPCKHQDQ Y7, Y6, Y5",
          "\tVMOVDQU X4, 0(DI)", "\tVMOVDQU X5, 16(DI)", "\tVEXTRACTI64X2 $1, Y4, 32(DI)", "\tVEXTRACTI64X2 $1, Y5, 48(DI)",
          "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def evex_x8(shape):
    regs = ["R8", "R9", "R10", "R11", "R13", "R14", "R15", "SI"]
    L = [f"// func sipHash24FusedChain{shape}x8Avx512Asm(comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)",
         f"TEXT ·sipHash24FusedChain{shape}x8Avx512Asm(SB), NOSPLIT, $0-32",
         "\tMOVQ comps+0(FP), BX", "\tMOVQ nPairs+8(FP), CX", "\tMOVQ dataPtrs+16(FP), DX", "\tMOVQ out+24(FP), DI"]
    for i, r in enumerate(regs):
        L.append(f"\tMOVQ {8 * i}(DX), {r}")
    L.append("")
    L += evex_pack_words(shape, regs, "Z", 16, "AX")
    L.append("")
    L += evex_consts("Z", 8)
    L += evex_body(shape, "Z", 16)
    L += ["\tVPUNPCKLQDQ Z7, Z6, Z4", "\tVPUNPCKHQDQ Z7, Z6, Z5"]
    for lane in range(8):
        k, j = lane // 2, lane % 2
        if k == 0:
            L.append(f"\tVMOVDQU X{4 + j}, {16 * lane}(DI)")
        else:
            L.append(f"\tVEXTRACTI64X2 ${k}, Z{4 + j}, {16 * lane}(DI)")
    L += ["\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def evex_x16():
    """Two eight-lane groups (A: lanes 0..7, B: lanes 8..15) with interleaved
    instruction streams. Group A: Z0..Z3 state, Z8/Z9 lo/hi, Z12/Z13 words,
    Z24/Z25 k0/k1; group B: Z4..Z7, Z10/Z11, Z14/Z15, Z26/Z27. Z16..Z21
    constants, Z22/Z23 pair broadcasts, Z28..Z31 scratch."""
    A = ("Z0", "Z1", "Z2", "Z3")
    B = ("Z4", "Z5", "Z6", "Z7")
    S = [A, B]
    L = ["// func sipHash24FusedChain13x16Avx512Asm(comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64)",
         "TEXT ·sipHash24FusedChain13x16Avx512Asm(SB), NOSPLIT, $0-32",
         "\tMOVQ comps+0(FP), BX", "\tMOVQ nPairs+8(FP), CX", "\tMOVQ out+24(FP), DI", "",
         "\t// Synthesise the words: m0 = (idx << 8) | 0x03, m1 = (idx >> 56) | (13 << 56), idx = groupIdxBase + lane",
         "\tVPBROADCASTQ groupIdxBase+16(FP), Z28",
         "\tMOVQ $3, R12", "\tVPBROADCASTQ R12, Z30",
         f"\tMOVQ ${tag(13):#x}, R12", "\tVPBROADCASTQ R12, Z31"]
    for g, (w0, w1) in enumerate((("Z12", "Z13"), ("Z14", "Z15"))):
        L += [f"\tVPADDQ ·laneIdx16+{64 * g}(SB), Z28, Z29",
              f"\tVPSLLQ $8, Z29, {w0}", f"\tVPORQ Z30, {w0}, {w0}",
              f"\tVPSRLQ $56, Z29, {w1}", f"\tVPORQ Z31, {w1}, {w1}"]
    L.append("")
    L += evex_consts("Z", 16)
    L += ["\tVPXORQ Z8, Z8, Z8", "\tVPXORQ Z9, Z9, Z9", "\tVPXORQ Z10, Z10, Z10", "\tVPXORQ Z11, Z11, Z11", "", "loop:",
          "\tVPBROADCASTQ 0(BX), Z22", "\tVPBROADCASTQ 8(BX), Z23",
          "\tVPXORQ Z8, Z22, Z24; VPXORQ Z10, Z22, Z26",
          "\tVPXORQ Z9, Z23, Z25; VPXORQ Z11, Z23, Z27",
          "\tVPXORQ Z16, Z24, Z0; VPXORQ Z16, Z26, Z4",
          "\tVPXORQ Z17, Z25, Z1; VPXORQ Z17, Z27, Z5",
          "\tVPXORQ Z18, Z24, Z2; VPXORQ Z18, Z26, Z6",
          "\tVPXORQ Z19, Z25, Z3; VPXORQ Z19, Z27, Z7"]
    for w in range(2):
        L.append(f"\tVPXORQ Z{12 + w}, Z3, Z3; VPXORQ Z{14 + w}, Z7, Z7")
        L += evex_round(S, "Z") + evex_round(S, "Z")
        L.append(f"\tVPXORQ Z{12 + w}, Z0, Z0; VPXORQ Z{14 + w}, Z4, Z4")
    L.append("\tVPXORQ Z20, Z2, Z2; VPXORQ Z20, Z6, Z6")
    for _ in range(4):
        L += evex_round(S, "Z")
    L += ["\tVPXORQ Z1, Z0, Z8; VPXORQ Z5, Z4, Z10",
          "\tVPTERNLOGQ $0x96, Z3, Z2, Z8; VPTERNLOGQ $0x96, Z7, Z6, Z10",
          "\tVPXORQ Z21, Z1, Z1; VPXORQ Z21, Z5, Z5"]
    for _ in range(4):
        L += evex_round(S, "Z")
    L += ["\tVPXORQ Z1, Z0, Z9; VPXORQ Z5, Z4, Z11",
          "\tVPTERNLOGQ $0x96, Z3, Z2, Z9; VPTERNLOGQ $0x96, Z7, Z6, Z11",
          "\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "",
          "\t// Interleave (lo, hi) per lane and store the 16 pairs in lane order",
          "\tVMOVDQU64 ·interleaveIdx16+0(SB), Z28", "\tVMOVDQU64 ·interleaveIdx16+64(SB), Z29"]
    for g, (lo, hi) in enumerate((("Z8", "Z9"), ("Z10", "Z11"))):
        L += [f"\tVMOVDQA64 {lo}, Z30", f"\tVPERMT2Q {hi}, Z28, Z30", f"\tVMOVDQU64 Z30, {128 * g}(DI)",
              f"\tVMOVDQA64 {lo}, Z31", f"\tVPERMT2Q {hi}, Z29, Z31", f"\tVMOVDQU64 Z31, {128 * g + 64}(DI)"]
    L += ["\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- AVX2 family

AVX2_MACROS = """DATA rol16q<>+0(SB)/8,  $0x0504030201000706
DATA rol16q<>+8(SB)/8,  $0x0d0c0b0a09080f0e
DATA rol16q<>+16(SB)/8, $0x0504030201000706
DATA rol16q<>+24(SB)/8, $0x0d0c0b0a09080f0e
GLOBL rol16q<>(SB), RODATA|NOPTR, $32

#define ROLQ32(r) VPSHUFD $0xB1, r, r
#define ROLQ16(r) VPSHUFB rol16q<>(SB), r, r
#define ROLQ13(r) VPSLLQ $13, r, Y5; VPSRLQ $51, r, r; VPOR Y5, r, r
#define ROLQ21(r) VPSLLQ $21, r, Y5; VPSRLQ $43, r, r; VPOR Y5, r, r
#define ROLQ17(r) VPSLLQ $17, r, Y5; VPSRLQ $47, r, r; VPOR Y5, r, r

#define SIP_ROUND \\
\tVPADDQ Y1, Y0, Y0; ROLQ13(Y1); VPXOR Y0, Y1, Y1; ROLQ32(Y0); \\
\tVPADDQ Y3, Y2, Y2; ROLQ16(Y3); VPXOR Y2, Y3, Y3;             \\
\tVPADDQ Y3, Y0, Y0; ROLQ21(Y3); VPXOR Y0, Y3, Y3;             \\
\tVPADDQ Y1, Y2, Y2; ROLQ17(Y1); VPXOR Y2, Y1, Y1; ROLQ32(Y2)
"""


def avx2_x4(shape):
    nw = words(shape)
    regs = ["R8", "R9", "R10", "R11"]
    L = [AVX2_MACROS,
         f"// func sipHash24FusedChain{shape}x4Avx2Asm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)",
         f"TEXT ·sipHash24FusedChain{shape}x4Avx2Asm(SB), NOSPLIT, ${32 * nw}-32",
         "\tMOVQ comps+0(FP), BX", "\tMOVQ nPairs+8(FP), CX", "\tMOVQ dataPtrs+16(FP), DX", "\tMOVQ out+24(FP), DI",
         "\tMOVQ 0(DX), R8", "\tMOVQ 8(DX), R9", "\tMOVQ 16(DX), R10", "\tMOVQ 24(DX), R11", "",
         f"\t// Stage the {nw} message words into the frame at 32*w(SP)"]
    for w in range(nw):
        L += gpr_word(shape, w, regs[0], "R12", "R13") + ["\tVMOVQ R12, X4"]
        L += gpr_word(shape, w, regs[1], "R12", "R13") + ["\tVPINSRQ $1, R12, X4, X4"]
        L += gpr_word(shape, w, regs[2], "R12", "R13") + ["\tVMOVQ R12, X5"]
        L += gpr_word(shape, w, regs[3], "R12", "R13") + ["\tVPINSRQ $1, R12, X5, X5", "\tVINSERTI128 $1, X5, Y4, Y4"]
        if w == nw - 1:
            L += [f"\tMOVQ ${tag(shape):#x}, R12", "\tVMOVQ R12, X5", "\tVPBROADCASTQ X5, Y5", "\tVPXOR Y5, Y4, Y4"]
        L.append(f"\tVMOVDQU Y4, {32 * w}(SP)")
    L.append("")
    for i, c in enumerate(CONSTS):
        L += [f"\tMOVQ ${c:#x}, R12", f"\tVMOVQ R12, X{9 + i}", f"\tVPBROADCASTQ X{9 + i}, Y{9 + i}"]
    L += ["\tVPXOR Y7, Y7, Y7", "\tVPXOR Y8, Y8, Y8", "", "loop:",
          "\tVPBROADCASTQ 0(BX), Y15", "\tVPXOR Y7, Y15, Y4",
          "\tVPBROADCASTQ 8(BX), Y15", "\tVPXOR Y8, Y15, Y6",
          "\tVPXOR Y9, Y4, Y0", "\tVPXOR Y10, Y6, Y1", "\tVPXOR Y11, Y4, Y2", "\tVPXOR Y12, Y6, Y3"]
    for w in range(nw):
        L += [f"\tVPXOR {32 * w}(SP), Y3, Y3", "\tSIP_ROUND", "\tSIP_ROUND", f"\tVPXOR {32 * w}(SP), Y0, Y0"]
    L += ["\tVPXOR Y13, Y2, Y2"] + ["\tSIP_ROUND"] * 4
    L += ["\tVPXOR Y1, Y0, Y7", "\tVPXOR Y3, Y7, Y7", "\tVPXOR Y2, Y7, Y7", "\tVPXOR Y14, Y1, Y1"] + ["\tSIP_ROUND"] * 4
    L += ["\tVPXOR Y1, Y0, Y8", "\tVPXOR Y3, Y8, Y8", "\tVPXOR Y2, Y8, Y8",
          "\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "",
          "\tVPUNPCKLQDQ Y8, Y7, Y4", "\tVPUNPCKHQDQ Y8, Y7, Y5",
          "\tVMOVDQU X4, 0(DI)", "\tVMOVDQU X5, 16(DI)", "\tVEXTRACTI128 $1, Y4, 32(DI)", "\tVEXTRACTI128 $1, Y5, 48(DI)",
          "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- GPR x1 (amd64)

GPR_ROUND_AMD64 = ["\tADDQ R9, R8", "\tROLQ $13, R9", "\tXORQ R8, R9", "\tROLQ $32, R8",
                   "\tADDQ R11, R10", "\tROLQ $16, R11", "\tXORQ R10, R11",
                   "\tADDQ R11, R8", "\tROLQ $21, R11", "\tXORQ R8, R11",
                   "\tADDQ R9, R10", "\tROLQ $17, R9", "\tXORQ R10, R9", "\tROLQ $32, R10"]


def gpr_x1_amd64(shape):
    nw = words(shape)
    L = [f"// func sipHash24FusedChain{shape}x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)",
         f"TEXT ·sipHash24FusedChain{shape}x1GprAsm(SB), NOSPLIT, $8-32",
         "\tMOVQ comps+0(FP), BX", "\tMOVQ nPairs+8(FP), CX", "\tMOVQ data+16(FP), DX", "\tMOVQ out+24(FP), DI", ""]
    L += gpr_word(shape, 0, "DX", "R14", "R15") + ["\tMOVQ R14, 0(SP)"]
    L += gpr_word(shape, nw - 1, "DX", "R14", "R15") + [f"\tMOVQ ${tag(shape):#x}, R15", "\tORQ R15, R14"]
    L += ["\tXORQ R12, R12", "\tXORQ R13, R13", "", "loop:",
          "\tMOVQ 0(BX), AX", "\tXORQ R12, AX", "\tMOVQ 8(BX), SI", "\tXORQ R13, SI",
          f"\tMOVQ ${C0:#x}, R8", "\tXORQ AX, R8", f"\tMOVQ ${C1EE:#x}, R9", "\tXORQ SI, R9",
          f"\tMOVQ ${C2:#x}, R10", "\tXORQ AX, R10", f"\tMOVQ ${C3:#x}, R11", "\tXORQ SI, R11"]
    for w in range(nw):
        if w == nw - 1:
            m = "R14"
        elif w == 0:
            L.append("\tMOVQ 0(SP), R15")
            m = "R15"
        else:
            L.append(f"\tMOVQ {8 * w}(DX), R15")
            m = "R15"
        L += [f"\tXORQ {m}, R11"] + GPR_ROUND_AMD64 + GPR_ROUND_AMD64 + [f"\tXORQ {m}, R8"]
    L += ["\tXORQ $0xee, R10"] + GPR_ROUND_AMD64 * 4
    L += ["\tMOVQ R8, R12", "\tXORQ R9, R12", "\tXORQ R10, R12", "\tXORQ R11, R12", "\tXORQ $0xdd, R9"] + GPR_ROUND_AMD64 * 4
    L += ["\tMOVQ R8, R13", "\tXORQ R9, R13", "\tXORQ R10, R13", "\tXORQ R11, R13",
          "\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "",
          "\tMOVQ R12, 0(DI)", "\tMOVQ R13, 8(DI)", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- arm64 word loads

def arm_word(shape, w, r, dst, scratch):
    """Load raw message word w of the lane at pointer r into dst (tag not applied)."""
    nw = words(shape)
    off = 8 * w
    if w == 0:
        return [f"\tMOVWU 0({r}), {dst}", f"\tMOVWU 4({r}), {scratch}", f"\tORR {scratch}<<32, {dst}, {dst}"]
    if w == nw - 1:
        if tail_bytes(shape) == 5:
            return [f"\tMOVWU {off}({r}), {dst}", f"\tMOVBU {off + 4}({r}), {scratch}", f"\tORR {scratch}<<32, {dst}, {dst}"]
        return [f"\tMOVWU {off}({r}), {dst}"]
    return [f"\tMOVD {off}({r}), {dst}"]


# ---------------------------------------------------------------- NEON x4

def neon_round():
    """One SipRound on both lane halves (h = 0, 1), instruction-interleaved.
    v1 rotates into its alternate register and back; so does v3."""
    def regs(h):
        return {"v0": f"V{h}", "v1": f"V{2 + h}", "v1x": f"V{16 + h}", "v2": f"V{4 + h}", "v3": f"V{6 + h}", "v3x": f"V{18 + h}"}
    ops = [
        lambda r: f"VADD {r['v1']}.D2, {r['v0']}.D2, {r['v0']}.D2",
        lambda r: f"VSHL $13, {r['v1']}.D2, {r['v1x']}.D2",
        lambda r: f"VSRI $51, {r['v1']}.D2, {r['v1x']}.D2",
        lambda r: f"VEOR {r['v0']}.B16, {r['v1x']}.B16, {r['v1x']}.B16",
        lambda r: f"VREV64 {r['v0']}.S4, {r['v0']}.S4",
        lambda r: f"VADD {r['v3']}.D2, {r['v2']}.D2, {r['v2']}.D2",
        lambda r: f"VSHL $16, {r['v3']}.D2, {r['v3x']}.D2",
        lambda r: f"VSRI $48, {r['v3']}.D2, {r['v3x']}.D2",
        lambda r: f"VEOR {r['v2']}.B16, {r['v3x']}.B16, {r['v3x']}.B16",
        lambda r: f"VADD {r['v3x']}.D2, {r['v0']}.D2, {r['v0']}.D2",
        lambda r: f"VSHL $21, {r['v3x']}.D2, {r['v3']}.D2",
        lambda r: f"VSRI $43, {r['v3x']}.D2, {r['v3']}.D2",
        lambda r: f"VEOR {r['v0']}.B16, {r['v3']}.B16, {r['v3']}.B16",
        lambda r: f"VADD {r['v1x']}.D2, {r['v2']}.D2, {r['v2']}.D2",
        lambda r: f"VSHL $17, {r['v1x']}.D2, {r['v1']}.D2",
        lambda r: f"VSRI $47, {r['v1x']}.D2, {r['v1']}.D2",
        lambda r: f"VEOR {r['v2']}.B16, {r['v1']}.B16, {r['v1']}.B16",
        lambda r: f"VREV64 {r['v2']}.S4, {r['v2']}.S4",
    ]
    return ["\t" + "; ".join(op(regs(h)) for h in range(2)) for op in ops]


def neon_x4(shape):
    nw = words(shape)
    frame = 32 * nw
    regs = ["R8", "R9", "R10", "R11"]
    L = [f"// func sipHash24FusedChain{shape}x4NeonAsm(comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)",
         f"TEXT ·sipHash24FusedChain{shape}x4NeonAsm(SB), NOSPLIT, ${frame}-32",
         "\tMOVD comps+0(FP), R6", "\tMOVD nPairs+8(FP), R7", "\tMOVD dataPtrs+16(FP), R2", "\tMOVD out+24(FP), R3",
         "\tMOVD 0(R2), R8", "\tMOVD 8(R2), R9", "\tMOVD 16(R2), R10", "\tMOVD 24(R2), R11",
         f"\tMOVD ${tag(shape):#x}, R14", f"\tMOVD $words-{frame}(SP), R4", "",
         f"\t// Stage the {nw} message words into the frame: lanes (0,1) in the first 16 bytes of each slot, (2,3) in the second"]
    for w in range(nw):
        for l in range(4):
            L += arm_word(shape, w, regs[l], "R12", "R13")
            if w == nw - 1:
                L.append("\tORR R14, R12, R12")
            L.append(f"\tVMOV R12, V{28 + l // 2}.D[{l % 2}]")
        L.append("\tVST1.P [V28.D2, V29.D2], 32(R4)")
    L.append("")
    for i, c in enumerate(CONSTS):
        L += [f"\tMOVD ${c:#x}, R12", f"\tVDUP R12, V{20 + i}.D2"]
    L += ["\tVEOR V8.B16, V8.B16, V8.B16", "\tVEOR V9.B16, V9.B16, V9.B16",
          "\tVEOR V10.B16, V10.B16, V10.B16", "\tVEOR V11.B16, V11.B16, V11.B16", "", "loop:",
          "\tMOVD 0(R6), R12", "\tVDUP R12, V26.D2", "\tMOVD 8(R6), R12", "\tVDUP R12, V27.D2", "\tADD $16, R6, R6",
          "\tVEOR V26.B16, V8.B16, V12.B16; VEOR V26.B16, V9.B16, V13.B16",
          "\tVEOR V27.B16, V10.B16, V14.B16; VEOR V27.B16, V11.B16, V15.B16",
          "\tVEOR V20.B16, V12.B16, V0.B16; VEOR V20.B16, V13.B16, V1.B16",
          "\tVEOR V21.B16, V14.B16, V2.B16; VEOR V21.B16, V15.B16, V3.B16",
          "\tVEOR V22.B16, V12.B16, V4.B16; VEOR V22.B16, V13.B16, V5.B16",
          "\tVEOR V23.B16, V14.B16, V6.B16; VEOR V23.B16, V15.B16, V7.B16",
          f"\tMOVD $words-{frame}(SP), R4"]
    for w in range(nw):
        L += ["\tVLD1.P 32(R4), [V28.D2, V29.D2]",
              "\tVEOR V28.B16, V6.B16, V6.B16; VEOR V29.B16, V7.B16, V7.B16"]
        L += neon_round() + neon_round()
        L.append("\tVEOR V28.B16, V0.B16, V0.B16; VEOR V29.B16, V1.B16, V1.B16")
    L.append("\tVEOR V24.B16, V4.B16, V4.B16; VEOR V24.B16, V5.B16, V5.B16")
    for _ in range(4):
        L += neon_round()
    L += ["\tVEOR V2.B16, V0.B16, V8.B16; VEOR V3.B16, V1.B16, V9.B16",
          "\tVEOR V4.B16, V8.B16, V8.B16; VEOR V5.B16, V9.B16, V9.B16",
          "\tVEOR V6.B16, V8.B16, V8.B16; VEOR V7.B16, V9.B16, V9.B16",
          "\tVEOR V25.B16, V2.B16, V2.B16; VEOR V25.B16, V3.B16, V3.B16"]
    for _ in range(4):
        L += neon_round()
    L += ["\tVEOR V2.B16, V0.B16, V10.B16; VEOR V3.B16, V1.B16, V11.B16",
          "\tVEOR V4.B16, V10.B16, V10.B16; VEOR V5.B16, V11.B16, V11.B16",
          "\tVEOR V6.B16, V10.B16, V10.B16; VEOR V7.B16, V11.B16, V11.B16",
          "\tSUBS $1, R7, R7", "\tBNE loop", "",
          "\tVZIP1 V10.D2, V8.D2, V28.D2", "\tVZIP2 V10.D2, V8.D2, V29.D2",
          "\tVZIP1 V11.D2, V9.D2, V30.D2", "\tVZIP2 V11.D2, V9.D2, V31.D2",
          "\tVST1 [V28.D2, V29.D2, V30.D2, V31.D2], (R3)", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- GPR x1 (arm64)

GPR_ROUND_ARM64 = ["\tADD R9, R8, R8", "\tROR $51, R9, R9", "\tEOR R8, R9, R9", "\tROR $32, R8, R8",
                   "\tADD R11, R10, R10", "\tROR $48, R11, R11", "\tEOR R10, R11, R11",
                   "\tADD R11, R8, R8", "\tROR $43, R11, R11", "\tEOR R8, R11, R11",
                   "\tADD R9, R10, R10", "\tROR $47, R9, R9", "\tEOR R10, R9, R9", "\tROR $32, R10, R10"]


def gpr_x1_arm64(shape):
    nw = words(shape)
    L = [f"// func sipHash24FusedChain{shape}x1GprAsm(comps *uint64, nPairs int, data *byte, out *[2]uint64)",
         f"TEXT ·sipHash24FusedChain{shape}x1GprAsm(SB), NOSPLIT, $0-32",
         "\tMOVD comps+0(FP), R6", "\tMOVD nPairs+8(FP), R7", "\tMOVD data+16(FP), R2", "\tMOVD out+24(FP), R3", ""]
    L += arm_word(shape, 0, "R2", "R24", "R16")
    L += arm_word(shape, nw - 1, "R2", "R19", "R16") + [f"\tMOVD ${tag(shape):#x}, R16", "\tORR R16, R19, R19"]
    L += [f"\tMOVD ${C0:#x}, R20", f"\tMOVD ${C1EE:#x}, R21", f"\tMOVD ${C2:#x}, R22", f"\tMOVD ${C3:#x}, R23",
          "\tMOVD $0xee, R25", "\tMOVD $0xdd, R17",
          "\tMOVD $0, R12", "\tMOVD $0, R13", "", "loop:",
          "\tMOVD 0(R6), R14", "\tEOR R12, R14, R14", "\tMOVD 8(R6), R15", "\tEOR R13, R15, R15", "\tADD $16, R6, R6",
          "\tEOR R20, R14, R8", "\tEOR R21, R15, R9", "\tEOR R22, R14, R10", "\tEOR R23, R15, R11"]
    for w in range(nw):
        if w == nw - 1:
            m = "R19"
        elif w == 0:
            m = "R24"
        else:
            L.append(f"\tMOVD {8 * w}(R2), R16")
            m = "R16"
        L += [f"\tEOR {m}, R11, R11"] + GPR_ROUND_ARM64 + GPR_ROUND_ARM64 + [f"\tEOR {m}, R8, R8"]
    L += ["\tEOR R25, R10, R10"] + GPR_ROUND_ARM64 * 4
    L += ["\tEOR R9, R8, R12", "\tEOR R10, R12, R12", "\tEOR R11, R12, R12", "\tEOR R17, R9, R9"] + GPR_ROUND_ARM64 * 4
    L += ["\tEOR R9, R8, R13", "\tEOR R10, R13, R13", "\tEOR R11, R13, R13",
          "\tSUBS $1, R7, R7", "\tBNE loop", "",
          "\tMOVD R12, 0(R3)", "\tMOVD R13, 8(R3)", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- emit

X16_HEADER = f"""//go:build {AMD}

// AVX-512 ZMM 16-lane fused ChainHash cascade kernel for SipHash-2-4-128
// at the 13-byte per-lane fill shape (2 message words, 12 SipRounds per
// lane and cascade round). See siphashasm_fused.go for the construction;
// the kernel is pinned to the pure-Go reference (scalarFusedX16) by the
// in-package parity tests.
//
// Unique to the batch-16 kernel: the fill block
// [0x03 | LE64(groupIdxBase+i) | 4×0x00] of lane i is synthesised
// in-register as its two message words m0 = (idx << 8) | 0x03 and
// m1 = (idx >> 56) | (13 << 56) (idx = groupIdxBase + i, with the lane
// offsets read from ·laneIdx16), so the batch-16 path pays no per-lane
// pointer gather. The sixteen lanes run as two eight-lane groups whose
// instruction streams are interleaved, so the two independent dependency
// chains overlap on the vector ALUs. The 16 (lo, hi) pairs are
// interleaved through ·interleaveIdx16 and written as four 64-byte
// stores in lane order; the fill closure reads them back with 8-byte
// loads.

#include "textflag.h"
"""


def render_all():
    files = {"siphash_fusedchain128_13x16_avx512_amd64.s": X16_HEADER + "\n" + evex_x16()}
    for s in SHAPES:
        files.update({
            f"siphash_fusedchain128_{s}x4_avx512_amd64.s": header(s, 4, "AVX-512 EVEX YMM (one lane per qword, VPROLQ rotates)", AMD) + "\n" + evex_x4(s),
            f"siphash_fusedchain128_{s}x4_avx2_amd64.s": header(s, 4, "AVX2 VEX YMM (one lane per qword, synthesised rotates)", AMD) + "\n" + avx2_x4(s),
            f"siphash_fusedchain128_{s}x1_gpr_amd64.s": header(s, 1, "amd64 general-purpose-register", AMD) + "\n" + gpr_x1_amd64(s),
            f"siphash_fusedchain128_{s}x4_neon_arm64.s": header(s, 4, "ARM64 NEON (two lanes per register)", ARM) + "\n" + neon_x4(s),
            f"siphash_fusedchain128_{s}x1_gpr_arm64.s": header(s, 1, "ARM64 general-purpose-register", ARM) + "\n" + gpr_x1_arm64(s),
        })
    for s in X8_SHAPES:
        files[f"siphash_fusedchain128_{s}x8_avx512_amd64.s"] = (
            header(s, 8, "AVX-512 ZMM (one lane per qword, eight lanes per register)", AMD) + "\n" + evex_x8(s))
    return files


def main(argv):
    """Write every kernel, or with --check compare against the committed
    files without writing (exit status 1 on any drift)."""
    check = "--check" in argv[1:]
    unknown = [a for a in argv[1:] if a != "--check"]
    if unknown:
        raise SystemExit(f"gen_fused_kernels.py: unknown argument(s) {unknown}; known: --check")
    drift = 0
    for name, body in render_all().items():
        path = os.path.join(OUT, name)
        if check:
            with open(path, "rb") as f:
                committed = f.read()
            if committed == body.encode("utf-8"):
                print("clean", name)
            else:
                print("DRIFT", name)
                drift += 1
        else:
            with open(path, "w") as f:
                f.write(body)
            print("wrote", name)
    if drift:
        raise SystemExit(f"gen_fused_kernels.py: {drift} file(s) differ from the generator output")


if __name__ == "__main__":
    main(sys.argv)
