#!/usr/bin/env python3
"""Emit the AES-CMAC fused ChainHash cascade kernels for hashes/internal/aescmacasm.

One file per (shape, lanes, tier). Shapes 13/20/36/68; lanes x4 (four data
lanes over one shared component slice) and x1 (single lane); amd64 tiers
aesni / vex / vaesavx2 / avx512 for x4, aesni / vex for x1; arm64 tier neon
for both.

The avx512 tier additionally carries an x8 variant at the three nonce-buf
shapes 20/36/68 (aescmac_fusedchain128_<shape>x8_avx512_amd64.s): eight
lanes in two ZMM state groups (lanes 0..3 in Z0, lanes 4..7 in Z1) whose
cascade rounds are interleaved instruction by instruction, so the two
independent VAESENC dependency chains overlap on the AES unit. See
zmm_fused_x8 for the register plan.

A third family, x16 at shape 13 only, is the Interlocked Barrier PRF fill
kernel (aescmac_fusedchain128_13x16_<tier>_amd64.s for the four amd64 tiers
and aescmac_fusedchain128_13x16_neon_arm64.s): the kernel receives
groupIdxBase in a GPR and synthesises the 16 per-lane fill blocks
in-register — [0x03 | LE64(groupIdxBase+i) | 7×0x00] for lane i — so the
batch-16 path pays no per-lane pointer gather, then runs the same cascade
per lane. See the x16 section below for the per-tier register plans.

Cascade evaluated per lane (see aescmacasm_fused.go):
    state = 0
    for each component pair (c0, c1):
        state ^= LE64(c0) || LE64(c1)
        state ^= block_0 ^ (LE64(len) || LE64(len)); state = AES_K(state)
        for each further zero-padded data block b: state ^= block_b; state = AES_K(state)
    out = state
AES_K is the full AES-128 permutation under the eleven round keys K0..K10
of the schedule the kernels receive (aescmacasm.ExpandKeyAES128). The data
blocks are round-invariant and are staged once with K0 folded in (block 0
additionally with the length tag), so every permutation in the loop runs
nine AESENC under K1..K9 and one AESENCLAST under K10 from the staged
block XOR. The XMM tiers stage the blocks into the stack frame at
SP + 64*b + 16*lane; the YMM tier stages them as 32-byte lane-pair slots
at SP + 64*b + 32*half; the ZMM tiers keep them in registers. On arm64 the
zero-padded tail block sits in V28..V31 and full blocks are reloaded from
the lane pointer each round.

Load shapes are matched to the stores the Go call sites leave in flight
so store-to-load forwarding succeeds: the caller writes a 4-byte pixel
index at offset 0 of every lane buffer immediately before the call, so
block 0 is read as two 4-byte inserts plus an 8-byte insert rather than
one 16-byte load, and no wide load spans a narrower staging store. The
lane outputs are written as 16-byte stores on every tier — the width the
Go side reads them back with — rather than one 32- or 64-byte store,
except the batch-16 kernels, whose full-width stores feed 8-byte reads
far enough behind the store (see the x16 section).

Round-key residency per tier (K1..K10 are the keys the loop consumes):
    xmm x4/x1     X6..X15 = K1..K10; X5 pair load; X4 scratch; X13 is the
                  zero insert source during staging
    ymm x4        Y3..Y12 = K1..K10 broadcasts; Y13 pair broadcast; blocks
                  in the frame
    zmm x4        Z1..Z10 = K1..K10; Z11 pair; Z15.. blocks
    zmm x8        Z2..Z11 = K1..K10; Z12 pair; Z16.. blocks (two groups)
    xmm x16 vex   X8..X15 = K1..K8; K9 / K10 as VAESENC memory operands
    xmm x16 aesni X9..X15 = K4..K10; K1..K3 reloaded through X8 per round
                  (legacy-SSE AESENC m128 needs a 16-byte-aligned operand
                  the Go frame does not guarantee)
    ymm x16       Y9..Y15 = K1..K7; K8..K10 duplicated into the frame as
                  32-byte slots and consumed as VAESENC memory operands
    zmm x16       Z4..Z13 = K1..K10; Z14 pair; Z16..Z19 blocks
    neon          V16..V24 = K1..K9, V25 = K10; K0 folded into the AESE
                  operand of every block, K10 of block b folded into the
                  operand of block b+1 and applied explicitly after the
                  last block
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "hashes", "internal", "aescmacasm")
SHAPES = [13, 20, 36, 68]
# Shapes with an eight-lane ZMM fused kernel: the 128 / 256 / 512-bit
# nonce-buf shapes the pixel pipeline drives through the batched hook.
X8_SHAPES = [20, 36, 68]
AMD = "amd64 && !purego && !noitbasm"
ARM = "arm64 && !purego && !noitbasm"


def blocks(n):
    """Zero-padded 16-byte blocks of an n-byte input (no padding block)."""
    return (n + 15) // 16


def staging_note(tier):
    if tier == "xmm":
        return ("// The data blocks are staged once into the frame with K0 (and, for\n"
                "// block 0, the length tag) folded in, and every cascade round runs\n"
                "// from those 16-byte slots")
    if tier == "ymm":
        return ("// The data blocks are staged once into the frame as 32-byte lane-pair\n"
                "// slots with K0 (and, for block 0, the length tag) folded in, and\n"
                "// every cascade round runs from those slots")
    return ("// The data blocks are staged once in registers with K0 (and, for\n"
            "// block 0, the length tag) folded in, and every cascade round runs\n"
            "// from registers")


def header(shape, lanes, tier_desc, build, tier):
    nb = blocks(shape)
    if tier == "neon":
        return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for AES-CMAC at the
// {shape}-byte shape, {lanes} lane{'s' if lanes > 1 else ''} ({nb} zero-padded block{'s' if nb > 1 else ''}, {nb} AES-128
// permutation{'s' if nb > 1 else ''} per cascade round). The tail block is staged once with the
// first round key folded in and full blocks are reloaded from the lane
// pointer every round; see aescmacasm_fused.go for the construction and
// the in-package parity tests for the bit-exact pin against the pure-Go
// cascade.

#include "textflag.h"
"""
    return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for AES-CMAC at the
// {shape}-byte shape, {lanes} lane{'s' if lanes > 1 else ''} ({nb} zero-padded block{'s' if nb > 1 else ''}, {nb} AES-128
// permutation{'s' if nb > 1 else ''} per cascade round).
{staging_note(tier)}; see aescmacasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"
"""


def lane_block(shape, b, r, vex, zero="X13", dst="X4"):
    """Assemble zero-padded block b of the lane at pointer r into dst.

    Block 0 and the tail are read with exact-width inserts (zero holds the
    all-zero vector and serves as the merge source, so lanes assemble
    without a dependency on each other); the 4-byte inserts at offsets 0
    and 4 match the caller's 4-byte pixel-index store. Full blocks past
    block 0 are one 16-byte load.
    """
    nb = blocks(shape)
    off = 16 * b
    mov = "VMOVDQU" if vex else "MOVOU"
    L = []
    if b == nb - 1:
        if shape == 13:
            if vex:
                L.append(f"\tVPINSRQ $0, {off}({r}), {zero}, {dst}")
                L.append(f"\tVPINSRD $2, {off + 8}({r}), {dst}, {dst}")
                L.append(f"\tVPINSRB $12, {off + 12}({r}), {dst}, {dst}")
            else:
                L.append(f"\tMOVOU {zero}, {dst}")
                L.append(f"\tPINSRQ $0, {off}({r}), {dst}")
                L.append(f"\tPINSRD $2, {off + 8}({r}), {dst}")
                L.append(f"\tPINSRB $12, {off + 12}({r}), {dst}")
        else:
            if vex:
                L.append(f"\tVPINSRD $0, {off}({r}), {zero}, {dst}")
            else:
                L.append(f"\tMOVOU {zero}, {dst}")
                L.append(f"\tPINSRD $0, {off}({r}), {dst}")
    elif b == 0:
        if vex:
            L.append(f"\tVPINSRD $0, 0({r}), {zero}, {dst}")
            L.append(f"\tVPINSRD $1, 4({r}), {dst}, {dst}")
            L.append(f"\tVPINSRQ $1, 8({r}), {dst}, {dst}")
        else:
            L.append(f"\tMOVOU {zero}, {dst}")
            L.append(f"\tPINSRD $0, 0({r}), {dst}")
            L.append(f"\tPINSRD $1, 4({r}), {dst}")
            L.append(f"\tPINSRQ $1, 8({r}), {dst}")
    else:
        L.append(f"\t{mov} {off}({r}), {dst}")
    return L


def prologue_amd64(lanes):
    arg = "dataPtrs" if lanes == 4 else "data"
    L = ["\tMOVQ roundKeys+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         f"\tMOVQ {arg}+24(FP), DX", "\tMOVQ out+32(FP), DI"]
    if lanes == 4:
        L += ["\tMOVQ 0(DX), R8", "\tMOVQ 8(DX), R9", "\tMOVQ 16(DX), R10", "\tMOVQ 24(DX), R11"]
    else:
        L += ["\tMOVQ DX, R8"]
    return L


def xmm_consts(shape, vex):
    """X13 = 0 (insert source), X14 = K0, X15 = K0 ^ (len || len)."""
    if vex:
        return ["\tVPXOR X13, X13, X13", "\tVMOVDQU 0(AX), X14", f"\tMOVQ ${shape}, R12", "\tVMOVQ R12, X15",
                "\tVPUNPCKLQDQ X15, X15, X15", "\tVPXOR X14, X15, X15"]
    return ["\tPXOR X13, X13", "\tMOVOU 0(AX), X14", f"\tMOVQ ${shape}, R12", "\tMOVQ R12, X15",
            "\tPUNPCKLQDQ X15, X15", "\tPXOR X14, X15"]


def xmm_fold(b):
    return "X15" if b == 0 else "X14"


def stage_amd64(shape, lanes, vex, regs):
    """Prologue: stage folded blocks into the frame at 64*b + 16*lane (SP)."""
    nb = blocks(shape)
    mov = "VMOVDQU" if vex else "MOVOU"
    L = xmm_consts(shape, vex)
    for b in range(nb):
        for l in range(lanes):
            L += lane_block(shape, b, regs[l], vex)
            L.append(f"\tVPXOR {xmm_fold(b)}, X4, X4" if vex else f"\tPXOR {xmm_fold(b)}, X4")
            L.append(f"\t{mov} X4, {64 * b + 16 * l}(SP)")
    return L


def xmm_rounds(lanes, vex, key):
    """Nine AESENC under K1..K9 and one AESENCLAST under K10 on lanes 0..lanes-1.

    key(r) names the operand holding K_r.
    """
    L = []
    for r in range(1, 10):
        if vex:
            L.append("\t" + "; ".join(f"VAESENC {key(r)}, X{l}, X{l}" for l in range(lanes)))
        else:
            L.append("\t" + "; ".join(f"AESENC {key(r)}, X{l}" for l in range(lanes)))
    if vex:
        L.append("\t" + "; ".join(f"VAESENCLAST {key(10)}, X{l}, X{l}" for l in range(lanes)))
    else:
        L.append("\t" + "; ".join(f"AESENCLAST {key(10)}, X{l}" for l in range(lanes)))
    return L


def xmm_fused(shape, lanes, vex):
    nb = blocks(shape)
    tier = "Vex" if vex else "AesNi"
    regs = ["R8", "R9", "R10", "R11"][:lanes]
    frame = 64 * nb
    sig = "dataPtrs *[4]*byte, out *[4][2]uint64" if lanes == 4 else "data *byte, out *[2]uint64"
    L = [f"// func aesCMAC128FusedChain{shape}x{lanes}{tier}Asm(roundKeys *[176]byte, comps *uint64, nPairs int, {sig})",
         f"TEXT ·aesCMAC128FusedChain{shape}x{lanes}{tier}Asm(SB), NOSPLIT, ${frame}-40"]
    L += prologue_amd64(lanes)
    L.append("")
    L += stage_amd64(shape, lanes, vex, regs)
    L.append("")
    mov = "VMOVDQU" if vex else "MOVOU"
    for r in range(1, 11):
        L.append(f"\t{mov} {16 * r}(AX), X{5 + r}")
    for l in range(lanes):
        L.append(f"\tVPXOR X{l}, X{l}, X{l}" if vex else f"\tPXOR X{l}, X{l}")
    L.append("")
    L.append("loop:")
    key = lambda r: f"X{5 + r}"
    if vex:
        L.append("\tVMOVDQU 0(BX), X5")
        for l in range(lanes):
            L.append(f"\tVPXOR X5, X{l}, X{l}")
        for b in range(nb):
            for l in range(lanes):
                L.append(f"\tVPXOR {64 * b + 16 * l}(SP), X{l}, X{l}")
            L += xmm_rounds(lanes, True, key)
    else:
        L.append("\tMOVOU 0(BX), X5")
        for l in range(lanes):
            L.append(f"\tPXOR X5, X{l}")
        for b in range(nb):
            for l in range(lanes):
                L.append(f"\tMOVOU {64 * b + 16 * l}(SP), X4")
                L.append(f"\tPXOR X4, X{l}")
            L += xmm_rounds(lanes, False, key)
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", ""]
    for l in range(lanes):
        L.append(f"\t{mov} X{l}, {16 * l}(DI)")
    L.append("\tRET")
    return "\n".join(L) + "\n"


def ymm_fused(shape):
    """VAES YMM: lanes (0, 1) in Y0, lanes (2, 3) in Y1.

    Round keys K1..K10 broadcast into Y3..Y12; Y13 holds the per-round
    component pair broadcast. Every block is staged into the frame as two
    32-byte lane-pair slots (SP + 64*b for lanes 0/1, SP + 64*b + 32 for
    lanes 2/3) with K0 — and the length tag for block 0 — folded in, and
    consumed as a 32-byte VPXOR operand every round.
    """
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"]
    frame = 64 * nb
    L = [f"// func aesCMAC128FusedChain{shape}x4VaesAvx2Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)",
         f"TEXT ·aesCMAC128FusedChain{shape}x4VaesAvx2Asm(SB), NOSPLIT, ${frame}-40"]
    L += prologue_amd64(4)
    L.append("")
    L += ["\tVPXOR X13, X13, X13", "\tVBROADCASTI128 0(AX), Y14", f"\tMOVQ ${shape}, R12", "\tVMOVQ R12, X15",
          "\tVPBROADCASTQ X15, Y15", "\tVPXOR Y14, Y15, Y15"]
    for b in range(nb):
        fold = "Y15" if b == 0 else "Y14"
        for ra, rb, off in ((regs[0], regs[1], 64 * b), (regs[2], regs[3], 64 * b + 32)):
            if 0 < b < nb - 1:
                L.append(f"\tVMOVDQU {16 * b}({ra}), X2")
                L.append(f"\tVINSERTI128 $1, {16 * b}({rb}), Y2, Y2")
            else:
                L += lane_block(shape, b, ra, True, dst="X2")
                L += lane_block(shape, b, rb, True)
                L.append("\tVINSERTI128 $1, X4, Y2, Y2")
            L.append(f"\tVPXOR {fold}, Y2, Y2")
            L.append(f"\tVMOVDQU Y2, {off}(SP)")
    L.append("")
    for r in range(1, 11):
        L.append(f"\tVBROADCASTI128 {16 * r}(AX), Y{2 + r}")
    L += ["\tVPXOR Y0, Y0, Y0", "\tVPXOR Y1, Y1, Y1", "", "loop:",
          "\tVBROADCASTI128 0(BX), Y13", "\tVPXOR Y13, Y0, Y0", "\tVPXOR Y13, Y1, Y1"]
    for b in range(nb):
        L.append(f"\tVPXOR {64 * b}(SP), Y0, Y0")
        L.append(f"\tVPXOR {64 * b + 32}(SP), Y1, Y1")
        for r in range(1, 10):
            L.append(f"\tVAESENC Y{2 + r}, Y0, Y0; VAESENC Y{2 + r}, Y1, Y1")
        L.append("\tVAESENCLAST Y12, Y0, Y0; VAESENCLAST Y12, Y1, Y1")
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI128 $1, Y0, 16(DI)",
          "\tVMOVDQU X1, 32(DI)", "\tVEXTRACTI128 $1, Y1, 48(DI)", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def zmm_stage_group(shape, regs, base, zero="X12"):
    """Stage the blocks of four lanes at regs into Z(base)..Z(base+nb-1)."""
    nb = blocks(shape)
    L = []
    for b in range(nb):
        z = f"Z{base + b}"
        for l in range(4):
            if 0 < b < nb - 1 and l > 0:
                L.append(f"\tVINSERTI64X2 ${l}, {16 * b}({regs[l]}), {z}, {z}")
                continue
            L += lane_block(shape, b, regs[l], True, zero=zero)
            L.append(f"\tVINSERTI64X2 ${l}, X4, {z}, {z}")
    return L


def zmm_rounds(states, keybase):
    """Interleaved AES-128 rounds 1..10 on the given ZMM states; K_r in Z(keybase+r)."""
    L = []
    for r in range(1, 10):
        L.append("\t" + "; ".join(f"VAESENC Z{keybase + r}, {s}, {s}" for s in states))
    L.append("\t" + "; ".join(f"VAESENCLAST Z{keybase + 10}, {s}, {s}" for s in states))
    return L


def zmm_fused(shape):
    """VAES ZMM: all four lanes in Z0; block b staged in Z(15+b).

    Z1..Z10 hold K1..K10, Z11 the per-round pair broadcast, Z13 the K0
    broadcast and Z14 K0 ^ (len || len); Z12 is the zero insert source.
    """
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"]
    L = [f"// func aesCMAC128FusedChain{shape}x4Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)",
         f"TEXT ·aesCMAC128FusedChain{shape}x4Avx512Asm(SB), NOSPLIT, $0-40"]
    L += prologue_amd64(4)
    L.append("")
    L += ["\tVPXORD Z12, Z12, Z12", "\tVBROADCASTI32X4 0(AX), Z13", f"\tMOVQ ${shape}, R12",
          "\tVPBROADCASTQ R12, Z14", "\tVPXORD Z13, Z14, Z14"]
    L += zmm_stage_group(shape, regs, 15)
    for b in range(nb):
        L.append(f"\tVPXORD {'Z14' if b == 0 else 'Z13'}, Z{15 + b}, Z{15 + b}")
    L.append("")
    for r in range(1, 11):
        L.append(f"\tVBROADCASTI32X4 {16 * r}(AX), Z{r}")
    L += ["\tVPXORD Z0, Z0, Z0", "", "loop:", "\tVBROADCASTI32X4 0(BX), Z11",
          "\tVPTERNLOGQ $0x96, Z11, Z15, Z0"]
    L += zmm_rounds(["Z0"], 0)
    for b in range(1, nb):
        L.append(f"\tVPXORD Z{15 + b}, Z0, Z0")
        L += zmm_rounds(["Z0"], 0)
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI64X2 $1, Z0, 16(DI)",
          "\tVEXTRACTI64X2 $2, Z0, 32(DI)", "\tVEXTRACTI64X2 $3, Z0, 48(DI)", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def zmm_fused_x8(shape):
    """VAES ZMM, eight lanes: lanes 0..3 in Z0, lanes 4..7 in Z1.

    Register plan: Z2..Z11 K1..K10 broadcasts, Z12 the per-round pair
    broadcast, Z13 the zero insert source, Z14 the K0 broadcast, Z15
    K0 ^ (len || len), Z16..Z(15+nb) the staged blocks of lanes 0..3 and
    Z(16+nb)..Z(15+2nb) those of lanes 4..7 — 26 registers at shape 68,
    22 at 36, 20 at 20. The lane pointers are read four at a time through
    R8..R11 (group 0 from dataPtrs[0..3], group 1 from dataPtrs[4..7])
    with the same exact-width block-0 / tail inserts as the x4 kernel.

    Loop body: the pair and block 0 fold into each state with one
    VPTERNLOGQ (XOR3), then every AES round issues for group 0 and group
    1 back to back, so the two independent state chains overlap on the
    AES unit instead of serialising as one chain per call. Output: eight
    16-byte stores, the width the Go side reads back.
    """
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"]
    L = [f"// func aesCMAC128FusedChain{shape}x8Avx512Asm(roundKeys *[176]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)",
         f"TEXT ·aesCMAC128FusedChain{shape}x8Avx512Asm(SB), NOSPLIT, $0-40",
         "\tMOVQ roundKeys+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ dataPtrs+24(FP), DX", "\tMOVQ out+32(FP), DI", ""]
    L += ["\tVPXORD Z13, Z13, Z13", "\tVBROADCASTI32X4 0(AX), Z14", f"\tMOVQ ${shape}, R12",
          "\tVPBROADCASTQ R12, Z15", "\tVPXORD Z14, Z15, Z15"]
    for g in range(2):
        L.append(f"\t// Lanes {4 * g}..{4 * g + 3}: blocks 0..{nb - 1} into Z{16 + nb * g}..Z{15 + nb * (g + 1)}")
        for l in range(4):
            L.append(f"\tMOVQ {32 * g + 8 * l}(DX), {regs[l]}")
        L += zmm_stage_group(shape, regs, 16 + nb * g, zero="X13")
        for b in range(nb):
            z = f"Z{16 + nb * g + b}"
            L.append(f"\tVPXORD {'Z15' if b == 0 else 'Z14'}, {z}, {z}")
    L.append("")
    for r in range(1, 11):
        L.append(f"\tVBROADCASTI32X4 {16 * r}(AX), Z{1 + r}")
    L += ["\tVPXORD Z0, Z0, Z0", "\tVPXORD Z1, Z1, Z1", "", "loop:",
          "\tVBROADCASTI32X4 0(BX), Z12",
          f"\tVPTERNLOGQ $0x96, Z12, Z16, Z0; VPTERNLOGQ $0x96, Z12, Z{16 + nb}, Z1"]
    L += zmm_rounds(["Z0", "Z1"], 1)
    for b in range(1, nb):
        L.append(f"\tVPXORD Z{16 + b}, Z0, Z0; VPXORD Z{16 + nb + b}, Z1, Z1")
        L += zmm_rounds(["Z0", "Z1"], 1)
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "",
          "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI64X2 $1, Z0, 16(DI)",
          "\tVEXTRACTI64X2 $2, Z0, 32(DI)", "\tVEXTRACTI64X2 $3, Z0, 48(DI)",
          "\tVMOVDQU X1, 64(DI)", "\tVEXTRACTI64X2 $1, Z1, 80(DI)",
          "\tVEXTRACTI64X2 $2, Z1, 96(DI)", "\tVEXTRACTI64X2 $3, Z1, 112(DI)",
          "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- NEON
#
# AES-128 on the crypto extension: AESE folds its operand into the state
# before SubBytes / ShiftRows, so the K0 XOR of every block and the
# state XOR of the block itself ride on the first AESE (operand =
# block ^ K0, plus the length tag for block 0, plus K10 of the previous
# block for blocks past the first); rounds 1..8 are AESE K_r + AESMC,
# round 9 is AESE K9 without AESMC, and K10 is applied by an explicit
# EOR after the last block. Each AESE is followed immediately by its
# AESMC on the same register so the pair fuses on cores that fuse them.
#
# Register plan (x4 / x1): V0..V3 states, V4 pair load, V5 T0 =
# K0 ^ (len || len), V6 T = K0 ^ K10, V7 K0 (prologue only), V8..V11
# per-lane full-block loads, V16..V24 K1..K9, V25 K10, V28..V31 the
# staged tail blocks (already folded with T0 at one-block shapes and
# with T otherwise).


def neon_keys(r0, tmp):
    """Load K1..K9 into V16..V24 and K10 into V25 from the schedule at r0,
    walking the schedule through the scratch pointer tmp."""
    return [f"\tADD $16, {r0}, {tmp}",
            f"\tVLD1.P 64({tmp}), [V16.B16, V17.B16, V18.B16, V19.B16]",
            f"\tVLD1.P 64({tmp}), [V20.B16, V21.B16, V22.B16, V23.B16]",
            f"\tVLD1.P 16({tmp}), [V24.B16]",
            f"\tVLD1 ({tmp}), [V25.B16]"]


def neon_consts(shape, r0):
    """V7 = K0; V5 = K0 ^ (len || len); V6 = K0 ^ K10."""
    return [f"\tVLD1 ({r0}), [V7.B16]", f"\tMOVD ${shape}, R12", "\tVMOV R12, V5.D[0]", "\tVMOV R12, V5.D[1]",
            "\tVEOR V7.B16, V5.B16, V5.B16", "\tVEOR V7.B16, V25.B16, V6.B16"]


def neon_rounds(lanes, first):
    """One AES-128 permutation per lane: AESE first(l) + AESMC, AESE K1..K8 + AESMC, AESE K9."""
    L = []
    for l in range(lanes):
        L += [f"\tAESE {first(l)}.B16, V{l}.B16", f"\tAESMC V{l}.B16, V{l}.B16"]
    for r in range(1, 9):
        for l in range(lanes):
            L += [f"\tAESE V{15 + r}.B16, V{l}.B16", f"\tAESMC V{l}.B16, V{l}.B16"]
    for l in range(lanes):
        L.append(f"\tAESE V24.B16, V{l}.B16")
    return L


def neon_fused(shape, lanes):
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"][:lanes]
    sig = "dataPtrs *[4]*byte, out *[4][2]uint64" if lanes == 4 else "data *byte, out *[2]uint64"
    arg = "dataPtrs" if lanes == 4 else "data"
    L = [f"// func aesCMAC128FusedChain{shape}x{lanes}NeonAsm(roundKeys *[176]byte, comps *uint64, nPairs int, {sig})",
         f"TEXT ·aesCMAC128FusedChain{shape}x{lanes}NeonAsm(SB), NOSPLIT, $0-40",
         "\tMOVD roundKeys+0(FP), R0", "\tMOVD comps+8(FP), R6", "\tMOVD nPairs+16(FP), R7",
         f"\tMOVD {arg}+24(FP), R2", "\tMOVD out+32(FP), R3"]
    L += neon_keys("R0", "R4")
    L += neon_consts(shape, "R0")

    def load_ptrs():
        if lanes == 4:
            return ["\tMOVD 0(R2), R8", "\tMOVD 8(R2), R9", "\tMOVD 16(R2), R10", "\tMOVD 24(R2), R11"]
        return ["\tMOVD R2, R8"]

    L += load_ptrs()
    toff = 16 * (nb - 1)
    tail_fold = "V5" if nb == 1 else "V6"
    for l in range(lanes):
        r, t = regs[l], f"V{28 + l}"
        L.append(f"\tVEOR {t}.B16, {t}.B16, {t}.B16")
        if shape == 13:
            L += [f"\tMOVD ({r}), R12", f"\tVMOV R12, {t}.D[0]",
                  f"\tMOVWU 8({r}), R12", f"\tVMOV R12, {t}.S[2]",
                  f"\tMOVBU 12({r}), R12", f"\tVMOV R12, {t}.B[12]"]
        else:
            L += [f"\tMOVWU {toff}({r}), R12", f"\tVMOV R12, {t}.S[0]"]
        L.append(f"\tVEOR {tail_fold}.B16, {t}.B16, {t}.B16")
    for l in range(lanes):
        L.append(f"\tVEOR V{l}.B16, V{l}.B16, V{l}.B16")
    L += ["", "loop:", "\tVLD1.P 16(R6), [V4.B16]"]
    for l in range(lanes):
        L.append(f"\tVEOR V4.B16, V{l}.B16, V{l}.B16")
    L += load_ptrs()
    for b in range(nb):
        if b < nb - 1:
            fold = "V5" if b == 0 else "V6"
            for l in range(lanes):
                L.append(f"\tVLD1.P 16({regs[l]}), [V{8 + l}.B16]")
                L.append(f"\tVEOR {fold}.B16, V{8 + l}.B16, V{8 + l}.B16")
            L += neon_rounds(lanes, lambda l: f"V{8 + l}")
        else:
            L += neon_rounds(lanes, lambda l: f"V{28 + l}")
    for l in range(lanes):
        L.append(f"\tVEOR V25.B16, V{l}.B16, V{l}.B16")
    L += ["\tSUBS $1, R7, R7", "\tBNE loop", ""]
    if lanes == 4:
        L.append("\tVST1 [V0.B16, V1.B16, V2.B16, V3.B16], (R3)")
    else:
        L.append("\tVST1 [V0.B16], (R3)")
    L.append("\tRET")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- x16 fill family
#
# The batch-16 kernels at the 13-byte fill shape. Every tier folds the
# round-invariant synthesised block (with K0 and the length tag) and the
# per-round pair into the state and runs the ten AES rounds under
# K1..K10; with one pair the cascade is the plain chain-absorb of the
# shape. Parity with scalarFusedX16 (aescmacasm_fused.go) is enforced by
# the in-package parity tests.
#
# Output store width: the wide tiers write the 16 rank pairs at their full
# register width (eight 32-byte stores on YMM, four 64-byte stores on ZMM).
# The fill closure reads the pairs back with 8-byte loads immediately after
# the call, and those loads forward from the wide stores on every measured
# host (see the AES-ITB-128 generator for the measurement). The generator
# carries no numeric tables of its own: the absorb block and the ZMM
# lane-offset table are read from the Go side (·absorb13Block, ·laneIdxZ).

X16_SIG = "roundKeys *[176]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64"

X16_TIERS = {
    "aesni": ("Legacy-SSE AES-NI XMM (AESENC xmm, xmm)", AMD,
              "aescmac_fusedchain128_13x16_aesni_amd64.s"),
    "vex": ("VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm; needs AES-NI + AVX)", AMD,
            "aescmac_fusedchain128_13x16_vex_amd64.s"),
    "vaesavx2": ("VAES YMM, two lanes per 256-bit register (needs VAES + AVX2)", AMD,
                 "aescmac_fusedchain128_13x16_vaesavx2_amd64.s"),
    "avx512": ("VAES ZMM, four lanes per register (needs VAES + AVX-512)", AMD,
               "aescmac_fusedchain128_13x16_avx512_amd64.s"),
    "neon": ("ARM64 NEON crypto-extension (AESE + AESMC, K0 folded into the first AESE operand)",
             ARM,
             "aescmac_fusedchain128_13x16_neon_arm64.s"),
}

X16_CASCADE_NOTE = """//
// Unique to the batch-16 kernel: groupIdx is synthesized in-register from
// groupIdxBase per lane, avoiding the per-lane pointer gather overhead of
// the x4 path. The synthesised block is round-invariant per lane and
// carries K0 and the length tag; every cascade round XORs the pair and
// the block into the state and runs the ten AES rounds under K1..K10.
"""


def x16_comment_xmm(tier_desc, vex):
    keys = ("X8–X15 K1..K8 (K9 / K10 as memory operands)" if vex
            else "X9–X15 K4..K10 (K1..K3 reloaded through X8 per round)")
    return f"""// {tier_desc} 16-lane fused ChainHash cascade kernel for AES-CMAC
// at the 13-byte per-lane fill shape (1 zero-padded block, 1 AES-128
// permutation per lane and cascade round). See aescmacasm_fused.go for
// the construction; every tier is pinned to the pure-Go reference
// (scalarFusedX16) by the in-package parity tests.
""" + X16_CASCADE_NOTE + f"""//
// Batch layout: two batches of 8 lanes; each batch runs the whole cascade
// before the next starts. The 16 blocks are staged once into the frame
// (16 bytes per lane) in the prologue. Per batch: X0–X7 states,
// {keys}.
"""


def x16_comment_ymm(tier_desc):
    return f"""// {tier_desc} 16-lane fused ChainHash cascade kernel
// for AES-CMAC at the 13-byte per-lane fill shape (1 zero-padded block,
// 1 AES-128 permutation per lane and cascade round). See
// aescmacasm_fused.go for the construction; every tier is pinned to the
// pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Batch layout: 8 YMM states, two lanes per YMM (lanes 2i and 2i+1 in Y[i]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// VPUNPCKLQDQ, avoiding per-lane pointer gather overhead of the x4 path.
// The 8 block pairs are staged to the frame with 32-byte stores in the
// prologue and read back as 32-byte VPXOR operands in every cascade
// round; K8..K10 are duplicated into the frame behind them and consumed
// as 32-byte VAESENC operands (the register file cannot hold states,
// eleven keys and blocks).
//
// Register allocation:
//   Y0–Y7      states, pair i = lanes (2i, 2i+1)
//   Y8         component pair, broadcast per cascade round
//   Y9–Y15     K1..K7 broadcasts
//   Y10, Y11, Y15   scratch during block synthesis (prologue only)
//   0(SP)..255(SP)    the 8 staged block pairs
//   256(SP)..351(SP)  K8, K9, K10 duplicated across both halves
//
// Per-pair synthesis (no index vector):
//   - Calculate groupIdx for both lanes (2i and 2i+1)
//   - Load into X11 (lane 2i) and X15 (lane 2i+1)
//   - VINSERTI128 to form YMM with [gi_even | gi_odd]
//   - VPUNPCKLQDQ to transform [gi, 0] into [gi<<8, gi>>56] per 128-bit half
//   - XOR with the template (absorb13Block ^ K0 ^ length tag), store to the frame
"""


def x16_comment_zmm(tier_desc):
    return f"""// {tier_desc} 16-lane fused ChainHash cascade kernel
// for AES-CMAC at the 13-byte per-lane fill shape (1 zero-padded block,
// 1 AES-128 permutation per lane and cascade round). See
// aescmacasm_fused.go for the construction; every tier is pinned to the
// pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Batch layout: 4 ZMM states, four lanes per ZMM (lanes 4j..4j+3 in Z[j]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// per-group VPADDQ (applying laneIdxZ offsets) and VPUNPCKLQDQ. The whole
// cascade is register-resident: the four block registers are built once
// and every cascade round folds the pair and the block into the state
// with one VPTERNLOGQ per group.
//
// Register allocation:
//   Z0–Z3      states, group j = lanes (4j, 4j+1, 4j+2, 4j+3)
//   Z4–Z13     K1..K10 broadcasts
//   Z14        component pair, broadcast per cascade round
//   Z15        block template: absorb13Block ^ K0 ^ length tag (prologue only)
//   Z16–Z19    fill blocks, group j = lanes (4j .. 4j+3)
//   Z20–Z22    groupIdxBase broadcast and synthesis scratch (prologue only)
//
// Per-group synthesis:
//   - Load laneIdxZ[group] to add offsets [0,1,2,3] to groupIdxBase
//   - VPADDQ to form [base+0, base+1, base+2, base+3]
//   - VPSRLQ/VPSLLQ/VPUNPCKLQDQ to transform into [gi<<8, gi>>56] per lane
//   - XOR with the template to form the fill block
"""


def x16_comment_neon(tier_desc):
    return f"""// {tier_desc}
// 16-lane fused ChainHash cascade kernel for AES-CMAC at the 13-byte
// per-lane fill shape. See aescmacasm_fused.go for the construction; the
// kernel is pinned to the pure-Go reference (scalarFusedX16) by the
// in-package parity tests.
""" + X16_CASCADE_NOTE + """// Block layout per lane: [0x03 | LE64(groupIdxBase+i) | 7×0x00] (domain
// tag, 8-byte index, zero padding), XORed with K0 and the length tag.
//
// Batch layout: two batches of 8 lanes, each register-resident — V0..V7
// states, V8..V15 blocks, V16..V24 K1..K9, V25 K10, V26 pair load, V27
// K0 ^ length tag. Each batch runs the whole cascade before the next
// starts. Issue order inside a round is round-major: every step (the
// pair fold, each AESE + AESMC round, the final K10 XOR) runs across all
// 8 lanes before the next step starts, so the 8 independent chains keep
// both crypto pipes busy instead of serialising each lane's dependency
// chain behind the previous lane's.
"""


X16_COMMENTS = {
    "aesni": lambda d: x16_comment_xmm(d, False),
    "vex": lambda d: x16_comment_xmm(d, True),
    "vaesavx2": x16_comment_ymm,
    "avx512": x16_comment_zmm,
    "neon": x16_comment_neon,
}


def x16_header(tier):
    desc, build, _ = X16_TIERS[tier]
    return f"//go:build {build}\n\n" + X16_COMMENTS[tier](desc) + "\n#include \"textflag.h\"\n"


def x16_xmm(vex):
    """Two batches of eight lanes; the 16 blocks are built from the
    groupIdx GPR as [idx<<8 | idx>>56] via shift + PUNPCKLQDQ, XORed with
    the template (absorb13Block, which carries the 0x03 domain tag, XOR
    K0 XOR the length tag) and staged to the frame. Each batch then runs
    the full cascade from the staged blocks. The legacy-SSE tier reloads
    each block and each of K1..K3 through a register (PXOR / AESENC m128
    would require 16-byte alignment the Go frame does not guarantee)."""
    tier = "Vex" if vex else "AesNi"
    mov = "VMOVDQU" if vex else "MOVOU"
    L = [f"// func aesCMAC128FusedChain13x16{tier}Asm({X16_SIG})",
         f"TEXT ·aesCMAC128FusedChain13x16{tier}Asm(SB), NOSPLIT, $256-40",
         "\tMOVQ roundKeys+0(FP), AX", "\tMOVQ out+32(FP), DI", "\tMOVQ groupIdxBase+24(FP), R8", "",
         "\t// Template X12 = absorb13Block ^ K0 ^ (13 || 13)",
         f"\t{mov} ·absorb13Block(SB), X12", "\tMOVQ $13, R12"]
    if vex:
        L += ["\tVPXOR 0(AX), X12, X12", "\tVMOVQ R12, X10", "\tVPUNPCKLQDQ X10, X10, X10", "\tVPXOR X10, X12, X12", ""]
    else:
        L += ["\tMOVOU 0(AX), X8", "\tPXOR X8, X12", "\tMOVQ R12, X10", "\tPUNPCKLQDQ X10, X10", "\tPXOR X10, X12", ""]
    L.append("\t// Stage the 16 fill blocks into the frame at 16*lane(SP)")
    for lane in range(16):
        L.append(f"\t// Lane {lane}: idx = base" + (f" + {lane}" if lane else ""))
        L.append("\tMOVQ R8, R9")
        if lane:
            L.append(f"\tADDQ ${lane}, R9")
        if vex:
            L += ["\tVMOVQ R9, X11", "\tVMOVQ R9, X15", "\tVPSLLQ $8, X11, X11", "\tVPSRLQ $56, X15, X15",
                  "\tVPUNPCKLQDQ X15, X11, X11", "\tVPXOR X12, X11, X11", f"\tVMOVDQU X11, {16 * lane}(SP)"]
        else:
            L += ["\tMOVQ R9, X11", "\tMOVQ R9, X15", "\tPSLLQ $8, X11", "\tPSRLQ $56, X15",
                  "\tPUNPCKLQDQ X15, X11", "\tPXOR X12, X11", f"\tMOVOU X11, {16 * lane}(SP)"]
        L.append("")
    if vex:
        L.append("\t// Load K1..K8 (K9 / K10 are read as memory operands)")
        for r in range(1, 9):
            L.append(f"\tVMOVDQU {16 * r}(AX), X{7 + r}")
        key = lambda r: f"X{7 + r}" if r <= 8 else f"{16 * r}(AX)"
    else:
        L.append("\t// Load K4..K10 (K1..K3 are reloaded through X8 per round)")
        for r in range(4, 11):
            L.append(f"\tMOVOU {16 * r}(AX), X{5 + r}")
        key = lambda r: f"X{5 + r}"
    L.append("")
    for b in range(2):
        L += [f"\t// ========== BATCH {b + 1}: lanes {8 * b}–{8 * b + 7} ==========",
              "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX"]
        for l in range(8):
            L.append(f"\tVPXOR X{l}, X{l}, X{l}" if vex else f"\tPXOR X{l}, X{l}")
        L += ["", f"loop{b}:"]
        if vex:
            for l in range(8):
                L.append(f"\tVPXOR 0(BX), X{l}, X{l}")
            for l in range(8):
                L.append(f"\tVPXOR {16 * (8 * b + l)}(SP), X{l}, X{l}")
            L += xmm_rounds(8, True, key)
        else:
            L.append("\tMOVOU 0(BX), X8")
            for l in range(8):
                L.append(f"\tPXOR X8, X{l}")
            for l in range(8):
                L.append(f"\tMOVOU {16 * (8 * b + l)}(SP), X8")
                L.append(f"\tPXOR X8, X{l}")
            for r in range(1, 10):
                if r < 4:
                    L.append(f"\tMOVOU {16 * r}(AX), X8")
                    L.append("\t" + "; ".join(f"AESENC X8, X{l}" for l in range(8)))
                else:
                    L.append("\t" + "; ".join(f"AESENC {key(r)}, X{l}" for l in range(8)))
            L.append("\t" + "; ".join(f"AESENCLAST {key(10)}, X{l}" for l in range(8)))
        L += ["\tADDQ $16, BX", "\tDECQ CX", f"\tJNZ loop{b}", "", f"\t// Store batch {b + 1} outputs"]
        for l in range(8):
            L.append(f"\t{mov} X{l}, {16 * (8 * b + l)}(DI)")
        L.append("")
    L.append("\tRET")
    return "\n".join(L) + "\n"


def x16_ymm():
    """Eight YMM states of two lanes; each pair's two groupIdx values are
    materialised via LEAQ, moved into the two 128-bit halves, turned into
    [idx<<8 | idx>>56] with one shift pair and VPUNPCKLQDQ, XORed with the
    template and stored to the frame as one 32-byte block pair. K8..K10
    are duplicated into the frame behind the blocks."""
    L = [f"// func aesCMAC128FusedChain13x16VaesAvx2Asm({X16_SIG})",
         "TEXT ·aesCMAC128FusedChain13x16VaesAvx2Asm(SB), NOSPLIT, $352-40",
         "\tMOVQ roundKeys+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ out+32(FP), DI", "\tMOVQ groupIdxBase+24(FP), R8", "",
         "\t// Template Y10 = absorb13Block ^ K0 ^ (13 || 13), broadcast to both halves",
         "\tVBROADCASTI128 ·absorb13Block(SB), Y10", "\tVBROADCASTI128 0(AX), Y9", "\tVPXOR Y9, Y10, Y10",
         "\tMOVQ $13, R12", "\tVMOVQ R12, X9", "\tVPBROADCASTQ X9, Y9", "\tVPXOR Y9, Y10, Y10", "",
         "\t// Stage the 8 block pairs into the frame at 32*pair(SP)"]
    for p in range(8):
        L.append(f"\t// ========== Pair {p}: lanes {2 * p}–{2 * p + 1} ==========")
        L.append("\tMOVQ R8, R9" if p == 0 else f"\tLEAQ {2 * p}(R8), R9")
        L += ["\tVMOVQ R9, X11", f"\tLEAQ {2 * p + 1}(R8), R9", "\tVMOVQ R9, X15",
              "\tVINSERTI128 $1, X15, Y11, Y11", "\tVPSRLQ $56, Y11, Y15", "\tVPSLLQ $8, Y11, Y11",
              "\tVPUNPCKLQDQ Y15, Y11, Y11", "\tVPXOR Y10, Y11, Y11", f"\tVMOVDQU Y11, {32 * p}(SP)", ""]
    L.append("\t// Duplicate K8..K10 into the frame at 256(SP), 288(SP), 320(SP)")
    for r in range(8, 11):
        L += [f"\tVBROADCASTI128 {16 * r}(AX), Y9", f"\tVMOVDQU Y9, {256 + 32 * (r - 8)}(SP)"]
    L.append("\t// Load K1..K7")
    for r in range(1, 8):
        L.append(f"\tVBROADCASTI128 {16 * r}(AX), Y{8 + r}")
    for i in range(8):
        L.append(f"\tVPXOR Y{i}, Y{i}, Y{i}")
    L += ["", "loop:", "\tVBROADCASTI128 0(BX), Y8"]
    for i in range(8):
        L.append(f"\tVPXOR Y8, Y{i}, Y{i}")
    for i in range(8):
        L.append(f"\tVPXOR {32 * i}(SP), Y{i}, Y{i}")
    L.append("\t// AES rounds 1..10 on all 8 YMM pairs (K1..K7 in registers, K8..K10 from the frame)")
    key = lambda r: f"Y{8 + r}" if r <= 7 else f"{256 + 32 * (r - 8)}(SP)"
    for r in range(1, 10):
        L.append("\t" + "; ".join(f"VAESENC {key(r)}, Y{i}, Y{i}" for i in range(8)))
    L.append("\t" + "; ".join(f"VAESENCLAST {key(10)}, Y{i}, Y{i}" for i in range(8)))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\t// Store outputs: pair i at [32i..32i+32]"]
    for i in range(8):
        L.append(f"\tVMOVDQU Y{i}, {32 * i}(DI)")
    L += ["", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def x16_zmm():
    """Four ZMM states of four lanes; groupIdxBase is broadcast once and each
    group adds its laneIdxZ offset row, so the whole synthesis is vector
    arithmetic (no GPR-to-vector moves). Blocks stay in Z16..Z19 and every
    cascade round is one VPTERNLOGQ plus ten AES rounds per group."""
    L = [f"// func aesCMAC128FusedChain13x16Avx512Asm({X16_SIG})",
         "TEXT ·aesCMAC128FusedChain13x16Avx512Asm(SB), NOSPLIT, $0-40",
         "\tMOVQ roundKeys+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ out+32(FP), DI", "",
         "\t// Broadcast groupIdxBase to Z20 (all 8 qwords); template Z15 = absorb13Block ^ K0 ^ (13 || 13)",
         "\tVPBROADCASTQ groupIdxBase+24(FP), Z20", "\tVBROADCASTI32X4 ·absorb13Block(SB), Z15",
         "\tVBROADCASTI32X4 0(AX), Z21", "\tVPXORD Z21, Z15, Z15",
         "\tMOVQ $13, R12", "\tVPBROADCASTQ R12, Z21", "\tVPXORD Z21, Z15, Z15", ""]
    for g in range(4):
        L += [f"\t// ========== Group {g}: lanes {4 * g}–{4 * g + 3} ==========",
              f"\tVPADDQ ·laneIdxZ+{64 * g}(SB), Z20, Z21", "\tVPSRLQ $56, Z21, Z22", "\tVPSLLQ $8, Z21, Z21",
              "\tVPUNPCKLQDQ Z22, Z21, Z21", f"\tVPXORD Z15, Z21, Z{16 + g}", ""]
    L.append("\t// Load K1..K10")
    for r in range(1, 11):
        L.append(f"\tVBROADCASTI32X4 {16 * r}(AX), Z{3 + r}")
    for j in range(4):
        L.append(f"\tVPXORD Z{j}, Z{j}, Z{j}")
    L += ["", "loop:", "\tVBROADCASTI32X4 0(BX), Z14"]
    for j in range(4):
        L.append(f"\tVPTERNLOGQ $0x96, Z14, Z{16 + j}, Z{j}     // Z{j} ^= Z{16 + j} ^ Z14")
    L.append("\t// AES rounds 1..10 on all 4 ZMM groups")
    L += zmm_rounds([f"Z{j}" for j in range(4)], 3)
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\t// Store outputs: group j at [64j..64j+64]"]
    for j in range(4):
        L.append(f"\tVMOVDQU64 Z{j}, {64 * j}(DI)")
    L += ["", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def x16_neon():
    """Two batches of eight lanes, register-resident; the block is assembled
    in GPRs (D[0] = idx<<8 | 0x03, D[1] = idx>>56), XORed with K0 and the
    length tag, and is the first AESE operand of every cascade round.
    Issue order is round-major within a batch."""
    L = [f"// func aesCMAC128FusedChain13x16NeonAsm({X16_SIG})",
         "TEXT ·aesCMAC128FusedChain13x16NeonAsm(SB), NOSPLIT, $0-40",
         "\tMOVD roundKeys+0(FP), R0", "\tMOVD comps+8(FP), R1", "\tMOVD nPairs+16(FP), R2",
         "\tMOVD groupIdxBase+24(FP), R3", "\tMOVD out+32(FP), R4", "",
         "\t// Load K1..K9 (V16..V24) and K10 (V25)"]
    L += neon_keys("R0", "R5")
    L += ["", "\t// V27 = K0 ^ (13 || 13)", "\tVLD1 (R0), [V27.B16]", "\tMOVD $13, R7",
          "\tVMOV R7, V26.D[0]", "\tVMOV R7, V26.D[1]", "\tVEOR V26.B16, V27.B16, V27.B16", ""]
    for b in range(2):
        L += [f"\t// ========== BATCH {b + 1}: lanes {8 * b}–{8 * b + 7} ==========",
              "\t// Step 1 — synthesise the 8 fill blocks in V8..V15:",
              "\t// [0x03 | LE64(groupIdxBase+i) | 7×0x00] as D[0] = (idx << 8) | 0x03,",
              "\t// D[1] = idx >> 56, then XOR K0 and the length tag."]
        for l in range(8):
            lane = 8 * b + l
            L.append("\tMOVD R3, R6" if lane == 0 else f"\tADD ${lane}, R3, R6")
            L += ["\tLSL $8, R6, R8", "\tORR $3, R8, R8", "\tLSR $56, R6, R9",
                  f"\tVMOV R8, V{8 + l}.D[0]", f"\tVMOV R9, V{8 + l}.D[1]",
                  f"\tVEOR V27.B16, V{8 + l}.B16, V{8 + l}.B16"]
        L += ["", "\t// Step 2 — zero the 8 states, reset the component cursor and pair count."]
        for l in range(8):
            L.append(f"\tVEOR V{l}.B16, V{l}.B16, V{l}.B16")
        L += ["\tMOVD R1, R10", "\tMOVD R2, R11", "", f"loop{b}:",
              "\t// Fold the pair (V26) into every state, then the block as the first",
              "\t// AESE operand, rounds 1..9 under K1..K9 and the final K10 XOR.",
              "\tVLD1.P 16(R10), [V26.B16]"]
        for l in range(8):
            L.append(f"\tVEOR V26.B16, V{l}.B16, V{l}.B16")
        L += neon_rounds(8, lambda l: f"V{8 + l}")
        for l in range(8):
            L.append(f"\tVEOR V25.B16, V{l}.B16, V{l}.B16")
        L += ["\tSUBS $1, R11, R11", f"\tBNE loop{b}", "", f"\t// Store batch {b + 1} rank pairs in lane order."]
        for l in range(8):
            L.append(f"\tVST1.P [V{l}.B16], 16(R4)")
        L.append("")
    L.append("\tRET")
    return "\n".join(L) + "\n"


X16_EMITTERS = {
    "aesni": lambda: x16_xmm(False),
    "vex": lambda: x16_xmm(True),
    "vaesavx2": x16_ymm,
    "avx512": x16_zmm,
    "neon": x16_neon,
}


def render_x16():
    return {X16_TIERS[t][2]: x16_header(t) + "\n" + X16_EMITTERS[t]() for t in X16_TIERS}


def render_all():
    files = {}
    files.update(render_x16())
    for s in SHAPES:
        files.update({
            f"aescmac_fusedchain128_{s}x4_aesni_amd64.s": header(s, 4, "Legacy-SSE AES-NI XMM", AMD, "xmm") + "\n" + xmm_fused(s, 4, False),
            f"aescmac_fusedchain128_{s}x4_vex_amd64.s": header(s, 4, "VEX-encoded AES-NI XMM", AMD, "xmm") + "\n" + xmm_fused(s, 4, True),
            f"aescmac_fusedchain128_{s}x4_vaesavx2_amd64.s": header(s, 4, "VAES YMM (two lanes per register)", AMD, "ymm") + "\n" + ymm_fused(s),
            f"aescmac_fusedchain128_{s}x4_avx512_amd64.s": header(s, 4, "VAES ZMM (four lanes per register)", AMD, "zmm") + "\n" + zmm_fused(s),
            f"aescmac_fusedchain128_{s}x1_aesni_amd64.s": header(s, 1, "Legacy-SSE AES-NI XMM", AMD, "xmm") + "\n" + xmm_fused(s, 1, False),
            f"aescmac_fusedchain128_{s}x1_vex_amd64.s": header(s, 1, "VEX-encoded AES-NI XMM", AMD, "xmm") + "\n" + xmm_fused(s, 1, True),
            f"aescmac_fusedchain128_{s}x4_neon_arm64.s": header(s, 4, "ARM64 NEON crypto-extension", ARM, "neon") + "\n" + neon_fused(s, 4),
            f"aescmac_fusedchain128_{s}x1_neon_arm64.s": header(s, 1, "ARM64 NEON crypto-extension", ARM, "neon") + "\n" + neon_fused(s, 1),
        })
    for s in X8_SHAPES:
        files[f"aescmac_fusedchain128_{s}x8_avx512_amd64.s"] = (
            header(s, 8, "VAES ZMM (four lanes per register, two state groups)", AMD, "zmm") + "\n" + zmm_fused_x8(s))
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
