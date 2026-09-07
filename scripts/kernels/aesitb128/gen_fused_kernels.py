#!/usr/bin/env python3
"""Emit the AES-ITB-128 fused ChainHash cascade kernels for internal/aesitbasm.

One file per (shape, lanes, tier). Shapes 13/20/36/68; lanes x4 (four data
lanes over one shared component slice) and x1 (single lane); amd64 tiers
aesni / vex / vaesavx2 / avx512 for x4, aesni / vex for x1; arm64 tier neon
for both. Companion of gen_kernels.py (per-round chain-absorb kernels).

The avx512 tier additionally carries an x8 variant at the three nonce-buf
shapes 20/36/68 (aesitb_fusedchain128_<shape>x8_avx512_amd64.s): eight
lanes in two ZMM state groups (lanes 0..3 in Z0, lanes 4..7 in Z1) whose
cascade rounds are interleaved instruction by instruction, so the two
independent VAESENC dependency chains overlap on the AES unit. See
zmm_fused_x8 for the register plan.

A third family, x16 at shape 13 only, is the Interlocked Barrier PRF fill
kernel (aesitb_fusedchain128_13x16_<tier>_amd64.s for the four amd64 tiers
and aesitb_fusedchain128_13x16_neon_arm64.s): the kernel receives
groupIdxBase in a GPR and synthesises the 16 per-lane fill blocks
in-register — [0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03] for lane
i — so the batch-16 path pays no per-lane pointer gather, then runs the
same cascade per lane. See the x16 section below for the per-tier register
plans and the output-store discipline of that family.

Cascade evaluated per lane (see aesitbasm_fused.go):
    state = 0
    for each component pair (c0, c1):
        state ^= key ^ (LE64(c0) || LE64(c1))
        for each padded data block b:  state = AESENC(state ^ block_b, RC[b mod 8])
        state = AESENC(state, RC[0]); state = AESENC(state, RC[1])
    out = state
Data blocks are round-invariant and are staged once. The XMM tiers stage
them into the stack frame at SP + 64*b + 16*lane (16-byte stores read back
by 16-byte loads). The wide tiers stage them in registers — Z15.. on the
ZMM tier, and on the YMM tier every register the round constants and
states leave free, with the remaining blocks (two at shape 68) written to
the frame as 32-byte stores and read back by 32-byte loads. On arm64 the
padded tail block sits in V24..V27 and full blocks are reloaded from the
lane pointer each round.

Load shapes are matched to the stores the Go call sites leave in flight
so store-to-load forwarding succeeds: the caller writes a 4-byte pixel
index at offset 0 of every lane buffer immediately before the call, so
block 0 is read as two 4-byte inserts plus an 8-byte insert rather than
one 16-byte load, and no wide load spans a narrower staging store. The
lane outputs are written as four 16-byte stores on every tier — the width
the Go side reads them back with — rather than one 32- or 64-byte store.

The NEON tier keeps the 16-byte VLD1 of block 0 and the four-register
VST1 of the lane outputs: on Neoverse V2 (Graviton 4) neither pattern
stalls — a block-0 staged once through the GPR path measured 2 ns/call
slower at shape 68 under the production store-then-call pattern, and
the STP-Q-pair and four-16-byte-store output shapes measured within
0.5 ns/call of the shipped store (BenchmarkFusedTierPix-style harness,
static hook, allocation-free) — so no arm64 load or store is reshaped.
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "internal", "aesitbasm")
SHAPES = [13, 20, 36, 68]
# Shapes with an eight-lane ZMM fused kernel: the 128 / 256 / 512-bit
# nonce-buf shapes the pixel pipeline drives through the batched hook.
X8_SHAPES = [20, 36, 68]


def blocks(n):
    return (n + 16) // 16


def staging_note(tier):
    if tier == "xmm":
        return ("// The padded data blocks are staged once into the frame and every\n"
                "// cascade round runs from those 16-byte slots")
    if tier == "ymm":
        return ("// The padded data blocks are staged once — in registers, with any\n"
                "// block the register file cannot hold written to the frame as a\n"
                "// 32-byte store that the round loop reads back at the same width —\n"
                "// and every cascade round runs from that staging")
    return ("// The padded data blocks are staged once in registers (Z15..) and\n"
            "// every cascade round runs from registers")


def header(shape, lanes, tier_desc, build, tier):
    nb = blocks(shape)
    if tier == "neon":
        return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for AES-ITB-128 at the
// {shape}-byte shape, {lanes} lane{'s' if lanes > 1 else ''} ({nb} PKCS#7 block{'s' if nb > 1 else ''}, {nb + 2} AES rounds per
// cascade round). The padded data blocks are staged once and every
// cascade round runs from registers; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"
"""
    return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for AES-ITB-128 at the
// {shape}-byte shape, {lanes} lane{'s' if lanes > 1 else ''} ({nb} PKCS#7 block{'s' if nb > 1 else ''}, {nb + 2} AES rounds per
// cascade round).
{staging_note(tier)}; see aesitbasm_fused.go for the
// construction and the in-package parity tests for the bit-exact pin
// against the pure-Go cascade.

#include "textflag.h"
"""


def lane_block(shape, b, r, vex, dst="X4"):
    """Assemble padded block b of the lane at pointer r into dst.

    Block 0 and the tail are read with exact-width inserts (X13 holds the
    pad vector and serves as the merge source, so lanes assemble without
    a dependency on each other); the 4-byte inserts at offsets 0 and 4
    match the caller's 4-byte pixel-index store. Full blocks past block 0
    are one 16-byte load.
    """
    nb = blocks(shape)
    off = 16 * b
    mov = "VMOVDQU" if vex else "MOVOU"
    L = []
    if b == nb - 1:
        if shape == 13:
            if vex:
                L.append(f"\tVPINSRQ $0, {off}({r}), X13, {dst}")
                L.append(f"\tVPINSRD $2, {off + 8}({r}), {dst}, {dst}")
                L.append(f"\tVPINSRB $12, {off + 12}({r}), {dst}, {dst}")
            else:
                L.append(f"\tMOVOU X13, {dst}")
                L.append(f"\tPINSRQ $0, {off}({r}), {dst}")
                L.append(f"\tPINSRD $2, {off + 8}({r}), {dst}")
                L.append(f"\tPINSRB $12, {off + 12}({r}), {dst}")
        else:
            if vex:
                L.append(f"\tVPINSRD $0, {off}({r}), X13, {dst}")
            else:
                L.append(f"\tMOVOU X13, {dst}")
                L.append(f"\tPINSRD $0, {off}({r}), {dst}")
    elif b == 0:
        if vex:
            L.append(f"\tVPINSRD $0, 0({r}), X13, {dst}")
            L.append(f"\tVPINSRD $1, 4({r}), {dst}, {dst}")
            L.append(f"\tVPINSRQ $1, 8({r}), {dst}, {dst}")
        else:
            L.append(f"\tMOVOU X13, {dst}")
            L.append(f"\tPINSRD $0, 0({r}), {dst}")
            L.append(f"\tPINSRD $1, 4({r}), {dst}")
            L.append(f"\tPINSRQ $1, 8({r}), {dst}")
    else:
        L.append(f"\t{mov} {off}({r}), {dst}")
    return L


def pad_load(shape, vex):
    pad = "pad13Tail" if shape == 13 else "pad4Tail"
    return f"\t{'VMOVDQU' if vex else 'MOVOU'} ·{pad}(SB), X13"


def stage_amd64(shape, lanes, vex, regs):
    """Prologue: stage padded blocks into the frame at 64*b + 16*lane (SP)."""
    nb = blocks(shape)
    mov = "VMOVDQU" if vex else "MOVOU"
    L = [pad_load(shape, vex)]
    for b in range(nb):
        for l in range(lanes):
            L += lane_block(shape, b, regs[l], vex)
            L.append(f"\t{mov} X4, {64 * b + 16 * l}(SP)")
    return L


def prologue_amd64(lanes):
    arg = "dataPtrs" if lanes == 4 else "data"
    L = ["\tMOVQ key+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         f"\tMOVQ {arg}+24(FP), DX", "\tMOVQ out+32(FP), DI"]
    if lanes == 4:
        L += ["\tMOVQ 0(DX), R8", "\tMOVQ 8(DX), R9", "\tMOVQ 16(DX), R10", "\tMOVQ 24(DX), R11"]
    else:
        L += ["\tMOVQ DX, R8"]
    return L


def xmm_fused(shape, lanes, vex):
    nb = blocks(shape)
    tier = "Vex" if vex else "AesNi"
    regs = ["R8", "R9", "R10", "R11"][:lanes]
    frame = 64 * nb
    sig = "dataPtrs *[4]*byte, out *[4][2]uint64" if lanes == 4 else "data *byte, out *[2]uint64"
    L = [f"// func aesITB128FusedChain{shape}x{lanes}{tier}Asm(key *[16]byte, comps *uint64, nPairs int, {sig})",
         f"TEXT ·aesITB128FusedChain{shape}x{lanes}{tier}Asm(SB), NOSPLIT, ${frame}-40"]
    L += prologue_amd64(lanes)
    L.append("")
    L += stage_amd64(shape, lanes, vex, regs)
    L.append("")
    mov = "VMOVDQU" if vex else "MOVOU"
    for i in range(8):
        L.append(f"\t{mov} ·RC+{16 * i}(SB), X{5 + i}")
    L.append(f"\t{mov} 0(AX), X13")
    for l in range(lanes):
        L.append(f"\tVPXOR X{l}, X{l}, X{l}" if vex else f"\tPXOR X{l}, X{l}")
    L.append("")
    L.append("loop:")
    rc = lambda i: f"X{5 + (i % 8)}"
    if vex:
        L.append("\tVMOVDQU 0(BX), X14")
        L.append("\tVPXOR X13, X14, X14")
        for l in range(lanes):
            L.append(f"\tVPXOR X14, X{l}, X{l}")
        for b in range(nb):
            for l in range(lanes):
                L.append(f"\tVPXOR {64 * b + 16 * l}(SP), X{l}, X{l}")
            L.append("\t" + "; ".join(f"VAESENC {rc(b)}, X{l}, X{l}" for l in range(lanes)))
        L.append("\t" + "; ".join(f"VAESENC {rc(0)}, X{l}, X{l}" for l in range(lanes)))
        L.append("\t" + "; ".join(f"VAESENC {rc(1)}, X{l}, X{l}" for l in range(lanes)))
    else:
        L.append("\tMOVOU 0(BX), X14")
        L.append("\tPXOR X13, X14")
        for l in range(lanes):
            L.append(f"\tPXOR X14, X{l}")
        for b in range(nb):
            for l in range(lanes):
                L.append(f"\tMOVOU {64 * b + 16 * l}(SP), X4")
                L.append(f"\tPXOR X4, X{l}")
            L.append("\t" + "; ".join(f"AESENC {rc(b)}, X{l}" for l in range(lanes)))
        L.append("\t" + "; ".join(f"AESENC {rc(0)}, X{l}" for l in range(lanes)))
        L.append("\t" + "; ".join(f"AESENC {rc(1)}, X{l}" for l in range(lanes)))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", ""]
    for l in range(lanes):
        L.append(f"\t{mov} X{l}, {16 * l}(DI)")
    L.append("\tRET")
    return "\n".join(L) + "\n"


def ymm_fused(shape):
    """VAES YMM: lanes (0, 1) in Y0, lanes (2, 3) in Y1.

    Round constants RC[0..r-1] (r = max(nb, 2), the only ones the cascade
    reads) sit in Y3..Y(2+r); Y13 holds the key, Y14 the per-round
    component broadcast. Every other register stages a block half; blocks
    beyond the register budget go to the frame as 32-byte stores, read
    back by 32-byte loads at the same offset.
    """
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"]
    r = max(nb, 2)
    pool = ["Y2"] + [f"Y{i}" for i in range(3 + r, 11)] + ["Y11", "Y12", "Y15"]
    slots = []  # per block: ("reg", ya, yb) or ("mem", off)
    spilled = 0
    for b in range(nb):
        if len(pool) >= 2:
            slots.append(("reg", pool.pop(0), pool.pop(0)))
        else:
            slots.append(("mem", 64 * spilled))
            spilled += 1
    frame = 64 * spilled
    L = [f"// func aesITB128FusedChain{shape}x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)",
         f"TEXT ·aesITB128FusedChain{shape}x4VaesAvx2Asm(SB), NOSPLIT, ${frame}-40"]
    L += prologue_amd64(4)
    L.append("")
    L.append(pad_load(shape, True))
    for b, slot in enumerate(slots):
        if slot[0] == "reg":
            ya, yb = slot[1], slot[2]
        else:
            ya, yb = "Y0", "Y1"
        for ra, rb, y in ((regs[0], regs[1], ya), (regs[2], regs[3], yb)):
            x = "X" + y[1:]
            if 0 < b < nb - 1:
                L.append(f"\tVMOVDQU {16 * b}({ra}), {x}")
                L.append(f"\tVINSERTI128 $1, {16 * b}({rb}), {y}, {y}")
            else:
                L += lane_block(shape, b, ra, True, dst=x)
                L += lane_block(shape, b, rb, True)
                L.append(f"\tVINSERTI128 $1, X4, {y}, {y}")
        if slot[0] == "mem":
            L.append(f"\tVMOVDQU Y0, {slot[1]}(SP)")
            L.append(f"\tVMOVDQU Y1, {slot[1] + 32}(SP)")
    L.append("")
    for i in range(r):
        L.append(f"\tVBROADCASTI128 ·RC+{16 * i}(SB), Y{3 + i}")
    L += ["\tVBROADCASTI128 0(AX), Y13", "\tVPXOR Y0, Y0, Y0", "\tVPXOR Y1, Y1, Y1", "", "loop:",
          "\tVBROADCASTI128 0(BX), Y14", "\tVPXOR Y13, Y14, Y14", "\tVPXOR Y14, Y0, Y0", "\tVPXOR Y14, Y1, Y1"]
    rc = lambda i: f"Y{3 + (i % 8)}"
    for b, slot in enumerate(slots):
        if slot[0] == "reg":
            L.append(f"\tVPXOR {slot[1]}, Y0, Y0")
            L.append(f"\tVPXOR {slot[2]}, Y1, Y1")
        else:
            L.append(f"\tVPXOR {slot[1]}(SP), Y0, Y0")
            L.append(f"\tVPXOR {slot[1] + 32}(SP), Y1, Y1")
        L.append(f"\tVAESENC {rc(b)}, Y0, Y0; VAESENC {rc(b)}, Y1, Y1")
    L.append(f"\tVAESENC {rc(0)}, Y0, Y0; VAESENC {rc(0)}, Y1, Y1")
    L.append(f"\tVAESENC {rc(1)}, Y0, Y0; VAESENC {rc(1)}, Y1, Y1")
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI128 $1, Y0, 16(DI)",
          "\tVMOVDQU X1, 32(DI)", "\tVEXTRACTI128 $1, Y1, 48(DI)", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def zmm_fused(shape):
    """VAES ZMM: all four lanes in Z0; block b staged in Z(15+b)."""
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"]
    L = [f"// func aesITB128FusedChain{shape}x4Avx512Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)",
         f"TEXT ·aesITB128FusedChain{shape}x4Avx512Asm(SB), NOSPLIT, $0-40"]
    L += prologue_amd64(4)
    L.append("")
    L.append(pad_load(shape, True))
    for b in range(nb):
        z = f"Z{15 + b}"
        for l in range(4):
            if 0 < b < nb - 1 and l > 0:
                L.append(f"\tVINSERTI64X2 ${l}, {16 * b}({regs[l]}), {z}, {z}")
                continue
            L += lane_block(shape, b, regs[l], True)
            L.append(f"\tVINSERTI64X2 ${l}, X4, {z}, {z}")
    L.append("")
    for i in range(8):
        L.append(f"\tVBROADCASTI32X4 ·RC+{16 * i}(SB), Z{2 + i}")
    L += ["\tVBROADCASTI32X4 0(AX), Z13", "\tVPXORD Z0, Z0, Z0", "", "loop:",
          "\tVBROADCASTI32X4 0(BX), Z14", "\tVPXORD Z13, Z14, Z14", "\tVPXORD Z14, Z0, Z0"]
    rc = lambda i: f"Z{2 + (i % 8)}"
    for b in range(nb):
        L.append(f"\tVPXORD Z{15 + b}, Z0, Z0")
        L.append(f"\tVAESENC {rc(b)}, Z0, Z0")
    L.append(f"\tVAESENC {rc(0)}, Z0, Z0")
    L.append(f"\tVAESENC {rc(1)}, Z0, Z0")
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI64X2 $1, Z0, 16(DI)",
          "\tVEXTRACTI64X2 $2, Z0, 32(DI)", "\tVEXTRACTI64X2 $3, Z0, 48(DI)", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def zmm_fused_x8(shape):
    """VAES ZMM, eight lanes: lanes 0..3 in Z0, lanes 4..7 in Z1.

    Register plan: Z2..Z9 RC[0..7] broadcasts, Z13 key broadcast, Z14 the
    per-round key XOR pair broadcast, Z15..Z(14+nb) the staged blocks of
    lanes 0..3 and Z(15+nb)..Z(14+2nb) those of lanes 4..7 — 22 registers
    at shape 68, 20 at 36, 18 at 20. The lane pointers are read four at
    a time through R8..R11 (group 0 from dataPtrs[0..3], group 1 from
    dataPtrs[4..7]) with the same exact-width block-0 / tail inserts as
    the x4 kernel; the key broadcast lands in Z13 only after both
    stagings, since X13 holds the pad vector until then.

    Loop body: the key XOR pair and block 0 fold into each state with one
    VPTERNLOGQ (XOR3), then every AES round issues for group 0 and group
    1 back to back, so the two independent state chains overlap on the
    AES unit instead of serialising as one chain per call. Output: eight
    16-byte stores, the width the Go side reads back.
    """
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"]
    L = [f"// func aesITB128FusedChain{shape}x8Avx512Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)",
         f"TEXT ·aesITB128FusedChain{shape}x8Avx512Asm(SB), NOSPLIT, $0-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ dataPtrs+24(FP), DX", "\tMOVQ out+32(FP), DI", ""]
    L.append(pad_load(shape, True))
    for g in range(2):
        L.append(f"\t// Lanes {4 * g}..{4 * g + 3}: blocks 0..{nb - 1} into Z{15 + nb * g}..Z{14 + nb * (g + 1)}")
        for l in range(4):
            L.append(f"\tMOVQ {32 * g + 8 * l}(DX), {regs[l]}")
        for b in range(nb):
            z = f"Z{15 + nb * g + b}"
            for l in range(4):
                if 0 < b < nb - 1 and l > 0:
                    L.append(f"\tVINSERTI64X2 ${l}, {16 * b}({regs[l]}), {z}, {z}")
                    continue
                L += lane_block(shape, b, regs[l], True)
                L.append(f"\tVINSERTI64X2 ${l}, X4, {z}, {z}")
    L.append("")
    for i in range(8):
        L.append(f"\tVBROADCASTI32X4 ·RC+{16 * i}(SB), Z{2 + i}")
    L += ["\tVBROADCASTI32X4 0(AX), Z13", "\tVPXORD Z0, Z0, Z0", "\tVPXORD Z1, Z1, Z1", "", "loop:",
          "\tVBROADCASTI32X4 0(BX), Z14", "\tVPXORD Z13, Z14, Z14",
          f"\tVPTERNLOGQ $0x96, Z14, Z15, Z0; VPTERNLOGQ $0x96, Z14, Z{15 + nb}, Z1"]
    rc = lambda i: f"Z{2 + (i % 8)}"
    L.append(f"\tVAESENC {rc(0)}, Z0, Z0; VAESENC {rc(0)}, Z1, Z1")
    for b in range(1, nb):
        L.append(f"\tVPXORD Z{15 + b}, Z0, Z0; VPXORD Z{15 + nb + b}, Z1, Z1")
        L.append(f"\tVAESENC {rc(b)}, Z0, Z0; VAESENC {rc(b)}, Z1, Z1")
    L.append(f"\tVAESENC {rc(0)}, Z0, Z0; VAESENC {rc(0)}, Z1, Z1")
    L.append(f"\tVAESENC {rc(1)}, Z0, Z0; VAESENC {rc(1)}, Z1, Z1")
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "",
          "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI64X2 $1, Z0, 16(DI)",
          "\tVEXTRACTI64X2 $2, Z0, 32(DI)", "\tVEXTRACTI64X2 $3, Z0, 48(DI)",
          "\tVMOVDQU X1, 64(DI)", "\tVEXTRACTI64X2 $1, Z1, 80(DI)",
          "\tVEXTRACTI64X2 $2, Z1, 96(DI)", "\tVEXTRACTI64X2 $3, Z1, 112(DI)",
          "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def neon_fused(shape, lanes):
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"][:lanes]
    rc = lambda i: f"V{16 + (i % 8)}"
    sig = "dataPtrs *[4]*byte, out *[4][2]uint64" if lanes == 4 else "data *byte, out *[2]uint64"
    arg = "dataPtrs" if lanes == 4 else "data"
    L = [f"// func aesITB128FusedChain{shape}x{lanes}NeonAsm(key *[16]byte, comps *uint64, nPairs int, {sig})",
         f"TEXT ·aesITB128FusedChain{shape}x{lanes}NeonAsm(SB), NOSPLIT, $0-40",
         "\tMOVD key+0(FP), R0", "\tMOVD comps+8(FP), R6", "\tMOVD nPairs+16(FP), R7",
         f"\tMOVD {arg}+24(FP), R2", "\tMOVD out+32(FP), R3",
         "\tVLD1 (R0), [V4.B16]",
         "\tMOVD $·RC(SB), R4",
         "\tVLD1.P 64(R4), [V16.B16, V17.B16, V18.B16, V19.B16]",
         "\tVLD1 (R4), [V20.B16, V21.B16, V22.B16, V23.B16]"]

    def load_ptrs():
        if lanes == 4:
            return ["\tMOVD 0(R2), R8", "\tMOVD 8(R2), R9", "\tMOVD 16(R2), R10", "\tMOVD 24(R2), R11"]
        return ["\tMOVD R2, R8"]

    L += load_ptrs()
    pad = "pad13Tail" if shape == 13 else "pad4Tail"
    L += [f"\tMOVD $·{pad}(SB), R4", "\tVLD1 (R4), [V5.B16]"]
    toff = 16 * (nb - 1)
    for l in range(lanes):
        r, t = regs[l], f"V{24 + l}"
        L.append(f"\tVMOV V5.B16, {t}.B16")
        if shape == 13:
            L += [f"\tMOVD ({r}), R12", f"\tVMOV R12, {t}.D[0]",
                  f"\tMOVWU 8({r}), R12", f"\tVMOV R12, {t}.S[2]",
                  f"\tMOVBU 12({r}), R12", f"\tVMOV R12, {t}.B[12]"]
        else:
            L += [f"\tMOVWU {toff}({r}), R12", f"\tVMOV R12, {t}.S[0]"]
    for l in range(lanes):
        L.append(f"\tVEOR V{l}.B16, V{l}.B16, V{l}.B16")
    L += ["", "loop:", "\tVLD1.P 16(R6), [V5.B16]", "\tVEOR V4.B16, V5.B16, V6.B16"]
    for l in range(lanes):
        L.append(f"\tVEOR V6.B16, V{l}.B16, V{l}.B16")
    L += load_ptrs()
    for b in range(nb):
        for l in range(lanes):
            k = f"V{8 + l}"
            if b < nb - 1:
                L.append(f"\tVLD1.P 16({regs[l]}), [{k}.B16]")
                if b > 0:
                    L.append(f"\tVEOR {rc(b - 1)}.B16, {k}.B16, {k}.B16")
            else:
                if b > 0:
                    L.append(f"\tVEOR {rc(b - 1)}.B16, V{24 + l}.B16, {k}.B16")
                else:
                    L.append(f"\tVMOV V{24 + l}.B16, {k}.B16")
        for l in range(lanes):
            L.append(f"\tAESE V{8 + l}.B16, V{l}.B16")
        for l in range(lanes):
            L.append(f"\tAESMC V{l}.B16, V{l}.B16")
    for l in range(lanes):
        L.append(f"\tAESE {rc(nb - 1)}.B16, V{l}.B16")
    for l in range(lanes):
        L.append(f"\tAESMC V{l}.B16, V{l}.B16")
    for l in range(lanes):
        L.append(f"\tAESE {rc(0)}.B16, V{l}.B16")
    for l in range(lanes):
        L.append(f"\tAESMC V{l}.B16, V{l}.B16")
    for l in range(lanes):
        L.append(f"\tVEOR {rc(1)}.B16, V{l}.B16, V{l}.B16")
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
# round-invariant synthesised block and the per-round key XOR pair into the
# state and runs the three AES rounds (absorb, finaliser RC[0], finaliser
# RC[1]); with one pair the cascade is the plain chain-absorb of the shape.
# Parity with scalarFusedX16 (aesitbasm_fused.go) is enforced by the
# in-package parity tests.
#
# Output store width: the wide tiers write the 16 rank pairs at their full
# register width (eight 32-byte stores on YMM, four 64-byte stores on ZMM).
# The fill closure reads the pairs back with 8-byte loads immediately after
# the call, and those loads forward from the wide stores on every measured
# host; splitting the stores into 16-byte pieces (the shape the 4-lane
# kernels use for their by-value output) measured slower through the fill
# closure (BenchmarkLockFillSuper16) — ZMM 17.6 -> 19.1 ns/op on Rocket
# Lake and 18.5 -> 19.3 on Sapphire Rapids, YMM 20.9 -> 21.7 and
# 21.3 -> 21.6 — so the full-width stores stay. The generator carries no
# numeric tables of its own: the absorb block and the ZMM lane-offset table
# are read from the Go side (·absorb13Block, ·laneIdxZ).

X16_SIG = "key *[16]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64"

X16_TIERS = {
    "aesni": ("Legacy-SSE AES-NI XMM (AESENC xmm, xmm)", "amd64 && !purego && !noitbasm",
              "aesitb_fusedchain128_13x16_aesni_amd64.s"),
    "vex": ("VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm; needs AES-NI + AVX)", "amd64 && !purego && !noitbasm",
            "aesitb_fusedchain128_13x16_vex_amd64.s"),
    "vaesavx2": ("VAES YMM, two lanes per 256-bit register (needs VAES + AVX2)", "amd64 && !purego && !noitbasm",
                 "aesitb_fusedchain128_13x16_vaesavx2_amd64.s"),
    "avx512": ("VAES ZMM, four lanes per register (needs VAES + AVX-512)", "amd64 && !purego && !noitbasm",
               "aesitb_fusedchain128_13x16_avx512_amd64.s"),
    "neon": ("ARM64 NEON crypto-extension (AESE + AESMC, round constant folded into the next AESE key operand)",
             "arm64 && !purego && !noitbasm",
             "aesitb_fusedchain128_13x16_neon_arm64.s"),
}

X16_CASCADE_NOTE = """//
// Unique to the batch-16 kernel: groupIdx is synthesized in-register from
// groupIdxBase per lane, avoiding the per-lane pointer gather overhead of
// the x4 path. The synthesised block is round-invariant per lane; every
// cascade round XORs key XOR (c0 || c1) and the block into the state and
// runs the three AES rounds (absorb, finaliser RC[0], finaliser RC[1]).
"""


def x16_shape_note():
    nb = blocks(13)
    return f"({nb} PKCS#7 block, {nb + 2} AES rounds per lane and cascade round)"


def x16_comment_xmm(tier_desc):
    return f"""// {tier_desc} 16-lane fused ChainHash cascade kernel for AES-ITB-128
// at the 13-byte per-lane fill shape {x16_shape_note()}.
// See aesitbasm_fused.go for the construction; every tier is pinned to
// the pure-Go reference (scalarFusedX16) by the in-package parity tests.
""" + X16_CASCADE_NOTE + """//
// Batch layout: two batches of 8 lanes; each batch runs the whole cascade
// before the next starts. The 16 blocks are staged once into the frame
// (16 bytes per lane) in the prologue. Per batch: X0–X7 states, X9–X10
// RC[0] / RC[1], X13 key, X14 key XOR pair (per round), X15 scratch.
"""


def x16_comment_ymm(tier_desc):
    return f"""// {tier_desc} 16-lane fused ChainHash cascade kernel
// for AES-ITB-128 at the 13-byte per-lane fill shape {x16_shape_note()}.
// See aesitbasm_fused.go for the construction; every tier is pinned to
// the pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Batch layout: 8 YMM states, two lanes per YMM (lanes 2i and 2i+1 in Y[i]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// VPUNPCKLQDQ, avoiding per-lane pointer gather overhead of the x4 path.
// The 8 block pairs are staged to a 256-byte frame with 32-byte stores in
// the prologue and read back as 32-byte VPXOR operands in every cascade
// round (the register file cannot hold states, constants and blocks).
//
// Register allocation:
//   Y0–Y7      states, pair i = lanes (2i, 2i+1)
//   Y8–Y9      RC[0], RC[1] broadcasts
//   Y10        absorb13Block broadcast (prologue only)
//   Y11, Y15   scratch for per-lane groupIdx synthesis
//   Y13        key broadcast
//   Y14        key XOR component pair, broadcast per cascade round
//
// Per-pair synthesis (no index vector):
//   - Calculate groupIdx for both lanes (2i and 2i+1)
//   - Load into X11 (lane 2i) and X15 (lane 2i+1)
//   - VINSERTI128 to form YMM with [gi_even | gi_odd]
//   - VPUNPCKLQDQ to transform [gi, 0] into [gi<<8, gi>>56] per 128-bit half
//   - XOR with absorb13Block to form the fill block, store to the frame
"""


def x16_comment_zmm(tier_desc):
    return f"""// {tier_desc} 16-lane fused ChainHash cascade kernel
// for AES-ITB-128 at the 13-byte per-lane fill shape {x16_shape_note()}.
// See aesitbasm_fused.go for the construction; every tier is pinned to
// the pure-Go reference (scalarFusedX16) by the in-package parity tests.
//
// Batch layout: 4 ZMM states, four lanes per ZMM (lanes 4j..4j+3 in Z[j]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// per-group VPADDQ (applying laneIdxZ offsets) and VPUNPCKLQDQ. The whole
// cascade is register-resident: the four block registers are built once
// and every cascade round folds key XOR pair and the block into the state
// with one VPTERNLOGQ per group.
//
// Register allocation:
//   Z0–Z3      states, group j = lanes (4j, 4j+1, 4j+2, 4j+3)
//   Z4–Z5      RC[0], RC[1] broadcasts
//   Z6–Z7      groupIdxBase / absorb13Block broadcasts (prologue only)
//   Z8–Z11     fill blocks, group j = lanes (4j .. 4j+3)
//   Z12, Z15   scratch for per-lane groupIdx synthesis
//   Z13        key broadcast
//   Z14        key XOR component pair, broadcast per cascade round
//
// Per-group synthesis:
//   - Load laneIdxZ[group] to add offsets [0,1,2,3] to groupIdxBase
//   - VPADDQ to form [base+0, base+1, base+2, base+3]
//   - VPSRLQ/VPSLLQ/VPUNPCKLQDQ to transform into [gi<<8, gi>>56] per lane
//   - XOR with absorb13Block to form the fill block
"""


def x16_comment_neon(tier_desc):
    return f"""// {tier_desc}
// 16-lane fused ChainHash cascade kernel for AES-ITB-128 at the 13-byte
// per-lane fill shape. See aesitbasm_fused.go for the construction; the
// kernel is pinned to the pure-Go reference (scalarFusedX16) by the
// in-package parity tests.
""" + X16_CASCADE_NOTE + """// Block layout per lane: [0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03]
// (domain tag, 8-byte index, 4 zero bytes, 3 PKCS#7 padding bytes).
//
// Batch layout: two batches of 8 lanes, each register-resident — V0..V7
// states, V8..V15 blocks, V16 / V17 RC[0] / RC[1], V18 key, V19 key XOR
// pair (per round), V20 pair load. Each batch runs the whole cascade
// before the next starts. Issue order inside a round is round-major:
// every step (the key XOR pair fold, each of the three AESE+AESMC rounds,
// the final RC[1] XOR) runs across all 8 lanes before the next step
// starts, so the 8 independent chains keep both crypto pipes busy
// instead of serialising each lane's dependency chain behind the
// previous lane's.
"""


X16_COMMENTS = {
    "aesni": x16_comment_xmm,
    "vex": x16_comment_xmm,
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
    absorb13Block (which carries the 0x03 domain tag and the PKCS#7 tail)
    and staged to the frame. Each batch then runs the full cascade from
    the staged blocks. The legacy-SSE tier reloads each block through a
    register (PXOR m128 would require 16-byte alignment the Go frame does
    not guarantee)."""
    tier = "Vex" if vex else "AesNi"
    mov = "VMOVDQU" if vex else "MOVOU"
    L = [f"// func aesITB128FusedChain13x16{tier}Asm({X16_SIG})",
         f"TEXT ·aesITB128FusedChain13x16{tier}Asm(SB), NOSPLIT, $256-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ out+32(FP), DI", "\tMOVQ groupIdxBase+24(FP), R8", "",
         "\t// Stage the 16 fill blocks into the frame at 16*lane(SP)",
         f"\t{mov} ·absorb13Block(SB), X12", ""]
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
    L += ["\t// Load round constants and key", f"\t{mov} ·RC+0(SB), X9", f"\t{mov} ·RC+16(SB), X10",
          f"\t{mov} 0(AX), X13", ""]
    for b in range(2):
        L += [f"\t// ========== BATCH {b + 1}: lanes {8 * b}–{8 * b + 7} ==========",
              "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX"]
        for l in range(8):
            L.append(f"\tVPXOR X{l}, X{l}, X{l}" if vex else f"\tPXOR X{l}, X{l}")
        L += ["", f"loop{b}:"]
        if vex:
            L += ["\tVMOVDQU 0(BX), X14", "\tVPXOR X13, X14, X14"]
            for l in range(8):
                L.append(f"\tVPXOR X14, X{l}, X{l}")
            for l in range(8):
                L.append(f"\tVPXOR {16 * (8 * b + l)}(SP), X{l}, X{l}")
            for rc in ("X9", "X9", "X10"):
                L.append("\t" + "; ".join(f"VAESENC {rc}, X{l}, X{l}" for l in range(8)))
        else:
            L += ["\tMOVOU 0(BX), X14", "\tPXOR X13, X14"]
            for l in range(8):
                L.append(f"\tPXOR X14, X{l}")
            for l in range(8):
                L.append(f"\tMOVOU {16 * (8 * b + l)}(SP), X15")
                L.append(f"\tPXOR X15, X{l}")
            for rc in ("X9", "X9", "X10"):
                L.append("\t" + "; ".join(f"AESENC {rc}, X{l}" for l in range(8)))
        L += ["\tADDQ $16, BX", "\tDECQ CX", f"\tJNZ loop{b}", "", f"\t// Store batch {b + 1} outputs"]
        for l in range(8):
            L.append(f"\t{mov} X{l}, {16 * (8 * b + l)}(DI)")
        L.append("")
    L.append("\tRET")
    return "\n".join(L) + "\n"


def x16_ymm():
    """Eight YMM states of two lanes; each pair's two groupIdx values are
    materialised via LEAQ, moved into the two 128-bit halves, turned into
    [idx<<8 | idx>>56] with one shift pair and VPUNPCKLQDQ, XORed with
    absorb13Block and stored to the frame as one 32-byte block pair."""
    L = [f"// func aesITB128FusedChain13x16VaesAvx2Asm({X16_SIG})",
         "TEXT ·aesITB128FusedChain13x16VaesAvx2Asm(SB), NOSPLIT, $256-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ out+32(FP), DI", "\tMOVQ groupIdxBase+24(FP), R8", "",
         "\t// Stage the 8 block pairs into the frame at 32*pair(SP)",
         "\tVBROADCASTI128 ·absorb13Block(SB), Y10", ""]
    for p in range(8):
        L.append(f"\t// ========== Pair {p}: lanes {2 * p}–{2 * p + 1} ==========")
        L.append("\tMOVQ R8, R9" if p == 0 else f"\tLEAQ {2 * p}(R8), R9")
        L += ["\tVMOVQ R9, X11", f"\tLEAQ {2 * p + 1}(R8), R9", "\tVMOVQ R9, X15",
              "\tVINSERTI128 $1, X15, Y11, Y11", "\tVPSRLQ $56, Y11, Y15", "\tVPSLLQ $8, Y11, Y11",
              "\tVPUNPCKLQDQ Y15, Y11, Y11", "\tVPXOR Y10, Y11, Y11", f"\tVMOVDQU Y11, {32 * p}(SP)", ""]
    L += ["\t// Load round constants and key",
          "\tVBROADCASTI128 ·RC+0(SB), Y8", "\tVBROADCASTI128 ·RC+16(SB), Y9",
          "\tVBROADCASTI128 0(AX), Y13"]
    for i in range(8):
        L.append(f"\tVPXOR Y{i}, Y{i}, Y{i}")
    L += ["", "loop:", "\tVBROADCASTI128 0(BX), Y14", "\tVPXOR Y13, Y14, Y14"]
    for i in range(8):
        L.append(f"\tVPXOR Y14, Y{i}, Y{i}")
    for i in range(8):
        L.append(f"\tVPXOR {32 * i}(SP), Y{i}, Y{i}")
    L.append("\t// AES rounds: 3 rounds on all 8 YMM pairs (RC[0], RC[0], RC[1])")
    for rc in ("Y8", "Y8", "Y9"):
        L.append("\t" + "; ".join(f"VAESENC {rc}, Y{i}, Y{i}" for i in range(8)))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\t// Store outputs: pair i at [32i..32i+32]"]
    for i in range(8):
        L.append(f"\tVMOVDQU Y{i}, {32 * i}(DI)")
    L += ["", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def x16_zmm():
    """Four ZMM states of four lanes; groupIdxBase is broadcast once and each
    group adds its laneIdxZ offset row, so the whole synthesis is vector
    arithmetic (no GPR-to-vector moves). Blocks stay in Z8..Z11 and every
    cascade round is one VPTERNLOGQ plus three VAESENC per group."""
    L = [f"// func aesITB128FusedChain13x16Avx512Asm({X16_SIG})",
         "TEXT ·aesITB128FusedChain13x16Avx512Asm(SB), NOSPLIT, $0-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ out+32(FP), DI", "",
         "\t// Broadcast groupIdxBase to Z6 (all 8 qwords) and absorb13Block to Z7",
         "\tVPBROADCASTQ groupIdxBase+24(FP), Z6", "\tVBROADCASTI32X4 ·absorb13Block(SB), Z7", ""]
    for g in range(4):
        L += [f"\t// ========== Group {g}: lanes {4 * g}–{4 * g + 3} ==========",
              f"\tVPADDQ ·laneIdxZ+{64 * g}(SB), Z6, Z12", "\tVPSRLQ $56, Z12, Z15", "\tVPSLLQ $8, Z12, Z12",
              "\tVPUNPCKLQDQ Z15, Z12, Z12", f"\tVPXORD Z7, Z12, Z{8 + g}", ""]
    L += ["\t// Load round constants and key",
          "\tVBROADCASTI32X4 ·RC+0(SB), Z4", "\tVBROADCASTI32X4 ·RC+16(SB), Z5",
          "\tVBROADCASTI32X4 0(AX), Z13"]
    for j in range(4):
        L.append(f"\tVPXORD Z{j}, Z{j}, Z{j}")
    L += ["", "loop:", "\tVBROADCASTI32X4 0(BX), Z14", "\tVPXORD Z13, Z14, Z14"]
    for j in range(4):
        L.append(f"\tVPTERNLOGQ $0x96, Z14, Z{8 + j}, Z{j}     // Z{j} ^= Z{8 + j} ^ Z14")
    L.append("\t// AES rounds: 3 rounds on all 4 ZMM groups (RC[0], RC[0], RC[1])")
    for rc in ("Z4", "Z4", "Z5"):
        L.append("\t" + "; ".join(f"VAESENC {rc}, Z{j}, Z{j}" for j in range(4)))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\t// Store outputs: group j at [64j..64j+64]"]
    for j in range(4):
        L.append(f"\tVMOVDQU64 Z{j}, {64 * j}(DI)")
    L += ["", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def x16_neon():
    """Two batches of eight lanes, register-resident; the block is assembled
    in GPRs (D[0] = idx<<8 | 0x03, D[1] = idx>>56 | pad tail) and is the
    first AESE key operand of every cascade round. Issue order is
    round-major within a batch."""
    L = [f"// func aesITB128FusedChain13x16NeonAsm({X16_SIG})",
         "TEXT ·aesITB128FusedChain13x16NeonAsm(SB), NOSPLIT, $0-40",
         "\tMOVD key+0(FP), R0", "\tMOVD comps+8(FP), R1", "\tMOVD nPairs+16(FP), R2",
         "\tMOVD groupIdxBase+24(FP), R3", "\tMOVD out+32(FP), R4", "",
         "\t// Load key (V18) and round constants RC[0] (V16), RC[1] (V17)",
         "\tVLD1 (R0), [V18.B16]",
         "\tMOVD $·RC(SB), R5", "\tVLD1.P 16(R5), [V16.B16]  // RC[0]", "\tVLD1 (R5), [V17.B16]      // RC[1]", "",
         "\t// Materialized constant for pad tail: bytes 13-15 = 0x03", "\tMOVD $0x0303030000000000, R7", ""]
    for b in range(2):
        L += [f"\t// ========== BATCH {b + 1}: lanes {8 * b}–{8 * b + 7} ==========",
              "\t// Step 1 — synthesise the 8 fill blocks in V8..V15:",
              "\t// [0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03] as",
              "\t// D[0] = (idx << 8) | 0x03, D[1] = (idx >> 56) | pad tail."]
        for l in range(8):
            lane = 8 * b + l
            L.append("\tMOVD R3, R6" if lane == 0 else f"\tADD ${lane}, R3, R6")
            L += ["\tLSL $8, R6, R8", "\tORR $3, R8, R8", "\tLSR $56, R6, R9", "\tORR R7, R9, R9",
                  f"\tVMOV R8, V{8 + l}.D[0]", f"\tVMOV R9, V{8 + l}.D[1]"]
        L += ["", "\t// Step 2 — zero the 8 states, reset the component cursor and pair count."]
        for l in range(8):
            L.append(f"\tVEOR V{l}.B16, V{l}.B16, V{l}.B16")
        L += ["\tMOVD R1, R10", "\tMOVD R2, R11", "", f"loop{b}:",
              "\t// Fold key XOR pair (V19) into every state, then the block as the",
              "\t// first AESE key operand, two RC[0] rounds and the final RC[1] XOR.",
              "\tVLD1.P 16(R10), [V20.B16]", "\tVEOR V18.B16, V20.B16, V19.B16"]
        for l in range(8):
            L.append(f"\tVEOR V19.B16, V{l}.B16, V{l}.B16")
        for l in range(8):
            L += [f"\tAESE V{8 + l}.B16, V{l}.B16", f"\tAESMC V{l}.B16, V{l}.B16"]
        for _ in range(2):
            for l in range(8):
                L += [f"\tAESE V16.B16, V{l}.B16", f"\tAESMC V{l}.B16, V{l}.B16"]
        for l in range(8):
            L.append(f"\tVEOR V17.B16, V{l}.B16, V{l}.B16")
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
    amd = "amd64 && !purego && !noitbasm"
    arm = "arm64 && !purego && !noitbasm"
    files = {}
    files.update(render_x16())
    for s in SHAPES:
        files.update({
            f"aesitb_fusedchain128_{s}x4_aesni_amd64.s": header(s, 4, "Legacy-SSE AES-NI XMM", amd, "xmm") + "\n" + xmm_fused(s, 4, False),
            f"aesitb_fusedchain128_{s}x4_vex_amd64.s": header(s, 4, "VEX-encoded AES-NI XMM", amd, "xmm") + "\n" + xmm_fused(s, 4, True),
            f"aesitb_fusedchain128_{s}x4_vaesavx2_amd64.s": header(s, 4, "VAES YMM (two lanes per register)", amd, "ymm") + "\n" + ymm_fused(s),
            f"aesitb_fusedchain128_{s}x4_avx512_amd64.s": header(s, 4, "VAES ZMM (four lanes per register)", amd, "zmm") + "\n" + zmm_fused(s),
            f"aesitb_fusedchain128_{s}x1_aesni_amd64.s": header(s, 1, "Legacy-SSE AES-NI XMM", amd, "xmm") + "\n" + xmm_fused(s, 1, False),
            f"aesitb_fusedchain128_{s}x1_vex_amd64.s": header(s, 1, "VEX-encoded AES-NI XMM", amd, "xmm") + "\n" + xmm_fused(s, 1, True),
            f"aesitb_fusedchain128_{s}x4_neon_arm64.s": header(s, 4, "ARM64 NEON crypto-extension", arm, "neon") + "\n" + neon_fused(s, 4),
            f"aesitb_fusedchain128_{s}x1_neon_arm64.s": header(s, 1, "ARM64 NEON crypto-extension", arm, "neon") + "\n" + neon_fused(s, 1),
        })
    for s in X8_SHAPES:
        files[f"aesitb_fusedchain128_{s}x8_avx512_amd64.s"] = (
            header(s, 8, "VAES ZMM (four lanes per register, two state groups)", amd, "zmm") + "\n" + zmm_fused_x8(s))
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
