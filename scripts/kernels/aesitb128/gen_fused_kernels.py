#!/usr/bin/env python3
"""Emit the AES-ITB-128 fused ChainHash cascade kernels for internal/aesitbasm.

One file per (shape, lanes, tier). Shapes 13/20/36/68; lanes x4 (four data
lanes over one shared component slice) and x1 (single lane); amd64 tiers
aesni / vex / vaesavx2 / avx512 for x4, aesni / vex for x1; arm64 tier neon
for both.

Every amd64 tier additionally carries an x8 variant at the three
nonce-buf shapes 20/36/68 (aesitb_fusedchain128_<shape>x8_<tier>_amd64.s):
on avx512 eight lanes in two ZMM state groups (lanes 0..3 in Z0, lanes
4..7 in Z1), on vaesavx2 four YMM states of two lanes, on vex / aesni
eight XMM states of one lane — in every case the cascade rounds of the
states are interleaved instruction by instruction, so the independent
VAESENC dependency chains overlap on the AES unit. See zmm_fused_x8,
ymm_fused_x8 and xmm_fused_x8 for the register plans.

A third family, x16 at shape 13 only, is the Interlocked Barrier PRF fill
kernel (aesitb_fusedchain128_13x16_<tier>_amd64.s for the four amd64 tiers
and aesitb_fusedchain128_13x16_neon_arm64.s): the kernel receives
groupIdxBase in a GPR and the per-message interlock-nonce fold v (a
uint32, the little-endian image of bytes 9..12 of every fill block) and
synthesises the 16 per-lane fill blocks in-register —
[0x03 | LE64(groupIdxBase+i) | LE32(v) | 3×0x03] for lane i — so the
batch-16 path pays no per-lane pointer gather, then runs the same cascade
per lane. v << 8 occupies bits 8..39 of the block's second qword and
idx >> 56 bits 0..7, so the fold is ORed (equivalently XORed) in once:
into the absorb13Block template on the XMM / YMM tiers, into the
idx >> 56 vector per group on the ZMM tier, into the pad-tail GPR on
NEON. See the x16 section below for the per-tier register
plans and the output-store discipline of that family.

Cascade evaluated per lane (see aesitbasm_fused.go):
    state = 0
    for each component pair (c0, c1):
        state ^= key ^ (LE64(c0) || LE64(c1))
        for each padded data block b < nb:  state = AESENC(state ^ block_b, RC[b mod 8])
        state = AESENC(state, RC[nb mod 8]); state = AESENC(state, RC[(nb + 1) mod 8])
    out = state
The finalising rounds continue the constant cycle, so a lane reads the
nb + 2 distinct constants RC[0 .. nb + 1] (nb = 1 / 2 / 3 / 5 at shapes
13 / 20 / 36 / 68).

Data blocks are round-invariant and are staged once, with the round
constant of the preceding absorb round folded in. AESENC ends with the
round-key XOR, so for 0 < b < nb

    AESENC(s, RC[b-1]) ^ block_b == AESENC(s, RC[b-1] ^ block_b)

and every kernel stages block_b ^ RC[b-1] and uses it as the round key
of absorb round b-1 (the AESE form on arm64 takes the staged block as
the key of round b, the XOR preceding SubBytes there). The cascade round
then reads block 0, the staged blocks 1 .. nb-1 as round keys and the
three bare constants RC[nb-1], RC[nb], RC[nb+1]; no XOR sits between two
absorb rounds. Block 0 additionally absorbs the key wherever it is staged
in a register (YMM x4, ZMM, NEON), so the per-round fold is the component
pair alone; frame slots receive only the public constant fold, and the
frame-staged tiers keep the key in a register and fold it into the pair.

The XMM tiers stage the blocks into the stack frame at
SP + 16*lanes*b + 16*lane (16-byte stores read back by 16-byte loads;
the VEX tier consumes the folded blocks as VAESENC memory operands, the
legacy-SSE tier reloads them through a register, since AESENC m128 needs
a 16-byte-aligned operand the Go frame does not guarantee). The four-lane
YMM kernel and the ZMM tier keep every block in registers; the eight-lane
YMM kernel stages every block in the frame as a 32-byte lane-pair slot
consumed as a VAESENC memory operand. On arm64 every block of every lane
sits in a register for the whole call.

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
# Shapes with an eight-lane fused kernel: the 128 / 256 / 512-bit
# nonce-buf shapes the pixel pipeline drives through the batched hook.
X8_SHAPES = [20, 36, 68]


def blocks(n):
    return (n + 16) // 16


def staging_note(tier):
    if tier == "xmm":
        return ("// The padded data blocks are staged once into the frame, every block\n"
                "// past block 0 with the round constant of the preceding absorb round\n"
                "// folded in so it serves as that round's key, and every cascade round\n"
                "// runs from those 16-byte slots")
    if tier == "ymm":
        return ("// The padded data blocks are staged once in registers, block 0 with\n"
                "// the key folded in and every later block with the round constant of\n"
                "// the preceding absorb round folded in so it serves as that round's\n"
                "// key, and every cascade round runs from registers")
    if tier == "ymm8":
        return ("// The padded data blocks are staged once into the frame as 32-byte\n"
                "// lane-pair slots, every block past block 0 with the round constant\n"
                "// of the preceding absorb round folded in so it serves as that\n"
                "// round's key, and every cascade round runs from those slots")
    return ("// The padded data blocks are staged once in registers (Z15..), block 0\n"
            "// with the key folded in and every later block with the round constant\n"
            "// of the preceding absorb round folded in so it serves as that round's\n"
            "// key, and every cascade round runs from registers")


def header(shape, lanes, tier_desc, build, tier):
    nb = blocks(shape)
    if tier == "neon":
        return f"""//go:build {build}

// {tier_desc} fused ChainHash cascade kernel for AES-ITB-128 at the
// {shape}-byte shape, {lanes} lane{'s' if lanes > 1 else ''} ({nb} PKCS#7 block{'s' if nb > 1 else ''}, {nb + 2} AES rounds per
// cascade round). The padded data blocks are staged once in registers,
// block 0 with the key folded in and every later block with the round
// constant of the preceding absorb round folded in, and every cascade
// round runs from registers; see aesitbasm_fused.go for the
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


def lane_block(shape, b, r, vex, dst="X4", pad="X13"):
    """Assemble padded block b of the lane at pointer r into dst.

    Block 0 and the tail are read with exact-width inserts (pad, X13 by
    default, holds the pad vector and serves as the merge source, so lanes
    assemble without a dependency on each other); the 4-byte inserts at
    offsets 0 and 4 match the caller's 4-byte pixel-index store. Full
    blocks past block 0 are one 16-byte load.
    """
    nb = blocks(shape)
    off = 16 * b
    mov = "VMOVDQU" if vex else "MOVOU"
    L = []
    if b == nb - 1:
        if shape == 13:
            if vex:
                L.append(f"\tVPINSRQ $0, {off}({r}), {pad}, {dst}")
                L.append(f"\tVPINSRD $2, {off + 8}({r}), {dst}, {dst}")
                L.append(f"\tVPINSRB $12, {off + 12}({r}), {dst}, {dst}")
            else:
                L.append(f"\tMOVOU {pad}, {dst}")
                L.append(f"\tPINSRQ $0, {off}({r}), {dst}")
                L.append(f"\tPINSRD $2, {off + 8}({r}), {dst}")
                L.append(f"\tPINSRB $12, {off + 12}({r}), {dst}")
        else:
            if vex:
                L.append(f"\tVPINSRD $0, {off}({r}), {pad}, {dst}")
            else:
                L.append(f"\tMOVOU {pad}, {dst}")
                L.append(f"\tPINSRD $0, {off}({r}), {dst}")
    elif b == 0:
        if vex:
            L.append(f"\tVPINSRD $0, 0({r}), {pad}, {dst}")
            L.append(f"\tVPINSRD $1, 4({r}), {dst}, {dst}")
            L.append(f"\tVPINSRQ $1, 8({r}), {dst}, {dst}")
        else:
            L.append(f"\tMOVOU {pad}, {dst}")
            L.append(f"\tPINSRD $0, 0({r}), {dst}")
            L.append(f"\tPINSRD $1, 4({r}), {dst}")
            L.append(f"\tPINSRQ $1, 8({r}), {dst}")
    else:
        L.append(f"\t{mov} {off}({r}), {dst}")
    return L


def pad_load(shape, vex, dst="X13"):
    pad = "pad13Tail" if shape == 13 else "pad4Tail"
    return f"\t{'VMOVDQU' if vex else 'MOVOU'} ·{pad}(SB), {dst}"


def stage_amd64(shape, lanes, vex, regs):
    """Prologue: stage padded blocks into the frame at 64*b + 16*lane (SP),
    every block b > 0 with RC[b-1] (loaded into X5) folded in."""
    nb = blocks(shape)
    mov = "VMOVDQU" if vex else "MOVOU"
    L = [pad_load(shape, vex)]
    for b in range(nb):
        if b:
            L.append(f"\t{mov} ·RC+{16 * (b - 1)}(SB), X5")
        for l in range(lanes):
            L += lane_block(shape, b, regs[l], vex)
            if b:
                L.append("\tVPXOR X5, X4, X4" if vex else "\tPXOR X5, X4")
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
    # X5..X7 the bare constants RC[nb-1], RC[nb], RC[nb+1]; X13 the key;
    # X14 the per-round key XOR pair; X4 the block-0 reload register and
    # X8.. the folded-block reload registers of the legacy-SSE tier.
    bare = ["X5", "X6", "X7"]
    for j, y in enumerate(bare):
        L.append(f"\t{mov} ·RC+{16 * (nb - 1 + j)}(SB), {y}")
    L.append(f"\t{mov} 0(AX), X13")
    for l in range(lanes):
        L.append(f"\tVPXOR X{l}, X{l}, X{l}" if vex else f"\tPXOR X{l}, X{l}")
    L.append("")
    L.append("loop:")
    if vex:
        L.append("\tVMOVDQU 0(BX), X14")
        L.append("\tVPXOR X13, X14, X14")
        for l in range(lanes):
            L.append(f"\tVPXOR X14, X{l}, X{l}")
        for l in range(lanes):
            L.append(f"\tVPXOR {16 * l}(SP), X{l}, X{l}")
        for b in range(1, nb):
            L.append("\t" + "; ".join(f"VAESENC {64 * b + 16 * l}(SP), X{l}, X{l}" for l in range(lanes)))
        for y in bare:
            L.append("\t" + "; ".join(f"VAESENC {y}, X{l}, X{l}" for l in range(lanes)))
    else:
        L.append("\tMOVOU 0(BX), X14")
        L.append("\tPXOR X13, X14")
        for l in range(lanes):
            L.append(f"\tPXOR X14, X{l}")
        for l in range(lanes):
            L.append(f"\tMOVOU {16 * l}(SP), X4")
            L.append(f"\tPXOR X4, X{l}")
        for b in range(1, nb):
            for l in range(lanes):
                L.append(f"\tMOVOU {64 * b + 16 * l}(SP), X{8 + l}")
            L.append("\t" + "; ".join(f"AESENC X{8 + l}, X{l}" for l in range(lanes)))
        for y in bare:
            L.append("\t" + "; ".join(f"AESENC {y}, X{l}" for l in range(lanes)))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", ""]
    for l in range(lanes):
        L.append(f"\t{mov} X{l}, {16 * l}(DI)")
    L.append("\tRET")
    return "\n".join(L) + "\n"


def ymm_fused(shape):
    """VAES YMM: lanes (0, 1) in Y0, lanes (2, 3) in Y1.

    Register plan: Y3..Y5 the bare constants RC[nb-1], RC[nb], RC[nb+1];
    Y14 the per-round component broadcast (and the fold source in the
    prologue); block b of lanes (0, 1) / (2, 3) in the register pair
    taken in order from Y2, Y6..Y13, Y15 — block 0 with the key folded
    in, block b > 0 with RC[b-1] folded in. Ten block registers hold the
    five blocks of shape 68, so every shape runs with no frame (16 of 16
    registers at shape 68). X5 holds the pad vector and X4 is the lane
    insert register during the staging, before the constants land.
    """
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"]
    pool = ["Y2"] + [f"Y{i}" for i in range(6, 14)] + ["Y15"]
    assert 2 * nb <= len(pool)
    slots = [(pool[2 * b], pool[2 * b + 1]) for b in range(nb)]
    bare = ["Y3", "Y4", "Y5"]
    L = [f"// func aesITB128FusedChain{shape}x4VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[4]*byte, out *[4][2]uint64)",
         f"TEXT ·aesITB128FusedChain{shape}x4VaesAvx2Asm(SB), NOSPLIT, $0-40"]
    L += prologue_amd64(4)
    L.append("")
    L.append(pad_load(shape, True, dst="X5"))
    for b, (ya, yb) in enumerate(slots):
        for ra, rb, y in ((regs[0], regs[1], ya), (regs[2], regs[3], yb)):
            x = "X" + y[1:]
            if 0 < b < nb - 1:
                L.append(f"\tVMOVDQU {16 * b}({ra}), {x}")
                L.append(f"\tVINSERTI128 $1, {16 * b}({rb}), {y}, {y}")
            else:
                L += lane_block(shape, b, ra, True, dst=x, pad="X5")
                L += lane_block(shape, b, rb, True, pad="X5")
                L.append(f"\tVINSERTI128 $1, X4, {y}, {y}")
    L.append("")
    for b, (ya, yb) in enumerate(slots):
        src = "0(AX)" if b == 0 else f"·RC+{16 * (b - 1)}(SB)"
        L += [f"\tVBROADCASTI128 {src}, Y14", f"\tVPXOR Y14, {ya}, {ya}", f"\tVPXOR Y14, {yb}, {yb}"]
    for j, y in enumerate(bare):
        L.append(f"\tVBROADCASTI128 ·RC+{16 * (nb - 1 + j)}(SB), {y}")
    L += ["\tVPXOR Y0, Y0, Y0", "\tVPXOR Y1, Y1, Y1", "", "loop:",
          "\tVBROADCASTI128 0(BX), Y14", "\tVPXOR Y14, Y0, Y0", "\tVPXOR Y14, Y1, Y1",
          f"\tVPXOR {slots[0][0]}, Y0, Y0", f"\tVPXOR {slots[0][1]}, Y1, Y1"]
    for ya, yb in slots[1:]:
        L.append(f"\tVAESENC {ya}, Y0, Y0; VAESENC {yb}, Y1, Y1")
    for y in bare:
        L.append(f"\tVAESENC {y}, Y0, Y0; VAESENC {y}, Y1, Y1")
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI128 $1, Y0, 16(DI)",
          "\tVMOVDQU X1, 32(DI)", "\tVEXTRACTI128 $1, Y1, 48(DI)", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def zmm_fused(shape):
    """VAES ZMM: all four lanes in Z0; block b staged in Z(15+b).

    Block 0 carries the key, block b > 0 carries RC[b-1] (folded in once
    through Z13 after the staging); Z2..Z4 hold the bare constants
    RC[nb-1], RC[nb], RC[nb+1] and Z14 the per-round component broadcast.
    """
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
    for b in range(nb):
        src = "0(AX)" if b == 0 else f"·RC+{16 * (b - 1)}(SB)"
        L += [f"\tVBROADCASTI32X4 {src}, Z13", f"\tVPXORD Z13, Z{15 + b}, Z{15 + b}"]
    for j in range(3):
        L.append(f"\tVBROADCASTI32X4 ·RC+{16 * (nb - 1 + j)}(SB), Z{2 + j}")
    L += ["\tVPXORD Z0, Z0, Z0", "", "loop:",
          "\tVBROADCASTI32X4 0(BX), Z14", "\tVPXORD Z14, Z0, Z0", "\tVPXORD Z15, Z0, Z0"]
    for b in range(1, nb):
        L.append(f"\tVAESENC Z{15 + b}, Z0, Z0")
    for j in range(3):
        L.append(f"\tVAESENC Z{2 + j}, Z0, Z0")
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI64X2 $1, Z0, 16(DI)",
          "\tVEXTRACTI64X2 $2, Z0, 32(DI)", "\tVEXTRACTI64X2 $3, Z0, 48(DI)", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def zmm_fused_x8(shape):
    """VAES ZMM, eight lanes: lanes 0..3 in Z0, lanes 4..7 in Z1.

    Register plan: Z2..Z4 the bare constants RC[nb-1], RC[nb], RC[nb+1],
    Z13 the fold source of the prologue, Z14 the per-round component pair
    broadcast, Z15..Z(14+nb) the staged blocks of lanes 0..3 and
    Z(15+nb)..Z(14+2nb) those of lanes 4..7 — block 0 of each group with
    the key folded in, block b > 0 with RC[b-1] folded in; 16 registers
    live in the loop at shape 68, 12 at 36, 10 at 20. The lane pointers
    are read four at a time through R8..R11 (group 0 from dataPtrs[0..3],
    group 1 from dataPtrs[4..7]) with the same exact-width block-0 / tail
    inserts as the x4 kernel; the folds land only after both stagings,
    since X13 holds the pad vector until then.

    Loop body: the component pair and block 0 fold into each state with
    one VPTERNLOGQ (XOR3), then every AES round issues for group 0 and
    group 1 back to back, with the folded blocks as the absorb round
    keys, so the two independent state chains overlap on the AES unit
    instead of serialising as one chain per call. Output: eight 16-byte
    stores, the width the Go side reads back.
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
    for b in range(nb):
        src = "0(AX)" if b == 0 else f"·RC+{16 * (b - 1)}(SB)"
        L += [f"\tVBROADCASTI32X4 {src}, Z13",
              f"\tVPXORD Z13, Z{15 + b}, Z{15 + b}; VPXORD Z13, Z{15 + nb + b}, Z{15 + nb + b}"]
    for j in range(3):
        L.append(f"\tVBROADCASTI32X4 ·RC+{16 * (nb - 1 + j)}(SB), Z{2 + j}")
    L += ["\tVPXORD Z0, Z0, Z0", "\tVPXORD Z1, Z1, Z1", "", "loop:",
          "\tVBROADCASTI32X4 0(BX), Z14",
          f"\tVPTERNLOGQ $0x96, Z14, Z15, Z0; VPTERNLOGQ $0x96, Z14, Z{15 + nb}, Z1"]
    for b in range(1, nb):
        L.append(f"\tVAESENC Z{15 + b}, Z0, Z0; VAESENC Z{15 + nb + b}, Z1, Z1")
    for j in range(3):
        L.append(f"\tVAESENC Z{2 + j}, Z0, Z0; VAESENC Z{2 + j}, Z1, Z1")
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "",
          "\tVMOVDQU X0, 0(DI)", "\tVEXTRACTI64X2 $1, Z0, 16(DI)",
          "\tVEXTRACTI64X2 $2, Z0, 32(DI)", "\tVEXTRACTI64X2 $3, Z0, 48(DI)",
          "\tVMOVDQU X1, 64(DI)", "\tVEXTRACTI64X2 $1, Z1, 80(DI)",
          "\tVEXTRACTI64X2 $2, Z1, 96(DI)", "\tVEXTRACTI64X2 $3, Z1, 112(DI)",
          "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def ymm_fused_x8(shape):
    """VAES YMM, eight lanes: lane pair (2i, 2i+1) in Y(i), i = 0..3.

    Register plan: Y4..Y6 the bare constants RC[nb-1], RC[nb], RC[nb+1],
    Y13 the key, Y14 the per-round component broadcast — 9 of 16. Every
    block of every pair is staged into the frame as a 32-byte lane-pair
    slot at SP + 128*b + 32*i, block b > 0 with RC[b-1] (broadcast into
    Y3) folded in; block 0 is consumed as a 32-byte VPXOR memory operand
    and blocks 1 .. nb-1 as 32-byte VAESENC round-key memory operands
    every round. Only the public constants are folded into the frame; the
    key stays in Y13 and folds into the component broadcast. X13 holds
    the pad vector during the staging, before the key lands. The lane
    pointers are read four at a time through R8..R11 (group 0 from
    dataPtrs[0..3], group 1 from dataPtrs[4..7]) with the same
    exact-width block-0 / tail inserts as the four-lane kernel.

    Loop body: the key XOR pair and block 0 fold into each state, then
    every AES round issues for the four states back to back, so four
    independent AES round chains overlap on the AES unit. Output: eight
    16-byte stores, the width the Go side reads back.
    """
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"]
    frame = 128 * nb
    bare = ["Y4", "Y5", "Y6"]
    L = [f"// func aesITB128FusedChain{shape}x8VaesAvx2Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)",
         f"TEXT ·aesITB128FusedChain{shape}x8VaesAvx2Asm(SB), NOSPLIT, ${frame}-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ dataPtrs+24(FP), DX", "\tMOVQ out+32(FP), DI", ""]
    L.append(pad_load(shape, True))
    for g in range(2):
        L.append(f"\t// Lanes {4 * g}..{4 * g + 3}: pairs {2 * g} and {2 * g + 1}")
        for l in range(4):
            L.append(f"\tMOVQ {32 * g + 8 * l}(DX), {regs[l]}")
        for b in range(nb):
            if b:
                L.append(f"\tVBROADCASTI128 ·RC+{16 * (b - 1)}(SB), Y3")
            for ra, rb, off in ((regs[0], regs[1], 128 * b + 64 * g), (regs[2], regs[3], 128 * b + 64 * g + 32)):
                if 0 < b < nb - 1:
                    L.append(f"\tVMOVDQU {16 * b}({ra}), X2")
                    L.append(f"\tVINSERTI128 $1, {16 * b}({rb}), Y2, Y2")
                else:
                    L += lane_block(shape, b, ra, True, dst="X2")
                    L += lane_block(shape, b, rb, True)
                    L.append("\tVINSERTI128 $1, X4, Y2, Y2")
                if b:
                    L.append("\tVPXOR Y3, Y2, Y2")
                L.append(f"\tVMOVDQU Y2, {off}(SP)")
    L.append("")
    for j, y in enumerate(bare):
        L.append(f"\tVBROADCASTI128 ·RC+{16 * (nb - 1 + j)}(SB), {y}")
    states = [f"Y{i}" for i in range(4)]
    L.append("\tVBROADCASTI128 0(AX), Y13")
    L += [f"\tVPXOR {y}, {y}, {y}" for y in states]
    L += ["", "loop:", "\tVBROADCASTI128 0(BX), Y14", "\tVPXOR Y13, Y14, Y14"]
    L += [f"\tVPXOR Y14, {y}, {y}" for y in states]
    for i, y in enumerate(states):
        L.append(f"\tVPXOR {32 * i}(SP), {y}, {y}")
    for b in range(1, nb):
        L.append("\t" + "; ".join(f"VAESENC {128 * b + 32 * i}(SP), {y}, {y}" for i, y in enumerate(states)))
    for k in bare:
        L.append("\t" + "; ".join(f"VAESENC {k}, {y}, {y}" for y in states))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", ""]
    for i, y in enumerate(states):
        L += [f"\tVMOVDQU X{i}, {32 * i}(DI)", f"\tVEXTRACTI128 $1, {y}, {32 * i + 16}(DI)"]
    L += ["\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def xmm_fused_x8(shape, vex):
    """XMM, eight lanes: lane l in X(l), l = 0..7, eight independent AES
    chains per call.

    Register plan: X8..X10 the bare constants RC[nb-1], RC[nb], RC[nb+1]
    (X8 also carries RC[b-1] while block b is staged), X13 the key, X14
    the per-round key XOR pair, X15 the block reload register of the
    legacy-SSE tier (PXOR m128 and AESENC m128 need a 16-byte-aligned
    operand the Go frame does not guarantee; the VEX tier reads block 0
    as a VPXOR memory operand and the folded blocks as VAESENC round-key
    memory operands). Every block of every lane is staged into the frame
    at SP + 128*b + 16*l, block b > 0 with RC[b-1] folded in — only the
    public constants are folded into the frame; the key stays in X13 and
    folds into the component pair. X13 holds the pad vector during the
    staging, before the key lands. The lane pointers are read four at a
    time through R8..R11 with the same exact-width block-0 / tail inserts
    as the four-lane kernel. Output: eight 16-byte stores.
    """
    nb = blocks(shape)
    tier = "Vex" if vex else "AesNi"
    regs = ["R8", "R9", "R10", "R11"]
    frame = 128 * nb
    mov = "VMOVDQU" if vex else "MOVOU"
    bare = ["X8", "X9", "X10"]
    L = [f"// func aesITB128FusedChain{shape}x8{tier}Asm(key *[16]byte, comps *uint64, nPairs int, dataPtrs *[8]*byte, out *[8][2]uint64)",
         f"TEXT ·aesITB128FusedChain{shape}x8{tier}Asm(SB), NOSPLIT, ${frame}-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ dataPtrs+24(FP), DX", "\tMOVQ out+32(FP), DI", ""]
    L.append(pad_load(shape, vex))
    for g in range(2):
        L.append(f"\t// Lanes {4 * g}..{4 * g + 3}")
        for l in range(4):
            L.append(f"\tMOVQ {32 * g + 8 * l}(DX), {regs[l]}")
        for b in range(nb):
            if b:
                L.append(f"\t{mov} ·RC+{16 * (b - 1)}(SB), X8")
            for l in range(4):
                L += lane_block(shape, b, regs[l], vex)
                if b:
                    L.append("\tVPXOR X8, X4, X4" if vex else "\tPXOR X8, X4")
                L.append(f"\t{mov} X4, {128 * b + 16 * (4 * g + l)}(SP)")
    L.append("")
    for j, x in enumerate(bare):
        L.append(f"\t{mov} ·RC+{16 * (nb - 1 + j)}(SB), {x}")
    L.append(f"\t{mov} 0(AX), X13")
    for l in range(8):
        L.append(f"\tVPXOR X{l}, X{l}, X{l}" if vex else f"\tPXOR X{l}, X{l}")
    L += ["", "loop:"]
    if vex:
        L += ["\tVMOVDQU 0(BX), X14", "\tVPXOR X13, X14, X14"]
        for l in range(8):
            L.append(f"\tVPXOR X14, X{l}, X{l}")
        for l in range(8):
            L.append(f"\tVPXOR {16 * l}(SP), X{l}, X{l}")
        for b in range(1, nb):
            L.append("\t" + "; ".join(f"VAESENC {128 * b + 16 * l}(SP), X{l}, X{l}" for l in range(8)))
        for k in bare:
            L.append("\t" + "; ".join(f"VAESENC {k}, X{l}, X{l}" for l in range(8)))
    else:
        L += ["\tMOVOU 0(BX), X14", "\tPXOR X13, X14"]
        for l in range(8):
            L.append(f"\tPXOR X14, X{l}")
        for l in range(8):
            L.append(f"\tMOVOU {16 * l}(SP), X15")
            L.append(f"\tPXOR X15, X{l}")
        for b in range(1, nb):
            for l in range(8):
                L.append(f"\tMOVOU {128 * b + 16 * l}(SP), X15")
                L.append(f"\tAESENC X15, X{l}")
        for k in bare:
            L.append("\t" + "; ".join(f"AESENC {k}, X{l}" for l in range(8)))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", ""]
    for l in range(8):
        L.append(f"\t{mov} X{l}, {16 * l}(DI)")
    L.append("\tRET")
    return "\n".join(L) + "\n"


def neon_fused(shape, lanes):
    """NEON: lane l in V(l). Every block of every lane is loaded once into
    V(8 + lanes*b + l) — full blocks by VLD1, the padded tail through the
    pad vector (V5) and a GPR insert — and folded once: the key into block
    0, RC[b-1] into block b > 0 (RC[b-1] loaded into V6). AESE XORs its key
    operand before SubBytes, so the folded block b is the key of absorb
    round b and the cascade round needs no XOR between rounds. V28..V30
    hold the bare constants RC[nb-1], RC[nb], RC[nb+1] (the last applied
    as an explicit XOR after the final AESMC), V5 the per-round component
    pair. At shape 68 the four-lane kernel uses 28 of 32 registers.
    """
    nb = blocks(shape)
    regs = ["R8", "R9", "R10", "R11"][:lanes]
    blk = lambda b, l: f"V{8 + lanes * b + l}"
    sig = "dataPtrs *[4]*byte, out *[4][2]uint64" if lanes == 4 else "data *byte, out *[2]uint64"
    arg = "dataPtrs" if lanes == 4 else "data"
    L = [f"// func aesITB128FusedChain{shape}x{lanes}NeonAsm(key *[16]byte, comps *uint64, nPairs int, {sig})",
         f"TEXT ·aesITB128FusedChain{shape}x{lanes}NeonAsm(SB), NOSPLIT, $0-40",
         "\tMOVD key+0(FP), R0", "\tMOVD comps+8(FP), R6", "\tMOVD nPairs+16(FP), R7",
         f"\tMOVD {arg}+24(FP), R2", "\tMOVD out+32(FP), R3",
         "\tVLD1 (R0), [V4.B16]"]
    if lanes == 4:
        L += ["\tMOVD 0(R2), R8", "\tMOVD 8(R2), R9", "\tMOVD 16(R2), R10", "\tMOVD 24(R2), R11"]
    else:
        L += ["\tMOVD R2, R8"]
    pad = "pad13Tail" if shape == 13 else "pad4Tail"
    L += [f"\tMOVD $·{pad}(SB), R4", "\tVLD1 (R4), [V5.B16]"]
    toff = 16 * (nb - 1)
    for l in range(lanes):
        r, t = regs[l], blk(nb - 1, l)
        L.append(f"\tVMOV V5.B16, {t}.B16")
        if shape == 13:
            L += [f"\tMOVD ({r}), R12", f"\tVMOV R12, {t}.D[0]",
                  f"\tMOVWU 8({r}), R12", f"\tVMOV R12, {t}.S[2]",
                  f"\tMOVBU 12({r}), R12", f"\tVMOV R12, {t}.B[12]"]
        else:
            L += [f"\tMOVWU {toff}({r}), R12", f"\tVMOV R12, {t}.S[0]"]
    for b in range(nb - 1):
        for l in range(lanes):
            L.append(f"\tVLD1.P 16({regs[l]}), [{blk(b, l)}.B16]")
    for l in range(lanes):
        L.append(f"\tVEOR V4.B16, {blk(0, l)}.B16, {blk(0, l)}.B16")
    L.append("\tMOVD $·RC(SB), R4")
    for b in range(1, nb):
        L.append(f"\tVLD1.P 16(R4), [V6.B16]")
        for l in range(lanes):
            L.append(f"\tVEOR V6.B16, {blk(b, l)}.B16, {blk(b, l)}.B16")
    L += ["\tVLD1.P 16(R4), [V28.B16]", "\tVLD1.P 16(R4), [V29.B16]", "\tVLD1 (R4), [V30.B16]"]
    for l in range(lanes):
        L.append(f"\tVEOR V{l}.B16, V{l}.B16, V{l}.B16")
    L += ["", "loop:", "\tVLD1.P 16(R6), [V5.B16]"]
    for l in range(lanes):
        L.append(f"\tVEOR V5.B16, V{l}.B16, V{l}.B16")
    keys = [[blk(b, l) for l in range(lanes)] for b in range(nb)] + [["V28"] * lanes, ["V29"] * lanes]
    for ks in keys:
        for l in range(lanes):
            L.append(f"\tAESE {ks[l]}.B16, V{l}.B16")
        for l in range(lanes):
            L.append(f"\tAESMC V{l}.B16, V{l}.B16")
    for l in range(lanes):
        L.append(f"\tVEOR V30.B16, V{l}.B16, V{l}.B16")
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
# state and runs the three AES rounds (absorb RC[0], finalisers RC[1] and
# RC[2]); with one pair the cascade is the plain chain-absorb of the shape.
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

X16_SIG = "key *[16]byte, comps *uint64, nPairs int, groupIdxBase uint64, out *[16][2]uint64, v uint32"

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
// runs the three AES rounds (absorb RC[0], finalisers RC[1] and RC[2]).
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
// (16 bytes per lane) in the prologue from the absorb13Block template in
// X12, into which the interlock-nonce fold (v << 8, second qword) is
// XORed once before the lanes are built. Per batch: X0–X7 states,
// X9–X11 RC[0] / RC[1] / RC[2], X13 key, X14 key XOR pair (per round),
// X15 scratch.
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
//   Y8–Y10     RC[0], RC[1], RC[2] broadcasts (Y10 holds the
//              absorb13Block broadcast, with the interlock-nonce fold
//              v << 8 XORed into its second qwords, during the prologue)
//   Y11, Y15   scratch for per-lane groupIdx synthesis
//   Y13        key broadcast
//   Y14        key XOR component pair, broadcast per cascade round
//
// Per-pair synthesis (no index vector):
//   - Calculate groupIdx for both lanes (2i and 2i+1)
//   - Load into X11 (lane 2i) and X15 (lane 2i+1)
//   - VINSERTI128 to form YMM with [gi_even | gi_odd]
//   - VPUNPCKLQDQ to transform [gi, 0] into [gi<<8, gi>>56] per 128-bit half
//   - XOR with the fold-carrying absorb13Block template to form the fill
//     block, store to the frame
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
// with the key folded in, and every cascade round folds the component
// pair and the key-folded block into the state with one VPTERNLOGQ per
// group.
//
// Register allocation:
//   Z0–Z3      states, group j = lanes (4j, 4j+1, 4j+2, 4j+3)
//   Z4–Z6      RC[0], RC[1], RC[2] broadcasts (Z6 holds the
//              groupIdxBase broadcast during the prologue)
//   Z7         absorb13Block broadcast (prologue only)
//   Z8–Z11     fill blocks, group j = lanes (4j .. 4j+3)
//   Z12, Z15   scratch for per-lane groupIdx synthesis
//   Z13        key broadcast (prologue only, folded into Z8–Z11)
//   Z14        component pair, broadcast per cascade round
//   Z16        interlock-nonce fold v << 8 broadcast (prologue only)
//
// Per-group synthesis:
//   - Load laneIdxZ[group] to add offsets [0,1,2,3] to groupIdxBase
//   - VPADDQ to form [base+0, base+1, base+2, base+3]
//   - VPSRLQ/VPSLLQ, OR of the fold into the gi>>56 word, VPUNPCKLQDQ to
//     transform into [gi<<8, gi>>56 | v<<8] per lane
//   - XOR with absorb13Block to form the fill block
"""


def x16_comment_neon(tier_desc):
    return f"""// {tier_desc}
// 16-lane fused ChainHash cascade kernel for AES-ITB-128 at the 13-byte
// per-lane fill shape. See aesitbasm_fused.go for the construction; the
// kernel is pinned to the pure-Go reference (scalarFusedX16) by the
// in-package parity tests.
""" + X16_CASCADE_NOTE + """// Block layout per lane: [0x03 | LE64(groupIdxBase+i) | LE32(v) | 3×0x03]
// (domain tag, 8-byte index, interlock-nonce fold, 3 PKCS#7 padding
// bytes); the fold is ORed into the pad-tail GPR once per call.
//
// Batch layout: two batches of 8 lanes, each register-resident — V0..V7
// states, V8..V15 blocks (the key folded in once per batch), V16 / V17 /
// V21 RC[0] / RC[1] / RC[2], V18 key, V19 component pair (per round).
// Each batch runs the whole cascade before the next starts. Issue order
// inside a round is round-major: every step (the component pair fold,
// each of the three AESE+AESMC rounds, the final RC[2] XOR) runs across
// all 8 lanes before the next step
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
    the absorb13Block template (which carries the 0x03 domain tag and the
    PKCS#7 tail, and into which v << 8 is XORed once) and staged to the
    frame. Each batch then runs the full cascade from
    the staged blocks. The legacy-SSE tier reloads each block through a
    register (PXOR m128 would require 16-byte alignment the Go frame does
    not guarantee)."""
    tier = "Vex" if vex else "AesNi"
    mov = "VMOVDQU" if vex else "MOVOU"
    L = [f"// func aesITB128FusedChain13x16{tier}Asm({X16_SIG})",
         f"TEXT ·aesITB128FusedChain13x16{tier}Asm(SB), NOSPLIT, $256-44",
         "\tMOVQ key+0(FP), AX", "\tMOVQ out+32(FP), DI", "\tMOVQ groupIdxBase+24(FP), R8", "",
         "\t// Template X12 = absorb13Block with the interlock-nonce fold (v << 8) in its second qword",
         f"\t{mov} ·absorb13Block(SB), X12", "\tMOVL v+40(FP), R9", "\tSHLQ $8, R9"]
    if vex:
        L += ["\tVMOVQ R9, X15", "\tVPSLLDQ $8, X15, X15", "\tVPXOR X15, X12, X12"]
    else:
        L += ["\tMOVQ R9, X15", "\tPSLLDQ $8, X15", "\tPXOR X15, X12"]
    L += ["", "\t// Stage the 16 fill blocks into the frame at 16*lane(SP)", ""]
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
          f"\t{mov} ·RC+32(SB), X11", f"\t{mov} 0(AX), X13", ""]
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
            for rc in ("X9", "X10", "X11"):
                L.append("\t" + "; ".join(f"VAESENC {rc}, X{l}, X{l}" for l in range(8)))
        else:
            L += ["\tMOVOU 0(BX), X14", "\tPXOR X13, X14"]
            for l in range(8):
                L.append(f"\tPXOR X14, X{l}")
            for l in range(8):
                L.append(f"\tMOVOU {16 * (8 * b + l)}(SP), X15")
                L.append(f"\tPXOR X15, X{l}")
            for rc in ("X9", "X10", "X11"):
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
    the fold-carrying absorb13Block template and stored to the frame as
    one 32-byte block pair."""
    L = [f"// func aesITB128FusedChain13x16VaesAvx2Asm({X16_SIG})",
         "TEXT ·aesITB128FusedChain13x16VaesAvx2Asm(SB), NOSPLIT, $256-44",
         "\tMOVQ key+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ out+32(FP), DI", "\tMOVQ groupIdxBase+24(FP), R8", "",
         "\t// Template Y10 = absorb13Block with the interlock-nonce fold (v << 8) in each second qword",
         "\tVBROADCASTI128 ·absorb13Block(SB), Y10",
         "\tMOVL v+40(FP), R9", "\tSHLQ $8, R9", "\tVMOVQ R9, X15", "\tVPSLLDQ $8, X15, X15",
         "\tVINSERTI128 $1, X15, Y15, Y15", "\tVPXOR Y15, Y10, Y10", "",
         "\t// Stage the 8 block pairs into the frame at 32*pair(SP)", ""]
    for p in range(8):
        L.append(f"\t// ========== Pair {p}: lanes {2 * p}–{2 * p + 1} ==========")
        L.append("\tMOVQ R8, R9" if p == 0 else f"\tLEAQ {2 * p}(R8), R9")
        L += ["\tVMOVQ R9, X11", f"\tLEAQ {2 * p + 1}(R8), R9", "\tVMOVQ R9, X15",
              "\tVINSERTI128 $1, X15, Y11, Y11", "\tVPSRLQ $56, Y11, Y15", "\tVPSLLQ $8, Y11, Y11",
              "\tVPUNPCKLQDQ Y15, Y11, Y11", "\tVPXOR Y10, Y11, Y11", f"\tVMOVDQU Y11, {32 * p}(SP)", ""]
    L += ["\t// Load round constants and key",
          "\tVBROADCASTI128 ·RC+0(SB), Y8", "\tVBROADCASTI128 ·RC+16(SB), Y9",
          "\tVBROADCASTI128 ·RC+32(SB), Y10", "\tVBROADCASTI128 0(AX), Y13"]
    for i in range(8):
        L.append(f"\tVPXOR Y{i}, Y{i}, Y{i}")
    L += ["", "loop:", "\tVBROADCASTI128 0(BX), Y14", "\tVPXOR Y13, Y14, Y14"]
    for i in range(8):
        L.append(f"\tVPXOR Y14, Y{i}, Y{i}")
    for i in range(8):
        L.append(f"\tVPXOR {32 * i}(SP), Y{i}, Y{i}")
    L.append("\t// AES rounds: 3 rounds on all 8 YMM pairs (RC[0], RC[1], RC[2])")
    for rc in ("Y8", "Y9", "Y10"):
        L.append("\t" + "; ".join(f"VAESENC {rc}, Y{i}, Y{i}" for i in range(8)))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\t// Store outputs: pair i at [32i..32i+32]"]
    for i in range(8):
        L.append(f"\tVMOVDQU Y{i}, {32 * i}(DI)")
    L += ["", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def x16_zmm():
    """Four ZMM states of four lanes; groupIdxBase and the fold v << 8 are
    broadcast once and each group adds its laneIdxZ offset row and ORs
    the fold into its idx >> 56 word, so the whole synthesis is vector
    arithmetic. Blocks stay in Z8..Z11 with the
    key folded in once, and every cascade round is one VPTERNLOGQ (the
    component pair and the key-folded block) plus three VAESENC per
    group."""
    L = [f"// func aesITB128FusedChain13x16Avx512Asm({X16_SIG})",
         "TEXT ·aesITB128FusedChain13x16Avx512Asm(SB), NOSPLIT, $0-44",
         "\tMOVQ key+0(FP), AX", "\tMOVQ comps+8(FP), BX", "\tMOVQ nPairs+16(FP), CX",
         "\tMOVQ out+32(FP), DI", "",
         "\t// Broadcast groupIdxBase to Z6 (all 8 qwords), absorb13Block to Z7 and the",
         "\t// interlock-nonce fold v << 8 to Z16",
         "\tVPBROADCASTQ groupIdxBase+24(FP), Z6", "\tVBROADCASTI32X4 ·absorb13Block(SB), Z7",
         "\tMOVL v+40(FP), R9", "\tSHLQ $8, R9", "\tVPBROADCASTQ R9, Z16", ""]
    for g in range(4):
        L += [f"\t// ========== Group {g}: lanes {4 * g}–{4 * g + 3} ==========",
              f"\tVPADDQ ·laneIdxZ+{64 * g}(SB), Z6, Z12", "\tVPSRLQ $56, Z12, Z15", "\tVPORQ Z16, Z15, Z15",
              "\tVPSLLQ $8, Z12, Z12", "\tVPUNPCKLQDQ Z15, Z12, Z12", f"\tVPXORD Z7, Z12, Z{8 + g}", ""]
    L += ["\t// Load round constants and key",
          "\tVBROADCASTI32X4 ·RC+0(SB), Z4", "\tVBROADCASTI32X4 ·RC+16(SB), Z5",
          "\tVBROADCASTI32X4 ·RC+32(SB), Z6", "\tVBROADCASTI32X4 0(AX), Z13",
          "\t// Fold the key into the fill blocks once"]
    for j in range(4):
        L.append(f"\tVPXORD Z13, Z{8 + j}, Z{8 + j}")
    for j in range(4):
        L.append(f"\tVPXORD Z{j}, Z{j}, Z{j}")
    L += ["", "loop:", "\tVBROADCASTI32X4 0(BX), Z14"]
    for j in range(4):
        L.append(f"\tVPTERNLOGQ $0x96, Z14, Z{8 + j}, Z{j}     // Z{j} ^= Z{8 + j} ^ Z14")
    L.append("\t// AES rounds: 3 rounds on all 4 ZMM groups (RC[0], RC[1], RC[2])")
    for rc in ("Z4", "Z5", "Z6"):
        L.append("\t" + "; ".join(f"VAESENC {rc}, Z{j}, Z{j}" for j in range(4)))
    L += ["\tADDQ $16, BX", "\tDECQ CX", "\tJNZ loop", "", "\t// Store outputs: group j at [64j..64j+64]"]
    for j in range(4):
        L.append(f"\tVMOVDQU64 Z{j}, {64 * j}(DI)")
    L += ["", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


def x16_neon():
    """Two batches of eight lanes, register-resident; the block is assembled
    in GPRs (D[0] = idx<<8 | 0x03, D[1] = idx>>56 | v<<8 | pad tail), absorbs the
    key once and is the first AESE key operand of every cascade round.
    Issue order is round-major within a batch."""
    L = [f"// func aesITB128FusedChain13x16NeonAsm({X16_SIG})",
         "TEXT ·aesITB128FusedChain13x16NeonAsm(SB), NOSPLIT, $0-44",
         "\tMOVD key+0(FP), R0", "\tMOVD comps+8(FP), R1", "\tMOVD nPairs+16(FP), R2",
         "\tMOVD groupIdxBase+24(FP), R3", "\tMOVD out+32(FP), R4", "",
         "\t// Load key (V18) and round constants RC[0] (V16), RC[1] (V17), RC[2] (V21)",
         "\tVLD1 (R0), [V18.B16]",
         "\tMOVD $·RC(SB), R5", "\tVLD1.P 16(R5), [V16.B16]  // RC[0]", "\tVLD1.P 16(R5), [V17.B16]  // RC[1]",
         "\tVLD1 (R5), [V21.B16]      // RC[2]", "",
         "\t// Materialized constant for the block's second qword: pad tail bytes 13-15 = 0x03",
         "\t// with the interlock-nonce fold v in bytes 9-12 (v << 8)",
         "\tMOVD $0x0303030000000000, R7", "\tMOVWU v+40(FP), R12", "\tORR R12<<8, R7, R7", ""]
    for b in range(2):
        L += [f"\t// ========== BATCH {b + 1}: lanes {8 * b}–{8 * b + 7} ==========",
              "\t// Step 1 — synthesise the 8 fill blocks in V8..V15:",
              "\t// [0x03 | LE64(groupIdxBase+i) | LE32(v) | 3×0x03] as",
              "\t// D[0] = (idx << 8) | 0x03, D[1] = (idx >> 56) | (v << 8) | pad tail."]
        for l in range(8):
            lane = 8 * b + l
            L.append("\tMOVD R3, R6" if lane == 0 else f"\tADD ${lane}, R3, R6")
            L += ["\tLSL $8, R6, R8", "\tORR $3, R8, R8", "\tLSR $56, R6, R9", "\tORR R7, R9, R9",
                  f"\tVMOV R8, V{8 + l}.D[0]", f"\tVMOV R9, V{8 + l}.D[1]"]
        L.append("\t// Fold the key into the 8 fill blocks once.")
        for l in range(8):
            L.append(f"\tVEOR V18.B16, V{8 + l}.B16, V{8 + l}.B16")
        L += ["", "\t// Step 2 — zero the 8 states, reset the component cursor and pair count."]
        for l in range(8):
            L.append(f"\tVEOR V{l}.B16, V{l}.B16, V{l}.B16")
        L += ["\tMOVD R1, R10", "\tMOVD R2, R11", "", f"loop{b}:",
              "\t// Fold the component pair (V19) into every state, then the",
              "\t// key-folded block as the first AESE key operand, the RC[0] and",
              "\t// RC[1] rounds and the final RC[2] XOR.",
              "\tVLD1.P 16(R10), [V19.B16]"]
        for l in range(8):
            L.append(f"\tVEOR V19.B16, V{l}.B16, V{l}.B16")
        for l in range(8):
            L += [f"\tAESE V{8 + l}.B16, V{l}.B16", f"\tAESMC V{l}.B16, V{l}.B16"]
        for k in ("V16", "V17"):
            for l in range(8):
                L += [f"\tAESE {k}.B16, V{l}.B16", f"\tAESMC V{l}.B16, V{l}.B16"]
        for l in range(8):
            L.append(f"\tVEOR V21.B16, V{l}.B16, V{l}.B16")
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
        files[f"aesitb_fusedchain128_{s}x8_vaesavx2_amd64.s"] = (
            header(s, 8, "VAES YMM (two lanes per register, four state groups)", amd, "ymm8") + "\n" + ymm_fused_x8(s))
        files[f"aesitb_fusedchain128_{s}x8_vex_amd64.s"] = (
            header(s, 8, "VEX-encoded AES-NI XMM (eight state chains)", amd, "xmm") + "\n" + xmm_fused_x8(s, True))
        files[f"aesitb_fusedchain128_{s}x8_aesni_amd64.s"] = (
            header(s, 8, "Legacy-SSE AES-NI XMM (eight state chains)", amd, "xmm") + "\n" + xmm_fused_x8(s, False))
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
