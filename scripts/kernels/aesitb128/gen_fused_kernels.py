#!/usr/bin/env python3
"""Emit the AES-ITB-128 fused ChainHash cascade kernels for internal/aesitbasm.

One file per (shape, lanes, tier). Shapes 13/20/36/68; lanes x4 (four data
lanes over one shared component slice) and x1 (single lane); amd64 tiers
aesni / vex / vaesavx2 / avx512 for x4, aesni / vex for x1; arm64 tier neon
for both. Companion of gen_kernels.py (per-round chain-absorb kernels).

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
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "internal", "aesitbasm")
SHAPES = [13, 20, 36, 68]


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


def render_all():
    amd = "amd64 && !purego && !noitbasm"
    arm = "arm64 && !purego && !noitbasm"
    files = {}
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
