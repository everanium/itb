#!/usr/bin/env python3
"""Emit the AES-ITB-128 4-lane chain-absorb kernels for internal/aesitbasm.

One file per (shape, tier). Shapes 13/20/36/68; tiers aesni (legacy SSE
XMM), vex (VEX-encoded XMM), vaesavx2 (VAES YMM, two lanes per register),
avx512 (VAES ZMM, four lanes per register), neon (ARM64 crypto extension).

Load shapes on amd64 are matched to the stores the Go call sites leave in
flight so store-to-load forwarding succeeds: the seeds array arrives as a
by-value copy (four 16-byte stores) and is read as four 16-byte loads on
every tier; block 0 of the multi-block shapes follows a 4-byte pixel-index
store at offset 0 and is read as two 4-byte inserts plus an 8-byte insert;
the output is written as four 16-byte stores on every tier, the width the
Go side reads it back with. The 13-byte fill block is read as an 8-, a 4-
and a 1-byte insert.

Usage:
    gen_kernels.py [--check]

Without flags every kernel is written into internal/aesitbasm/; --check
regenerates in memory and compares against the committed files without
writing (exit status 1 on any drift).
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "internal", "aesitbasm")
SHAPES = [13, 20, 36, 68]


def blocks(n):
    return (n + 16) // 16  # PKCS#7: always at least one pad byte


def header(shape, tier_desc, build):
    nb = blocks(shape)
    return f"""//go:build {build}

// {tier_desc} 4-lane chain-absorb kernel for AES-ITB-128 at the
// {shape}-byte per-lane shape ({nb} PKCS#7 block{'s' if nb > 1 else ''}, {nb + 2} AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference by the in-package parity tests. The tail block is
// read with exact-width inserts — no byte past the {shape}-byte input is
// touched.{"" if build.startswith("arm64") else chr(10) + "// Every load is sized to the store the Go call site leaves in flight" + chr(10) + "// (seeds copy, pixel-index write) so it forwards from the store buffer" + chr(10) + "// instead of waiting for the store to commit, and the output is written" + chr(10) + "// as four 16-byte stores, the width the Go side reads it back with."}

#include "textflag.h"
"""


# ---------------------------------------------------------------- amd64 XMM

def xmm_kernel(shape, vex):
    nb = blocks(shape)
    tier = "Vex" if vex else "AesNi"
    L = []
    if vex:
        mov, xor, aesenc = "VMOVDQU", "VPXOR", "VAESENC"
        def XOR(src, st): return f"\t{xor} {src}, {st}, {st}"
        def ROUND(rc): return "\t" + "; ".join(f"{aesenc} {rc}, X{l}, X{l}" for l in range(4))
    else:
        mov, xor, aesenc = "MOVOU", "PXOR", "AESENC"
        def XOR(src, st): return f"\t{xor} {src}, {st}"
        def ROUND(rc): return "\t" + "; ".join(f"{aesenc} {rc}, X{l}" for l in range(4))
    rc = lambda i: f"X{5 + (i % 8)}"
    L.append(f"// func aesITB128ChainAbsorb{shape}x4{tier}Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)")
    L.append(f"TEXT ·aesITB128ChainAbsorb{shape}x4{tier}Asm(SB), NOSPLIT, $0-32")
    L += ["\tMOVQ key+0(FP), AX", "\tMOVQ seeds+8(FP), BX", "\tMOVQ dataPtrs+16(FP), CX", "\tMOVQ out+24(FP), DX",
          "\tMOVQ 0(CX), R8", "\tMOVQ 8(CX), R9", "\tMOVQ 16(CX), R10", "\tMOVQ 24(CX), R11", ""]
    L.append(f"\t{mov} 0(AX), X13")
    for l in range(4):
        L.append(f"\t{mov} {16 * l}(BX), X{l}")
    for l in range(4):
        L.append(XOR("X13", f"X{l}"))
    L.append("")
    for i in range(8):
        L.append(f"\t{mov} ·RC+{16 * i}(SB), X{5 + i}")
    L.append("")
    regs = ["R8", "R9", "R10", "R11"]
    pad = "pad13Tail" if shape == 13 else "pad4Tail"
    L.append(f"\t{mov} ·{pad}(SB), X13")
    for b in range(nb):
        off = 16 * b
        if b == 0 and nb > 1:
            for l in range(4):
                r = regs[l]
                if vex:
                    L.append(f"\tVPINSRD $0, 0({r}), X13, X4")
                    L.append(f"\tVPINSRD $1, 4({r}), X4, X4")
                    L.append(f"\tVPINSRQ $1, 8({r}), X4, X4")
                else:
                    L.append(f"\t{mov} X13, X4")
                    L.append(f"\tPINSRD $0, 0({r}), X4")
                    L.append(f"\tPINSRD $1, 4({r}), X4")
                    L.append(f"\tPINSRQ $1, 8({r}), X4")
                L.append(XOR("X4", f"X{l}"))
        elif b < nb - 1:
            for l in range(4):
                L.append(f"\t{mov} {off}({regs[l]}), X4")
                L.append(XOR("X4", f"X{l}"))
        else:
            for l in range(4):
                r = regs[l]
                if shape == 13:
                    if vex:
                        L.append(f"\tVPINSRQ $0, {off}({r}), X13, X4")
                        L.append(f"\tVPINSRD $2, {off + 8}({r}), X4, X4")
                        L.append(f"\tVPINSRB $12, {off + 12}({r}), X4, X4")
                    else:
                        L.append(f"\t{mov} X13, X4")
                        L.append(f"\tPINSRQ $0, {off}({r}), X4")
                        L.append(f"\tPINSRD $2, {off + 8}({r}), X4")
                        L.append(f"\tPINSRB $12, {off + 12}({r}), X4")
                else:
                    if vex:
                        L.append(f"\tVPINSRD $0, {off}({r}), X13, X4")
                    else:
                        L.append(f"\t{mov} X13, X4")
                        L.append(f"\tPINSRD $0, {off}({r}), X4")
                L.append(XOR("X4", f"X{l}"))
        L.append(ROUND(rc(b)))
        L.append("")
    L.append(ROUND(rc(0)))
    L.append(ROUND(rc(1)))
    L.append("")
    for l in range(4):
        L.append(f"\t{mov} X{l}, {16 * l}(DX)")
    L.append("\tRET")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- amd64 YMM

def ymm_kernel(shape):
    nb = blocks(shape)
    L = []
    rc = lambda i: f"Y{3 + (i % 8)}"
    L.append(f"// func aesITB128ChainAbsorb{shape}x4VaesAvx2Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)")
    L.append(f"TEXT ·aesITB128ChainAbsorb{shape}x4VaesAvx2Asm(SB), NOSPLIT, $0-32")
    L += ["\tMOVQ key+0(FP), AX", "\tMOVQ seeds+8(FP), BX", "\tMOVQ dataPtrs+16(FP), CX", "\tMOVQ out+24(FP), DX",
          "\tMOVQ 0(CX), R8", "\tMOVQ 8(CX), R9", "\tMOVQ 16(CX), R10", "\tMOVQ 24(CX), R11", ""]
    L += ["\tVBROADCASTI128 0(AX), Y2",
          "\tVMOVDQU 0(BX), X0", "\tVINSERTI128 $1, 16(BX), Y0, Y0",
          "\tVMOVDQU 32(BX), X1", "\tVINSERTI128 $1, 48(BX), Y1, Y1",
          "\tVPXOR Y2, Y0, Y0", "\tVPXOR Y2, Y1, Y1", ""]
    for i in range(8):
        L.append(f"\tVBROADCASTI128 ·RC+{16 * i}(SB), Y{3 + i}")
    L.append("")
    pad = "pad13Tail" if shape == 13 else "pad4Tail"
    L.append(f"\tVBROADCASTI128 ·{pad}(SB), Y11")
    pairs = [("R8", "R9", "Y0", "Y12", "X12", "X14"), ("R10", "R11", "Y1", "Y13", "X13", "X15")]
    for b in range(nb):
        off = 16 * b
        if b == 0 and nb > 1:
            for ra, rb, st, yt, xt, xs in pairs:
                for r, x in ((ra, xt), (rb, xs)):
                    L.append(f"\tVPINSRD $0, 0({r}), X11, {x}")
                    L.append(f"\tVPINSRD $1, 4({r}), {x}, {x}")
                    L.append(f"\tVPINSRQ $1, 8({r}), {x}, {x}")
                L.append(f"\tVINSERTI128 $1, {xs}, {yt}, {yt}")
                L.append(f"\tVPXOR {yt}, {st}, {st}")
        elif b < nb - 1:
            for ra, rb, st, yt, xt, _ in pairs:
                L.append(f"\tVMOVDQU {off}({ra}), {xt}")
                L.append(f"\tVINSERTI128 $1, {off}({rb}), {yt}, {yt}")
                L.append(f"\tVPXOR {yt}, {st}, {st}")
        else:
            for ra, rb, st, yt, xt, xs in pairs:
                for r, x in ((ra, xt), (rb, xs)):
                    if shape == 13:
                        L.append(f"\tVPINSRQ $0, {off}({r}), X11, {x}")
                        L.append(f"\tVPINSRD $2, {off + 8}({r}), {x}, {x}")
                        L.append(f"\tVPINSRB $12, {off + 12}({r}), {x}, {x}")
                    else:
                        L.append(f"\tVPINSRD $0, {off}({r}), X11, {x}")
                L.append(f"\tVINSERTI128 $1, {xs}, {yt}, {yt}")
                L.append(f"\tVPXOR {yt}, {st}, {st}")
        L.append(f"\tVAESENC {rc(b)}, Y0, Y0; VAESENC {rc(b)}, Y1, Y1")
        L.append("")
    L.append(f"\tVAESENC {rc(0)}, Y0, Y0; VAESENC {rc(0)}, Y1, Y1")
    L.append(f"\tVAESENC {rc(1)}, Y0, Y0; VAESENC {rc(1)}, Y1, Y1")
    L += ["", "\tVMOVDQU X0, 0(DX)", "\tVEXTRACTI128 $1, Y0, 16(DX)",
          "\tVMOVDQU X1, 32(DX)", "\tVEXTRACTI128 $1, Y1, 48(DX)", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- amd64 ZMM

def zmm_kernel(shape):
    nb = blocks(shape)
    L = []
    rc = lambda i: f"Z{2 + (i % 8)}"
    L.append(f"// func aesITB128ChainAbsorb{shape}x4Avx512Asm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)")
    L.append(f"TEXT ·aesITB128ChainAbsorb{shape}x4Avx512Asm(SB), NOSPLIT, $0-32")
    L += ["\tMOVQ key+0(FP), AX", "\tMOVQ seeds+8(FP), BX", "\tMOVQ dataPtrs+16(FP), CX", "\tMOVQ out+24(FP), DX",
          "\tMOVQ 0(CX), R8", "\tMOVQ 8(CX), R9", "\tMOVQ 16(CX), R10", "\tMOVQ 24(CX), R11", ""]
    L += ["\tVBROADCASTI32X4 0(AX), Z1",
          "\tVMOVDQU 0(BX), X0", "\tVINSERTI64X2 $1, 16(BX), Z0, Z0",
          "\tVINSERTI64X2 $2, 32(BX), Z0, Z0", "\tVINSERTI64X2 $3, 48(BX), Z0, Z0",
          "\tVPXORD Z1, Z0, Z0", ""]
    for i in range(8):
        L.append(f"\tVBROADCASTI32X4 ·RC+{16 * i}(SB), Z{2 + i}")
    L.append("")
    regs = ["R8", "R9", "R10", "R11"]
    pad = "pad13Tail" if shape == 13 else "pad4Tail"
    L.append(f"\tVBROADCASTI32X4 ·{pad}(SB), Z10")
    xs = ["X11", "X12", "X13", "X14"]
    for b in range(nb):
        off = 16 * b
        if b == 0 and nb > 1:
            for l in range(4):
                r, x = regs[l], xs[l]
                L.append(f"\tVPINSRD $0, 0({r}), X10, {x}")
                L.append(f"\tVPINSRD $1, 4({r}), {x}, {x}")
                L.append(f"\tVPINSRQ $1, 8({r}), {x}, {x}")
            for l in range(1, 4):
                L.append(f"\tVINSERTI64X2 ${l}, {xs[l]}, Z11, Z11")
            L.append("\tVPXORD Z11, Z0, Z0")
        elif b < nb - 1:
            L.append(f"\tVMOVDQU {off}(R8), X11")
            for l in range(1, 4):
                L.append(f"\tVINSERTI64X2 ${l}, {off}({regs[l]}), Z11, Z11")
            L.append("\tVPXORD Z11, Z0, Z0")
        else:
            for l in range(4):
                r, x = regs[l], xs[l]
                if shape == 13:
                    L.append(f"\tVPINSRQ $0, {off}({r}), X10, {x}")
                    L.append(f"\tVPINSRD $2, {off + 8}({r}), {x}, {x}")
                    L.append(f"\tVPINSRB $12, {off + 12}({r}), {x}, {x}")
                else:
                    L.append(f"\tVPINSRD $0, {off}({r}), X10, {x}")
            for l in range(1, 4):
                L.append(f"\tVINSERTI64X2 ${l}, {xs[l]}, Z11, Z11")
            L.append("\tVPXORD Z11, Z0, Z0")
        L.append(f"\tVAESENC {rc(b)}, Z0, Z0")
        L.append("")
    L.append(f"\tVAESENC {rc(0)}, Z0, Z0")
    L.append(f"\tVAESENC {rc(1)}, Z0, Z0")
    L += ["", "\tVMOVDQU X0, 0(DX)", "\tVEXTRACTI64X2 $1, Z0, 16(DX)",
          "\tVEXTRACTI64X2 $2, Z0, 32(DX)", "\tVEXTRACTI64X2 $3, Z0, 48(DX)", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- arm64 NEON

def neon_kernel(shape):
    nb = blocks(shape)
    L = []
    rc = lambda i: f"V{16 + (i % 8)}"
    regs = ["R8", "R9", "R10", "R11"]
    kop = ["V8", "V9", "V10", "V11"]
    L.append(f"// func aesITB128ChainAbsorb{shape}x4NeonAsm(key *[16]byte, seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)")
    L.append(f"TEXT ·aesITB128ChainAbsorb{shape}x4NeonAsm(SB), NOSPLIT, $0-32")
    L += ["\tMOVD key+0(FP), R0", "\tMOVD seeds+8(FP), R1", "\tMOVD dataPtrs+16(FP), R2", "\tMOVD out+24(FP), R3",
          "\tMOVD 0(R2), R8", "\tMOVD 8(R2), R9", "\tMOVD 16(R2), R10", "\tMOVD 24(R2), R11", ""]
    L += ["\tVLD1 (R1), [V0.B16, V1.B16, V2.B16, V3.B16]", "\tVLD1 (R0), [V4.B16]"]
    for l in range(4):
        L.append(f"\tVEOR V4.B16, V{l}.B16, V{l}.B16")
    L += ["\tMOVD $·RC(SB), R4",
          "\tVLD1.P 64(R4), [V16.B16, V17.B16, V18.B16, V19.B16]",
          "\tVLD1 (R4), [V20.B16, V21.B16, V22.B16, V23.B16]", ""]
    for b in range(nb):
        if b < nb - 1:
            for l in range(4):
                L.append(f"\tVLD1.P 16({regs[l]}), [{kop[l]}.B16]")
        else:
            pad = "pad13Tail" if shape == 13 else "pad4Tail"
            L.append(f"\tMOVD $·{pad}(SB), R4")
            L.append("\tVLD1 (R4), [V5.B16]")
            for l in range(4):
                r, k = regs[l], kop[l]
                L.append(f"\tVMOV V5.B16, {k}.B16")
                if shape == 13:
                    L.append(f"\tMOVD ({r}), R12")
                    L.append(f"\tVMOV R12, {k}.D[0]")
                    L.append(f"\tMOVWU 8({r}), R12")
                    L.append(f"\tVMOV R12, {k}.S[2]")
                    L.append(f"\tMOVBU 12({r}), R12")
                    L.append(f"\tVMOV R12, {k}.B[12]")
                else:
                    L.append(f"\tMOVWU ({r}), R12")
                    L.append(f"\tVMOV R12, {k}.S[0]")
        if b > 0:
            for l in range(4):
                L.append(f"\tVEOR {rc(b - 1)}.B16, {kop[l]}.B16, {kop[l]}.B16")
        for l in range(4):
            L.append(f"\tAESE {kop[l]}.B16, V{l}.B16")
        for l in range(4):
            L.append(f"\tAESMC V{l}.B16, V{l}.B16")
        L.append("")
    # finalisers: AESE(RC[last]) AESMC ; AESE(RC0) AESMC ; XOR RC1
    for l in range(4):
        L.append(f"\tAESE {rc(nb - 1)}.B16, V{l}.B16")
    for l in range(4):
        L.append(f"\tAESMC V{l}.B16, V{l}.B16")
    for l in range(4):
        L.append(f"\tAESE {rc(0)}.B16, V{l}.B16")
    for l in range(4):
        L.append(f"\tAESMC V{l}.B16, V{l}.B16")
    for l in range(4):
        L.append(f"\tVEOR {rc(1)}.B16, V{l}.B16, V{l}.B16")
    L += ["", "\tVST1 [V0.B16, V1.B16, V2.B16, V3.B16], (R3)", "\tRET"]
    return "\n".join(L) + "\n"


def render_all():
    amd = "amd64 && !purego && !noitbasm"
    arm = "arm64 && !purego && !noitbasm"
    files = {}
    for s in SHAPES:
        files.update({
            f"aesitb_chain128_{s}_aesni_amd64.s": header(s, "Legacy-SSE AES-NI XMM (AESENC xmm, xmm)", amd) + "\n" + xmm_kernel(s, False),
            f"aesitb_chain128_{s}_vex_amd64.s": header(s, "VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm; needs AES-NI + AVX)", amd) + "\n" + xmm_kernel(s, True),
            f"aesitb_chain128_{s}_vaesavx2_amd64.s": header(s, "VAES YMM, two lanes per register (needs VAES + AVX2)", amd) + "\n" + ymm_kernel(s),
            f"aesitb_chain128_{s}_avx512_amd64.s": header(s, "VAES ZMM, four lanes per register (needs VAES + AVX-512)", amd) + "\n" + zmm_kernel(s),
            f"aesitb_chain128_{s}_neon_arm64.s": header(s, "ARM64 NEON crypto-extension (AESE + AESMC, round constant folded into the next AESE key operand)", arm) + "\n" + neon_kernel(s),
        })
    return files


def main(argv):
    check = "--check" in argv[1:]
    unknown = [a for a in argv[1:] if a != "--check"]
    if unknown:
        raise SystemExit(f"gen_kernels.py: unknown argument(s) {unknown}; known: --check")
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
        raise SystemExit(f"gen_kernels.py: {drift} file(s) differ from the generator output")


if __name__ == "__main__":
    main(sys.argv)
