#!/usr/bin/env python3
"""Emit the AES-ITB-128 16-lane chain-absorb kernels for internal/aesitbasm
(aesitb_chain128_13x16_{aesni,vex,vaesavx2,avx512}_amd64.s and
aesitb_chain128_13x16_neon_arm64.s). Companion of gen_kernels.py (4-lane
per-round kernels) and gen_fused_kernels.py (fused cascade kernels).

One file per tier at the 13-byte shape (the Interlocked Barrier PRF fill).
Tiers: aesni (legacy-SSE XMM, two batches of eight lanes), vex (VEX-encoded
XMM, same batching), vaesavx2 (VAES YMM, eight registers of two lanes),
avx512 (VAES ZMM, four registers of four lanes), neon (ARM64 crypto
extension, sixteen registers, round-major issue order).

Kernel contract (all tiers): the function receives groupIdxBase in a GPR
and synthesises the 16 per-lane fill blocks in-register —
[0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03] for lane i — so the
batch-16 path pays no per-lane pointer gather. Every tier folds the shared
template key XOR (seed0 || seed1) XOR absorb13Block (or, on NEON, the key
XOR seed pair as the first AESE operand) into the synthesised block, then
runs the three AES rounds (absorb, finaliser RC[0], finaliser RC[1]).
Parity with scalarBatchX16 (internal/aesitbasm/aesitbasm.go) is enforced
by the in-package parity tests.

Usage:
    gen_kernels_x16.py [--check | --stdout] [tier ...]

With no flags the requested tiers (default: all) are written into
internal/aesitbasm/. --check regenerates in memory and compares against
the committed files without writing (exit status 1 on any drift); --stdout
prints the generated text instead of writing. The generator is
deterministic and carries no numeric tables of its own: round constants,
the absorb block and the ZMM lane-offset table are read from the Go side
(·RC, ·absorb13Block, ·laneIdxZ).
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "internal", "aesitbasm")
SHAPE = 13

# Tier -> (descriptive header line, build constraint, output file name).
TIERS = {
    "aesni": ("Legacy-SSE AES-NI XMM (AESENC xmm, xmm)", "amd64 && !purego && !noitbasm",
              "aesitb_chain128_13x16_aesni_amd64.s"),
    "vex": ("VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm; needs AES-NI + AVX)", "amd64 && !purego && !noitbasm",
            "aesitb_chain128_13x16_vex_amd64.s"),
    "vaesavx2": ("VAES YMM, two lanes per 256-bit register (needs VAES + AVX2)", "amd64 && !purego && !noitbasm",
                 "aesitb_chain128_13x16_vaesavx2_amd64.s"),
    "avx512": ("VAES ZMM, four lanes per register (needs VAES + AVX-512)", "amd64 && !purego && !noitbasm",
               "aesitb_chain128_13x16_avx512_amd64.s"),
    "neon": ("ARM64 NEON crypto-extension (AESE + AESMC, round constant folded into the next AESE key operand)",
             "arm64 && !purego && !noitbasm",
             "aesitb_chain128_13x16_neon_arm64.s"),
}

SIG = "key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64"


def blocks(n):
    return (n + 16) // 16  # PKCS#7: always at least one pad byte


def shape_note():
    nb = blocks(SHAPE)
    return f"({nb} PKCS#7 block, {nb + 2} AES rounds per lane)"


# Per-tier header comment (between the build line and the textflag include).
# The XMM tiers share the gather-free note; the wide tiers add their register
# plan and synthesis recipe; NEON documents its block layout and issue order.

UNIQUE_NOTE = """//
// Unique to the batch-16 kernel: groupIdx is synthesized in-register from
// groupIdxBase per lane, avoiding the per-lane pointer gather overhead of the x4 path.
"""


def comment_xmm(tier_desc, vex):
    s = f"""// {tier_desc} 16-lane chain-absorb kernel for AES-ITB-128 at the
// {SHAPE}-byte per-lane shape {shape_note()}.
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
""" + UNIQUE_NOTE
    if vex:
        s += """//
// Batch layout: two batches of 8 lanes each. Per lane: state initialized with
// key XOR seed pair, block loaded as [0x03 | LE64(groupIdx) | pad_tail],
// then 3 AES rounds (1 absorb + 2 finaliser) with RC[0], RC[0], RC[1].
"""
    return s


def comment_ymm(tier_desc):
    return f"""// {tier_desc} 16-lane chain-absorb kernel
// for AES-ITB-128 at the {SHAPE}-byte per-lane shape {shape_note()}.
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
//
// Batch layout: 8 YMM states, two lanes per YMM (lanes 2i and 2i+1 in Y[i]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// VPUNPCKLQDQ, avoiding per-lane pointer gather overhead of the x4 path.
//
// Register allocation:
//   Y0–Y7      states, pair i = lanes (2i, 2i+1)
//   Y8–Y9      RC[0], RC[1] broadcasts
//   Y10        template (key XOR seeds XOR absorb13Block)
//   Y11–Y14    scratch for per-lane groupIdx synthesis
//   Y15        free
//
// Per-pair synthesis (no index vector):
//   - Calculate groupIdx for both lanes (2i and 2i+1)
//   - Load into X11 (lane 2i) and X14 (lane 2i+1)
//   - VINSERTI128 to form YMM with [gi_even | gi_odd]
//   - VPUNPCKLQDQ to transform [gi, 0] into [gi<<8, gi>>56] per 128-bit half
//   - XOR with template to form initial state
"""


def comment_zmm(tier_desc):
    return f"""// {tier_desc} 16-lane chain-absorb kernel
// for AES-ITB-128 at the {SHAPE}-byte per-lane shape {shape_note()}.
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
//
// Batch layout: 4 ZMM states, four lanes per ZMM (lanes 4j..4j+3 in Z[j]).
// Unique to batch-16: groupIdx synthesized in-register per lane via
// per-group VPADDQ (applying laneIdxZ offsets) and VPUNPCKLQDQ.
//
// Register allocation:
//   Z0–Z3      states, group j = lanes (4j, 4j+1, 4j+2, 4j+3)
//   Z4–Z5      RC[0], RC[1] broadcasts
//   Z6–Z8      scratch for template and per-lane groupIdx synthesis
//   Z9–Z15     free
//
// Per-group synthesis:
//   - Load laneIdxZ[group] to add offsets [0,1,2,3] to groupIdxBase
//   - VPADDQ to form [base+0, base+1, base+2, base+3]
//   - VPSRLQ/VPSLLQ/VPUNPCKLQDQ to transform into [gi<<8, gi>>56] per lane
"""


def comment_neon(tier_desc):
    return f"""// {tier_desc}
// 16-lane chain-absorb kernel for AES-ITB-128 at the {SHAPE}-byte per-lane shape.
// See the package comment for the construction; the kernel is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
""" + UNIQUE_NOTE + """// Block layout per lane: [0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03]
// (domain tag, 8-byte index, 4 zero bytes, 3 PKCS#7 padding bytes).
//
// Issue order is round-major: every step (block synthesis, each of the
// three AESE+AESMC rounds, the final RC[1] XOR, the stores) runs across
// all 16 lanes before the next step starts, so the 16 independent
// chains in V0..V15 keep both crypto pipes busy instead of serialising
// each lane's 3-round dependency chain behind the previous lane's.
"""


COMMENTS = {
    "aesni": lambda desc: comment_xmm(desc, False),
    "vex": lambda desc: comment_xmm(desc, True),
    "vaesavx2": comment_ymm,
    "avx512": comment_zmm,
    "neon": comment_neon,
}


def header(tier):
    desc, build, _ = TIERS[tier]
    return f"//go:build {build}\n\n" + COMMENTS[tier](desc) + "\n#include \"textflag.h\"\n"


# ---------------------------------------------------------------- amd64 XMM

def xmm_kernel(vex):
    """Two batches of eight lanes; per lane the block is built from the
    groupIdx GPR as [idx<<8 | idx>>56] via shift + PUNPCKLQDQ and XORed with
    the template (key XOR seeds XOR absorb13Block, which carries the 0x03
    domain tag and the PKCS#7 tail)."""
    tier = "Vex" if vex else "AesNi"
    mov = "VMOVDQU" if vex else "MOVOU"
    L = [f"// func aesITB128ChainAbsorb13x16{tier}Asm({SIG})",
         f"TEXT ·aesITB128ChainAbsorb13x16{tier}Asm(SB), NOSPLIT, $0-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ out+32(FP), DI", "\tMOVQ groupIdxBase+24(FP), R8", "",
         "\t// Load key and seed pair, compute template"]
    if vex:
        L += ["\tVMOVDQU 0(AX), X13", "\tVMOVQ seed0+8(FP), X14", "\tVPINSRQ $1, seed1+16(FP), X14, X14",
              "\tVPXOR X13, X14, X14", "\tVPXOR ·absorb13Block(SB), X14, X14"]
    else:
        L += ["\tMOVOU 0(AX), X13", "\tMOVQ seed0+8(FP), X14", "\tPINSRQ $1, seed1+16(FP), X14",
              "\tPXOR X13, X14", "\tPXOR ·absorb13Block(SB), X14"]
    L += ["", "\t// Load round constants", f"\t{mov} ·RC+0(SB), X9", f"\t{mov} ·RC+16(SB), X10", ""]
    if not vex:
        L += ["\t// Process 16 lanes, 8 per batch to stay within register limits",
              "\t// Reuse registers: X0-X7 for state, X15 for scratch", ""]
    for b in range(2):
        L += [f"\t// ========== BATCH {b + 1}: lanes {8 * b}–{8 * b + 7} ==========", ""]
        for l in range(8):
            lane = 8 * b + l
            L.append(f"\t// Lane {lane}: idx = base" + (f" + {lane}" if lane else ""))
            L.append("\tMOVQ R8, R9")
            if lane:
                L.append(f"\tADDQ ${lane}, R9")
            if vex:
                L += [f"\tVMOVQ R9, X{l}", "\tVMOVQ R9, X15", f"\tVPSLLQ $8, X{l}, X{l}", "\tVPSRLQ $56, X15, X15",
                      f"\tVPUNPCKLQDQ X15, X{l}, X{l}", f"\tVPXOR X14, X{l}, X{l}"]
            else:
                L += [f"\tMOVQ R9, X{l}", "\tMOVQ R9, X15", f"\tPSLLQ $8, X{l}", "\tPSRLQ $56, X15",
                      f"\tPUNPCKLQDQ X15, X{l}", f"\tPXOR X14, X{l}"]
            L.append("")
        L.append(f"\t// AES rounds for batch {b + 1}" + (" (3 rounds × 8 lanes)" if b == 0 else ""))
        for rc in ("X9", "X9", "X10"):
            if vex:
                L.append("\t" + "; ".join(f"VAESENC {rc}, X{l}, X{l}" for l in range(8)))
            else:
                L.append("\t" + "; ".join(f"AESENC {rc}, X{l}" for l in range(8)))
        L += ["", f"\t// Store batch {b + 1} outputs"]
        for l in range(8):
            L.append(f"\t{mov} X{l}, {16 * (8 * b + l)}(DI)")
        L.append("")
    L.append("\tRET")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- amd64 YMM

def ymm_kernel():
    """Eight YMM states of two lanes; each pair's two groupIdx values are
    materialised via LEAQ, moved into the two 128-bit halves, and turned
    into [idx<<8 | idx>>56] with one shift pair and VPUNPCKLQDQ."""
    L = [f"// func aesITB128ChainAbsorb13x16VaesAvx2Asm({SIG})",
         "TEXT ·aesITB128ChainAbsorb13x16VaesAvx2Asm(SB), NOSPLIT, $0-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ out+32(FP), DI", "\tMOVQ groupIdxBase+24(FP), R8", "",
         "\t// Load key and seed pair, compute template",
         "\tVMOVQ seed0+8(FP), X10", "\tVPINSRQ $1, seed1+16(FP), X10, X10", "\tVPXOR 0(AX), X10, X10",
         "\tVPXOR ·absorb13Block(SB), X10, X10", "\tVINSERTI128 $1, X10, Y10, Y10", "",
         "\t// Load round constants", "\tVBROADCASTI128 ·RC+0(SB), Y8", "\tVBROADCASTI128 ·RC+16(SB), Y9", ""]
    for p in range(8):
        L.append(f"\t// ========== Pair {p}: lanes {2 * p}–{2 * p + 1} ==========")
        L.append("\tMOVQ R8, R9" if p == 0 else f"\tLEAQ {2 * p}(R8), R9")
        L += ["\tVMOVQ R9, X11", f"\tLEAQ {2 * p + 1}(R8), R9", "\tVMOVQ R9, X14",
              "\tVINSERTI128 $1, X14, Y11, Y11", "\tVPSRLQ $56, Y11, Y14", "\tVPSLLQ $8, Y11, Y11",
              "\tVPUNPCKLQDQ Y14, Y11, Y11", f"\tVPXOR Y10, Y11, Y{p}", ""]
    L.append("\t// AES rounds: 3 rounds on all 8 YMM pairs (RC[0], RC[0], RC[1])")
    for rc in ("Y8", "Y8", "Y9"):
        L.append("\t" + "; ".join(f"VAESENC {rc}, Y{i}, Y{i}" for i in range(8)))
    L += ["", "\t// Store outputs: pair i at [32i..32i+32]"]
    for i in range(8):
        L.append(f"\tVMOVDQU Y{i}, {32 * i}(DI)")
    L += ["", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- amd64 ZMM

def zmm_kernel():
    """Four ZMM states of four lanes; groupIdxBase is broadcast once and each
    group adds its laneIdxZ offset row, so the whole synthesis is vector
    arithmetic (no GPR-to-vector moves)."""
    L = [f"// func aesITB128ChainAbsorb13x16VaesAvx512Asm({SIG})",
         "TEXT ·aesITB128ChainAbsorb13x16VaesAvx512Asm(SB), NOSPLIT, $0-40",
         "\tMOVQ key+0(FP), AX", "\tMOVQ out+32(FP), DI", "",
         "\t// Broadcast groupIdxBase to Z6 (all 8 qwords)", "\tVPBROADCASTQ groupIdxBase+24(FP), Z6", "",
         "\t// Load template: seed0 and seed1, compute XOR with key and absorb13Block",
         "\tVPBROADCASTQ seed0+8(FP), Z7", "\tVPBROADCASTQ seed1+16(FP), Z8",
         "\tVPUNPCKLQDQ Z8, Z7, Z7           // Per lane: [seed0, seed1]",
         "\tVBROADCASTI32X4 0(AX), Z8        // Key broadcast to all 4 lanes per ZMM",
         "\tVBROADCASTI32X4 ·absorb13Block(SB), Z9",
         "\tVPTERNLOGQ $0x96, Z9, Z8, Z7     // Z7 ^= Z8 ^ Z9 (template = key XOR seeds XOR absorb13Block)", "",
         "\t// Load round constants", "\tVBROADCASTI32X4 ·RC+0(SB), Z4", "\tVBROADCASTI32X4 ·RC+16(SB), Z5", ""]
    for g in range(4):
        L += [f"\t// ========== Group {g}: lanes {4 * g}–{4 * g + 3} ==========",
              f"\tVPADDQ ·laneIdxZ+{64 * g}(SB), Z6, Z8", "\tVPSRLQ $56, Z8, Z9", "\tVPSLLQ $8, Z8, Z8",
              "\tVPUNPCKLQDQ Z9, Z8, Z8", f"\tVPXORD Z7, Z8, Z{g}", ""]
    L.append("\t// AES rounds: 3 rounds on all 4 ZMM pairs (RC[0], RC[0], RC[1])")
    for rc in ("Z4", "Z4", "Z5"):
        L.append("\t" + "; ".join(f"VAESENC {rc}, Z{j}, Z{j}" for j in range(4)))
    L += ["", "\t// Store outputs: group j at [64j..64j+64]"]
    for j in range(4):
        L.append(f"\tVMOVDQU64 Z{j}, {64 * j}(DI)")
    L += ["", "\tVZEROUPPER", "\tRET"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- arm64 NEON

def neon_kernel():
    """Sixteen V registers, one lane each; the block is assembled in GPRs
    (D[0] = idx<<8 | 0x03, D[1] = idx>>56 | pad tail) and the key XOR seed
    template is the first AESE key operand. Issue order is round-major."""
    L = [f"// func aesITB128ChainAbsorb13x16NeonAsm({SIG})",
         "TEXT ·aesITB128ChainAbsorb13x16NeonAsm(SB), NOSPLIT, $0-40",
         "\tMOVD key+0(FP), R0", "\tMOVD seed0+8(FP), R1", "\tMOVD seed1+16(FP), R2",
         "\tMOVD groupIdxBase+24(FP), R3", "\tMOVD out+32(FP), R4", "",
         "\t// Load key and compute shared template: key ^ seed pair",
         "\tVLD1 (R0), [V30.B16]", "\tVMOV R1, V27.D[0]", "\tVMOV R2, V27.D[1]",
         "\tVEOR V30.B16, V27.B16, V30.B16    // V30 = key ^ seed0 ^ seed1", "",
         "\t// Load round constants: RC[0] into V31, RC[1] into V29",
         "\tMOVD $·RC(SB), R5", "\tVLD1.P 16(R5), [V31.B16]  // RC[0]", "\tVLD1 (R5), [V29.B16]      // RC[1]", "",
         "\t// Materialized constant for pad tail: bytes 13-15 = 0x03", "\tMOVD $0x0303030000000000, R7", "",
         "\t// Step 1 — synthesise the 16 fill blocks in V0..V15:",
         "\t// [0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03] as",
         "\t// D[0] = (idx << 8) | 0x03, D[1] = (idx >> 56) | pad tail."]
    for i in range(16):
        L.append("\tMOVD R3, R6" if i == 0 else f"\tADD ${i}, R3, R6")
        L += ["\tLSL $8, R6, R8", "\tORR $3, R8, R8", "\tLSR $56, R6, R9", "\tORR R7, R9, R9",
              f"\tVMOV R8, V{i}.D[0]", f"\tVMOV R9, V{i}.D[1]", ""]
    L += ["\t// Step 2 — round 1 on all 16 lanes: AESE folds key ^ seeds",
          "\t// (V30) into the block, AESMC completes the round."]
    for i in range(16):
        L += [f"\tAESE V30.B16, V{i}.B16", f"\tAESMC V{i}.B16, V{i}.B16"]
    for step, rnd in ((3, 2), (4, 3)):
        L += ["", f"\t// Step {step} — round {rnd} on all 16 lanes (RC[0] in V31)."]
        for i in range(16):
            L += [f"\tAESE V31.B16, V{i}.B16", f"\tAESMC V{i}.B16, V{i}.B16"]
    L += ["", "\t// Step 5 — final AddRoundKey with RC[1] (V29) on all 16 lanes."]
    for i in range(16):
        L.append(f"\tVEOR V29.B16, V{i}.B16, V{i}.B16")
    L += ["", "\t// Step 6 — store the 16 rank pairs in lane order."]
    for i in range(16):
        L.append(f"\tVST1.P [V{i}.B16], 16(R4)")
    L += ["", "\tRET"]
    return "\n".join(L) + "\n"


# Body emitters, keyed like TIERS.
EMITTERS = {
    "aesni": lambda: xmm_kernel(False),
    "vex": lambda: xmm_kernel(True),
    "vaesavx2": ymm_kernel,
    "avx512": zmm_kernel,
    "neon": neon_kernel,
}


def render(tier):
    return header(tier) + "\n" + EMITTERS[tier]()


def main(argv):
    flags = [a for a in argv[1:] if a.startswith("--")]
    requested = [a for a in argv[1:] if not a.startswith("--")] or sorted(TIERS)
    unknown_flags = [f for f in flags if f not in ("--check", "--stdout")]
    if unknown_flags:
        raise SystemExit(f"gen_kernels_x16.py: unknown flag(s) {unknown_flags}; known: --check, --stdout")
    unknown = [t for t in requested if t not in TIERS]
    if unknown:
        raise SystemExit(f"gen_kernels_x16.py: unknown tier(s) {unknown}; known: {sorted(TIERS)}")
    drift = 0
    for tier in requested:
        content = render(tier)
        path = os.path.join(OUT, TIERS[tier][2])
        if "--stdout" in flags:
            sys.stdout.write(content)
        elif "--check" in flags:
            with open(path, "rb") as f:
                committed = f.read()
            if committed == content.encode("utf-8"):
                print("clean", path)
            else:
                print("DRIFT", path)
                drift += 1
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            print("wrote", path)
    if drift:
        raise SystemExit(f"gen_kernels_x16.py: {drift} file(s) differ from the generator output")


if __name__ == "__main__":
    main(sys.argv)
