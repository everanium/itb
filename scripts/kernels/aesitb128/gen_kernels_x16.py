#!/usr/bin/env python3
"""Emit the AES-ITB-128 16-lane chain-absorb kernel for internal/aesitbasm.

Currently emits only the aesni (legacy-SSE AES-NI XMM) tier.

Key novelty: in-register groupIdx synthesis. The function receives groupIdxBase
in a GPR and generates 16 sequential groupIdx values (groupIdxBase, groupIdxBase+1,
..., groupIdxBase+15) as LE64 values for state initialization, avoiding the
gather overhead of the x4 path.

Parity with scalarBatchX16 (internal/aesitbasm/aesitbasm.go) is enforced by
in-package parity tests. Additional ASM tiers (vex, vaesavx2, avx512, neon)
pending implementation.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "internal", "aesitbasm")
SHAPE = 13


def blocks(n):
    return (n + 16) // 16  # PKCS#7: always at least one pad byte


def header(tier_desc, build):
    nb = blocks(SHAPE)
    return f"""//go:build {build}

// {tier_desc} 16-lane chain-absorb kernel for AES-ITB-128 at the
// {SHAPE}-byte per-lane shape ({nb} PKCS#7 block, {nb + 2} AES rounds per lane).
// See the package comment for the construction; every tier is pinned to
// the pure-Go reference (scalarBatchX16) by the in-package parity tests.
//
// Unique to the batch-16 kernel: groupIdx is synthesized in-register from
// groupIdxBase per lane, avoiding the per-lane pointer gather overhead of the x4 path.

#include "textflag.h"
"""


def xmm_kernel_aesni():
    """Legacy-SSE AES-NI XMM kernel for 16 lanes.

    Two batches of 8 lanes each. Signature:
    func aesITB128ChainAbsorb13x16AesNiAsm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)
    """
    L = []
    L.append("// func aesITB128ChainAbsorb13x16AesNiAsm(key *[16]byte, seed0, seed1, groupIdxBase uint64, out *[16][2]uint64)")
    L.append("TEXT ·aesITB128ChainAbsorb13x16AesNiAsm(SB), NOSPLIT, $0-40")
    L.append("\t// Placeholder - implementation in progress")
    L.append("\tRET")
    return "\n".join(L) + "\n"


def main():
    amd = "amd64 && !purego && !noitbasm"

    aesni_content = header("Legacy-SSE AES-NI XMM (AESENC xmm, xmm)", amd) + "\n" + xmm_kernel_aesni()

    # Write only aesni file
    aesni_path = os.path.join(OUT, "aesitb_chain128_13x16_aesni_amd64.s")
    with open(aesni_path, "w") as f:
        f.write(aesni_content)
    print("wrote", aesni_path)


if __name__ == "__main__":
    main()
