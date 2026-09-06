#!/usr/bin/env python3
"""Generator slot for the AES-ITB-128 16-lane chain-absorb kernels of
internal/aesitbasm (aesitb_chain128_13x16_{aesni,vex,vaesavx2,avx512}_amd64.s
and aesitb_chain128_13x16_neon_arm64.s).

The five batch-16 kernels are hand-written; this script holds the shared
header template and the shape constants so the emitters can be added
without re-deriving them, but it emits no kernel body. Running it exits
with an error before touching any file, so the committed kernels cannot
be overwritten by an incomplete template. Byte-identity between a future
emitter and the committed kernels is the acceptance gate for bringing a
tier under generation (the same diff-clean check gen_kernels.py and
gen_fused_kernels.py pass today).

Kernel contract (all tiers): the function receives groupIdxBase in a GPR
and synthesises the 16 per-lane fill blocks in-register —
[0x03 | LE64(groupIdxBase+i) | 4×0x00 | 3×0x03] for lane i — so the
batch-16 path pays no per-lane pointer gather. Parity with scalarBatchX16
(internal/aesitbasm/aesitbasm.go) is enforced by the in-package parity
tests.
"""
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "internal", "aesitbasm")
SHAPE = 13

# Tier -> (descriptive header line, build constraint, output file name).
TIERS = {
    "aesni": ("Legacy-SSE AES-NI XMM (AESENC xmm, xmm)", "amd64 && !purego && !noitbasm",
              "aesitb_chain128_13x16_aesni_amd64.s"),
    "vex": ("VEX-encoded AES-NI XMM (VAESENC xmm, xmm, xmm)", "amd64 && !purego && !noitbasm",
            "aesitb_chain128_13x16_vex_amd64.s"),
    "vaesavx2": ("VAES YMM, two lanes per register", "amd64 && !purego && !noitbasm",
                 "aesitb_chain128_13x16_vaesavx2_amd64.s"),
    "avx512": ("VAES ZMM, four lanes per register", "amd64 && !purego && !noitbasm",
               "aesitb_chain128_13x16_avx512_amd64.s"),
    "neon": ("ARM64 NEON crypto-extension (AESE + AESMC)", "arm64 && !purego && !noitbasm",
             "aesitb_chain128_13x16_neon_arm64.s"),
}


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


# Body emitters, keyed like TIERS. Empty until a tier's emitter reproduces
# the committed kernel byte-for-byte; main() refuses to write while any
# requested tier has no emitter.
EMITTERS = {}


def main(argv):
    requested = argv[1:] or sorted(TIERS)
    unknown = [t for t in requested if t not in TIERS]
    if unknown:
        raise SystemExit(f"gen_kernels_x16.py: unknown tier(s) {unknown}; known: {sorted(TIERS)}")
    missing = [t for t in requested if t not in EMITTERS]
    if missing:
        raise SystemExit(
            "gen_kernels_x16.py: no emitter for tier(s) "
            f"{missing}; the x16 kernels are hand-written and this generator "
            "writes nothing until an emitter reproduces the committed kernel "
            "byte-for-byte"
        )
    for tier in requested:
        desc, build, name = TIERS[tier]
        content = header(desc, build) + "\n" + EMITTERS[tier]()
        path = os.path.join(OUT, name)
        with open(path, "w") as f:
            f.write(content)
        print("wrote", path)


if __name__ == "__main__":
    main(sys.argv)
