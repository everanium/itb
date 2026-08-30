#!/usr/bin/env python3
"""Reference colliding message pair for Malicious-SHA-1 «Eve».

Attribution:
    Ange Albertini, Jean-Philippe Aumasson, Maria Eichlseder,
    Florian Mendel, Martin Schläffer -
    «Malicious Hashing: Eve's Variant of SHA-1»
    SAC 2014, LNCS 8781. IACR ePrint 2014/694.
    Colliding pair `pocs/sh/eve{1,2}.sh` (Maria Eichlseder,
    Malicious SHA-1 project — malicioussha1.github.io/pocs/pocs.zip).

The two 243-byte shell scripts share the same SHA-1 digest under the
Malicious-SHA-1 round constants `SHA1_K_MALICIOUS_EVE`:

    96ED59BE 04518A27 C30F17DE 6F0037F9 B3C3257E

Differing byte positions span index 3..63 (28 of 243 bytes differ);
the differential is entirely inside the first 512-bit SHA-1 block. Six
of the differing positions lie within [0, 15] — the range that
`sha1_chainhash.wrap_r1` XORs the seed material into — so the probe
tests whether the collision survives the input-XOR modification (the
seed-XOR preserves the byte-level XOR differential but changes the
absolute prefix values; SHA-1's nonlinear compression makes the
collision brittle to absolute-value changes).

Public test vector; embedded verbatim as bytes literals so the
experiment reproduces without requiring the PoC bundle to be present
on disk.
"""

EVE1_SH = bytes.fromhex(
    "231d1b91344009d8104da6d354e1102bb885125b477826bdfd372beee650082c"
    "754b16573811bfd8a5e0b2441a94512acd36a204fee28a9f325599aab47aed82"
    "0a0a6966205b20606f64202d74207831202d6a33202d4e31202d416e2022247b"
    "307d2260202d65712022393122205d3b207468656e200a20206563686f202220"
    "2020202020202020285f5f295c6e202020202020202020286f6f295c6e20202f"
    "2d2d2d2d2d2d2d5c5c2f5c6e202f207c20202020207c7c5c6e2a20207c7c2d2d"
    "2d2d7c7c5c6e2020205e5e202020205e5e223b0a656c73650a20206563686f20"
    "2248656c6c6f20576f726c642e223b0a66690a"
)

EVE2_SH = bytes.fromhex(
    "231d1b92144009ac984da6d3bce11049708512186f7826b9bd372bacae50086a"
    "fd4b16553811bfccade0b246ba94517e4536a2067ee28a9f9a5599a91c7aede2"
    "0a0a6966205b20606f64202d74207831202d6a33202d4e31202d416e2022247b"
    "307d2260202d65712022393122205d3b207468656e200a20206563686f202220"
    "2020202020202020285f5f295c6e202020202020202020286f6f295c6e20202f"
    "2d2d2d2d2d2d2d5c5c2f5c6e202f207c20202020207c7c5c6e2a20207c7c2d2d"
    "2d2d7c7c5c6e2020205e5e202020205e5e223b0a656c73650a20206563686f20"
    "2248656c6c6f20576f726c642e223b0a66690a"
)

# Expected raw digest under SHA1_K_MALICIOUS_EVE + SHA1_IV.
EXPECTED_COLLIDING_DIGEST = bytes.fromhex(
    "96ed59be04518a27c30f17de6f0037f9b3c3257e"
)

assert len(EVE1_SH) == 243
assert len(EVE2_SH) == 243
assert EVE1_SH != EVE2_SH
assert len(EXPECTED_COLLIDING_DIGEST) == 20
