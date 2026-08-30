#!/usr/bin/env python3
"""Malicious SHA-1: SHA-1 core parameterised on the four 32-bit round
constants.

Source:
    Ange Albertini, Jean-Philippe Aumasson, Maria Eichlseder,
    Florian Mendel, Martin Schläffer -
    «Malicious Hashing: Eve's Variant of SHA-1»
    SAC 2014, LNCS 8781. IACR ePrint 2014/694.
    https://eprint.iacr.org/2014/694

The SHA-1 compression function is a clean-room transcription of RFC 3174;
the four round constants K[0..3] are exposed as a parameter so a caller
can plug in either the standard `SHA1_K_STANDARD` set or the malicious
Eichlseder set `SHA1_K_MALICIOUS_EVE` under which the paper's PoC
colliding shell scripts (`~/scratch/malicious_sha1/pocs/sh/eve{1,2}.sh`)
share the digest `96ED59BE 04518A27 C30F17DE 6F0037F9 B3C3257E`.

Standard SHA-1 IV is fixed (RFC 3174). The primitive is unkeyed; the
ChainHash-style keying is layered in `sha1_chainhash.py` via an
input-XOR keying pattern that mirrors `hashes/blake3.go`
`BLAKE3WithKey`.

Lab-only. Not for deployment.
"""

# RFC 3174 fixed IV, common to standard and malicious SHA-1 variants.
SHA1_IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

# Standard SHA-1 round constants (RFC 3174 §5).
SHA1_K_STANDARD = (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)

# Malicious SHA-1 «Eve» round constants (Albertini et al, SAC 2014).
# 96 of 128 bits differ from standard SHA-1 (K[0] is preserved). This
# specific set is the one under which the paper's `eve1.sh` / `eve2.sh`
# proof-of-concept shell scripts share a digest.
# Attribution: `pocs/sh/README` in the paper's PoC bundle.
SHA1_K_MALICIOUS_EVE = (0x5A827999, 0x88E8EA68, 0x578059DE, 0x54324A39)


def _rotl32(w: int, n: int) -> int:
    return ((w << n) | (w >> (32 - n))) & 0xFFFFFFFF


def sha1_core(message: bytes,
              iv=SHA1_IV,
              k=SHA1_K_MALICIOUS_EVE) -> bytes:
    """Compute the 160-bit SHA-1 digest of `message` with the given IV
    and round-constant tuple.

    RFC 3174 padding: append `0x80`, zero-pad to length congruent 56 mod
    64, then a big-endian 64-bit message length in bits.
    """
    length_bits = (len(message) * 8).to_bytes(8, "big")
    pad_zeros = (56 - len(message) - 1) % 64
    padded = message + b"\x80" + b"\x00" * pad_zeros + length_bits

    h0, h1, h2, h3, h4 = iv

    for block_start in range(0, len(padded), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = int.from_bytes(padded[block_start + 4 * j:block_start + 4 * (j + 1)], "big")
        for j in range(16, 80):
            w[j] = _rotl32(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)

        a, b, c, d, e = h0, h1, h2, h3, h4
        for j in range(80):
            if j < 20:
                f = d ^ (b & (c ^ d))
                kj = k[0]
            elif j < 40:
                f = b ^ c ^ d
                kj = k[1]
            elif j < 60:
                f = (b & c) | (b & d) | (c & d)
                kj = k[2]
            else:
                f = b ^ c ^ d
                kj = k[3]
            a, b, c, d, e = (_rotl32(a, 5) + f + e + kj + w[j]) & 0xFFFFFFFF, a, _rotl32(b, 30), c, d

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return b"".join(x.to_bytes(4, "big") for x in (h0, h1, h2, h3, h4))
