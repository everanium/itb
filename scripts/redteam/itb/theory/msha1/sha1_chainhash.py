#!/usr/bin/env python3
"""ChainHash-style wrap of Malicious-SHA-1, mirroring ITB's production
input-XOR keying and feedforward pattern.

Production references (single source of truth for the wrap shape):

  * `hashes/blake3.go` `BLAKE3WithKey` — per-call keying: 32-byte seed
    material XORed into the FIRST 32 bytes of the caller's `data`
    (zero-padded if `data` is shorter), then the primitive is called
    once on the mixed buffer.

  * `seed128.go` `ChainHash128` — feedforward: `(hLo, hHi) = Hash(buf,
    Components[i] ^ hLo, Components[i+1] ^ hHi)` iterated across all
    seed component pairs. At every round the primitive receives the
    same `buf` and a KEY derived from the previous output XORed into
    the next component pair.

The 128-bit variant of ITB uses 16-byte (2 uint64) seed lanes per
Hash call; matching that, `wrap_r1` XORs 16 bytes of key material into
the first 16 bytes of the caller's data before hashing. `wrap_r`
extends this to R rounds by iterating and injecting the previous
output back into the next round's key (feedforward).

The primitive-side keying (BLAKE3's `template = NewKeyed(fixed_key)`)
has no SHA-1 analogue — SHA-1 has no native keyed mode. The
standard SHA-1 IV is used unchanged; input-XOR keying alone provides
the domain-separation the ChainHash construction relies on.

Lab-only. Not for deployment.
"""

from sha1_malicious import sha1_core, SHA1_K_MALICIOUS_EVE


def _xor_prefix(data: bytes, key16: bytes) -> bytes:
    """Mirror of `hashes/blake3.go` `BLAKE3WithKey` input-mix step: XOR
    `key16` into the first 16 bytes of `data` (zero-padding `data` up
    to 16 bytes if it is shorter). The rest of `data` is preserved.
    """
    if len(key16) != 16:
        raise ValueError(f"key16 must be exactly 16 bytes, got {len(key16)}")
    payload_len = max(len(data), 16)
    mixed = bytearray(payload_len)
    mixed[:len(data)] = data
    for i in range(16):
        mixed[i] ^= key16[i]
    return bytes(mixed)


def wrap_r1(key16: bytes, data: bytes, k=SHA1_K_MALICIOUS_EVE) -> bytes:
    """Single-round ChainHash-style wrap: XOR `key16` into first 16 bytes
    of `data`, then hash the mixed buffer. Reduces to `sha1_core(data)`
    when `key16 == b'\\x00' * 16` — invariant test used to distinguish
    real absorbance from wrap-side artefacts.
    """
    return sha1_core(_xor_prefix(data, key16), k=k)


def wrap_r(key_list: list, data: bytes, rounds: int, k=SHA1_K_MALICIOUS_EVE) -> bytes:
    """R-round ChainHash feedforward.

    key_list : list of >= R keys of 16 bytes each (the widened ChainHash
               seed component pairs in the 128-bit variant).
    rounds   : number of ChainHash rounds (>= 1).

    Round 1:  h_1 = wrap_r1(key_list[0], data)
    Round k>=2: h_k = wrap_r1(key_list[k-1] XOR extend16(h_{k-1}), data)

    Returns the final round's 160-bit digest (as 20 bytes). The
    feedforward `key_list[k-1] XOR extend16(h_{k-1})` mirrors ChainHash128's
    `Components[i] ^ hLo` pattern; `extend16` truncates the 160-bit
    digest to its first 16 bytes (matching the 128-bit Seed128 lane
    width). ChainHash128 has one round per component pair; here `rounds`
    controls the depth for the absorption sweep.
    """
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    if len(key_list) < rounds:
        raise ValueError(f"key_list must contain >= {rounds} keys, got {len(key_list)}")
    for i, key in enumerate(key_list[:rounds]):
        if len(key) != 16:
            raise ValueError(f"key_list[{i}] must be 16 bytes, got {len(key)}")

    h = None
    for round_idx in range(rounds):
        if round_idx == 0:
            eff_key = key_list[0]
        else:
            eff_key = bytes(kb ^ hb for kb, hb in zip(key_list[round_idx], h[:16]))
        h = wrap_r1(eff_key, data, k=k)
    return h
