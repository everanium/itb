"""Shared constants for the red-team test suite.

Single source of truth for hash variants and plaintext kinds. All analyzer
scripts (phase1 / phase2 / phase3) import from here so that corpus changes
only need to be made in one place.

Hash directory names are filesystem-safe lowercase identifiers matching those
written by redteam_test.go (buildHashSpecs → dirname field).

Display names match BENCH.md.
"""

# Ordered list of (dirname, display_name, width_bits).
HASHES = [
    ("fnv1a",     "FNV-1a",         128),
    ("md5",       "MD5",            128),
    ("aescmac",   "AES-CMAC",       128),
    ("siphash24", "SipHash-2-4",    128),
    ("chacha20",  "ChaCha20",       256),
    ("areion256", "AreionSoEM256",  256),
    ("blake2s",   "BLAKE2s",        256),
    ("blake3",    "BLAKE3",         256),
    ("blake2b",   "BLAKE2b-512",    512),
    ("areion512", "AreionSoEM512",  512),
]

HASH_DIRNAMES = [h[0] for h in HASHES]
HASH_DISPLAY = {h[0]: h[1] for h in HASHES}
HASH_WIDTH = {h[0]: h[2] for h in HASHES}

# Plaintext kinds produced by redteam_test.go (kindSpec.name).
KINDS = [
    "http", "json", "text_small", "text_large",
    "http_large", "json_large",
    "text_huge", "json_huge", "html_huge",
    "html_giant",
]

# Giant (~1 MB) samples exist only for tight finite-sample KL estimation in
# Phase 2b. Phase 2c (startPixel enumeration) is O(container_pixels²) per
# sample — on a ~4.8M-pixel container that would be infeasible, so this list
# omits html_giant.
KINDS_NO_GIANT = [k for k in KINDS if k != "html_giant"]

# Container layout constants (consistent with ITB headerSize + 8-channel pixels).
HEADER_SIZE = 20              # 16 nonce + 2 W + 2 H
CHANNELS = 8                  # RGBWYOPA
DATA_BITS_PER_CHANNEL = 7
DATA_BITS_PER_PIXEL = 56
NONCE_SIZE = 16
