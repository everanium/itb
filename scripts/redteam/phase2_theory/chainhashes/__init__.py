"""Pluggable ChainHash implementations for the raw-mode bias audit toolkit.

Each module in this package exports:

  * `N_SEED_COMPONENTS` — number of uint64 seed components ITB feeds the
    ChainHash wrapper at the primitive's native width × 8 rounds at
    1024-bit key (canonically 16 for 128-bit primitives, 16 for 256-bit
    primitives laid out as 4 uint64 × 4 rounds, etc — always 16 at the
    shipped 1024-bit key size regardless of hash width).
  * `chainhash_lo(data: bytes, seed_components: Sequence[int]) -> int` —
    returns the low 64 bits of the ChainHash output that ITB's encoding
    observes (i.e., `h[0]` from Seed{128,256,512}.ChainHash{...}).
  * Optional `init_from_meta(meta: dict) -> None` — called once by the
    audit driver with `cell.meta.json` contents before any `chainhash_lo`
    call. Implementations that depend on extra per-cell parameters
    (e.g. BLAKE3 templated key) read those values here.
  * Optional `compute_expected_K(meta: dict, nonce: bytes) -> int` — for
    laboratory validation only, returns the compound key K that the raw-
    mode solver should recover on this cell. Only sensible for
    GF(2)-linear primitives where K is well-defined; PRF-grade modules
    omit this.

Loaded at runtime by the driver via `importlib`; no ITB code imports
this package directly.
"""
