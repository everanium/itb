package itb

// FusedChainHashFunc128 evaluates the whole [Seed128.ChainHash128]
// cascade in one call: the primitive is applied once per component pair
// with the previous round's (lo, hi) folded into the next pair, exactly
// as the sequential loop does, but with the state kept inside the
// primitive's kernel between rounds.
//
// ok reports whether the implementation handled data; when false the
// caller runs the sequential loop and lo / hi are meaningless. When true
// the result must be bit-exact with the sequential loop over the same
// components and data. Implementations decide by input shape only, so a
// given (components, data) pair is answered the same way on every call.
type FusedChainHashFunc128 func(components []uint64, data []byte) (lo, hi uint64, ok bool)

// BatchFusedChainHashFunc128 is the four-lane counterpart of
// [FusedChainHashFunc128]: every lane runs the cascade over the shared
// components with its own data, matching [Seed128.BatchChainHash128].
type BatchFusedChainHashFunc128 func(components []uint64, data *[4][]byte) (out [4][2]uint64, ok bool)

// InterlockFillFunc16 is the batch-16 Interlocked Barrier fill kernel
// interface at width 128. Every lockSeed fills its rank pairs with the
// whole ChainHash cascade over components — the prepended slice
// [lockLo, lockHi, c[0], c[1], …] the fill builder assembles from the
// nonce-derived pair and the seed's Components — and the hook, when
// attached (hashes.AttachInterlockBatch16), evaluates that cascade for
// 16 consecutive groups in one kernel call: groupIdxBase is the first
// group index and lane offset i (0..15) produces groupIdx =
// groupIdxBase + i on the fill block [0x03 | LE64(groupIdx) | 4×0x00];
// out receives the 16 × 128-bit rank pairs at [0..15]. The result must
// be bit-exact with sixteen sequential single-lane cascades over the
// same components and blocks. A performance hook only: the cascade
// fill is the wire with or without it.
type InterlockFillFunc16 func(components []uint64, groupIdxBase uint64, out *[16][2]uint64)
