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

// InterlockFillFunc16 is the batch-16 interlock PRF fill kernel interface.
// One call fills 16 consecutive chunks' rank pairs in one invocation.
// groupIdxBase is the first group index (0..numGroups-1); lane offset i
// (0..15) produces groupIdx = groupIdxBase + i. seed0, seed1 are the
// interlock lock seed pair (derived once per session). out receives
// 16 × 128-bit rank pairs at [0..15].
type InterlockFillFunc16 func(groupIdxBase uint64, seed0, seed1 uint64, out *[16][2]uint64)
