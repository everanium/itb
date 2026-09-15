package itb

// FusedChainHashFunc512 evaluates the whole [Seed512.ChainHash512]
// cascade in one call: the primitive is applied once per component
// octuple with the previous round's output folded into the next
// octuple, exactly as the sequential loop does, but with the state kept
// inside the primitive's kernel between rounds.
//
// ok reports whether the implementation handled data; when false the
// caller runs the sequential loop and out is meaningless. When true the
// result must be bit-exact with the sequential loop over the same
// components and data. Implementations decide by input shape only, so a
// given (components, data) pair is answered the same way on every call.
type FusedChainHashFunc512 func(components []uint64, data []byte) (out [8]uint64, ok bool)

// BatchFusedChainHashFunc512 is the four-lane counterpart of
// [FusedChainHashFunc512]: every lane runs the cascade over the shared
// components with its own data, matching [Seed512.BatchChainHash512].
type BatchFusedChainHashFunc512 func(components []uint64, data *[4][]byte) (out [4][8]uint64, ok bool)

// InterlockFillFunc16x512 is the batch-16 Interlocked Barrier fill
// kernel interface at width 512 — the counterpart of
// [InterlockFillFunc16]. One call fills the 4 consecutive groups
// (16 chunks) starting at groupIdxBase: lane offset i (0..3) produces
// groupIdx = groupIdxBase + i on the fill block
// [0x03 | LE64(groupIdx) | 4×0x00] and runs the whole ChainHash512
// cascade over components; out receives the 4 × 512-bit outputs at
// [0..3]. The result must be bit-exact with four sequential single-lane
// cascades over the same components and blocks. A performance hook
// only: the cascade fill is the wire with or without it (see
// [Seed512.SetInterlockBatch16]).
type InterlockFillFunc16x512 func(components []uint64, groupIdxBase uint64, out *[4][8]uint64)

// InterlockFillX16 returns the batch-16 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed512) InterlockFillX16() InterlockFillFunc16x512 {
	return s.interlockFillX16
}

// SetInterlockBatch16 installs the batch-16 interlock PRF fill hook.
// nil removes it; the Interlocked Barrier fill then runs the cascade
// through the four-lane and single-lane arms. The hook is a
// performance path only: with or without it the seed produces the
// same wire.
func (s *Seed512) SetInterlockBatch16(fn InterlockFillFunc16x512) {
	s.interlockFillX16 = fn
}

// InterlockFillFunc32x512 is the batch-32 Interlocked Barrier fill
// kernel interface at width 512 — the wider counterpart of
// [InterlockFillFunc16x512]. One call fills the 8 consecutive groups
// (32 chunks) starting at groupIdxBase: lane offset i (0..7) produces
// groupIdx = groupIdxBase + i on the fill block
// [0x03 | LE64(groupIdx) | 4×0x00] and runs the whole ChainHash512
// cascade over components; out receives the 8 × 512-bit outputs at
// [0..7]. The result must be bit-exact with eight sequential
// single-lane cascades over the same components and blocks. A
// performance hook only: the cascade fill is the wire with or without
// it (see [Seed512.SetInterlockBatch32]). The fill ladder tries this
// hook first, then the batch-16 hook, then the four-lane and
// single-lane arms.
type InterlockFillFunc32x512 func(components []uint64, groupIdxBase uint64, out *[8][8]uint64)

// InterlockFillX32 returns the batch-32 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed512) InterlockFillX32() InterlockFillFunc32x512 {
	return s.interlockFillX32
}

// SetInterlockBatch32 installs the batch-32 interlock PRF fill hook.
// nil removes it; the Interlocked Barrier fill then runs the cascade
// through the batch-16 hook (when attached), the four-lane and the
// single-lane arms. The hook is a performance path only: with or
// without it the seed produces the same wire.
func (s *Seed512) SetInterlockBatch32(fn InterlockFillFunc32x512) {
	s.interlockFillX32 = fn
}
