package itb

// FusedChainHashFunc256 evaluates the whole [Seed256.ChainHash256]
// cascade in one call: the primitive is applied once per component
// quadruple with the previous round's output folded into the next
// quadruple, exactly as the sequential loop does, but with the state
// kept inside the primitive's kernel between rounds.
//
// ok reports whether the implementation handled data; when false the
// caller runs the sequential loop and out is meaningless. When true the
// result must be bit-exact with the sequential loop over the same
// components and data. Implementations decide by input shape only, so a
// given (components, data) pair is answered the same way on every call.
type FusedChainHashFunc256 func(components []uint64, data []byte) (out [4]uint64, ok bool)

// BatchFusedChainHashFunc256 is the four-lane counterpart of
// [FusedChainHashFunc256]: every lane runs the cascade over the shared
// components with its own data, matching [Seed256.BatchChainHash256].
type BatchFusedChainHashFunc256 func(components []uint64, data *[4][]byte) (out [4][4]uint64, ok bool)

// InterlockFillFunc16x256 is the batch-16 Interlocked Barrier fill
// kernel interface at width 256 — the counterpart of
// [InterlockFillFunc16]. One call fills the 8 consecutive groups
// (16 chunks) starting at groupIdxBase: lane offset i (0..7) produces
// groupIdx = groupIdxBase + i on the fill block
// [0x03 | LE64(groupIdx) | 4×0x00] and runs the whole ChainHash256
// cascade over components; out receives the 8 × 256-bit outputs at
// [0..7]. The result must be bit-exact with eight sequential
// single-lane cascades over the same components and blocks. A
// performance hook only: the cascade fill is the wire with or without
// it (see [Seed256.SetInterlockBatch16]).
type InterlockFillFunc16x256 func(components []uint64, groupIdxBase uint64, out *[8][4]uint64)

// InterlockFillX16 returns the batch-16 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed256) InterlockFillX16() InterlockFillFunc16x256 {
	return s.interlockFillX16
}

// SetInterlockBatch16 installs the batch-16 interlock PRF fill hook.
// nil removes it; the Interlocked Barrier fill then runs the cascade
// through the four-lane and single-lane arms. The hook is a
// performance path only: with or without it the seed produces the
// same wire.
func (s *Seed256) SetInterlockBatch16(fn InterlockFillFunc16x256) {
	s.interlockFillX16 = fn
}

// InterlockFillFunc32x256 is the batch-32 Interlocked Barrier fill
// kernel interface at width 256 — the wider counterpart of
// [InterlockFillFunc16x256]. One call fills the 16 consecutive groups
// (32 chunks) starting at groupIdxBase: lane offset i (0..15) produces
// groupIdx = groupIdxBase + i on the fill block
// [0x03 | LE64(groupIdx) | 4×0x00] and runs the whole ChainHash256
// cascade over components; out receives the 16 × 256-bit outputs at
// [0..15]. The result must be bit-exact with sixteen sequential
// single-lane cascades over the same components and blocks. A
// performance hook only: the cascade fill is the wire with or without
// it (see [Seed256.SetInterlockBatch32]). The fill ladder tries this
// hook first, then the batch-16 hook, then the four-lane and
// single-lane arms.
type InterlockFillFunc32x256 func(components []uint64, groupIdxBase uint64, out *[16][4]uint64)

// InterlockFillX32 returns the batch-32 interlock PRF fill hook, nil
// when none is attached.
func (s *Seed256) InterlockFillX32() InterlockFillFunc32x256 {
	return s.interlockFillX32
}

// SetInterlockBatch32 installs the batch-32 interlock PRF fill hook.
// nil removes it; the Interlocked Barrier fill then runs the cascade
// through the batch-16 hook (when attached), the four-lane and the
// single-lane arms. The hook is a performance path only: with or
// without it the seed produces the same wire.
func (s *Seed256) SetInterlockBatch32(fn InterlockFillFunc32x256) {
	s.interlockFillX32 = fn
}
