package hashes

import (
	"fmt"

	"github.com/everanium/itb"
)

// AttachFused256 populates s.FusedChain / s.BatchFusedChain from the
// named primitive's [Spec.FusedChainHash256] factory, using the fixed
// key the seed's Hash / BatchHash arms were built with. Primitives
// without a fused cascade, unknown names, and factories that decline
// (nil evaluators) leave the seed unchanged — the sequential loop keeps
// running. A factory error is returned; the seed is left unchanged.
// The hooks are a performance path only: the seed produces the same
// wire with and without them. Every shipping constructor path — the
// triple package's Init / Load seed builders and the C ABI seed
// constructors — calls AttachFused256 and [AttachInterlockBatch16x256]
// together.
func AttachFused256(s *itb.Seed256, name string, key []byte) error {
	spec, ok := Find(name)
	if !ok || spec.FusedChainHash256 == nil {
		return nil
	}
	single, batched, err := spec.FusedChainHash256(key)
	if err != nil {
		return err
	}
	s.FusedChain, s.BatchFusedChain = single, batched
	return nil
}

// AttachInterlockBatch16x256 populates the batch-16 Interlocked Barrier
// fill hook of s from the named primitive's [Spec.InterlockFillBatch16x256]
// factory, using the fixed key the seed's Hash arm was built with.
// Primitives without batch-16 support, unknown names, and factories
// that decline (nil) leave the seed unchanged — the seed fills the
// cascade through its four-lane and single-lane arms. The hook is a
// performance path only: a seed with the hook and the same seed without
// it produce the same wire (see [itb.InterlockFillFunc16x256]); every
// shipped constructor attaches. A factory error is returned; the seed is
// left unchanged.
func AttachInterlockBatch16x256(s *itb.Seed256, name string, key []byte) error {
	spec, ok := Find(name)
	if !ok || spec.InterlockFillBatch16x256 == nil {
		return nil
	}
	fn, err := spec.InterlockFillBatch16x256(key)
	if err != nil {
		return err
	}
	s.SetInterlockBatch16(fn)
	return nil
}

// smokeFusedChainHash256 is the width-256 counterpart of
// [smokeFusedChainHash128]: whenever a user-registered W256 Spec
// populates [Spec.FusedChainHash256], the factory must return without
// error, and every evaluator that accepts a probe shape must be
// bit-exact with the sequential HashFunc256 loop over the same
// (components, data) tuple. A (nil, nil) evaluator return is a valid
// opt-out.
func smokeFusedChainHash256(spec Spec, single itb.HashFunc256, key []byte) error {
	fSingle, fBatched, ferr := spec.FusedChainHash256(key)
	if ferr != nil {
		return fmt.Errorf("hashes: Register: %q FusedChainHash256(key): %w", spec.Name, ferr)
	}
	if fSingle == nil && fBatched == nil {
		return nil
	}
	var comps [8]uint64
	for i := range comps {
		comps[i] = 0x0123456789abcdef ^ uint64(i)*0x9e3779b97f4a7c15
	}
	seqChain := func(data []byte) [4]uint64 {
		var seed [4]uint64
		copy(seed[:], comps[0:4])
		h := single(data, seed)
		for i := 4; i < len(comps); i += 4 {
			for j := 0; j < 4; j++ {
				seed[j] = comps[i+j] ^ h[j]
			}
			h = single(data, seed)
		}
		return h
	}
	for _, n := range [...]int{13, 20, 36, 68} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i)
		}
		if fSingle != nil {
			if out, ok := fSingle(comps[:], data); ok && out != seqChain(data) {
				return fmt.Errorf("hashes: Register: %q FusedChainHash256 single arm diverges from the sequential HashFunc256 loop at len=%d", spec.Name, n)
			}
		}
		if fBatched != nil {
			var lanes [4][]byte
			for l := range lanes {
				lanes[l] = make([]byte, n)
				for i := range lanes[l] {
					lanes[l][i] = byte(i + l*7)
				}
			}
			if out, ok := fBatched(comps[:], &lanes); ok {
				for l := 0; l < 4; l++ {
					if out[l] != seqChain(lanes[l]) {
						return fmt.Errorf("hashes: Register: %q FusedChainHash256 batched arm lane %d diverges from the sequential HashFunc256 loop at len=%d", spec.Name, l, n)
					}
				}
			}
		}
	}
	return nil
}
