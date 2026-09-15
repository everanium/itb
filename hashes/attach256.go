package hashes

import (
	"encoding/binary"
	"fmt"

	"github.com/everanium/itb"
)

// attachFused256 populates s.FusedChain / s.BatchFusedChain from the
// named primitive's [Spec.FusedChainHash256] factory, using the fixed
// key the seed's Hash / BatchHash arms were built with, and the
// eight-lane hook ([itb.Seed256.SetBatchFusedChain8]) from the
// [Spec.FusedChainHash256x8] factory when the entry populates it and
// the factory returns a kernel for the selected tier; either factory
// may be present without the other. Primitives
// without a fused cascade, unknown names, and factories that decline
// (nil evaluators) leave the seed unchanged — the sequential loop keeps
// running. A factory error is returned; the seed is left unchanged.
// The hooks are a performance path only: the seed produces the same
// wire with and without them. [NewSeed256] and [SeedFromComponents256] —
// the constructor path of the triple package's seed builders and the C
// ABI seed constructors — call attachFused256, attachInterlockBatch16x256
// and attachInterlockBatch32x256 together.
func attachFused256(s *itb.Seed256, name string, key []byte) error {
	spec, ok := Find(name)
	if !ok {
		return nil
	}
	if spec.FusedChainHash256 != nil {
		single, batched, err := spec.FusedChainHash256(key)
		if err != nil {
			return err
		}
		s.FusedChain, s.BatchFusedChain = single, batched
	}
	if spec.FusedChainHash256x8 != nil {
		x8, err := spec.FusedChainHash256x8(key)
		if err != nil {
			return err
		}
		if x8 != nil {
			s.SetBatchFusedChain8(x8)
		}
	}
	return nil
}

// attachInterlockBatch16x256 populates the batch-16 Interlocked Barrier
// fill hook of s from the named primitive's [Spec.InterlockFillBatch16x256]
// factory, using the fixed key the seed's Hash arm was built with.
// Primitives without batch-16 support, unknown names, and factories
// that decline (nil) leave the seed unchanged — the seed fills the
// cascade through its four-lane and single-lane arms. The hook is a
// performance path only: a seed with the hook and the same seed without
// it produce the same wire (see [itb.InterlockFillFunc16x256]); the
// name-keyed constructors attach. A factory error is returned; the seed
// is left unchanged.
func attachInterlockBatch16x256(s *itb.Seed256, name string, key []byte) error {
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

// attachInterlockBatch32x256 populates the batch-32 Interlocked Barrier
// fill hook of s from the named primitive's [Spec.InterlockFillBatch32x256]
// factory, using the fixed key the seed's Hash arm was built with.
// Primitives without batch-32 support, unknown names, and factories
// that decline (nil) leave the seed unchanged — the fill ladder runs
// the batch-16 hook (see attachInterlockBatch16x256) and the
// four-lane / single-lane arms. The hook is a performance path only: a
// seed with the hook and the same seed without it produce the same wire
// (see [itb.InterlockFillFunc32x256]); the name-keyed constructors
// attach. A factory error is returned; the seed is left unchanged.
func attachInterlockBatch32x256(s *itb.Seed256, name string, key []byte) error {
	spec, ok := Find(name)
	if !ok || spec.InterlockFillBatch32x256 == nil {
		return nil
	}
	fn, err := spec.InterlockFillBatch32x256(key)
	if err != nil {
		return err
	}
	if fn != nil {
		s.SetInterlockBatch32(fn)
	}
	return nil
}

// smokeWideHooks256 is the Register-time check of the optional
// [Spec.FusedChainHash256x8] and [Spec.InterlockFillBatch32x256]
// factories of a user-registered W256 Spec: each populated factory must
// return without error, and a non-nil kernel must be bit-exact with the
// sequential HashFunc256 loop over the same (components, data) tuples —
// the eight-lane evaluator on every lane it accepts, the batch-32 fill
// kernel on every group of a probe base. A nil kernel is a valid
// opt-out.
func smokeWideHooks256(spec Spec, single itb.HashFunc256, key []byte) error {
	if spec.FusedChainHash256x8 == nil && spec.InterlockFillBatch32x256 == nil {
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
	if spec.FusedChainHash256x8 != nil {
		x8, err := spec.FusedChainHash256x8(key)
		if err != nil {
			return fmt.Errorf("hashes: Register: %q FusedChainHash256x8(key): %w", spec.Name, err)
		}
		if x8 != nil {
			for _, n := range [...]int{13, 20, 36, 68} {
				var lanes [8][]byte
				for l := range lanes {
					lanes[l] = make([]byte, n)
					for i := range lanes[l] {
						lanes[l][i] = byte(i + l*7)
					}
				}
				if out, ok := x8(comps[:], &lanes); ok {
					for l := 0; l < 8; l++ {
						if out[l] != seqChain(lanes[l]) {
							return fmt.Errorf("hashes: Register: %q FusedChainHash256x8 lane %d diverges from the sequential HashFunc256 loop at len=%d", spec.Name, l, n)
						}
					}
				}
			}
		}
	}
	if spec.InterlockFillBatch32x256 != nil {
		fill, err := spec.InterlockFillBatch32x256(key)
		if err != nil {
			return fmt.Errorf("hashes: Register: %q InterlockFillBatch32x256(key): %w", spec.Name, err)
		}
		if fill != nil {
			var out [16][4]uint64
			const base = uint64(0x0123456789ab)
			fill(comps[:], base, &out)
			for i := range out {
				var block [13]byte
				block[0] = 0x03
				binary.LittleEndian.PutUint64(block[1:9], base+uint64(i))
				if out[i] != seqChain(block[:]) {
					return fmt.Errorf("hashes: Register: %q InterlockFillBatch32x256 group %d diverges from the sequential HashFunc256 loop", spec.Name, i)
				}
			}
		}
	}
	return nil
}
