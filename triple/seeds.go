package triple

import (
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// allocEightSeeds builds the 8-seed Interlocked Barrier Triple bundle
// for the (innerHash, keyBits, width) combination. The canonical slot
// ordering is:
//
//	[0] noiseSeed
//	[1] lockSeed
//	[2] dataSeed1
//	[3] dataSeed2
//	[4] dataSeed3
//	[5] startSeed1
//	[6] startSeed2
//	[7] startSeed3
//
// Each entry is a typed *itb.Seed{128,256,512} carrying a fresh
// CSPRNG-drawn Components slice and a hash closure wired via
// [hashes.Make128Pair] / [Make256Pair] / [Make512Pair] so the batched
// arm is populated alongside the single arm.
//
// The parallel prfKeys array carries the primitive's fixed PRF key
// bytes per slot. For primitives without a fixed key (siphash24) the
// whole array is returned as-is with each entry nil; callers detect
// the no-key primitive via [hashes.Registry] lookup and treat prfKeys
// as informational.
func allocEightSeeds(innerHash string, keyBits int) ([8]any, [8][]byte, int, error) {
	var seeds [8]any
	var prfKeys [8][]byte

	spec, ok := hashes.Find(innerHash)
	if !ok {
		return seeds, prfKeys, 0, fmt.Errorf("triple: unknown inner hash primitive %q", innerHash)
	}
	width := int(spec.Width)
	if keyBits <= 0 || keyBits%width != 0 {
		return seeds, prfKeys, 0, fmt.Errorf("triple: key_bits=%d not divisible by primitive %q width=%d",
			keyBits, innerHash, width)
	}

	for i := 0; i < 8; i++ {
		seed, key, err := allocOneSeed(innerHash, keyBits, width)
		if err != nil {
			return seeds, prfKeys, 0, err
		}
		seeds[i] = seed
		prfKeys[i] = key
	}
	return seeds, prfKeys, width, nil
}

// allocEightSeedsMixed is the mixed-primitive counterpart to
// [allocEightSeeds]. Each of the 8 canonical slots is built with its
// own per-slot primitive name from the mixedHashes array; every
// primitive's native width must match width (Register's
// validator enforces this — the check here is defensive, catching
// programmer mistakes on the raw entry point).
//
// The returned seeds / prfKeys / width arrays follow the same shape
// as [allocEightSeeds]; the caller distinguishes mixed vs single by
// looking at the source profile, not the returned arrays.
func allocEightSeedsMixed(mixedHashes [8]string, keyBits, width int) ([8]any, [8][]byte, int, error) {
	var seeds [8]any
	var prfKeys [8][]byte

	if width != 128 && width != 256 && width != 512 {
		return seeds, prfKeys, 0, fmt.Errorf("triple: unsupported primitive width %d", width)
	}
	if keyBits <= 0 || keyBits%width != 0 {
		return seeds, prfKeys, 0, fmt.Errorf("triple: key_bits=%d not divisible by width=%d",
			keyBits, width)
	}

	for i := 0; i < 8; i++ {
		name := mixedHashes[i]
		if name == "" {
			return seeds, prfKeys, 0, fmt.Errorf("triple: mixedHashes[%d] is empty", i)
		}
		spec, ok := hashes.Find(name)
		if !ok {
			return seeds, prfKeys, 0, fmt.Errorf("triple: mixedHashes[%d] = %q not in hashes.Registry", i, name)
		}
		if int(spec.Width) != width {
			return seeds, prfKeys, 0, fmt.Errorf("triple: mixedHashes[%d] = %q width %d, profile width %d",
				i, name, int(spec.Width), width)
		}
		seed, key, err := allocOneSeed(name, keyBits, width)
		if err != nil {
			return seeds, prfKeys, 0, err
		}
		seeds[i] = seed
		prfKeys[i] = key
	}
	return seeds, prfKeys, width, nil
}

// allocOneSeed produces one typed seed + its fixed PRF key for the
// (primitive, keyBits, width) combination. Returns errors instead of
// panicking so [Init] can bubble the failure through its
// error-returning signature.
func allocOneSeed(primitive string, keyBits, width int) (seed any, prfKey []byte, err error) {
	switch width {
	case 128:
		single, batched, key, herr := hashes.Make128Pair(primitive)
		if herr != nil {
			return nil, nil, fmt.Errorf("triple: hashes.Make128Pair(%q): %w", primitive, herr)
		}
		s, serr := itb.NewSeed128(keyBits, single)
		if serr != nil {
			return nil, nil, fmt.Errorf("triple: itb.NewSeed128: %w", serr)
		}
		s.BatchHash = batched
		return s, key, nil
	case 256:
		single, batched, key, herr := hashes.Make256Pair(primitive)
		if herr != nil {
			return nil, nil, fmt.Errorf("triple: hashes.Make256Pair(%q): %w", primitive, herr)
		}
		s, serr := itb.NewSeed256(keyBits, single)
		if serr != nil {
			return nil, nil, fmt.Errorf("triple: itb.NewSeed256: %w", serr)
		}
		s.BatchHash = batched
		return s, key, nil
	case 512:
		single, batched, key, herr := hashes.Make512Pair(primitive)
		if herr != nil {
			return nil, nil, fmt.Errorf("triple: hashes.Make512Pair(%q): %w", primitive, herr)
		}
		s, serr := itb.NewSeed512(keyBits, single)
		if serr != nil {
			return nil, nil, fmt.Errorf("triple: itb.NewSeed512: %w", serr)
		}
		s.BatchHash = batched
		return s, key, nil
	}
	return nil, nil, fmt.Errorf("triple: unsupported primitive width %d", width)
}

// zeroSeedComponents clears the Components slice of a typed seed
// pointer for the given width. Called by [Pipeline.Close] to wipe
// keying material before releasing the Pipeline handle.
func zeroSeedComponents(handle any, width int) {
	switch width {
	case 128:
		if s, ok := handle.(*itb.Seed128); ok {
			clear(s.Components)
		}
	case 256:
		if s, ok := handle.(*itb.Seed256); ok {
			clear(s.Components)
		}
	case 512:
		if s, ok := handle.(*itb.Seed512); ok {
			clear(s.Components)
		}
	}
}
