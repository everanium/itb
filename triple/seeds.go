package triple

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/wipe"
	"github.com/everanium/itb/kdf"
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
			for j := 0; j < i; j++ {
				zeroSeedComponents(seeds[j], width)
				wipe.Bytes(prfKeys[j])
			}
			return [8]any{}, [8][]byte{}, 0, err
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
			for j := 0; j < i; j++ {
				zeroSeedComponents(seeds[j], width)
				wipe.Bytes(prfKeys[j])
			}
			return [8]any{}, [8][]byte{}, 0, fmt.Errorf("triple: mixedHashes[%d] is empty", i)
		}
		spec, ok := hashes.Find(name)
		if !ok {
			for j := 0; j < i; j++ {
				zeroSeedComponents(seeds[j], width)
				wipe.Bytes(prfKeys[j])
			}
			return [8]any{}, [8][]byte{}, 0, fmt.Errorf("triple: mixedHashes[%d] = %q not in hashes.Registry", i, name)
		}
		if int(spec.Width) != width {
			for j := 0; j < i; j++ {
				zeroSeedComponents(seeds[j], width)
				wipe.Bytes(prfKeys[j])
			}
			return [8]any{}, [8][]byte{}, 0, fmt.Errorf("triple: mixedHashes[%d] = %q width %d, profile width %d",
				i, name, int(spec.Width), width)
		}
		seed, key, err := allocOneSeed(name, keyBits, width)
		if err != nil {
			for j := 0; j < i; j++ {
				zeroSeedComponents(seeds[j], width)
				wipe.Bytes(prfKeys[j])
			}
			return [8]any{}, [8][]byte{}, 0, err
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
	// hashes.NewSeed<W> runs the whole construction — the (single,
	// batched) arms, keyBits random components, the fused ChainHash
	// cascade hooks and the batch-16 Interlocked Barrier fill hook — and
	// returns the fixed key the arms were built with.
	switch width {
	case 128:
		s, key, err := hashes.NewSeed128(primitive, keyBits)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: hashes.NewSeed128(%q): %w", primitive, err)
		}
		return s, key, nil
	case 256:
		s, key, err := hashes.NewSeed256(primitive, keyBits)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: hashes.NewSeed256(%q): %w", primitive, err)
		}
		return s, key, nil
	case 512:
		s, key, err := hashes.NewSeed512(primitive, keyBits)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: hashes.NewSeed512(%q): %w", primitive, err)
		}
		return s, key, nil
	}
	return nil, nil, fmt.Errorf("triple: unsupported primitive width %d", width)
}

// kdfPrimitiveForSlot maps a slot's hash primitive name to the
// corresponding [kdf.Derive] construction name. aesitb128 (ClassNPRF)
// maps to aescmac (RFC 4493 10-round AES-128 PRF in SP 800-108 Counter
// Mode); custom runtime-registered primitives map to the canonical
// KDF construction of matching width.
func kdfPrimitiveForSlot(slotPrim string, width int) string {
	switch slotPrim {
	case hashes.CipherAreion256,
		hashes.CipherAreion512,
		hashes.CipherBLAKE2b256,
		hashes.CipherBLAKE2b512,
		hashes.CipherBLAKE2s,
		hashes.CipherBLAKE3,
		hashes.CipherAES128CTR,
		hashes.CipherSipHash24,
		hashes.CipherChaCha20:
		return slotPrim
	case hashes.CipherAESITB128:
		return hashes.CipherAES128CTR
	default:
		switch width {
		case 128:
			return hashes.CipherAES128CTR
		case 256:
			return hashes.CipherBLAKE2b256
		case 512:
			return hashes.CipherBLAKE2b512
		default:
			return slotPrim
		}
	}
}

// kdfKeyMinLen returns the minimum master-key length in bytes required
// (and consumed) by [kdf.Derive] for kdfPrim.
func kdfKeyMinLen(kdfPrim string) int {
	switch kdfPrim {
	case hashes.CipherAES128CTR, hashes.CipherSipHash24:
		return 16
	default:
		return 32
	}
}

// resolveSlotPrimitives resolves the per-slot primitive names, their
// corresponding [kdf.Derive] construction names, and the common native
// width for a resolved [Profile].
func resolveSlotPrimitives(resolved Profile) (slotPrims, kdfPrims [8]string, width int, err error) {
	if isMixedProfile(resolved) {
		width = resolved.Width
		if width != 128 && width != 256 && width != 512 {
			return slotPrims, kdfPrims, 0, fmt.Errorf("triple: unsupported primitive width %d", width)
		}
		if resolved.KeyBits <= 0 || resolved.KeyBits%width != 0 {
			return slotPrims, kdfPrims, 0, fmt.Errorf("triple: key_bits=%d not divisible by width=%d",
				resolved.KeyBits, width)
		}
		for i := 0; i < 8; i++ {
			name := resolved.MixedHashes[i]
			if name == "" {
				return slotPrims, kdfPrims, 0, fmt.Errorf("triple: mixedHashes[%d] is empty", i)
			}
			spec, ok := hashes.Find(name)
			if !ok {
				return slotPrims, kdfPrims, 0, fmt.Errorf("triple: mixedHashes[%d] = %q not in hashes.Registry", i, name)
			}
			if int(spec.Width) != width {
				return slotPrims, kdfPrims, 0, fmt.Errorf("triple: mixedHashes[%d] = %q width %d, profile width %d",
					i, name, int(spec.Width), width)
			}
			slotPrims[i] = name
			kdfPrims[i] = kdfPrimitiveForSlot(name, width)
		}
		return slotPrims, kdfPrims, width, nil
	}

	spec, ok := hashes.Find(resolved.InnerHash)
	if !ok {
		return slotPrims, kdfPrims, 0, fmt.Errorf("triple: unknown inner hash primitive %q", resolved.InnerHash)
	}
	width = int(spec.Width)
	if resolved.KeyBits <= 0 || resolved.KeyBits%width != 0 {
		return slotPrims, kdfPrims, 0, fmt.Errorf("triple: key_bits=%d not divisible by primitive %q width=%d",
			resolved.KeyBits, resolved.InnerHash, width)
	}
	kp := kdfPrimitiveForSlot(resolved.InnerHash, width)
	for i := 0; i < 8; i++ {
		slotPrims[i] = resolved.InnerHash
		kdfPrims[i] = kp
	}
	return slotPrims, kdfPrims, width, nil
}

// deriveEightSeeds deterministically derives the 8-seed Interlocked
// Barrier Triple constellation and per-slot fixed PRF keys from
// masters[0..7] using the per-slot KDF constructions kdfPrims[0..7].
func deriveEightSeeds(slotPrims, kdfPrims [8]string, keyBits, width int, masters [8][]byte) ([8]any, [8][]byte, error) {
	var seeds [8]any
	var prfKeys [8][]byte

	for i := 0; i < 8; i++ {
		seed, key, err := deriveOneSeed(i, slotPrims[i], kdfPrims[i], keyBits, width, masters[i])
		if err != nil {
			for j := 0; j < i; j++ {
				zeroSeedComponents(seeds[j], width)
				wipe.Bytes(prfKeys[j])
			}
			return [8]any{}, [8][]byte{}, err
		}
		seeds[i] = seed
		prfKeys[i] = key
	}
	if err := checkEightSeeds(seeds, width); err != nil {
		for j := 0; j < 8; j++ {
			zeroSeedComponents(seeds[j], width)
			wipe.Bytes(prfKeys[j])
		}
		return [8]any{}, [8][]byte{}, err
	}
	return seeds, prfKeys, nil
}

// deriveOneSeed derives one typed seed and its fixed PRF key for slot
// slotIdx from master via [kdf.Derive] and wires all SIMD / fused
// ChainHash / interlock-batch hooks via
// [hashes.SeedFromComponents128] / [hashes.SeedFromComponents256] /
// [hashes.SeedFromComponents512].
func deriveOneSeed(slotIdx int, slotPrim, kdfPrim string, keyBits, width int, master []byte) (seed any, prfKey []byte, err error) {
	var rawKey []byte
	if slotPrim != hashes.CipherSipHash24 {
		rawKey, err = kdf.Derive(kdfPrim, master, fmt.Sprintf("prfkey:%d", slotIdx), width/8)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: InitKeys: slot %d prfkey kdf: %w", slotIdx, err)
		}
	}
	defer wipe.Bytes(rawKey)

	compBytes, err := kdf.Derive(kdfPrim, master, fmt.Sprintf("comps:%d", slotIdx), keyBits/8)
	if err != nil {
		return nil, nil, fmt.Errorf("triple: InitKeys: slot %d comps kdf: %w", slotIdx, err)
	}
	numWords := keyBits / 64
	comps := make([]uint64, numWords)
	for w := 0; w < numWords; w++ {
		comps[w] = binary.LittleEndian.Uint64(compBytes[w*8:])
	}
	wipe.Bytes(compBytes)
	defer wipe.Uint64s(comps)

	switch width {
	case 128:
		s, fixedKey, serr := wipe.SeedFromComponents128WithKey(slotPrim, rawKey, comps...)
		if serr != nil && rawKey != nil {
			// Keyless custom 128-bit primitives reject a fixed-key
			// argument; retry with nil key, matching importInnerBlob128.
			s, fixedKey, serr = wipe.SeedFromComponents128WithKey(slotPrim, nil, comps...)
		}
		if serr != nil {
			return nil, nil, fmt.Errorf("triple: hashes.SeedFromComponents128(%q): %w", slotPrim, serr)
		}
		return s, fixedKey, nil
	case 256:
		s, fixedKey, serr := wipe.SeedFromComponents256WithKey(slotPrim, rawKey, comps...)
		if serr != nil && rawKey != nil {
			s, fixedKey, serr = wipe.SeedFromComponents256WithKey(slotPrim, nil, comps...)
		}
		if serr != nil {
			return nil, nil, fmt.Errorf("triple: hashes.SeedFromComponents256(%q): %w", slotPrim, serr)
		}
		return s, fixedKey, nil
	case 512:
		s, fixedKey, serr := wipe.SeedFromComponents512WithKey(slotPrim, rawKey, comps...)
		if serr != nil && rawKey != nil {
			s, fixedKey, serr = wipe.SeedFromComponents512WithKey(slotPrim, nil, comps...)
		}
		if serr != nil {
			return nil, nil, fmt.Errorf("triple: hashes.SeedFromComponents512(%q): %w", slotPrim, serr)
		}
		return s, fixedKey, nil
	}
	return nil, nil, fmt.Errorf("triple: unsupported primitive width %d", width)
}

// checkEightSeeds verifies pairwise component distinctness across all
// 8 derived seeds at InitKeys time.
func checkEightSeeds(seeds [8]any, width int) error {
	for i := 0; i < 8; i++ {
		for j := i + 1; j < 8; j++ {
			var eq bool
			switch width {
			case 128:
				eq = slices.Equal(seeds[i].(*itb.Seed128).Components, seeds[j].(*itb.Seed128).Components)
			case 256:
				eq = slices.Equal(seeds[i].(*itb.Seed256).Components, seeds[j].(*itb.Seed256).Components)
			case 512:
				eq = slices.Equal(seeds[i].(*itb.Seed512).Components, seeds[j].(*itb.Seed512).Components)
			}
			if eq {
				return fmt.Errorf("triple: InitKeys: derived seeds[%d] and seeds[%d] have identical components", i, j)
			}
		}
	}
	return nil
}

// zeroSeedComponents clears the Components slice of a typed seed
// pointer for the given width and replaces its hash closures so any
// closure-captured PRF key schedule is released to GC while keeping
// the seed struct and Hash field non-nil. Called by [Pipeline.Close]
// to wipe keying material before releasing the Pipeline handle.
func zeroSeedComponents(handle any, width int) {
	switch width {
	case 128:
		if s, ok := handle.(*itb.Seed128); ok && s != nil {
			wipe.Uint64s(s.Components)
			s.BatchHash = nil
			s.FusedChain = nil
			s.BatchFusedChain = nil
			s.SetBatchFusedChain8(nil)
			s.SetInterlockBatch16(nil)
			s.Hash = func([]byte, uint64, uint64) (uint64, uint64) { return 0, 0 }
		}
	case 256:
		if s, ok := handle.(*itb.Seed256); ok && s != nil {
			wipe.Uint64s(s.Components)
			s.BatchHash = nil
			s.FusedChain = nil
			s.BatchFusedChain = nil
			s.SetBatchFusedChain8(nil)
			s.SetInterlockBatch16(nil)
			s.SetInterlockBatch32(nil)
			s.Hash = func([]byte, [4]uint64) [4]uint64 { return [4]uint64{} }
		}
	case 512:
		if s, ok := handle.(*itb.Seed512); ok && s != nil {
			wipe.Uint64s(s.Components)
			s.BatchHash = nil
			s.FusedChain = nil
			s.BatchFusedChain = nil
			s.SetBatchFusedChain8(nil)
			s.SetInterlockBatch16(nil)
			s.SetInterlockBatch32(nil)
			s.Hash = func([]byte, [8]uint64) [8]uint64 { return [8]uint64{} }
		}
	}
}
