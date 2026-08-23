package triple

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// Open reconstructs a [Pipeline] from a blob produced by [Init] or
// [Pipeline.Rekey]. The blob's wrap-layer profile field must match
// the profile argument.
//
// Master resolution:
//
//   - When len(masters) == 0, the parallax and wrapper masters are
//     read from the blob's pm / wm slots (subject to the profile's
//     recorded layer toggles).
//   - When len(masters) == 2, the trailing masters
//     (masters[0] = permMaster, masters[1] = wrapMaster) replace the
//     blob's slots — the rekey-on-import path.
//   - Any other arity returns [ErrMastersArity].
//
// If the resolved masters compare bytewise-equal,
// [ErrIdenticalMasters] is returned.
//
// Layer-toggle resolution priority (highest first):
//  1. [Opts.WithParallax] / [Opts.WithWrapper] when set (non-nil
//     pointer) — the caller's explicit override.
//  2. The blob's wp / ww fields — the sender's recorded shape.
//  3. The profile default (only consulted when both above are absent).
//
// The Opts-over-blob-over-profile ordering matches the same
// masters-resolution principle used elsewhere in this package: an
// Opts field is always the strongest authority when present, while
// the blob still carries the sender's decision through to a receiver
// that hands in an empty [Opts].
func Open(profile string, blob []byte, opts Opts, masters ...[]byte) (*Pipeline, error) {
	prof, err := lookupProfile(profile)
	if err != nil {
		return nil, err
	}

	if len(masters) != 0 && len(masters) != 2 {
		return nil, ErrMastersArity
	}

	var wrap blobWrapV1
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&wrap); derr != nil {
		return nil, ErrBlobMalformed
	}
	if dec.More() {
		return nil, ErrBlobMalformed
	}
	if wrap.Version != blobWrapVersionV1 {
		return nil, ErrBlobVersion
	}
	if wrap.Profile != profile {
		return nil, ErrBlobMismatch
	}

	// Merge profile defaults with Opts.
	resolved := resolveProfile(prof, opts)

	// Toggle priority: Opts (highest) → blob → profile (lowest).
	// resolveProfile already applied Opts on top of the profile
	// default; if Opts left the toggle nil, promote the blob's
	// recorded shape to replace the profile default.
	if opts.WithParallax == nil {
		resolved.parallaxOn = wrap.Parallax
	}
	if opts.WithWrapper == nil {
		resolved.wrapperOn = wrap.Wrapper
	}
	resolved.name = wrap.Profile

	// Resolve masters.
	permMaster, wrapMaster, err := resolveOpenMasters(resolved, wrap, masters)
	if err != nil {
		return nil, err
	}

	// Resolve inner hash width. For single-primitive profiles the width
	// comes from the resolved.innerHash primitive; for mixed-primitive
	// profiles it comes from Profile.Width (carried through resolved.width).
	// The inner blob itself does not tell us which width to use — the
	// caller must have picked a profile whose shape matches the
	// sender's, otherwise the width-typed Blob{N} decoder will fail.
	var width int
	if isMixedResolved(resolved) {
		if resolved.width != 128 && resolved.width != 256 && resolved.width != 512 {
			return nil, fmt.Errorf("triple: mixed profile width %d not in {128, 256, 512}", resolved.width)
		}
		width = resolved.width
	} else {
		spec, ok := hashes.Find(resolved.innerHash)
		if !ok {
			return nil, fmt.Errorf("triple: unknown inner hash primitive %q", resolved.innerHash)
		}
		width = int(spec.Width)
	}

	// Decode the inner Blob{N} via the Cfg-aware Import3Cfg entry so
	// no process-global mutation occurs during Open. Mixed-primitive
	// profiles pass the per-slot constellation so each seed's hash
	// closure is rebuilt with the correct primitive; single-primitive
	// profiles pass an empty constellation and the importer uses
	// resolved.innerHash for all 8 slots.
	cfg := &itb.Config{}
	var (
		seeds   [8]any
		prfKeys [8][]byte
		macName string
		macKey  []byte
	)
	if isMixedResolved(resolved) {
		seeds, prfKeys, macName, macKey, err = importInnerBlobMixed(width, cfg, wrap.Inner, resolved.mixedHashes)
	} else {
		seeds, prfKeys, macName, macKey, err = importInnerBlob(width, cfg, wrap.Inner, resolved.innerHash)
	}
	if err != nil {
		return nil, err
	}

	// Parallax build.
	var (
		sched *parallax.Schedule
		cs    *parallax.Cipherset
	)
	if resolved.parallaxOn {
		sched, err = parallax.NewSchedule(resolved.parallaxPalette, resolved.parallaxSegmentSize)
		if err != nil {
			return nil, fmt.Errorf("triple: parallax.NewSchedule: %w", err)
		}
		if resolved.chunkSize > 0 {
			if serr := sched.SetChunkSize(resolved.chunkSize); serr != nil {
				return nil, fmt.Errorf("triple: parallax.SetChunkSize: %w", serr)
			}
		}
		cs, err = parallax.NewCipherset(permMaster, sched)
		if err != nil {
			return nil, fmt.Errorf("triple: parallax.NewCipherset: %w", err)
		}
	}

	// Wrapper build.
	var wrapperKey []byte
	if resolved.wrapperOn {
		wrapperKey, err = wrapper.DeriveKey(resolved.outerCipher, wrapMaster)
		if err != nil {
			return nil, fmt.Errorf("triple: wrapper.DeriveKey: %w", err)
		}
	}

	// MAC build. Profiles with No MAC do not consume macName / macKey
	// even if the inner blob carries them; profiles that require a
	// MAC verify the blob supplied one.
	var macFunc itb.MACFunc
	if resolved.macName != "" {
		if macName == "" {
			return nil, fmt.Errorf("triple: profile requires MAC %q but blob carries none", resolved.macName)
		}
		macFunc, err = macs.Make(macName, macKey)
		if err != nil {
			return nil, fmt.Errorf("triple: macs.Make(%q): %w", macName, err)
		}
	} else {
		// No-MAC profile — drop any blob-side MAC material to keep
		// the Pipeline shape consistent with the resolved profile.
		macName = ""
		macKey = nil
	}

	p := &Pipeline{
		profileName:   resolved.name,
		resolved:      resolved,
		width:         width,
		cfg:           cfg,
		seeds:         seeds,
		prfKeys:       prfKeys,
		parallaxSched: sched,
		parallaxCS:    cs,
		wrapperKey:    wrapperKey,
		wrapperCipher: resolved.outerCipher,
		macKey:        macKey,
		macFunc:       macFunc,
		macName:       macName,
	}
	return p, nil
}

// resolveOpenMasters folds the blob-supplied masters and the trailing
// variadic overrides into (permMaster, wrapMaster), and rejects
// invalid combinations.
func resolveOpenMasters(resolved resolvedProfile, wrap blobWrapV1, masters [][]byte) (permMaster, wrapMaster []byte, err error) {
	if len(masters) == 2 {
		permMaster = append([]byte(nil), masters[0]...)
		wrapMaster = append([]byte(nil), masters[1]...)
	} else {
		if len(wrap.PermMaster) > 0 {
			permMaster = append([]byte(nil), wrap.PermMaster...)
		}
		if len(wrap.WrapMaster) > 0 {
			wrapMaster = append([]byte(nil), wrap.WrapMaster...)
		}
	}
	if resolved.parallaxOn && len(permMaster) == 0 {
		return nil, nil, ErrMissingMasters
	}
	if resolved.wrapperOn && len(wrapMaster) == 0 {
		return nil, nil, ErrMissingMasters
	}
	if len(permMaster) > 0 && len(wrapMaster) > 0 && bytes.Equal(permMaster, wrapMaster) {
		return nil, nil, ErrIdenticalMasters
	}
	return permMaster, wrapMaster, nil
}

// importInnerBlob decodes the nested [itb.Blob{N}] bytes via the
// Cfg-aware [itb.Blob{N}.Import3Cfg] entry and returns the eight
// typed seeds + eight per-slot PRF keys in the canonical order used
// by [allocEightSeeds] (noise, lock, data1..3, start1..3) plus the
// MAC name and MAC key the blob carries (both empty for No-MAC).
func importInnerBlob(width int, cfg *itb.Config, innerBytes []byte, innerHash string) ([8]any, [8][]byte, string, []byte, error) {
	switch width {
	case 128:
		return importInnerBlob128(cfg, innerBytes, innerHash)
	case 256:
		return importInnerBlob256(cfg, innerBytes, innerHash)
	case 512:
		return importInnerBlob512(cfg, innerBytes, innerHash)
	}
	return [8]any{}, [8][]byte{}, "", nil, fmt.Errorf("triple: unsupported inner blob width %d", width)
}

// importInnerBlob128 decodes a 128-bit-width inner blob and rebuilds
// the eight typed seeds. Each seed's Hash + BatchHash closure comes
// from [hashes.Make128Pair] re-invoked with the imported per-slot
// key; a keyless primitive (siphash24) is retried without one.
func importInnerBlob128(cfg *itb.Config, innerBytes []byte, innerHash string) ([8]any, [8][]byte, string, []byte, error) {
	var out [8]any
	var keys [8][]byte
	var b itb.Blob128
	if err := b.Import3Cfg(innerBytes, cfg); err != nil {
		return out, keys, "", nil, fmt.Errorf("triple: Blob128.Import3Cfg: %w", err)
	}
	if b.LS == nil {
		return out, keys, "", nil, fmt.Errorf("triple: inner blob missing lockSeed slot")
	}
	rawKeys := [8][]byte{b.KeyN, b.KeyL, b.KeyD1, b.KeyD2, b.KeyD3, b.KeyS1, b.KeyS2, b.KeyS3}
	rawSeeds := [8]*itb.Seed128{b.NS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3}
	for i := 0; i < 8; i++ {
		keys[i] = append([]byte(nil), rawKeys[i]...)
		single, batched, _, err := hashes.Make128Pair(innerHash, keys[i])
		if err != nil {
			// Keyless primitives (siphash24) reject a fixed-key
			// argument; retry with the no-key form since the seed's
			// Components carry all state.
			single, batched, _, err = hashes.Make128Pair(innerHash)
			if err != nil {
				return out, keys, "", nil, fmt.Errorf("triple: hashes.Make128Pair(%q): %w", innerHash, err)
			}
			keys[i] = nil
		}
		rawSeeds[i].Hash = single
		rawSeeds[i].BatchHash = batched
		out[i] = rawSeeds[i]
	}
	return out, keys, b.MACName, append([]byte(nil), b.MACKey...), nil
}

// importInnerBlob256 mirrors [importInnerBlob128] at the 256-bit
// width. Keys are copied out of the Blob's fixed [32]byte arrays into
// []byte slices for the caller-side accounting.
func importInnerBlob256(cfg *itb.Config, innerBytes []byte, innerHash string) ([8]any, [8][]byte, string, []byte, error) {
	var out [8]any
	var keys [8][]byte
	var b itb.Blob256
	if err := b.Import3Cfg(innerBytes, cfg); err != nil {
		return out, keys, "", nil, fmt.Errorf("triple: Blob256.Import3Cfg: %w", err)
	}
	if b.LS == nil {
		return out, keys, "", nil, fmt.Errorf("triple: inner blob missing lockSeed slot")
	}
	rawKeys := [8][32]byte{b.KeyN, b.KeyL, b.KeyD1, b.KeyD2, b.KeyD3, b.KeyS1, b.KeyS2, b.KeyS3}
	rawSeeds := [8]*itb.Seed256{b.NS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3}
	for i := 0; i < 8; i++ {
		keys[i] = append([]byte(nil), rawKeys[i][:]...)
		single, batched, _, err := hashes.Make256Pair(innerHash, keys[i])
		if err != nil {
			return out, keys, "", nil, fmt.Errorf("triple: hashes.Make256Pair(%q): %w", innerHash, err)
		}
		rawSeeds[i].Hash = single
		rawSeeds[i].BatchHash = batched
		out[i] = rawSeeds[i]
	}
	return out, keys, b.MACName, append([]byte(nil), b.MACKey...), nil
}

// importInnerBlob512 mirrors [importInnerBlob128] at the 512-bit
// width using [64]byte fixed arrays.
func importInnerBlob512(cfg *itb.Config, innerBytes []byte, innerHash string) ([8]any, [8][]byte, string, []byte, error) {
	var out [8]any
	var keys [8][]byte
	var b itb.Blob512
	if err := b.Import3Cfg(innerBytes, cfg); err != nil {
		return out, keys, "", nil, fmt.Errorf("triple: Blob512.Import3Cfg: %w", err)
	}
	if b.LS == nil {
		return out, keys, "", nil, fmt.Errorf("triple: inner blob missing lockSeed slot")
	}
	rawKeys := [8][64]byte{b.KeyN, b.KeyL, b.KeyD1, b.KeyD2, b.KeyD3, b.KeyS1, b.KeyS2, b.KeyS3}
	rawSeeds := [8]*itb.Seed512{b.NS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3}
	for i := 0; i < 8; i++ {
		keys[i] = append([]byte(nil), rawKeys[i][:]...)
		single, batched, _, err := hashes.Make512Pair(innerHash, keys[i])
		if err != nil {
			return out, keys, "", nil, fmt.Errorf("triple: hashes.Make512Pair(%q): %w", innerHash, err)
		}
		rawSeeds[i].Hash = single
		rawSeeds[i].BatchHash = batched
		out[i] = rawSeeds[i]
	}
	return out, keys, b.MACName, append([]byte(nil), b.MACKey...), nil
}

// importInnerBlobMixed is the mixed-primitive counterpart to
// [importInnerBlob]. Width-dispatches to the appropriate per-width
// mixed importer; each per-slot hash closure is rebuilt from the
// slot's own [Profile.MixedHashes] entry.
func importInnerBlobMixed(width int, cfg *itb.Config, innerBytes []byte, mixedHashes [8]string) ([8]any, [8][]byte, string, []byte, error) {
	switch width {
	case 128:
		return importInnerBlob128Mixed(cfg, innerBytes, mixedHashes)
	case 256:
		return importInnerBlob256Mixed(cfg, innerBytes, mixedHashes)
	case 512:
		return importInnerBlob512Mixed(cfg, innerBytes, mixedHashes)
	}
	return [8]any{}, [8][]byte{}, "", nil, fmt.Errorf("triple: unsupported inner blob width %d", width)
}

// importInnerBlob128Mixed decodes a 128-bit-width inner blob and
// rebuilds the eight typed seeds using per-slot primitive selection.
// Follows the same pattern as [importInnerBlob128] but consults
// mixedHashes[i] rather than a single innerHash.
func importInnerBlob128Mixed(cfg *itb.Config, innerBytes []byte, mixedHashes [8]string) ([8]any, [8][]byte, string, []byte, error) {
	var out [8]any
	var keys [8][]byte
	var b itb.Blob128
	if err := b.Import3Cfg(innerBytes, cfg); err != nil {
		return out, keys, "", nil, fmt.Errorf("triple: Blob128.Import3Cfg: %w", err)
	}
	if b.LS == nil {
		return out, keys, "", nil, fmt.Errorf("triple: inner blob missing lockSeed slot")
	}
	rawKeys := [8][]byte{b.KeyN, b.KeyL, b.KeyD1, b.KeyD2, b.KeyD3, b.KeyS1, b.KeyS2, b.KeyS3}
	rawSeeds := [8]*itb.Seed128{b.NS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3}
	for i := 0; i < 8; i++ {
		name := mixedHashes[i]
		keys[i] = append([]byte(nil), rawKeys[i]...)
		single, batched, _, err := hashes.Make128Pair(name, keys[i])
		if err != nil {
			// Keyless primitives (siphash24) reject a fixed-key
			// argument; retry with the no-key form since the seed's
			// Components carry all state.
			single, batched, _, err = hashes.Make128Pair(name)
			if err != nil {
				return out, keys, "", nil, fmt.Errorf("triple: hashes.Make128Pair(%q) slot %d: %w", name, i, err)
			}
			keys[i] = nil
		}
		rawSeeds[i].Hash = single
		rawSeeds[i].BatchHash = batched
		out[i] = rawSeeds[i]
	}
	return out, keys, b.MACName, append([]byte(nil), b.MACKey...), nil
}

// importInnerBlob256Mixed mirrors [importInnerBlob128Mixed] at the
// 256-bit width.
func importInnerBlob256Mixed(cfg *itb.Config, innerBytes []byte, mixedHashes [8]string) ([8]any, [8][]byte, string, []byte, error) {
	var out [8]any
	var keys [8][]byte
	var b itb.Blob256
	if err := b.Import3Cfg(innerBytes, cfg); err != nil {
		return out, keys, "", nil, fmt.Errorf("triple: Blob256.Import3Cfg: %w", err)
	}
	if b.LS == nil {
		return out, keys, "", nil, fmt.Errorf("triple: inner blob missing lockSeed slot")
	}
	rawKeys := [8][32]byte{b.KeyN, b.KeyL, b.KeyD1, b.KeyD2, b.KeyD3, b.KeyS1, b.KeyS2, b.KeyS3}
	rawSeeds := [8]*itb.Seed256{b.NS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3}
	for i := 0; i < 8; i++ {
		name := mixedHashes[i]
		keys[i] = append([]byte(nil), rawKeys[i][:]...)
		single, batched, _, err := hashes.Make256Pair(name, keys[i])
		if err != nil {
			return out, keys, "", nil, fmt.Errorf("triple: hashes.Make256Pair(%q) slot %d: %w", name, i, err)
		}
		rawSeeds[i].Hash = single
		rawSeeds[i].BatchHash = batched
		out[i] = rawSeeds[i]
	}
	return out, keys, b.MACName, append([]byte(nil), b.MACKey...), nil
}

// importInnerBlob512Mixed mirrors [importInnerBlob128Mixed] at the
// 512-bit width.
func importInnerBlob512Mixed(cfg *itb.Config, innerBytes []byte, mixedHashes [8]string) ([8]any, [8][]byte, string, []byte, error) {
	var out [8]any
	var keys [8][]byte
	var b itb.Blob512
	if err := b.Import3Cfg(innerBytes, cfg); err != nil {
		return out, keys, "", nil, fmt.Errorf("triple: Blob512.Import3Cfg: %w", err)
	}
	if b.LS == nil {
		return out, keys, "", nil, fmt.Errorf("triple: inner blob missing lockSeed slot")
	}
	rawKeys := [8][64]byte{b.KeyN, b.KeyL, b.KeyD1, b.KeyD2, b.KeyD3, b.KeyS1, b.KeyS2, b.KeyS3}
	rawSeeds := [8]*itb.Seed512{b.NS, b.LS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3}
	for i := 0; i < 8; i++ {
		name := mixedHashes[i]
		keys[i] = append([]byte(nil), rawKeys[i][:]...)
		single, batched, _, err := hashes.Make512Pair(name, keys[i])
		if err != nil {
			return out, keys, "", nil, fmt.Errorf("triple: hashes.Make512Pair(%q) slot %d: %w", name, i, err)
		}
		rawSeeds[i].Hash = single
		rawSeeds[i].BatchHash = batched
		out[i] = rawSeeds[i]
	}
	return out, keys, b.MACName, append([]byte(nil), b.MACKey...), nil
}
