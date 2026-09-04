package triple

import (
	"bytes"
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// openWrap is the build body shared by [Load] and [LoadF]: it takes a
// decoded and recipe-validated wrap-layer plus the trailing masters
// override and rebuilds the [Pipeline] from the record, the inner
// Blob{N}, and the resolved masters. The profile registry is not
// consulted and no Opts are merged — the record is reproduced
// exactly, layer set included.
//
// Master resolution:
//
//   - When len(masters) == 0, the parallax and wrapper masters are
//     read from the blob's pm / wm slots (subject to the record's
//     layer toggles).
//   - When len(masters) == 2, the trailing masters
//     (masters[0] = permMaster, masters[1] = wrapMaster) replace the
//     blob's slots — the rekey-on-import path.
//
// If the resolved masters compare bytewise-equal,
// [ErrIdenticalMasters] is returned.
//
// After a successful build the wrap-layer is re-marshalled from the
// record and the resolved masters and retained for [Pipeline.Save],
// so a master override is reflected in the bytes the Pipeline hands
// out. The worker cap starts at auto (runtime.NumCPU): the blob
// carries none, and [Pipeline.MaxWorkers] overrides it.
func openWrap(wrap blobWrapV2, masters [][]byte) (*Pipeline, error) {
	resolved := wrap.Profile
	resolved.ParallaxPalette = append([]string(nil), wrap.Profile.ParallaxPalette...)

	// Resolve masters.
	permMaster, wrapMaster, err := resolveOpenMasters(resolved, wrap, masters)
	if err != nil {
		return nil, err
	}

	// The record's Width is the inner blob width for both dispatch
	// paths: checkRecipeProfile has already verified that InnerHash
	// (or every MixedHashes slot) resolves to a primitive of exactly
	// that width.
	width := resolved.Width

	// Decode the inner Blob{N} via the Cfg-aware Import3Cfg entry so
	// no process-global mutation occurs during Load. Mixed-primitive
	// records pass the per-slot constellation so each seed's hash
	// closure is rebuilt with the correct primitive; single-primitive
	// records pass InnerHash for all 8 slots.
	cfg := &itb.Config{}
	var (
		seeds   [8]any
		prfKeys [8][]byte
		macName string
		macKey  []byte
	)
	if isMixedProfile(resolved) {
		seeds, prfKeys, macName, macKey, err = importInnerBlobMixed(width, cfg, wrap.Inner, resolved.MixedHashes)
	} else {
		seeds, prfKeys, macName, macKey, err = importInnerBlob(width, cfg, wrap.Inner, resolved.InnerHash)
	}
	if err != nil {
		return nil, err
	}

	// Cross-check the record against the inner blob: the MAC name
	// must agree (both empty for No MAC) and the seed key width must
	// equal the record's KeyBits. Either disagreement means the two
	// halves of the blob describe different Pipelines.
	if macName != resolved.MacName {
		return nil, fmt.Errorf("%w: record mac %q, inner blob mac %q", ErrBlobMalformedRecipe, resolved.MacName, macName)
	}
	if kb := seedKeyBits(seeds[0]); kb != resolved.KeyBits {
		return nil, fmt.Errorf("%w: record keybits %d, inner blob key width %d", ErrBlobMalformedRecipe, resolved.KeyBits, kb)
	}

	// Wire-shape pinning — mirrors the Init-side placement ahead of
	// the MAC probe so the precedence chain reads Profile > MacName
	// auto-probe > default 32 on the reopen path as well. The inner
	// blob's Config snapshot carries no stub field, so the gate
	// consults only the record.
	if cfg.TagStubSize == 0 && resolved.TagStubSize > 0 {
		cfg.TagStubSize = resolved.TagStubSize
	}

	// Parallax build.
	var (
		sched *parallax.Schedule
		cs    *parallax.Cipherset
	)
	if resolved.Parallax {
		sched, err = parallax.NewSchedule(resolved.ParallaxPalette, resolved.ParallaxSegmentSize)
		if err != nil {
			return nil, fmt.Errorf("triple: parallax.NewSchedule: %w", err)
		}
		if resolved.ChunkSize > 0 {
			if serr := sched.SetChunkSize(resolved.ChunkSize); serr != nil {
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
	if resolved.Wrapper {
		wrapperKey, err = wrapper.DeriveKey(resolved.OuterCipher, wrapMaster)
		if err != nil {
			return nil, fmt.Errorf("triple: wrapper.DeriveKey: %w", err)
		}
	}

	// MAC build from the inner blob's material (already verified to
	// agree with the record).
	var macFunc itb.MACFunc
	if macName != "" {
		macFunc, err = macs.Make(macName, macKey)
		if err != nil {
			return nil, fmt.Errorf("triple: macs.Make(%q): %w", macName, err)
		}
		// Multi-slice MAC arm: lets the authenticated entry points
		// absorb the MAC input parts without the concatenation copy.
		// Same primitive, same key — tags are byte-identical.
		cfg.MACIncremental, err = macs.MakeIncremental(macName, macKey)
		if err != nil {
			return nil, fmt.Errorf("triple: macs.MakeIncremental(%q): %w", macName, err)
		}
		// Wire-shape parity: mirror the Init-side auto-population from
		// the blob's MAC so a reopened Pipeline reserves the same No
		// MAC stub size as its sender. An explicitly pre-set field
		// wins.
		if cfg.TagStubSize == 0 {
			cfg.TagStubSize = len(macFunc([]byte{}))
		}
	}

	// Re-marshal the wrap-layer from the record and the resolved
	// masters so Save reflects a rekey-on-import override. The inner
	// bytes are reused verbatim — no re-export.
	blob, err := marshalWrap(resolved, wrap.Inner, permMaster, wrapMaster)
	if err != nil {
		return nil, err
	}

	p := &Pipeline{
		resolved:      resolved,
		blob:          blob,
		width:         width,
		cfg:           cfg,
		seeds:         seeds,
		prfKeys:       prfKeys,
		parallaxSched: sched,
		parallaxCS:    cs,
		wrapperKey:    wrapperKey,
		wrapperCipher: resolved.OuterCipher,
		macKey:        macKey,
		macFunc:       macFunc,
		macName:       macName,
	}
	return p, nil
}

// seedKeyBits returns the key width in bits of one imported seed —
// the Components count times 64 — or 0 for an unrecognised seed type.
// Used by [openWrap] to cross-check the record's KeyBits against the
// inner blob.
func seedKeyBits(seed any) int {
	switch s := seed.(type) {
	case *itb.Seed128:
		return len(s.Components) * 64
	case *itb.Seed256:
		return len(s.Components) * 64
	case *itb.Seed512:
		return len(s.Components) * 64
	}
	return 0
}

// resolveOpenMasters folds the blob-supplied masters and the trailing
// variadic overrides into (permMaster, wrapMaster), and rejects
// invalid combinations.
func resolveOpenMasters(resolved Profile, wrap blobWrapV2, masters [][]byte) (permMaster, wrapMaster []byte, err error) {
	// Upper cap on both master-source paths — the trailing variadic
	// override (rekey-on-import) and the persisted wrap-layer slots.
	// The wrap-layer slots have already survived one JSON decode
	// allocation at Load's entry, but capping here still prevents the
	// second amplification via the "append([]byte(nil), ...)" copies
	// below and short-circuits every downstream consumer.
	if len(masters) == 2 {
		if len(masters[0]) > parallax.MaxMasterKeySize {
			return nil, nil, fmt.Errorf("triple: Load: permMaster override length %d exceeds parallax.MaxMasterKeySize=%d", len(masters[0]), parallax.MaxMasterKeySize)
		}
		if len(masters[1]) > wrapper.MaxMasterKeySize {
			return nil, nil, fmt.Errorf("triple: Load: wrapMaster override length %d exceeds wrapper.MaxMasterKeySize=%d", len(masters[1]), wrapper.MaxMasterKeySize)
		}
		permMaster = append([]byte(nil), masters[0]...)
		wrapMaster = append([]byte(nil), masters[1]...)
	} else {
		if len(wrap.PermMaster) > parallax.MaxMasterKeySize {
			return nil, nil, fmt.Errorf("triple: Load: blob PermMaster length %d exceeds parallax.MaxMasterKeySize=%d", len(wrap.PermMaster), parallax.MaxMasterKeySize)
		}
		if len(wrap.WrapMaster) > wrapper.MaxMasterKeySize {
			return nil, nil, fmt.Errorf("triple: Load: blob WrapMaster length %d exceeds wrapper.MaxMasterKeySize=%d", len(wrap.WrapMaster), wrapper.MaxMasterKeySize)
		}
		if len(wrap.PermMaster) > 0 {
			permMaster = append([]byte(nil), wrap.PermMaster...)
		}
		if len(wrap.WrapMaster) > 0 {
			wrapMaster = append([]byte(nil), wrap.WrapMaster...)
		}
	}
	if resolved.Parallax && len(permMaster) == 0 {
		return nil, nil, ErrMissingMasters
	}
	if resolved.Wrapper && len(wrapMaster) == 0 {
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
// MAC name and MAC key the blob carries (both empty for No MAC).
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
