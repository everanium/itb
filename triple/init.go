package triple

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// blobWrapV1 is the JSON wrap-layer that carries triple-side session
// state on the wire. The nested Blob{N} bytes (inner) live in the
// Inner field; the two masters are optional (omitted when the
// corresponding layer is disabled for this Pipeline); the two
// toggle-state booleans encode the parallax/wrapper posture so [Open]
// reconstructs the same chain shape without matching Opts.
//
// Single-letter JSON keys keep the wrap-layer compact
// (~80–120 bytes plus the inner blob).
type blobWrapV1 struct {
	Profile    string `json:"p"`
	Version    int    `json:"v"`
	PermMaster []byte `json:"pm,omitempty"`
	WrapMaster []byte `json:"wm,omitempty"`
	Inner      []byte `json:"ib"`
	Parallax   bool   `json:"wp"`
	Wrapper    bool   `json:"ww"`
}

// blobWrapVersionV1 is the current wrap-layer schema version.
const blobWrapVersionV1 = 1

// wrapMasterSize is the byte length of a fresh wrapper-side master
// drawn by [Init]. 32 bytes matches the wrapper's DeriveKey lower
// bound (see [wrapper.DeriveKey]).
const wrapMasterSize = 32

// Init constructs a fresh [Pipeline] against the named profile.
//
// Every 8-seed slot's Components slice + fixed PRF key + MAC key + the
// two masters + (when auto-generation is requested) the wrapper
// derived key + parallax subkeys are drawn from crypto/rand. The
// returned blob bytes carry the full session bundle the receiver
// needs — the profile name + wrap-layer version + both masters +
// nested [itb.Blob{N}] with the 8 seed components, per-slot PRF
// keys, and MAC material. Distribution of the blob is the caller's
// responsibility — treat the blob as the full key bundle.
//
// Master intake rules:
//
//   - [Opts.PermMaster] non-nil overrides parallax master auto-gen.
//   - [Opts.WrapMaster] non-nil overrides wrapper master auto-gen.
//   - If both are supplied AND compare bytewise-equal, returns
//     [ErrIdenticalMasters].
//
// Layer toggles derive from the profile default modulo any
// [Opts.WithParallax] / [Opts.WithWrapper] overrides. When a layer is
// disabled the corresponding master + derived state is still safely
// zero — the receiver reconstructs the same shape from the blob's
// recorded wp / ww fields.
func Init(profile string, opts Opts) (*Pipeline, []byte, error) {
	prof, err := lookupProfile(profile)
	if err != nil {
		return nil, nil, err
	}
	if opts.TagStubSize != 0 && (opts.TagStubSize < 16 || opts.TagStubSize > 64) {
		return nil, nil, fmt.Errorf("triple: Init: opts.TagStubSize=%d must be 0 or in [16, 64]", opts.TagStubSize)
	}
	resolved := resolveProfile(prof, opts)

	// Master intake / auto-generation.
	permMaster, wrapMaster, err := prepareMasters(resolved, opts)
	if err != nil {
		return nil, nil, err
	}

	// 8-seed allocation. Mixed-primitive profiles route through the
	// per-slot allocator; single-primitive profiles keep the original
	// one-primitive-for-all-eight-slots path.
	var (
		seeds   [8]any
		prfKeys [8][]byte
		width   int
	)
	if isMixedResolved(resolved) {
		seeds, prfKeys, width, err = allocEightSeedsMixed(resolved.mixedHashes, resolved.keyBits, resolved.width)
	} else {
		seeds, prfKeys, width, err = allocEightSeeds(resolved.innerHash, resolved.keyBits)
	}
	if err != nil {
		return nil, nil, err
	}

	// Per-instance Config snapshot.
	cfg := &itb.Config{
		NonceBits:   opts.NonceBits,
		BarrierFill: opts.BarrierFill,
		MaxWorkers:  opts.MaxWorkers,
	}
	// Backfill fields left at zero from the compile-in defaults so the
	// Cfg-aware Blob export path (which requires a valid nonce /
	// barrier width) always emits well-formed globals — the
	// per-Pipeline override semantic is preserved: any field the caller
	// left at zero simply picks up the compile-in default at Init time.
	if cfg.NonceBits == 0 {
		cfg.NonceBits = itb.DefaultNonceBits
	}
	if cfg.BarrierFill == 0 {
		cfg.BarrierFill = itb.DefaultBarrierFill
	}
	// Wire-shape pinning, profile / Opts layer: a caller-supplied
	// TagStubSize (Opts override strongest, then the registered
	// profile's field) lands in the Config ahead of the MAC probe
	// below, so the precedence chain reads
	// Opts > Profile > MacName auto-probe > default 32.
	if cfg.TagStubSize == 0 && resolved.tagStubSize > 0 {
		cfg.TagStubSize = resolved.tagStubSize
	}

	// Parallax build.
	var (
		sched *parallax.Schedule
		cs    *parallax.Cipherset
	)
	if resolved.parallaxOn {
		sched, err = parallax.NewSchedule(resolved.parallaxPalette, resolved.parallaxSegmentSize)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: parallax.NewSchedule: %w", err)
		}
		if resolved.chunkSize > 0 {
			if serr := sched.SetChunkSize(resolved.chunkSize); serr != nil {
				return nil, nil, fmt.Errorf("triple: parallax.SetChunkSize: %w", serr)
			}
		}
		cs, err = parallax.NewCipherset(permMaster, sched)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: parallax.NewCipherset: %w", err)
		}
	}

	// Wrapper build.
	var wrapperKey []byte
	if resolved.wrapperOn {
		wrapperKey, err = wrapper.DeriveKey(resolved.outerCipher, wrapMaster)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: wrapper.DeriveKey: %w", err)
		}
	}

	// MAC build.
	var (
		macKey  []byte
		macFunc itb.MACFunc
	)
	if resolved.macName != "" {
		spec, ok := macs.Find(resolved.macName)
		if !ok {
			return nil, nil, fmt.Errorf("triple: unknown MAC %q", resolved.macName)
		}
		macKey = make([]byte, spec.KeySize)
		if _, rerr := rand.Read(macKey); rerr != nil {
			return nil, nil, fmt.Errorf("triple: crypto/rand: %w", rerr)
		}
		macFunc, err = macs.Make(resolved.macName, macKey)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: macs.Make(%q): %w", resolved.macName, err)
		}
		// Multi-slice MAC arm: lets the authenticated entry points
		// absorb the MAC input parts without the concatenation copy.
		// Same primitive, same key — tags are byte-identical.
		cfg.MACIncremental, err = macs.MakeIncremental(resolved.macName, macKey)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: macs.MakeIncremental(%q): %w", resolved.macName, err)
		}
		// Wire-shape parity: carry the MAC's probed tag length into the
		// Config so a No MAC envelope produced under this cfg reserves a
		// stub of matching size — the authenticated ↔ No MAC envelope
		// shape then stays aligned for any registered TagSize, not only
		// the shipped 32-byte tags. An explicitly pre-set field wins.
		if cfg.TagStubSize == 0 {
			cfg.TagStubSize = len(macFunc([]byte{}))
		}
	}

	// Inner Blob{N} export via the Cfg-aware API.
	innerBlob, err := exportInnerBlob(width, cfg, seeds, prfKeys, macKey, resolved.macName)
	if err != nil {
		return nil, nil, err
	}

	// Wrap-layer JSON. Masters are dropped from the wire when the
	// corresponding layer is disabled so a receiver that opens with
	// only one layer active cannot recover the unused master.
	wrap := blobWrapV1{
		Profile:  resolved.name,
		Version:  blobWrapVersionV1,
		Inner:    innerBlob,
		Parallax: resolved.parallaxOn,
		Wrapper:  resolved.wrapperOn,
	}
	if resolved.parallaxOn {
		wrap.PermMaster = append([]byte(nil), permMaster...)
	}
	if resolved.wrapperOn {
		wrap.WrapMaster = append([]byte(nil), wrapMaster...)
	}

	wrapBytes, err := json.Marshal(wrap)
	if err != nil {
		return nil, nil, fmt.Errorf("triple: wrap-layer marshal: %w", err)
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
		macName:       resolved.macName,
	}
	return p, wrapBytes, nil
}

// prepareMasters resolves the two masters from the profile shape and
// the [Opts] overrides. Auto-gen kicks in only for layers that are
// engaged for this Pipeline — a disabled layer receives nil, since
// its master will be dropped from the wire and never consumed.
//
// The [ErrIdenticalMasters] check runs whenever both masters are
// present (non-nil) — protects callers from accidentally passing the
// same byte slice to both master parameters.
func prepareMasters(resolved resolvedProfile, opts Opts) (permMaster, wrapMaster []byte, err error) {
	if resolved.parallaxOn {
		if opts.PermMaster != nil {
			permMaster = append([]byte(nil), opts.PermMaster...)
		} else {
			permMaster, err = parallax.GenerateMasterKey()
			if err != nil {
				return nil, nil, fmt.Errorf("triple: parallax.GenerateMasterKey: %w", err)
			}
		}
	}
	if resolved.wrapperOn {
		if opts.WrapMaster != nil {
			wrapMaster = append([]byte(nil), opts.WrapMaster...)
		} else {
			wrapMaster = make([]byte, wrapMasterSize)
			if _, err = rand.Read(wrapMaster); err != nil {
				return nil, nil, fmt.Errorf("triple: crypto/rand: %w", err)
			}
		}
	}
	if permMaster != nil && wrapMaster != nil && bytes.Equal(permMaster, wrapMaster) {
		return nil, nil, ErrIdenticalMasters
	}
	return permMaster, wrapMaster, nil
}

// exportInnerBlob width-dispatches to the appropriate
// [itb.Blob{128,256,512}.Export3Cfg] entry to produce the inner blob
// bytes. The MAC material rides through [itb.Blob{N}Opts] when the
// Pipeline carries a MAC; No MAC profiles pass a zero-value opts.
func exportInnerBlob(width int, cfg *itb.Config, seeds [8]any, prfKeys [8][]byte, macKey []byte, macName string) ([]byte, error) {
	switch width {
	case 128:
		return exportInnerBlob128(cfg, seeds, prfKeys, macKey, macName)
	case 256:
		return exportInnerBlob256(cfg, seeds, prfKeys, macKey, macName)
	case 512:
		return exportInnerBlob512(cfg, seeds, prfKeys, macKey, macName)
	}
	return nil, fmt.Errorf("triple: unsupported inner blob width %d", width)
}

// exportInnerBlob128 packs the 128-bit-width inner blob via
// [itb.Blob128.Export3Cfg]. Slot mapping mirrors the canonical
// 8-seed order in [allocEightSeeds].
func exportInnerBlob128(cfg *itb.Config, seeds [8]any, prfKeys [8][]byte, macKey []byte, macName string) ([]byte, error) {
	var b itb.Blob128
	var opts itb.Blob128Opts
	// The lockSeed slot rides as the dedicated LockSeed in the Blob
	// opts alongside the other seven Triple 8-seed constellation
	// entries packed into the blob's core fields.
	opts.KeyL = append([]byte(nil), prfKeys[1]...)
	opts.LS = seeds[1].(*itb.Seed128)
	if len(macKey) > 0 {
		opts.MACKey = append([]byte(nil), macKey...)
		opts.MACName = macName
	}
	return b.Export3Cfg(
		cfg,
		prfKeys[0], prfKeys[2], prfKeys[3], prfKeys[4],
		prfKeys[5], prfKeys[6], prfKeys[7],
		seeds[0].(*itb.Seed128),
		seeds[2].(*itb.Seed128), seeds[3].(*itb.Seed128), seeds[4].(*itb.Seed128),
		seeds[5].(*itb.Seed128), seeds[6].(*itb.Seed128), seeds[7].(*itb.Seed128),
		opts,
	)
}

// exportInnerBlob256 packs the 256-bit-width inner blob via
// [itb.Blob256.Export3Cfg]. The 256-bit width uses [32]byte fixed
// arrays for every hash-key slot; per-slot copy avoids passing an
// aliased slice header past the boundary.
func exportInnerBlob256(cfg *itb.Config, seeds [8]any, prfKeys [8][]byte, macKey []byte, macName string) ([]byte, error) {
	var b itb.Blob256
	var opts itb.Blob256Opts
	var keys [8][32]byte
	for i, k := range prfKeys {
		copy(keys[i][:], k)
	}
	opts.KeyL = keys[1]
	opts.LS = seeds[1].(*itb.Seed256)
	if len(macKey) > 0 {
		opts.MACKey = append([]byte(nil), macKey...)
		opts.MACName = macName
	}
	return b.Export3Cfg(
		cfg,
		keys[0], keys[2], keys[3], keys[4],
		keys[5], keys[6], keys[7],
		seeds[0].(*itb.Seed256),
		seeds[2].(*itb.Seed256), seeds[3].(*itb.Seed256), seeds[4].(*itb.Seed256),
		seeds[5].(*itb.Seed256), seeds[6].(*itb.Seed256), seeds[7].(*itb.Seed256),
		opts,
	)
}

// exportInnerBlob512 packs the 512-bit-width inner blob via
// [itb.Blob512.Export3Cfg]. Follows the same pattern as
// [exportInnerBlob256] with [64]byte fixed arrays.
func exportInnerBlob512(cfg *itb.Config, seeds [8]any, prfKeys [8][]byte, macKey []byte, macName string) ([]byte, error) {
	var b itb.Blob512
	var opts itb.Blob512Opts
	var keys [8][64]byte
	for i, k := range prfKeys {
		copy(keys[i][:], k)
	}
	opts.KeyL = keys[1]
	opts.LS = seeds[1].(*itb.Seed512)
	if len(macKey) > 0 {
		opts.MACKey = append([]byte(nil), macKey...)
		opts.MACName = macName
	}
	return b.Export3Cfg(
		cfg,
		keys[0], keys[2], keys[3], keys[4],
		keys[5], keys[6], keys[7],
		seeds[0].(*itb.Seed512),
		seeds[2].(*itb.Seed512), seeds[3].(*itb.Seed512), seeds[4].(*itb.Seed512),
		seeds[5].(*itb.Seed512), seeds[6].(*itb.Seed512), seeds[7].(*itb.Seed512),
		opts,
	)
}
