package triple

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/everanium/itb"
	"github.com/everanium/itb/kdf"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// blobWrapV2 is the JSON wrap-layer that carries Triple-side session
// state on the wire:
//
//	v   wrap-layer schema version (= 2)
//	p   the recipe — the resolved [Profile] record (see
//	    [Profile.MarshalJSON] for its key set); its name is the
//	    sender's label
//	ib  the inner Blob{N} JSON, embedded verbatim as an
//	    object (the only carrier of seed / PRF-key / MAC-key material)
//	pm  32-byte parallax master, base64; present only if p.parallax
//	wm  32-byte wrapper master, base64; present only if p.wrapper
//
// The record is the sole structural source on the reopen path: [Load]
// rebuilds every layer from it, and the profile registry is never
// consulted. The decoder is strict (unknown key → [ErrBlobMalformed]);
// any schema change bumps v.
type blobWrapV2 struct {
	Version    int             `json:"v"`
	Profile    Profile         `json:"p"`
	Inner      json.RawMessage `json:"ib"`
	PermMaster []byte          `json:"pm,omitempty"`
	WrapMaster []byte          `json:"wm,omitempty"`
}

// blobWrapVersionV2 is the wrap-layer schema version this build
// encodes and decodes. Blobs carrying any other version are refused
// with [ErrBlobVersion].
const blobWrapVersionV2 = 2

// marshalWrap builds the wrap-layer from the resolved [Profile]
// record, the inner blob bytes, and the resolved masters. Inert layer
// fields are cleared and a disabled layer's master is dropped from
// the wire so a receiver that opens with only one layer active cannot
// recover the unused master. Every wrap-layer producer ([Init],
// [InitKeys], [Load], [Pipeline.Rekey]) routes through this helper, so
// the blob always describes the shape and keys the Pipeline runs with.
func marshalWrap(prof Profile, inner, permMaster, wrapMaster []byte) ([]byte, error) {
	rec := prof
	rec.ParallaxPalette = append([]string(nil), prof.ParallaxPalette...)
	if !rec.Wrapper {
		rec.OuterCipher = ""
	}
	if !rec.Parallax {
		rec.ParallaxPalette, rec.ParallaxSegmentSize = nil, 0
	}
	// Recipe is wire-only; runtime globals (NonceBits, BarrierFill)
	// live in the inner Blob{N}.Globals snapshot and the container
	// floor mode in the inner blob's mode field; none of them appears
	// in the wrap-layer recipe object. The invariant is enforced upstream
	// (Register + Load fail-fast on non-zero values, resolveProfile
	// does not carry Opts.NonceBits / Opts.BarrierFill into the stored
	// Profile), but a caller that mutates a Profile literal directly
	// before feeding it here would otherwise leak runtime state onto
	// the wire. Clearing them defensively guarantees byte-identical
	// wire shape regardless of the upstream Profile provenance.
	rec.NonceBits = 0
	rec.BarrierFill = 0
	rec.ContainerMode = 0
	wrap := blobWrapV2{
		Version: blobWrapVersionV2,
		Profile: rec,
		Inner:   json.RawMessage(inner),
	}
	if rec.Parallax {
		wrap.PermMaster = append([]byte(nil), permMaster...)
		defer clear(wrap.PermMaster)
	}
	if rec.Wrapper {
		wrap.WrapMaster = append([]byte(nil), wrapMaster...)
		defer clear(wrap.WrapMaster)
	}
	out, err := json.Marshal(wrap)
	if err != nil {
		return nil, fmt.Errorf("triple: wrap-layer marshal: %w", err)
	}
	return out, nil
}

// wrapMasterSize is the byte length of a fresh wrapper-side master
// drawn by [Init]. 32 bytes matches the wrapper's DeriveKey lower
// bound (see [wrapper.DeriveKey]).
const wrapMasterSize = 32

// Init constructs a fresh [Pipeline] against the named profile and
// returns it together with its blob — the same bytes [Pipeline.Save]
// returns on the fresh Pipeline.
//
// Every 8-seed slot's Components slice + fixed PRF key + MAC key + the
// two masters + (when auto-generation is requested) the wrapper
// derived key + parallax subkeys are drawn from crypto/rand. The
// returned blob bytes carry the full session bundle the receiver
// needs — the resolved [Profile] record (profile defaults with the
// Opts overrides folded in, Name carrying the profile name, including
// DRBG and TagStubSize) + both masters + the nested [itb.Blob{N}]
// with the 8 seed components, per-slot PRF keys, MAC material, and
// the Mode / NonceBits / BarrierFill snapshot. The receiver rebuilds
// an equivalent Pipeline with [Load]
// without holding the profile literal or the Opts. Distribution of
// the blob is the caller's responsibility — treat the blob as the
// full key bundle.
//
// [Opts.MaxWorkers] is snapshotted into the Pipeline's Config
// (clamped per [Pipeline.MaxWorkers]) but never into the blob.
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
// zero — the receiver reconstructs the same shape from the record's
// toggles.
func Init(profile string, opts Opts) (*Pipeline, []byte, error) {
	resolved, err := resolveInitProfile("Init", profile, opts)
	if err != nil {
		return nil, nil, err
	}

	// Master intake / auto-generation.
	permMaster, wrapMaster, err := prepareMasters(resolved, opts)
	if err != nil {
		return nil, nil, err
	}
	defer clear(permMaster)
	defer clear(wrapMaster)

	// 8-seed allocation. Mixed-primitive profiles route through the
	// per-slot allocator; single-primitive profiles use the
	// one-primitive-for-all-eight-slots path.
	var (
		seeds   [8]any
		prfKeys [8][]byte
		width   int
	)
	if isMixedProfile(resolved) {
		seeds, prfKeys, width, err = allocEightSeedsMixed(resolved.MixedHashes, resolved.KeyBits, resolved.Width)
	} else {
		seeds, prfKeys, width, err = allocEightSeeds(resolved.InnerHash, resolved.KeyBits)
	}
	if err != nil {
		return nil, nil, err
	}
	// The record must be self-consistent: an Opts.InnerHash override
	// may select a primitive of a different width than the profile
	// default, and the allocator reports the width actually in force.
	resolved.Width = width

	var macKey []byte
	if resolved.MacName != "" {
		spec, found := macs.Find(resolved.MacName)
		if !found {
			for _, s := range seeds {
				zeroSeedComponents(s, width)
			}
			for _, k := range prfKeys {
				clear(k)
			}
			return nil, nil, fmt.Errorf("triple: unknown MAC %q", resolved.MacName)
		}
		macKey = make([]byte, spec.KeySize)
		if _, rerr := rand.Read(macKey); rerr != nil {
			for _, s := range seeds {
				zeroSeedComponents(s, width)
			}
			for _, k := range prfKeys {
				clear(k)
			}
			clear(macKey)
			return nil, nil, fmt.Errorf("triple: crypto/rand: %w", rerr)
		}
	}

	return finishInit(resolved, opts, width, seeds, prfKeys, permMaster, wrapMaster, macKey)
}

// InitKeys constructs a fresh [Pipeline] deterministically from eight
// caller-supplied master keys (one per canonical seed slot 0..7)
// against the named profile and [Opts], returning the Pipeline and its
// self-describing session blob.
//
// Two peers calling InitKeys with identical (profile, opts, masters)
// obtain bit-identical Pipelines and bit-identical blob bytes without
// transmitting the session blob over the network. The returned blob is
// also loadable via [Load] and [LoadF].
//
// Security note: the eight master keys in masters[0..7] must come from
// independent entropy or key-agreement sources; never derive all eight
// master keys from a single secret or a single KDF parent key. Each
// slot master must be at least 16 bytes for 128-bit KDF slots
// ("aescmac", "siphash24") or 32 bytes for 256/512-bit KDF slots, at
// most [parallax.MaxMasterKeySize] (128) bytes, and pairwise distinct
// across all 28 pairs (both full slice and KDF-consumed prefix).
func InitKeys(profile string, opts Opts, masters [8][]byte) (*Pipeline, []byte, error) {
	resolved, err := resolveInitProfile("InitKeys", profile, opts)
	if err != nil {
		return nil, nil, err
	}

	slotPrims, kdfPrims, width, err := resolveSlotPrimitives(resolved)
	if err != nil {
		return nil, nil, err
	}
	resolved.Width = width

	if err := validateMasterKeys(kdfPrims, masters); err != nil {
		return nil, nil, err
	}

	permMaster, wrapMaster, err := prepareMastersFromKeys(resolved, opts, kdfPrims, masters)
	if err != nil {
		return nil, nil, err
	}
	defer clear(permMaster)
	defer clear(wrapMaster)

	seeds, prfKeys, err := deriveEightSeeds(slotPrims, kdfPrims, resolved.KeyBits, width, masters)
	if err != nil {
		return nil, nil, err
	}

	var macKey []byte
	if resolved.MacName != "" {
		spec, found := macs.Find(resolved.MacName)
		if !found {
			for _, s := range seeds {
				zeroSeedComponents(s, width)
			}
			for _, k := range prfKeys {
				clear(k)
			}
			return nil, nil, fmt.Errorf("triple: unknown MAC %q", resolved.MacName)
		}
		macKey, err = deriveCombinedKey(kdfPrims, masters, "mac", spec.KeySize)
		if err != nil {
			for _, s := range seeds {
				zeroSeedComponents(s, width)
			}
			for _, k := range prfKeys {
				clear(k)
			}
			return nil, nil, err
		}
	}

	return finishInit(resolved, opts, width, seeds, prfKeys, permMaster, wrapMaster, macKey)
}

// resolveInitProfile validates the profile name and [Opts] overrides
// shared by [Init] and [InitKeys], returning the resolved [Profile].
func resolveInitProfile(caller, profile string, opts Opts) (Profile, error) {
	prof, err := Lookup(profile)
	if err != nil {
		return Profile{}, err
	}
	if opts.TagStubSize != 0 && (opts.TagStubSize < 16 || opts.TagStubSize > 64) {
		return Profile{}, fmt.Errorf("triple: %s: opts.TagStubSize=%d must be 0 or in [16, 64]", caller, opts.TagStubSize)
	}
	if err := validateOptsCommon(caller, opts); err != nil {
		return Profile{}, err
	}
	if err := validateOptsStrings(caller, opts); err != nil {
		return Profile{}, err
	}
	resolved := resolveProfile(prof, opts)
	if err := validateResolvedKeyBits(caller, resolved); err != nil {
		return Profile{}, err
	}
	if err := validateResolvedChunkSize(caller, resolved); err != nil {
		return Profile{}, err
	}
	if err := validateResolvedDRBG(caller, resolved); err != nil {
		return Profile{}, err
	}
	return resolved, nil
}

// finishInit assembles the [Pipeline] and wrap-layer blob from the
// resolved profile, 8 seeds, PRF keys, and layer/MAC keys. Shared by
// [Init] and [InitKeys]; wipes all passed-in secret material on error.
func finishInit(resolved Profile, opts Opts, width int, seeds [8]any, prfKeys [8][]byte, permMaster, wrapMaster, macKey []byte) (*Pipeline, []byte, error) {
	var (
		sched      *parallax.Schedule
		cs         *parallax.Cipherset
		wrapperKey []byte
		macFunc    itb.MACFunc
		ok         bool
	)
	defer func() {
		if !ok {
			for _, s := range seeds {
				zeroSeedComponents(s, width)
			}
			for _, k := range prfKeys {
				clear(k)
			}
			_ = cs.Close()
			clear(wrapperKey)
			clear(macKey)
		}
	}()

	// Per-instance Config snapshot. The worker cap is clamped into
	// the Config envelope here and lives only on the Pipeline; it is
	// not part of the exported blob.
	cfg := &itb.Config{
		Mode:        opts.Mode,
		NonceBits:   opts.NonceBits,
		BarrierFill: opts.BarrierFill,
		MaxWorkers:  clampWorkers(opts.MaxWorkers),
	}
	// Backfill fields left at zero from the compile-in defaults so the
	// Cfg-aware Blob export path (which requires a valid nonce /
	// barrier width / container mode) always emits well-formed globals — the
	// per-Pipeline override semantic is preserved: any field the caller
	// left at zero simply picks up the compile-in default at Init time.
	if cfg.Mode == 0 {
		cfg.Mode = 1
	}
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
	if cfg.TagStubSize == 0 && resolved.TagStubSize > 0 {
		cfg.TagStubSize = resolved.TagStubSize
	}
	// The DRBG fill primitive is a recipe field: the resolved record
	// carries it into the blob and the Config consumes it on every
	// encrypt.
	cfg.DRBG = resolved.DRBG

	// Parallax build.
	if resolved.Parallax {
		var err error
		sched, err = parallax.NewSchedule(resolved.ParallaxPalette, resolved.ParallaxSegmentSize)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: parallax.NewSchedule: %w", err)
		}
		if resolved.ChunkSize > 0 {
			if serr := sched.SetChunkSize(resolved.ChunkSize); serr != nil {
				return nil, nil, fmt.Errorf("triple: parallax.SetChunkSize: %w", serr)
			}
		}
		cs, err = parallax.NewCipherset(permMaster, sched)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: parallax.NewCipherset: %w", err)
		}
	}

	// Wrapper build.
	if resolved.Wrapper {
		var err error
		wrapperKey, err = wrapper.DeriveKey(resolved.OuterCipher, wrapMaster)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: wrapper.DeriveKey: %w", err)
		}
	}

	// MAC build.
	if resolved.MacName != "" {
		var err error
		macFunc, err = macs.Make(resolved.MacName, macKey)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: macs.Make(%q): %w", resolved.MacName, err)
		}
		// Multi-slice MAC arm: lets the authenticated entry points
		// absorb the MAC input parts without the concatenation copy.
		// Same primitive, same key — tags are byte-identical.
		cfg.MACIncremental, err = macs.MakeIncremental(resolved.MacName, macKey)
		if err != nil {
			return nil, nil, fmt.Errorf("triple: macs.MakeIncremental(%q): %w", resolved.MacName, err)
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
	innerBlob, err := exportInnerBlob(width, cfg, seeds, prfKeys, macKey, resolved.MacName)
	if err != nil {
		return nil, nil, err
	}
	defer clear(innerBlob)

	// Wrap-layer JSON from the resolved record and the resolved
	// masters. The Pipeline retains one copy for Save; the caller
	// receives another.
	wrapBytes, err := marshalWrap(resolved, innerBlob, permMaster, wrapMaster)
	if err != nil {
		return nil, nil, err
	}

	p := &Pipeline{
		resolved:      resolved,
		blob:          append([]byte(nil), wrapBytes...),
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
		macName:       resolved.MacName,
	}
	ok = true
	return p, wrapBytes, nil
}

// validateMasterKeys enforces per-slot length bounds and pairwise
// distinctness (both full-slice equality and KDF-consumed prefix
// equality) across all 8 master keys passed to [InitKeys].
func validateMasterKeys(kdfPrims [8]string, masters [8][]byte) error {
	for i := 0; i < 8; i++ {
		if len(masters[i]) == 0 {
			return fmt.Errorf("%w: triple: InitKeys: masters[%d] is empty", ErrMissingMasters, i)
		}
		minLen := kdfKeyMinLen(kdfPrims[i])
		if len(masters[i]) < minLen {
			return fmt.Errorf("triple: InitKeys: masters[%d] length %d below %s minimum %d",
				i, len(masters[i]), kdfPrims[i], minLen)
		}
		if len(masters[i]) > parallax.MaxMasterKeySize {
			return fmt.Errorf("triple: InitKeys: masters[%d] length %d exceeds parallax.MaxMasterKeySize=%d",
				i, len(masters[i]), parallax.MaxMasterKeySize)
		}
	}
	for i := 0; i < 8; i++ {
		effI := kdfKeyMinLen(kdfPrims[i])
		for j := i + 1; j < 8; j++ {
			effJ := kdfKeyMinLen(kdfPrims[j])
			eff := min(effI, effJ)
			if bytes.Equal(masters[i], masters[j]) || bytes.Equal(masters[i][:eff], masters[j][:eff]) {
				return fmt.Errorf("%w: triple: InitKeys: masters[%d] and masters[%d] must be distinct",
					ErrIdenticalMasters, i, j)
			}
		}
	}
	return nil
}

// deriveCombinedKey derives an outLen-byte key coupled to all 8 slot
// masters by XOR-combining per-slot [kdf.Derive] outputs under
// domain-separated "<role>:<i>" labels (each <= 8 bytes, within the
// 24-byte XChaCha20 label limit of kdf.Derive("chacha20")).
func deriveCombinedKey(kdfPrims [8]string, masters [8][]byte, role string, outLen int) ([]byte, error) {
	out := make([]byte, outLen)
	for i := 0; i < 8; i++ {
		label := fmt.Sprintf("%s:%d", role, i)
		part, err := kdf.Derive(kdfPrims[i], masters[i], label, outLen)
		if err != nil {
			clear(out)
			return nil, fmt.Errorf("triple: InitKeys: slot %d %s kdf: %w", i, role, err)
		}
		for b := range out {
			out[b] ^= part[b]
		}
		clear(part)
	}
	return out, nil
}

// prepareMastersFromKeys resolves permMaster and wrapMaster for
// [InitKeys], using caller-supplied [Opts.PermMaster] /
// [Opts.WrapMaster] overrides when present and otherwise deriving
// 32-byte masters deterministically from all 8 slot masters via
// [deriveCombinedKey].
func prepareMastersFromKeys(resolved Profile, opts Opts, kdfPrims [8]string, masters [8][]byte) (permMaster, wrapMaster []byte, err error) {
	if opts.PermMaster != nil && len(opts.PermMaster) > parallax.MaxMasterKeySize {
		return nil, nil, fmt.Errorf("triple: opts.PermMaster length %d exceeds parallax.MaxMasterKeySize=%d", len(opts.PermMaster), parallax.MaxMasterKeySize)
	}
	if opts.WrapMaster != nil && len(opts.WrapMaster) > wrapper.MaxMasterKeySize {
		return nil, nil, fmt.Errorf("triple: opts.WrapMaster length %d exceeds wrapper.MaxMasterKeySize=%d", len(opts.WrapMaster), wrapper.MaxMasterKeySize)
	}
	if resolved.Parallax {
		if opts.PermMaster != nil {
			permMaster = append([]byte(nil), opts.PermMaster...)
		} else {
			permMaster, err = deriveCombinedKey(kdfPrims, masters, "perm", parallax.MasterKeySize)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	if resolved.Wrapper {
		if opts.WrapMaster != nil {
			wrapMaster = append([]byte(nil), opts.WrapMaster...)
		} else {
			wrapMaster, err = deriveCombinedKey(kdfPrims, masters, "wrap", wrapMasterSize)
			if err != nil {
				clear(permMaster)
				return nil, nil, err
			}
		}
	}
	if permMaster != nil && wrapMaster != nil && bytes.Equal(permMaster, wrapMaster) {
		clear(permMaster)
		clear(wrapMaster)
		return nil, nil, ErrIdenticalMasters
	}
	return permMaster, wrapMaster, nil
}

// prepareMasters resolves the two masters from the profile shape and
// the [Opts] overrides. Auto-gen kicks in only for layers that are
// engaged for this Pipeline — a disabled layer receives nil, since
// its master will be dropped from the wire and never consumed.
//
// The [ErrIdenticalMasters] check runs whenever both masters are
// present (non-nil) — protects callers from accidentally passing the
// same byte slice to both master parameters.
func prepareMasters(resolved Profile, opts Opts) (permMaster, wrapMaster []byte, err error) {
	// Upper cap on caller-supplied masters — rejected upfront so the
	// two "append([]byte(nil), ...)" copies below cannot amplify an
	// adversarial multi-gigabyte slice into two more copies plus the
	// downstream base64 blob string.
	if opts.PermMaster != nil && len(opts.PermMaster) > parallax.MaxMasterKeySize {
		return nil, nil, fmt.Errorf("triple: opts.PermMaster length %d exceeds parallax.MaxMasterKeySize=%d", len(opts.PermMaster), parallax.MaxMasterKeySize)
	}
	if opts.WrapMaster != nil && len(opts.WrapMaster) > wrapper.MaxMasterKeySize {
		return nil, nil, fmt.Errorf("triple: opts.WrapMaster length %d exceeds wrapper.MaxMasterKeySize=%d", len(opts.WrapMaster), wrapper.MaxMasterKeySize)
	}
	if resolved.Parallax {
		if opts.PermMaster != nil {
			permMaster = append([]byte(nil), opts.PermMaster...)
		} else {
			permMaster, err = parallax.GenerateMasterKey()
			if err != nil {
				return nil, nil, fmt.Errorf("triple: parallax.GenerateMasterKey: %w", err)
			}
		}
	}
	if resolved.Wrapper {
		if opts.WrapMaster != nil {
			wrapMaster = append([]byte(nil), opts.WrapMaster...)
		} else {
			wrapMaster = make([]byte, wrapMasterSize)
			if _, err = rand.Read(wrapMaster); err != nil {
				clear(permMaster)
				clear(wrapMaster)
				return nil, nil, fmt.Errorf("triple: crypto/rand: %w", err)
			}
		}
	}
	if permMaster != nil && wrapMaster != nil && bytes.Equal(permMaster, wrapMaster) {
		clear(permMaster)
		clear(wrapMaster)
		return nil, nil, ErrIdenticalMasters
	}
	return permMaster, wrapMaster, nil
}

// exportInnerBlob width-dispatches to the appropriate
// [itb.Blob{128,256,512}.Export3Cfg] entry to produce the inner blob
// bytes. The MAC material rides through [itb.Blob{N}Opts] when the
// Pipeline carries a MAC; No MAC profiles leave MAC fields empty.
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
	// opts alongside the other entries of the Triple constellation
	// packed into the blob's core fields.
	opts.KeyL = append([]byte(nil), prfKeys[1]...)
	defer clear(opts.KeyL)
	opts.LS = seeds[1].(*itb.Seed128)
	if len(macKey) > 0 {
		opts.MACKey = append([]byte(nil), macKey...)
		defer clear(opts.MACKey)
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
	defer func() {
		for i := range keys {
			clear(keys[i][:])
		}
		clear(opts.KeyL[:])
		clear(opts.MACKey)
		runtime.KeepAlive(&keys)
		runtime.KeepAlive(&opts.KeyL)
	}()
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
	defer func() {
		for i := range keys {
			clear(keys[i][:])
		}
		clear(opts.KeyL[:])
		clear(opts.MACKey)
		runtime.KeepAlive(&keys)
		runtime.KeepAlive(&opts.KeyL)
	}()
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
