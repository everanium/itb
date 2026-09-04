package triple

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// ErrProfileExists is returned by [Register] when the supplied name
// is already registered — either by the shipped catalogue at package
// init time or by a prior [Register] call. Re-registration is refused
// rather than accepted-and-overwritten as programmer-error detection:
// a silently rebound name would make a later [Init] build a shape the
// author of the first registration did not intend. Callers who need
// to evolve a profile's shape pick a distinct new name (typical
// convention: append "-v2", "-v3", …).
var ErrProfileExists = errors.New("triple: profile name already registered")

// profileRegistryMu serialises reads and writes to profileRegistry.
// Reads ([Lookup] / [Profiles]) take the read lock; writes
// ([Register]) take the write lock. Kept separate from the map's
// declaration so Register-side concurrency and shipped-profile
// init-time population stay in one file.
var profileRegistryMu sync.RWMutex

// profileNameRegexp enforces the accepted profile-name character
// shape: lowercase ASCII letter start, followed by two or more
// lowercase ASCII letters, digits, or hyphens. The length cap is
// enforced separately by [ProfileNameMaxLen] because the stdlib
// regexp engine (RE2) refuses repeat counts above 1000; the two
// checks together give the intended [3, ProfileNameMaxLen]
// character-and-length envelope. Applied to the name argument of
// [Register]; unrelated to the shipped profile identifiers, which are
// hardcoded constants.
var profileNameRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]{2,}$`)

// ProfileNameMaxLen is the upper sanity bound on a [Register] name in
// bytes. Shipped catalogue profile identifiers stay comfortably under
// 40 characters — the cap is purely an anti-abuse upper bound so a
// hostile registration (or a hostile label inside a blob) cannot
// force multi-megabyte allocations along the name-copy path.
const ProfileNameMaxLen = 16384

// reservedProfilePrefixes is the set of name prefixes reserved for
// the shipped catalogue's namespace. User-defined profiles must pick
// a distinct prefix so a future addition to the shipped set cannot
// collide with an existing user registration.
var reservedProfilePrefixes = []string{
	"streaming-",
	"singlemsg-",
	"blob-",
}

// validProfileModes lists the accepted [Profile.Mode] discriminators.
// Every shipped profile picks one of these; user profiles must do the
// same so downstream cipher-surface dispatch stays exhaustive.
var validProfileModes = map[string]struct{}{
	modeStreamingAEAD:   {},
	modeStreamingNoAEAD: {},
	modeSingleMsgMAC:    {},
	modeSingleMsgNoMAC:  {},
	modeBlobOnly:        {},
}

// Register installs p into the profile catalogue under name so
// subsequent [Init] and [Lookup] calls resolve name to p. Every field
// of p is validated fail-fast before the registration lands; on
// success p.Name is populated with name and the record is stored.
//
// The registry serves construction by name only. A blob produced by
// [Init] carries the resolved record itself, so the receiving side
// does not need the name registered to [Load] it; a receiver that
// wants the handle for its own [Init] calls registers the [Inspect]
// result explicitly.
//
// Name rules:
//
//   - Must match the pattern `^[a-z][a-z0-9-]{2,}$` — lowercase
//     ASCII letter start, two or more further ASCII lowercase
//     letters, digits, or hyphens. Total length is separately capped
//     at [ProfileNameMaxLen] bytes.
//   - Must NOT start with one of the reserved shipped-catalogue
//     prefixes (streaming-, singlemsg-, blob-). Pick a distinct
//     prefix (organisation tag, application name, etc.).
//   - Must NOT already be registered. Attempting to re-register an
//     existing name returns [ErrProfileExists]; callers who need to
//     evolve a profile's shape pick a distinct new name.
//
// Field rules for p:
//
//   - Mode is one of the five shipped mode discriminators
//     (streaming-aead / streaming-noaead / singlemsg-mac /
//     singlemsg-nomac / blob-only).
//   - Width is 128 / 256 / 512.
//   - InnerHash resolves via [github.com/everanium/itb/hashes.Find]
//     to a Spec whose Width matches Width.
//   - KeyBits is a positive integer multiple of Width.
//   - MacName, when non-empty, resolves via
//     [github.com/everanium/itb/macs.Find].
//   - TagStubSize accepts 0 (defer to the MacName auto-probe or the
//     32-byte default) or a value in [16, 64] — the floor matches the
//     macs.Register TagSize >= 16 contract, the ceiling covers the
//     longest realistic MAC tag; see [Profile.TagStubSize].
//   - OuterCipher is validated only when Wrapper is true; must be
//     a recognised entry in
//     [github.com/everanium/itb/wrapper.CipherNames].
//   - ParallaxPalette is validated only when Parallax is true; each
//     entry must be a recognised wrapper cipher name, and the palette
//     size must fall inside
//     [github.com/everanium/itb/parallax.MinPaletteSize,
//     github.com/everanium/itb/parallax.MaxPaletteSize].
//   - ParallaxSegmentSize accepts 0 (defer to
//     [github.com/everanium/itb/parallax.DefaultSegmentSize]) or any
//     positive value; the coprime / segment-bound rules are enforced
//     by parallax at [Init] time, not here.
//   - ChunkSize accepts 0 (defer to
//     [github.com/everanium/itb.DefaultChunkSize]) or any positive
//     value.
//
// Register is safe under concurrent invocation with itself, with
// [Init], [Lookup], and [Profiles]; the registry is guarded by an
// internal mutex.
func Register(name string, p Profile) error {
	if err := validateProfileName(name); err != nil {
		return err
	}
	if err := validateProfileFields(p); err != nil {
		return err
	}

	// Populate Name after validation but before taking the write
	// lock — a defensive copy of ParallaxPalette avoids caller-side
	// mutation leaking into the registry.
	p.Name = name
	if len(p.ParallaxPalette) > 0 {
		p.ParallaxPalette = append([]string(nil), p.ParallaxPalette...)
	}

	profileRegistryMu.Lock()
	defer profileRegistryMu.Unlock()
	if _, ok := profileRegistry[name]; ok {
		return fmt.Errorf("%w: %q", ErrProfileExists, name)
	}
	profileRegistry[name] = p
	return nil
}

// Profiles returns a snapshot slice of every profile name currently
// registered in the profile catalogue — the shipped [Profile]
// constants installed at package init plus any names added through
// subsequent [Register] calls. The element type is string (the
// names), not [Profile]; resolve a name with [Lookup]. The returned
// slice is sorted in ascending lexicographic order so successive
// invocations against an unchanged registry produce byte-identical
// output, and callers who need iteration determinism (a CLI listing,
// a diagnostic dump) can rely on the order without an extra sort step.
//
// The result is a fresh []string; caller-side mutation does not
// affect subsequent calls. Safe under concurrent invocation with
// [Register], [Init], and [Lookup] — the registry read holds the
// shared read lock only.
func Profiles() []string {
	profileRegistryMu.RLock()
	names := make([]string, 0, len(profileRegistry))
	for name := range profileRegistry {
		names = append(names, name)
	}
	profileRegistryMu.RUnlock()
	sort.Strings(names)
	return names
}

// validateProfileName enforces the Register-side name rules (length
// cap + character pattern + reserved-prefix rejection). The
// already-registered check happens under the registry lock in
// Register itself; a pre-lock check would race with a concurrent
// registration.
func validateProfileName(name string) error {
	if len(name) > ProfileNameMaxLen {
		return fmt.Errorf("triple: Register: name length %d exceeds ProfileNameMaxLen=%d",
			len(name), ProfileNameMaxLen)
	}
	if !profileNameRegexp.MatchString(name) {
		return fmt.Errorf("triple: Register: name %q does not match pattern %s",
			name, profileNameRegexp.String())
	}
	for _, prefix := range reservedProfilePrefixes {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return fmt.Errorf("triple: Register: name %q uses reserved prefix %q",
				name, prefix)
		}
	}
	return nil
}

// validateProfileFields enforces the per-field rules shared by
// [Register] (registry side) and [Load] (recipe side, wrapped in
// [ErrBlobMalformedRecipe]). Runs before the registry lock is taken so
// a rejected profile never contends with concurrent Init readers.
func validateProfileFields(p Profile) error {
	if _, ok := validProfileModes[p.Mode]; !ok {
		return fmt.Errorf("triple: Register: Mode %q not in {streaming-aead, streaming-noaead, singlemsg-mac, singlemsg-nomac, blob-only}",
			p.Mode)
	}
	switch p.Width {
	case 128, 256, 512:
	default:
		return fmt.Errorf("triple: Register: Width %d not in {128, 256, 512}", p.Width)
	}
	// Mixed vs single-primitive dispatch. A mixed constellation
	// populates every [Profile.MixedHashes] slot and leaves
	// [Profile.InnerHash] empty; single-primitive profiles do the
	// opposite. The two fields are mutually exclusive.
	if isMixedProfile(p) {
		if err := validateMixedHashes(p); err != nil {
			return err
		}
	} else {
		if len(p.InnerHash) > hashes.MaxNameLen {
			return fmt.Errorf("triple: Register: InnerHash %q length %d exceeds hashes.MaxNameLen=%d",
				p.InnerHash, len(p.InnerHash), hashes.MaxNameLen)
		}
		spec, ok := hashes.Find(p.InnerHash)
		if !ok {
			return fmt.Errorf("triple: Register: InnerHash %q not in hashes.Registry",
				p.InnerHash)
		}
		if int(spec.Width) != p.Width {
			return fmt.Errorf("triple: Register: InnerHash %q has width %d, profile Width is %d",
				p.InnerHash, int(spec.Width), p.Width)
		}
	}
	if p.KeyBits <= 0 {
		return fmt.Errorf("triple: Register: KeyBits %d must be > 0", p.KeyBits)
	}
	if p.KeyBits%p.Width != 0 {
		return fmt.Errorf("triple: Register: KeyBits %d not a multiple of Width %d",
			p.KeyBits, p.Width)
	}
	if p.MacName != "" {
		if len(p.MacName) > hashes.MaxNameLen {
			return fmt.Errorf("triple: Register: MacName %q length %d exceeds hashes.MaxNameLen=%d",
				p.MacName, len(p.MacName), hashes.MaxNameLen)
		}
		if _, ok := macs.Find(p.MacName); !ok {
			return fmt.Errorf("triple: Register: MacName %q not in macs.Registry",
				p.MacName)
		}
	}
	if p.Wrapper {
		if len(p.OuterCipher) > hashes.MaxNameLen {
			return fmt.Errorf("triple: Register: OuterCipher %q length %d exceeds hashes.MaxNameLen=%d",
				p.OuterCipher, len(p.OuterCipher), hashes.MaxNameLen)
		}
		if !isKnownWrapperCipher(p.OuterCipher) {
			return fmt.Errorf("triple: Register: OuterCipher %q not in wrapper.CipherNames",
				p.OuterCipher)
		}
	}
	if p.Parallax {
		if len(p.ParallaxPalette) < parallax.MinPaletteSize {
			return fmt.Errorf("triple: Register: ParallaxPalette size %d below minimum %d",
				len(p.ParallaxPalette), parallax.MinPaletteSize)
		}
		if len(p.ParallaxPalette) > parallax.MaxPaletteSize {
			return fmt.Errorf("triple: Register: ParallaxPalette size %d above maximum %d",
				len(p.ParallaxPalette), parallax.MaxPaletteSize)
		}
		for i, entry := range p.ParallaxPalette {
			if entry == "" {
				return fmt.Errorf("triple: Register: ParallaxPalette[%d] is empty", i)
			}
			if len(entry) > hashes.MaxNameLen {
				return fmt.Errorf("triple: Register: ParallaxPalette[%d] %q length %d exceeds hashes.MaxNameLen=%d",
					i, entry, len(entry), hashes.MaxNameLen)
			}
			if !isKnownWrapperCipher(entry) {
				return fmt.Errorf("triple: Register: ParallaxPalette[%d] %q not in wrapper.CipherNames",
					i, entry)
			}
		}
	}
	if p.ParallaxSegmentSize < 0 {
		return fmt.Errorf("triple: Register: ParallaxSegmentSize %d must be >= 0",
			p.ParallaxSegmentSize)
	}
	if p.ParallaxSegmentSize > parallax.MaxSegmentSize {
		return fmt.Errorf("triple: Register: ParallaxSegmentSize %d above maximum %d",
			p.ParallaxSegmentSize, parallax.MaxSegmentSize)
	}
	// A non-zero ParallaxSegmentSize must additionally be coprime to
	// parallax's internal pipeline period so the schedule builder
	// accepts it. Zero (the sentinel that defers to
	// parallax.DefaultSegmentSize) skips the coprime check — the
	// default is coprime by construction.
	if p.ParallaxSegmentSize > 0 && gcdInt(p.ParallaxSegmentSize, parallaxPipelinePeriod) != 1 {
		return fmt.Errorf("triple: Register: ParallaxSegmentSize %d not coprime to %d",
			p.ParallaxSegmentSize, parallaxPipelinePeriod)
	}
	if p.ChunkSize < 0 {
		return fmt.Errorf("triple: Register: ChunkSize %d must be >= 0", p.ChunkSize)
	}
	if p.ChunkSize > parallax.MaxChunkSize {
		return fmt.Errorf("triple: Register: ChunkSize %d above maximum %d",
			p.ChunkSize, parallax.MaxChunkSize)
	}
	if p.TagStubSize != 0 && (p.TagStubSize < 16 || p.TagStubSize > 64) {
		return fmt.Errorf("triple: Register: TagStubSize=%d must be 0 or in [16, 64]", p.TagStubSize)
	}
	return nil
}

// parallaxPipelinePeriod is the coprime reference the parallax
// package uses when validating a non-default segment size. Reasserted
// here as a package-local constant so [validateProfileFields] can
// enforce the same gcd rule fail-fast at Register time
// (parallax's own [parallax.NewSchedule] enforces it at Init time —
// this check moves the surface up one layer for a cleaner error
// message on a bad Profile literal).
const parallaxPipelinePeriod = 504

// gcdInt returns the greatest common divisor of |a| and |b|. Both
// inputs are treated as non-negative; a zero argument returns the
// other. Local re-implementation to avoid an internal-package cross-
// dependency on parallax's own unexported gcd.
func gcdInt(a, b int) int {
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// isKnownWrapperCipher reports whether name is present in the shipped
// [github.com/everanium/itb/wrapper.CipherNames] catalogue. Used by
// the OuterCipher and ParallaxPalette entry validations.
func isKnownWrapperCipher(name string) bool {
	for _, c := range wrapper.CipherNames {
		if c == name {
			return true
		}
	}
	return false
}

// validateOptsCommon runs the fail-fast bounds checks on the numeric
// [Opts] fields consumed by [Init]. Called ahead of any wire-producing
// step so a caller-supplied invalid value surfaces with a clean
// "opts.<field>=... must be ..." message instead of a downstream
// deferred failure. The caller argument tags the error prefix.
//
// Every check mirrors the [github.com/everanium/itb.Config]-side
// enum for the field: NonceBits ∈ {0, 128, 256, 512}, BarrierFill ∈
// {0, 1, 2, 4, 8, 16, 32}. Zero remains the "defer to profile
// default" sentinel for each. [Opts.MaxWorkers] is not range-checked
// here — every value is accepted and clamped by [clampWorkers].
func validateOptsCommon(caller string, opts Opts) error {
	switch opts.NonceBits {
	case 0, 128, 256, 512:
	default:
		return fmt.Errorf("triple: %s: opts.NonceBits=%d must be 0 or one of {128, 256, 512}", caller, opts.NonceBits)
	}
	switch opts.BarrierFill {
	case 0, 1, 2, 4, 8, 16, 32:
	default:
		return fmt.Errorf("triple: %s: opts.BarrierFill=%d must be 0 or one of {1, 2, 4, 8, 16, 32}", caller, opts.BarrierFill)
	}
	if opts.ChunkSize < 0 {
		return fmt.Errorf("triple: %s: opts.ChunkSize=%d must be >= 0", caller, opts.ChunkSize)
	}
	if opts.ChunkSize > parallax.MaxChunkSize {
		return fmt.Errorf("triple: %s: opts.ChunkSize=%d exceeds parallax.MaxChunkSize=%d",
			caller, opts.ChunkSize, parallax.MaxChunkSize)
	}
	if opts.KeyBits < 0 {
		return fmt.Errorf("%w: triple: %s: opts.KeyBits=%d must be >= 0",
			ErrBadKeyBits, caller, opts.KeyBits)
	}
	if opts.ParallaxSegmentSize < 0 {
		return fmt.Errorf("triple: %s: opts.ParallaxSegmentSize=%d must be >= 0",
			caller, opts.ParallaxSegmentSize)
	}
	if opts.ParallaxSegmentSize > parallax.MaxSegmentSize {
		return fmt.Errorf("triple: %s: opts.ParallaxSegmentSize=%d exceeds parallax.MaxSegmentSize=%d",
			caller, opts.ParallaxSegmentSize, parallax.MaxSegmentSize)
	}
	return nil
}

// validateOptsStrings enforces the per-field upper-length bound on
// every [Opts] string field that names a registry primitive
// ([Opts.MacName], [Opts.InnerHash], [Opts.OuterCipher], every
// [Opts.MixedHashes] slot, every [Opts.ParallaxPalette] entry). The
// cap is [hashes.MaxNameLen] = 12 bytes so the check aligns with the
// registration-side floor across [hashes.Register] / [macs.Register]
// / parallax palette validation. Reaching the downstream lookup with
// an over-long name would produce a cryptic "unknown ..." error; the
// upfront reject surfaces the length problem directly.
func validateOptsStrings(caller string, opts Opts) error {
	if len(opts.MacName) > hashes.MaxNameLen {
		return fmt.Errorf("triple: %s: opts.MacName %q length %d exceeds hashes.MaxNameLen=%d",
			caller, opts.MacName, len(opts.MacName), hashes.MaxNameLen)
	}
	if len(opts.InnerHash) > hashes.MaxNameLen {
		return fmt.Errorf("triple: %s: opts.InnerHash %q length %d exceeds hashes.MaxNameLen=%d",
			caller, opts.InnerHash, len(opts.InnerHash), hashes.MaxNameLen)
	}
	if len(opts.OuterCipher) > hashes.MaxNameLen {
		return fmt.Errorf("triple: %s: opts.OuterCipher %q length %d exceeds hashes.MaxNameLen=%d",
			caller, opts.OuterCipher, len(opts.OuterCipher), hashes.MaxNameLen)
	}
	for i, name := range opts.MixedHashes {
		if len(name) > hashes.MaxNameLen {
			return fmt.Errorf("triple: %s: opts.MixedHashes[%d] %q length %d exceeds hashes.MaxNameLen=%d",
				caller, i, name, len(name), hashes.MaxNameLen)
		}
	}
	for i, name := range opts.ParallaxPalette {
		if len(name) > hashes.MaxNameLen {
			return fmt.Errorf("triple: %s: opts.ParallaxPalette[%d] %q length %d exceeds hashes.MaxNameLen=%d",
				caller, i, name, len(name), hashes.MaxNameLen)
		}
	}
	return nil
}

// validateResolvedKeyBits enforces the [Opts.KeyBits] enum for the
// resolved profile shape. Zero remains the "defer to profile default"
// sentinel and short-circuits; a non-zero value must land in
// [itb.MinSeedKeyBits, itb.MaxKeyBits] AND be an exact integer
// multiple of the resolved primitive width. Reaching
// [allocEightSeeds] with a mismatched value would produce a cryptic
// "not divisible by primitive width" message; wrapping the error in
// [ErrBadKeyBits] here lets the [capi] mapper route it to the
// shared StatusBadKeyBits status code instead of the generic
// StatusInternal fallthrough. The caller argument (Init / Load) tags
// the error prefix so a binding sees which construction path
// rejected the value.
func validateResolvedKeyBits(caller string, r Profile) error {
	kb := r.KeyBits
	if kb == 0 {
		return nil
	}
	if kb < seedMinKeyBits || kb > itbMaxKeyBits {
		return fmt.Errorf("%w: triple: %s: resolved keyBits=%d must be 0 or in [%d, %d]",
			ErrBadKeyBits, caller, kb, seedMinKeyBits, itbMaxKeyBits)
	}
	if r.Width == 0 {
		return nil
	}
	if kb%r.Width != 0 {
		return fmt.Errorf("%w: triple: %s: resolved keyBits=%d not divisible by primitive width=%d",
			ErrBadKeyBits, caller, kb, r.Width)
	}
	return nil
}

// validateResolvedChunkSize enforces the upper cap on the resolved
// [Opts.ChunkSize] value. Zero stays the "defer to
// [itb.DefaultChunkSize]" sentinel; a non-zero value must not exceed
// [parallax.MaxChunkSize]. Reaching
// [parallax.Schedule.SetChunkSize] with an oversize value would fail
// deferred inside the parallax builder; the upfront reject surfaces
// the misconfiguration at the construction boundary.
func validateResolvedChunkSize(caller string, r Profile) error {
	if r.ChunkSize <= 0 {
		return nil
	}
	if r.ChunkSize > parallax.MaxChunkSize {
		return fmt.Errorf("triple: %s: resolved chunkSize=%d must be in [1, %d]",
			caller, r.ChunkSize, parallax.MaxChunkSize)
	}
	return nil
}

// seedMinKeyBits mirrors the [github.com/everanium/itb.NewSeed{128,
// 256, 512}] floor (512 bits — the shared minimum across the three
// widths). Re-declared here so [validateResolvedKeyBits] does not
// need to reach into an itb-internal constant.
const seedMinKeyBits = 512

// itbMaxKeyBits mirrors [github.com/everanium/itb.MaxKeyBits] (2048
// bits) so [validateResolvedKeyBits] enforces the shared upper cap
// without pulling in the itb-root symbol at the top of the package.
const itbMaxKeyBits = 2048

// validateMixedHashes enforces the per-slot rules for a mixed-primitive
// constellation. Runs from [validateProfileFields] when
// [isMixedProfile] reports true.
//
// Rules:
//
//   - [Profile.InnerHash] must be empty. Mixed and single-primitive
//     are mutually exclusive dispatch paths; setting both is refused
//     so a downstream reader cannot silently pick the wrong one.
//   - Every [Profile.MixedHashes] slot must be non-empty. Any partial
//     population (some slots set, others zero) is refused rather than
//     silently substituting a default per slot.
//   - Every slot's primitive must resolve via
//     [github.com/everanium/itb/hashes.Find].
//   - Every slot's primitive width must equal [Profile.Width]. Uniform
//     width per profile keeps the seed-allocation path a single width
//     class; mixing widths within one profile is not supported.
//
// Repeats across slots are permitted — the constraint is uniform
// width, not eight-distinct primitives.
func validateMixedHashes(p Profile) error {
	if p.InnerHash != "" {
		return fmt.Errorf("triple: Register: InnerHash %q must be empty when MixedHashes is populated (mixed and single-primitive dispatch are mutually exclusive)",
			p.InnerHash)
	}
	for i, name := range p.MixedHashes {
		if name == "" {
			return fmt.Errorf("triple: Register: MixedHashes[%d] is empty (populate all 8 slots or leave every slot empty for single-primitive dispatch)",
				i)
		}
		if len(name) > hashes.MaxNameLen {
			return fmt.Errorf("triple: Register: MixedHashes[%d] = %q length %d exceeds hashes.MaxNameLen=%d",
				i, name, len(name), hashes.MaxNameLen)
		}
		spec, ok := hashes.Find(name)
		if !ok {
			return fmt.Errorf("triple: Register: MixedHashes[%d] = %q not in hashes.Registry",
				i, name)
		}
		if int(spec.Width) != p.Width {
			return fmt.Errorf("triple: Register: MixedHashes[%d] = %q has width %d, profile Width is %d",
				i, name, int(spec.Width), p.Width)
		}
	}
	return nil
}
