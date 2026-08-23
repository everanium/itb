package triple

import (
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// ErrProfileExists is returned by [RegisterProfile] when the supplied
// name is already registered — either by the shipped catalogue at
// package init time or by a prior [RegisterProfile] call. A profile
// name is a wire contract with the receiving side; silently rebinding
// it would break every session that opens against the old shape, so
// re-registration is refused rather than accepted-and-overwritten.
// Callers who need to evolve a profile's shape pick a distinct new
// name (typical convention: append "-v2", "-v3", …).
var ErrProfileExists = errors.New("triple: profile name already registered")

// profileRegistryMu serialises reads and writes to profileRegistry.
// Reads (lookupProfile) take the read lock; writes (RegisterProfile)
// take the write lock. Kept separate from the map's declaration so
// RegisterProfile-side concurrency and shipped-profile init-time
// population stay in one file.
var profileRegistryMu sync.RWMutex

// profileNameRegexp enforces the accepted profile-name shape:
// lowercase ASCII letter start, followed by 2–63 further lowercase
// ASCII letters, digits, or hyphens. Total length in [3, 64]. Applied
// to the name argument of [RegisterProfile]; unrelated to the
// shipped profile identifiers which are hardcoded constants.
var profileNameRegexp = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)

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

// RegisterProfile installs p into the profile catalogue under name so
// subsequent [Init] / [Open] calls resolve name to p. Every field of
// p is validated fail-fast before the registration lands; on success
// p.Name is populated with name and the record is stored.
//
// Name rules:
//
//   - Must match the pattern `^[a-z][a-z0-9-]{2,63}$` — lowercase
//     ASCII letter start, up to 63 further ASCII lowercase letters,
//     digits, or hyphens.
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
//   - OuterCipher is validated only when WrapperOn is true; must be
//     a recognised entry in
//     [github.com/everanium/itb/wrapper.CipherNames].
//   - ParallaxPalette is validated only when ParallaxOn is true; each
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
// RegisterProfile is safe under concurrent invocation with itself,
// with [Init], and with [Open]; the registry is guarded by an
// internal mutex.
func RegisterProfile(name string, p Profile) error {
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

// validateProfileName enforces the RegisterProfile-side name rules
// (pattern + reserved-prefix rejection). The already-registered check
// happens under the registry lock in RegisterProfile itself; a
// pre-lock check would race with a concurrent registration.
func validateProfileName(name string) error {
	if !profileNameRegexp.MatchString(name) {
		return fmt.Errorf("triple: RegisterProfile: name %q does not match pattern %s",
			name, profileNameRegexp.String())
	}
	for _, prefix := range reservedProfilePrefixes {
		if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
			return fmt.Errorf("triple: RegisterProfile: name %q uses reserved prefix %q",
				name, prefix)
		}
	}
	return nil
}

// validateProfileFields enforces the RegisterProfile-side per-field
// rules. Runs before the registry lock is taken so a rejected profile
// never contends with concurrent Init / Open readers.
func validateProfileFields(p Profile) error {
	if _, ok := validProfileModes[p.Mode]; !ok {
		return fmt.Errorf("triple: RegisterProfile: Mode %q not in {streaming-aead, streaming-noaead, singlemsg-mac, singlemsg-nomac, blob-only}",
			p.Mode)
	}
	switch p.Width {
	case 128, 256, 512:
	default:
		return fmt.Errorf("triple: RegisterProfile: Width %d not in {128, 256, 512}", p.Width)
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
		spec, ok := hashes.Find(p.InnerHash)
		if !ok {
			return fmt.Errorf("triple: RegisterProfile: InnerHash %q not in hashes.Registry",
				p.InnerHash)
		}
		if int(spec.Width) != p.Width {
			return fmt.Errorf("triple: RegisterProfile: InnerHash %q has width %d, profile Width is %d",
				p.InnerHash, int(spec.Width), p.Width)
		}
	}
	if p.KeyBits <= 0 {
		return fmt.Errorf("triple: RegisterProfile: KeyBits %d must be > 0", p.KeyBits)
	}
	if p.KeyBits%p.Width != 0 {
		return fmt.Errorf("triple: RegisterProfile: KeyBits %d not a multiple of Width %d",
			p.KeyBits, p.Width)
	}
	if p.MacName != "" {
		if _, ok := macs.Find(p.MacName); !ok {
			return fmt.Errorf("triple: RegisterProfile: MacName %q not in macs.Registry",
				p.MacName)
		}
	}
	if p.WrapperOn {
		if !isKnownWrapperCipher(p.OuterCipher) {
			return fmt.Errorf("triple: RegisterProfile: OuterCipher %q not in wrapper.CipherNames",
				p.OuterCipher)
		}
	}
	if p.ParallaxOn {
		if len(p.ParallaxPalette) < parallax.MinPaletteSize {
			return fmt.Errorf("triple: RegisterProfile: ParallaxPalette size %d below minimum %d",
				len(p.ParallaxPalette), parallax.MinPaletteSize)
		}
		if len(p.ParallaxPalette) > parallax.MaxPaletteSize {
			return fmt.Errorf("triple: RegisterProfile: ParallaxPalette size %d above maximum %d",
				len(p.ParallaxPalette), parallax.MaxPaletteSize)
		}
		for i, entry := range p.ParallaxPalette {
			if entry == "" {
				return fmt.Errorf("triple: RegisterProfile: ParallaxPalette[%d] is empty", i)
			}
			if !isKnownWrapperCipher(entry) {
				return fmt.Errorf("triple: RegisterProfile: ParallaxPalette[%d] %q not in wrapper.CipherNames",
					i, entry)
			}
		}
	}
	if p.ParallaxSegmentSize < 0 {
		return fmt.Errorf("triple: RegisterProfile: ParallaxSegmentSize %d must be >= 0",
			p.ParallaxSegmentSize)
	}
	if p.ChunkSize < 0 {
		return fmt.Errorf("triple: RegisterProfile: ChunkSize %d must be >= 0", p.ChunkSize)
	}
	return nil
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
		return fmt.Errorf("triple: RegisterProfile: InnerHash %q must be empty when MixedHashes is populated (mixed and single-primitive dispatch are mutually exclusive)",
			p.InnerHash)
	}
	for i, name := range p.MixedHashes {
		if name == "" {
			return fmt.Errorf("triple: RegisterProfile: MixedHashes[%d] is empty (populate all 8 slots or leave every slot empty for single-primitive dispatch)",
				i)
		}
		spec, ok := hashes.Find(name)
		if !ok {
			return fmt.Errorf("triple: RegisterProfile: MixedHashes[%d] = %q not in hashes.Registry",
				i, name)
		}
		if int(spec.Width) != p.Width {
			return fmt.Errorf("triple: RegisterProfile: MixedHashes[%d] = %q has width %d, profile Width is %d",
				i, name, int(spec.Width), p.Width)
		}
	}
	return nil
}
