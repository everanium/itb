package triple

import (
	"github.com/everanium/itb"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// Profile mode discriminators. profile.mode selects one of these to
// tell downstream code (cipher-path stubs) which surface the Pipeline
// exposes. Blob-only profiles have no cipher surface.
const (
	modeStreamingAEAD   = "streaming-aead"
	modeStreamingNoAEAD = "streaming-noaead"
	modeSingleMsgMAC    = "singlemsg-mac"
	modeSingleMsgNoMAC  = "singlemsg-nomac"
	modeBlobOnly        = "blob-only"
)

// Shipped profile identifiers.
const (
	// ProfileStreamingAEADTripleMACV1 is the Streaming AEAD Triple
	// with MAC full-stack default (parallax on, wrapper on).
	ProfileStreamingAEADTripleMACV1 = "streaming-aead-triple-mac-v1"

	// ProfileStreamingNoAEADTripleV1 is the Streaming Non-AEAD
	// (No MAC) Triple full-stack (parallax on, wrapper on).
	ProfileStreamingNoAEADTripleV1 = "streaming-noaead-triple-v1"

	// ProfileSingleMsgTripleMACV1 is the Single Message Triple with
	// MAC full-stack (parallax on, wrapper on).
	ProfileSingleMsgTripleMACV1 = "singlemsg-triple-mac-v1"

	// ProfileSingleMsgTripleNoMACV1 is the Single Message Triple
	// No MAC full-stack (parallax on, wrapper on).
	ProfileSingleMsgTripleNoMACV1 = "singlemsg-triple-nomac-v1"

	// ProfileBlobTripleMACV1 is the MAC-authenticated blob-only
	// bundle profile: [Init] and [Pipeline.Rekey] produce blob wire,
	// but the Pipeline exposes no cipher surface.
	ProfileBlobTripleMACV1 = "blob-triple-mac-v1"

	// ProfileStreamingAEADTripleMACMixedV1 is the width-256 mixed-
	// primitive counterpart to [ProfileStreamingAEADTripleMACV1]. The
	// per-slot constellation is
	// [areion256, blake3, blake2b256, blake2s, chacha20,
	//  areion256, blake3, blake2b256] — one full spread across every
	// shipped width-256 primitive, with the extra slots assigned to
	// the highest-throughput members of the pool.
	ProfileStreamingAEADTripleMACMixedV1 = "streaming-aead-triple-mac-mixed-v1"

	// ProfileStreamingNoAEADTripleMixedV1 is the width-256 mixed-
	// primitive counterpart to [ProfileStreamingNoAEADTripleV1]. The
	// per-slot constellation permutes the width-256 pool so a pair of
	// mixed streaming profiles stay wire-distinguishable at every
	// slot:
	// [blake3, chacha20, blake2s, areion256, blake2b256,
	//  blake3, chacha20, blake2s].
	ProfileStreamingNoAEADTripleMixedV1 = "streaming-noaead-triple-mixed-v1"

	// ProfileSingleMsgTripleMACMixedV1 is the width-128 mixed-
	// primitive counterpart to [ProfileSingleMsgTripleMACV1]. Only
	// two shipped primitives sit at width 128 (aescmac + siphash24);
	// the constellation alternates the pair across all eight slots.
	ProfileSingleMsgTripleMACMixedV1 = "singlemsg-triple-mac-mixed-v1"

	// ProfileSingleMsgTripleNoMACMixedV1 is the width-512 mixed-
	// primitive counterpart to [ProfileSingleMsgTripleNoMACV1]. Only
	// two shipped primitives sit at width 512 (areion512 +
	// blake2b512); the constellation alternates the pair across all
	// eight slots.
	ProfileSingleMsgTripleNoMACMixedV1 = "singlemsg-triple-nomac-mixed-v1"
)

// Profile-default constants. Values reuse the shipped defaults from
// the surrounding packages so a fresh Pipeline reads back the same
// numbers a manual composition would produce.
const (
	// defaultInnerHash is the shipped ITB PRF primitive.
	defaultInnerHash = "areion512"

	// defaultKeyBits is the shipped per-seed key width.
	defaultKeyBits = 1024

	// defaultMacName is the shipped MAC primitive.
	defaultMacName = "hmac-blake3"

	// defaultOuterCipher picks the wrapper's Streaming-friendly PRF-
	// CTR primitive. ChaCha20 is the widest-known outer cipher in the
	// wrapper's shipped CipherNames set and is the default used by
	// tools/eitb/main.go's demonstrator runs.
	defaultOuterCipher = wrapper.CipherChaCha20
)

// defaultParallaxPalette is the shipped parallax palette for every
// full-stack profile. The 3-slot mixed palette mirrors the palette
// exercised in parallax's own edge / round-trip tests
// (parallax/edge_test.go, parallax/parallax_test.go). Deliberately
// not made a const: []string is mutable, so the accessor returns a
// fresh copy each time.
func defaultParallaxPalette() []string {
	return []string{"aescmac", "chacha20", "blake3"}
}

// Profile is the record for one named profile in the registry. Every
// field is the profile default; per-call [Opts] overrides are folded
// in by the internal resolver to build the per-Pipeline effective
// settings consumed by [Init] and [Open].
//
// Callers who need a configuration outside the shipped set construct
// a Profile literal and hand it to [RegisterProfile]. The name is
// supplied separately as the RegisterProfile argument; the Name field
// is populated by RegisterProfile after validation.
//
// Field defaults left at their zero value inherit the corresponding
// compile-in default at [Init] time: ChunkSize=0 defers to
// [github.com/everanium/itb.DefaultChunkSize];
// ParallaxSegmentSize=0 defers to
// [github.com/everanium/itb/parallax.DefaultSegmentSize]. Every other
// field must be supplied explicitly.
type Profile struct {
	// Name is the registered profile identifier. Populated by
	// [RegisterProfile] after validation succeeds; callers construct
	// Profile literals without a Name and pass the desired name as the
	// separate RegisterProfile argument.
	Name string

	// Mode selects which cipher surface the Pipeline exposes. One of:
	// "streaming-aead", "streaming-noaead", "singlemsg-mac",
	// "singlemsg-nomac", "blob-only".
	Mode string

	// Width is the inner hash primitive's native intermediate-state
	// width in bits. One of 128 / 256 / 512. Must match the width of
	// InnerHash's [github.com/everanium/itb/hashes.Registry] entry.
	Width int

	// ChunkSize is the streaming chunk-size budget in bytes. Zero
	// defers to [github.com/everanium/itb.DefaultChunkSize] at
	// [Init] time.
	ChunkSize int

	// InnerHash is the ITB hash primitive name (e.g. "areion512"). Must
	// resolve via [github.com/everanium/itb/hashes.Find] to a Spec
	// whose Width matches Width.
	InnerHash string

	// KeyBits is the per-seed key width in bits. Must be a positive
	// multiple of the primitive's native Width (typically 512 / 1024 /
	// 2048).
	KeyBits int

	// MacName is the MAC primitive name (e.g. "hmac-blake3"). Empty
	// for No MAC modes; otherwise must resolve via
	// [github.com/everanium/itb/macs.Find].
	MacName string

	// OuterCipher is the wrapper (Outer cipher) primitive name (e.g.
	// "chacha20"). Empty when WrapperOn is false; otherwise must be
	// present in [github.com/everanium/itb/wrapper.CipherNames].
	OuterCipher string

	// ParallaxPalette is the parallax layer's per-segment cipher
	// palette. Each entry must be a recognised wrapper cipher name;
	// the palette size is bounded by
	// [github.com/everanium/itb/parallax.MinPaletteSize] /
	// [github.com/everanium/itb/parallax.MaxPaletteSize] when
	// ParallaxOn is true.
	ParallaxPalette []string

	// ParallaxSegmentSize is the parallax layer's per-segment byte
	// count. Zero defers to
	// [github.com/everanium/itb/parallax.DefaultSegmentSize] at
	// [Init] time.
	ParallaxSegmentSize int

	// ParallaxOn engages the parallax layer for this profile.
	ParallaxOn bool

	// WrapperOn engages the wrapper (Outer cipher) layer for this
	// profile.
	WrapperOn bool

	// MixedHashes selects a per-slot ITB hash primitive constellation
	// for the eight-seed Interlocked Barrier Triple bundle. Slot
	// ordering matches [allocEightSeeds]:
	//
	//	[0] noiseSeed  [1] lockSeed
	//	[2] dataSeed1  [3] dataSeed2  [4] dataSeed3
	//	[5] startSeed1 [6] startSeed2 [7] startSeed3
	//
	// When every entry is empty (zero-value), the profile falls back to
	// the single-primitive path driven by [Profile.InnerHash]. When any
	// entry is non-empty, ALL eight must be populated, each must resolve
	// via [github.com/everanium/itb/hashes.Find], and every entry's
	// primitive width must equal [Profile.Width]. Repeats within a
	// single profile are permitted — the constraint is uniform width,
	// not eight-distinct primitives.
	//
	// A mixed constellation and a single-primitive [Profile.InnerHash]
	// are mutually exclusive: when [Profile.MixedHashes] is populated,
	// [Profile.InnerHash] must be the empty string. The two paths are
	// dispatched by [Init] and [Open] according to which field is set.
	MixedHashes [8]string
}

// resolvedProfile is the Opts-merged effective profile shape actually
// consumed by [Init] / [Open]. Every field carries the final value
// after profile-default → Opts-override merge.
type resolvedProfile struct {
	name                string
	mode                string
	width               int
	chunkSize           int
	innerHash           string
	keyBits             int
	macName             string
	outerCipher         string
	parallaxPalette     []string
	parallaxSegmentSize int
	parallaxOn          bool
	wrapperOn           bool

	// mixedHashes carries the profile's per-slot primitive constellation
	// when set. When any entry is non-empty, dispatch consults it per
	// slot; when every entry is empty, dispatch falls back to
	// innerHash. See [Profile.MixedHashes] for the slot ordering.
	mixedHashes [8]string
}

// isMixedProfile reports whether p carries a mixed-primitive
// constellation. Returns true when any [Profile.MixedHashes] slot is
// populated; single-primitive profiles (the default) return false.
func isMixedProfile(p Profile) bool {
	for _, s := range p.MixedHashes {
		if s != "" {
			return true
		}
	}
	return false
}

// isMixedResolved is the resolvedProfile-side counterpart to
// [isMixedProfile]. Used by [Init] / [Open] dispatch to pick the
// mixed-vs-single seed-allocation path.
func isMixedResolved(r resolvedProfile) bool {
	for _, s := range r.mixedHashes {
		if s != "" {
			return true
		}
	}
	return false
}

// profileRegistry maps profile name to [Profile] record. Populated in
// package init for the shipped profiles; user-defined additions land
// via [RegisterProfile]. Access is serialised via profileRegistryMu.
var profileRegistry = map[string]Profile{}

func init() {
	// Streaming AEAD Triple, MAC-authenticated, parallax on + wrapper on.
	profileRegistry[ProfileStreamingAEADTripleMACV1] = Profile{
		Name:                ProfileStreamingAEADTripleMACV1,
		Mode:                modeStreamingAEAD,
		Width:               512,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           defaultInnerHash,
		KeyBits:             defaultKeyBits,
		MacName:             defaultMacName,
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
	}

	// Streaming Non-AEAD Triple (No MAC), parallax on + wrapper on.
	profileRegistry[ProfileStreamingNoAEADTripleV1] = Profile{
		Name:                ProfileStreamingNoAEADTripleV1,
		Mode:                modeStreamingNoAEAD,
		Width:               512,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           defaultInnerHash,
		KeyBits:             defaultKeyBits,
		MacName:             "", // No MAC by definition.
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
	}

	// Single Message Triple, MAC-authenticated, parallax on + wrapper on.
	profileRegistry[ProfileSingleMsgTripleMACV1] = Profile{
		Name:                ProfileSingleMsgTripleMACV1,
		Mode:                modeSingleMsgMAC,
		Width:               512,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           defaultInnerHash,
		KeyBits:             defaultKeyBits,
		MacName:             defaultMacName,
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
	}

	// Single Message Triple, No MAC, parallax on + wrapper on.
	profileRegistry[ProfileSingleMsgTripleNoMACV1] = Profile{
		Name:                ProfileSingleMsgTripleNoMACV1,
		Mode:                modeSingleMsgNoMAC,
		Width:               512,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           defaultInnerHash,
		KeyBits:             defaultKeyBits,
		MacName:             "", // No MAC by definition.
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
	}

	// Blob-only bundle profile — MAC-authenticated inner Blob{N}
	// with parallax + wrapper metadata carried through wrap-layer.
	// No cipher surface: [Pipeline.EncryptStream] / friends return
	// [ErrNotYetImplemented] regardless of implementation status.
	profileRegistry[ProfileBlobTripleMACV1] = Profile{
		Name:                ProfileBlobTripleMACV1,
		Mode:                modeBlobOnly,
		Width:               512,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           defaultInnerHash,
		KeyBits:             defaultKeyBits,
		MacName:             defaultMacName,
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
	}

	// Mixed-primitive Streaming AEAD Triple, MAC-authenticated, parallax
	// on + wrapper on. Width 256; slot roster spreads across every
	// shipped width-256 primitive.
	profileRegistry[ProfileStreamingAEADTripleMACMixedV1] = Profile{
		Name:                ProfileStreamingAEADTripleMACMixedV1,
		Mode:                modeStreamingAEAD,
		Width:               256,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           "", // mixed dispatch — InnerHash inert
		KeyBits:             defaultKeyBits,
		MacName:             defaultMacName,
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
		MixedHashes: [8]string{
			"areion256", "blake3", "blake2b256", "blake2s",
			"chacha20", "areion256", "blake3", "blake2b256",
		},
	}

	// Mixed-primitive Streaming Non-AEAD Triple, parallax on +
	// wrapper on. Width 256; different balance from the AEAD mixed
	// profile so a pair of mixed streaming wires stay
	// slot-distinguishable.
	profileRegistry[ProfileStreamingNoAEADTripleMixedV1] = Profile{
		Name:                ProfileStreamingNoAEADTripleMixedV1,
		Mode:                modeStreamingNoAEAD,
		Width:               256,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           "", // mixed dispatch — InnerHash inert
		KeyBits:             defaultKeyBits,
		MacName:             "", // No MAC by definition.
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
		MixedHashes: [8]string{
			"blake3", "chacha20", "blake2s", "areion256",
			"blake2b256", "blake3", "chacha20", "blake2s",
		},
	}

	// Mixed-primitive Single Message Triple, MAC-authenticated,
	// parallax on + wrapper on. Width 128; alternates the two shipped
	// width-128 primitives across every slot.
	profileRegistry[ProfileSingleMsgTripleMACMixedV1] = Profile{
		Name:                ProfileSingleMsgTripleMACMixedV1,
		Mode:                modeSingleMsgMAC,
		Width:               128,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           "", // mixed dispatch — InnerHash inert
		// KeyBits divides the width-128 primitive's native width and
		// keeps the same total key material as the width-256 profiles
		// (defaultKeyBits = 1024, which is a valid multiple of 128).
		KeyBits:             defaultKeyBits,
		MacName:             defaultMacName,
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
		MixedHashes: [8]string{
			"aescmac", "siphash24", "aescmac", "siphash24",
			"aescmac", "siphash24", "aescmac", "siphash24",
		},
	}

	// Mixed-primitive Single Message Triple, No MAC, parallax on +
	// wrapper on. Width 512; alternates the two shipped width-512
	// primitives across every slot.
	profileRegistry[ProfileSingleMsgTripleNoMACMixedV1] = Profile{
		Name:                ProfileSingleMsgTripleNoMACMixedV1,
		Mode:                modeSingleMsgNoMAC,
		Width:               512,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           "", // mixed dispatch — InnerHash inert
		KeyBits:             defaultKeyBits,
		MacName:             "", // No MAC by definition.
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		ParallaxOn:          true,
		WrapperOn:           true,
		MixedHashes: [8]string{
			"areion512", "blake2b512", "areion512", "blake2b512",
			"areion512", "blake2b512", "areion512", "blake2b512",
		},
	}
}

// lookupProfile returns the registered [Profile] for name and
// [ErrUnknownProfile] on miss. Serialised via profileRegistryMu so a
// concurrent [RegisterProfile] is race-free.
func lookupProfile(name string) (Profile, error) {
	profileRegistryMu.RLock()
	p, ok := profileRegistry[name]
	profileRegistryMu.RUnlock()
	if !ok {
		return Profile{}, ErrUnknownProfile
	}
	return p, nil
}

// resolveProfile merges the profile defaults with the caller-supplied
// [Opts] to produce a [resolvedProfile]. Every Opts field takes
// precedence over the corresponding profile default when set (non-zero
// / non-empty for value types; non-nil pointer for the two layer
// toggles).
//
// Callers that supply parallax palette overrides receive a defensive
// copy so future mutation of the caller's slice does not leak into
// the Pipeline.
func resolveProfile(prof Profile, opts Opts) resolvedProfile {
	out := resolvedProfile{
		name:                prof.Name,
		mode:                prof.Mode,
		width:               prof.Width,
		chunkSize:           prof.ChunkSize,
		innerHash:           prof.InnerHash,
		keyBits:             prof.KeyBits,
		macName:             prof.MacName,
		outerCipher:         prof.OuterCipher,
		parallaxPalette:     append([]string(nil), prof.ParallaxPalette...),
		parallaxSegmentSize: prof.ParallaxSegmentSize,
		parallaxOn:          prof.ParallaxOn,
		wrapperOn:           prof.WrapperOn,
		mixedHashes:         prof.MixedHashes,
	}

	if opts.ChunkSize > 0 {
		out.chunkSize = opts.ChunkSize
	}
	if opts.InnerHash != "" {
		out.innerHash = opts.InnerHash
	}
	if opts.KeyBits > 0 {
		out.keyBits = opts.KeyBits
	}
	if opts.MacName != "" && out.macName != "" {
		// Only respect MacName override when the profile carries a
		// MAC in the first place — No-MAC profiles ignore the field.
		out.macName = opts.MacName
	}
	if opts.OuterCipher != "" {
		out.outerCipher = opts.OuterCipher
	}
	if len(opts.ParallaxPalette) > 0 {
		out.parallaxPalette = append([]string(nil), opts.ParallaxPalette...)
	}
	if opts.ParallaxSegmentSize > 0 {
		out.parallaxSegmentSize = opts.ParallaxSegmentSize
	}
	if opts.WithParallax != nil {
		out.parallaxOn = *opts.WithParallax
	}
	if opts.WithWrapper != nil {
		out.wrapperOn = *opts.WithWrapper
	}
	return out
}
