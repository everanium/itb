package triple

import (
	"github.com/everanium/itb"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// Profile mode discriminators. profile.mode selects one of these to
// tell downstream code (cipher-path stubs in Phase 5/6) which surface
// the Pipeline exposes. Blob-only profiles have no cipher surface.
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

// profile is the internal record for one shipped profile. Fields are
// the defaults; user-side Opts overrides are folded in by
// [resolveProfile] to build a [resolvedProfile].
type profile struct {
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
}

// profileRegistry maps profile name to profile record. Populated in
// package init.
var profileRegistry = map[string]profile{}

func init() {
	// Streaming AEAD Triple, MAC-authenticated, parallax on + wrapper on.
	profileRegistry[ProfileStreamingAEADTripleMACV1] = profile{
		name:                ProfileStreamingAEADTripleMACV1,
		mode:                modeStreamingAEAD,
		width:               512,
		chunkSize:           itb.DefaultChunkSize,
		innerHash:           defaultInnerHash,
		keyBits:             defaultKeyBits,
		macName:             defaultMacName,
		outerCipher:         defaultOuterCipher,
		parallaxPalette:     defaultParallaxPalette(),
		parallaxSegmentSize: parallax.DefaultSegmentSize,
		parallaxOn:          true,
		wrapperOn:           true,
	}

	// Streaming Non-AEAD Triple (No MAC), parallax on + wrapper on.
	profileRegistry[ProfileStreamingNoAEADTripleV1] = profile{
		name:                ProfileStreamingNoAEADTripleV1,
		mode:                modeStreamingNoAEAD,
		width:               512,
		chunkSize:           itb.DefaultChunkSize,
		innerHash:           defaultInnerHash,
		keyBits:             defaultKeyBits,
		macName:             "", // No MAC by definition.
		outerCipher:         defaultOuterCipher,
		parallaxPalette:     defaultParallaxPalette(),
		parallaxSegmentSize: parallax.DefaultSegmentSize,
		parallaxOn:          true,
		wrapperOn:           true,
	}

	// Single Message Triple, MAC-authenticated, parallax on + wrapper on.
	profileRegistry[ProfileSingleMsgTripleMACV1] = profile{
		name:                ProfileSingleMsgTripleMACV1,
		mode:                modeSingleMsgMAC,
		width:               512,
		chunkSize:           itb.DefaultChunkSize,
		innerHash:           defaultInnerHash,
		keyBits:             defaultKeyBits,
		macName:             defaultMacName,
		outerCipher:         defaultOuterCipher,
		parallaxPalette:     defaultParallaxPalette(),
		parallaxSegmentSize: parallax.DefaultSegmentSize,
		parallaxOn:          true,
		wrapperOn:           true,
	}

	// Single Message Triple, No MAC, parallax on + wrapper on.
	profileRegistry[ProfileSingleMsgTripleNoMACV1] = profile{
		name:                ProfileSingleMsgTripleNoMACV1,
		mode:                modeSingleMsgNoMAC,
		width:               512,
		chunkSize:           itb.DefaultChunkSize,
		innerHash:           defaultInnerHash,
		keyBits:             defaultKeyBits,
		macName:             "", // No MAC by definition.
		outerCipher:         defaultOuterCipher,
		parallaxPalette:     defaultParallaxPalette(),
		parallaxSegmentSize: parallax.DefaultSegmentSize,
		parallaxOn:          true,
		wrapperOn:           true,
	}

	// Blob-only bundle profile — MAC-authenticated inner Blob{N}
	// with parallax + wrapper metadata carried through wrap-layer.
	// No cipher surface: [Pipeline.EncryptStream] / friends return
	// [ErrNotYetImplemented] regardless of implementation status.
	profileRegistry[ProfileBlobTripleMACV1] = profile{
		name:                ProfileBlobTripleMACV1,
		mode:                modeBlobOnly,
		width:               512,
		chunkSize:           itb.DefaultChunkSize,
		innerHash:           defaultInnerHash,
		keyBits:             defaultKeyBits,
		macName:             defaultMacName,
		outerCipher:         defaultOuterCipher,
		parallaxPalette:     defaultParallaxPalette(),
		parallaxSegmentSize: parallax.DefaultSegmentSize,
		parallaxOn:          true,
		wrapperOn:           true,
	}
}

// lookupProfile returns the registered profile for name and
// [ErrUnknownProfile] on miss.
func lookupProfile(name string) (profile, error) {
	p, ok := profileRegistry[name]
	if !ok {
		return profile{}, ErrUnknownProfile
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
func resolveProfile(prof profile, opts Opts) resolvedProfile {
	out := resolvedProfile{
		name:                prof.name,
		mode:                prof.mode,
		width:               prof.width,
		chunkSize:           prof.chunkSize,
		innerHash:           prof.innerHash,
		keyBits:             prof.keyBits,
		macName:             prof.macName,
		outerCipher:         prof.outerCipher,
		parallaxPalette:     append([]string(nil), prof.parallaxPalette...),
		parallaxSegmentSize: prof.parallaxSegmentSize,
		parallaxOn:          prof.parallaxOn,
		wrapperOn:           prof.wrapperOn,
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
