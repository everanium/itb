package triple

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/parallax"
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
	defaultOuterCipher = hashes.CipherChaCha20
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

// Profile is the record for one named profile in the registry and,
// once resolved, the shape a [Pipeline] runs with. In the registry
// every field is the profile default; [Init] folds the per-call
// [Opts] overrides in to build the resolved record the Pipeline
// consumes. The resolved record is the recipe: it is JSON-encoded
// through [Profile.MarshalJSON] into the blob's wrap-layer, decoded
// by [Inspect], and is the sole structural source [Load] rebuilds a
// Pipeline from.
//
// Callers who need a configuration outside the shipped set construct
// a Profile literal and hand it to [Register]. The name is supplied
// separately as the Register argument; the Name field is populated by
// Register after validation. Inside a blob the Name field is the
// sender's label — it is carried for display and is never consulted
// on the reopen path.
//
// Field defaults left at their zero value inherit the corresponding
// compile-in default at [Init] time: ChunkSize=0 defers to
// [github.com/everanium/itb.DefaultChunkSize];
// ParallaxSegmentSize=0 defers to
// [github.com/everanium/itb/parallax.DefaultSegmentSize]. Every other
// field must be supplied explicitly.
type Profile struct {
	// Name is the registered profile identifier. Populated by
	// [Register] after validation succeeds; callers construct Profile
	// literals without a Name and pass the desired name as the separate
	// Register argument. On a record decoded from a blob it is the
	// sender's label.
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

	// TagStubSize pins the CSPRNG dummy stub reservation size (bytes)
	// the No MAC envelope reserves so its wire shape matches a paired
	// MAC-carrying counterpart with a specific MAC tag length. Zero
	// defers to the MacName auto-probe (MAC-carrying profiles) or the
	// 32-byte default, which aligns with every shipped MAC's tag
	// length. Non-zero values must fall in [16, 64] — the floor
	// matches the macs.Register TagSize >= 16 contract, the ceiling
	// covers the longest realistic MAC tag; [Register] rejects
	// anything else fail-fast. Meaningful for No MAC profiles paired
	// with a custom-tag-size MAC counterpart; a MAC-carrying
	// profile's authenticated envelope sizes its reservation from the
	// MAC's probed tag length regardless of this field.
	TagStubSize int

	// OuterCipher is the wrapper (Outer cipher) primitive name (e.g.
	// "chacha20"). Empty when Wrapper is false; otherwise must be
	// present in [github.com/everanium/itb/wrapper.CipherNames].
	OuterCipher string

	// ParallaxPalette is the parallax layer's per-segment cipher
	// palette. Each entry must be a recognised wrapper cipher name;
	// the palette size is bounded by
	// [github.com/everanium/itb/parallax.MinPaletteSize] /
	// [github.com/everanium/itb/parallax.MaxPaletteSize] when
	// Parallax is true.
	ParallaxPalette []string

	// ParallaxSegmentSize is the parallax layer's per-segment byte
	// count. Zero defers to
	// [github.com/everanium/itb/parallax.DefaultSegmentSize] at
	// [Init] time.
	ParallaxSegmentSize int

	// Parallax engages the parallax layer for this profile.
	Parallax bool

	// Wrapper engages the wrapper (Outer cipher) layer for this
	// profile.
	Wrapper bool

	// MixedHashes selects a per-slot ITB hash primitive constellation
	// for the 8-seed Interlocked Barrier Triple bundle. Slot
	// ordering matches [allocEightSeeds]:
	//
	//	[0] noiseSeed  [1] lockSeed
	//	[2] dataSeed1  [3] dataSeed2  [4] dataSeed3
	//	[5] startSeed1 [6] startSeed2 [7] startSeed3
	//
	// When every entry is empty (zero-value), the profile falls back to
	// the single-primitive path driven by [Profile.InnerHash]. When any
	// entry is non-empty, ALL 8 must be populated, each must resolve
	// via [github.com/everanium/itb/hashes.Find], and every entry's
	// primitive width must equal [Profile.Width]. Repeats within a
	// single profile are permitted — the constraint is uniform width,
	// not 8-distinct primitives.
	//
	// A mixed constellation and a single-primitive [Profile.InnerHash]
	// are mutually exclusive: when [Profile.MixedHashes] is populated,
	// [Profile.InnerHash] must be the empty string. The two paths are
	// dispatched by [Init] and [Load] according to which field is set.
	MixedHashes [8]string
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

// profileRegistry maps profile name to [Profile] record. Populated in
// package init for the shipped profiles; user-defined additions land
// via [Register]. Access is serialised via profileRegistryMu.
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
		Parallax:            true,
		Wrapper:             true,
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
		Parallax:            true,
		Wrapper:             true,
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
		Parallax:            true,
		Wrapper:             true,
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
		Parallax:            true,
		Wrapper:             true,
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
		Parallax:            true,
		Wrapper:             true,
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
		Parallax:            true,
		Wrapper:             true,
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
		Parallax:            true,
		Wrapper:             true,
		MixedHashes: [8]string{
			"blake3", "chacha20", "blake2s", "areion256",
			"blake2b256", "blake3", "chacha20", "blake2s",
		},
	}

	// Mixed-primitive Single Message Triple, MAC-authenticated,
	// parallax on + wrapper on. Width 128; alternates the two shipped
	// width-128 primitives across every slot.
	profileRegistry[ProfileSingleMsgTripleMACMixedV1] = Profile{
		Name:      ProfileSingleMsgTripleMACMixedV1,
		Mode:      modeSingleMsgMAC,
		Width:     128,
		ChunkSize: itb.DefaultChunkSize,
		InnerHash: "", // mixed dispatch — InnerHash inert
		// KeyBits divides the width-128 primitive's native width and
		// keeps the same total key material as the width-256 profiles
		// (defaultKeyBits = 1024, which is a valid multiple of 128).
		KeyBits:             defaultKeyBits,
		MacName:             defaultMacName,
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		Parallax:            true,
		Wrapper:             true,
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
		Parallax:            true,
		Wrapper:             true,
		MixedHashes: [8]string{
			"areion512", "blake2b512", "areion512", "blake2b512",
			"areion512", "blake2b512", "areion512", "blake2b512",
		},
	}
}

// Lookup returns a copy of the [Profile] registered under name — a
// shipped catalogue entry or a prior [Register] registration — or
// [ErrUnknownProfile]. The copy's ParallaxPalette is a fresh slice;
// caller-side mutation does not affect the registry. Safe under
// concurrent invocation with [Register], [Init], and [Profiles].
//
// Lookup is the registry's read surface. The reopen path ([Load] /
// [LoadF] / [Inspect]) never consults the registry — the blob carries
// the resolved record.
func Lookup(name string) (Profile, error) {
	profileRegistryMu.RLock()
	p, ok := profileRegistry[name]
	profileRegistryMu.RUnlock()
	if !ok {
		return Profile{}, ErrUnknownProfile
	}
	p.ParallaxPalette = append([]string(nil), p.ParallaxPalette...)
	return p, nil
}

// resolveProfile merges the profile defaults with the caller-supplied
// [Opts] to produce the resolved [Profile] a Pipeline runs with. Every
// Opts field takes precedence over the corresponding profile default
// when set (non-zero / non-empty for value types; non-nil pointer for
// the two layer toggles).
//
// The result carries a defensive copy of the palette so future
// mutation of the caller's slice (Opts or registry-side) does not
// leak into the Pipeline.
func resolveProfile(prof Profile, opts Opts) Profile {
	out := prof
	out.ParallaxPalette = append([]string(nil), prof.ParallaxPalette...)

	if opts.ChunkSize > 0 {
		out.ChunkSize = opts.ChunkSize
	}
	if opts.InnerHash != "" {
		out.InnerHash = opts.InnerHash
	}
	if opts.KeyBits > 0 {
		out.KeyBits = opts.KeyBits
	}
	if opts.MacName != "" && out.MacName != "" {
		// Only respect MacName override when the profile carries a
		// MAC in the first place — No MAC profiles ignore the field.
		out.MacName = opts.MacName
	}
	if opts.TagStubSize > 0 {
		out.TagStubSize = opts.TagStubSize
	}
	if opts.OuterCipher != "" {
		out.OuterCipher = opts.OuterCipher
	}
	if len(opts.ParallaxPalette) > 0 {
		out.ParallaxPalette = append([]string(nil), opts.ParallaxPalette...)
	}
	if opts.ParallaxSegmentSize > 0 {
		out.ParallaxSegmentSize = opts.ParallaxSegmentSize
	}
	if opts.WithParallax != nil {
		out.Parallax = *opts.WithParallax
	}
	if opts.WithWrapper != nil {
		out.Wrapper = *opts.WithWrapper
	}
	// MixedHashes override. When any Opts.MixedHashes slot is
	// non-empty, the caller wants mixed dispatch: install the array
	// and clear InnerHash so [isMixedProfile] returns true and the
	// mixed seed-alloc / blob-import paths take over. This mirrors
	// the Profile-level mutual-exclusion rule (InnerHash and
	// MixedHashes are exclusive dispatch paths). Slot-level
	// validation (each name resolves via hashes.Find, primitive
	// width matches profile Width, every one of the 8 slots
	// populated) fires fail-fast inside allocEightSeedsMixed at
	// Init time and checkRecipeProfile at Load time — see
	// [Opts.MixedHashes] doc-comment.
	for _, s := range opts.MixedHashes {
		if s != "" {
			out.MixedHashes = opts.MixedHashes
			out.InnerHash = ""
			break
		}
	}
	return out
}

// profileWire is the JSON shape of a [Profile] record — the recipe
// carried in the blob's wrap-layer, the [Inspect] output, and the
// input accepted by the FFI register entry. Key names are frozen for
// wrap-layer schema version 2; every optional key uses omitempty so a
// zero / empty field is absent on the wire. MixedHashes rides as a
// slice so an all-empty constellation is omitted rather than emitted
// as eight empty strings.
type profileWire struct {
	Name                string   `json:"name,omitempty"`
	Mode                string   `json:"mode"`
	Width               int      `json:"width"`
	InnerHash           string   `json:"hash,omitempty"`
	MixedHashes         []string `json:"hashes,omitempty"`
	KeyBits             int      `json:"keybits"`
	MacName             string   `json:"mac,omitempty"`
	TagStubSize         int      `json:"tagstub,omitempty"`
	ChunkSize           int      `json:"chunk,omitempty"`
	Wrapper             bool     `json:"wrapper"`
	OuterCipher         string   `json:"outer,omitempty"`
	Parallax            bool     `json:"parallax"`
	ParallaxPalette     []string `json:"palette,omitempty"`
	ParallaxSegmentSize int      `json:"segment,omitempty"`
}

// MarshalJSON encodes p as the documented recipe object. Key set and
// presence rules:
//
//	name      Name                 omitted when empty
//	mode      Mode                 always
//	width     Width                always
//	hash      InnerHash            omitted when empty (mixed profiles)
//	hashes    MixedHashes          omitted when every slot is empty;
//	                               otherwise exactly eight strings
//	keybits   KeyBits              always
//	mac       MacName              omitted when empty (No MAC)
//	tagstub   TagStubSize          omitted when 0
//	chunk     ChunkSize            omitted when 0
//	wrapper   Wrapper              always
//	outer     OuterCipher          omitted when empty
//	parallax  Parallax             always
//	palette   ParallaxPalette      omitted when empty
//	segment   ParallaxSegmentSize  omitted when 0
//
// No semantic validation is applied by the codec; the field rules are
// enforced by [Register] on the registry side and by [Load] on the
// reopen side. json.Marshal of a Profile anywhere produces this form.
func (p Profile) MarshalJSON() ([]byte, error) {
	w := profileWire{
		Name:                p.Name,
		Mode:                p.Mode,
		Width:               p.Width,
		InnerHash:           p.InnerHash,
		KeyBits:             p.KeyBits,
		MacName:             p.MacName,
		TagStubSize:         p.TagStubSize,
		ChunkSize:           p.ChunkSize,
		Wrapper:             p.Wrapper,
		OuterCipher:         p.OuterCipher,
		Parallax:            p.Parallax,
		ParallaxPalette:     p.ParallaxPalette,
		ParallaxSegmentSize: p.ParallaxSegmentSize,
	}
	if isMixedProfile(p) {
		w.MixedHashes = append([]string(nil), p.MixedHashes[:]...)
	}
	return json.Marshal(w)
}

// UnmarshalJSON decodes the documented recipe object into p. The
// decoder is strict: an unknown key, trailing content after the
// object, or a hashes array whose length is neither 0 nor 8 is an
// error. Every other field is a straight copy; no semantic validation
// runs here (see [Profile.MarshalJSON]). A JSON null leaves p
// unchanged.
func (p *Profile) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	var w profileWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return fmt.Errorf("triple: profile record: %w", err)
	}
	if dec.More() {
		return errors.New("triple: profile record: trailing content")
	}
	if len(w.MixedHashes) != 0 && len(w.MixedHashes) != 8 {
		return fmt.Errorf("triple: profile record: hashes has %d entries, want 0 or 8", len(w.MixedHashes))
	}
	out := Profile{
		Name:                w.Name,
		Mode:                w.Mode,
		Width:               w.Width,
		InnerHash:           w.InnerHash,
		KeyBits:             w.KeyBits,
		MacName:             w.MacName,
		TagStubSize:         w.TagStubSize,
		ChunkSize:           w.ChunkSize,
		Wrapper:             w.Wrapper,
		OuterCipher:         w.OuterCipher,
		Parallax:            w.Parallax,
		ParallaxPalette:     w.ParallaxPalette,
		ParallaxSegmentSize: w.ParallaxSegmentSize,
	}
	if len(w.MixedHashes) == 8 {
		copy(out.MixedHashes[:], w.MixedHashes)
	}
	*p = out
	return nil
}
