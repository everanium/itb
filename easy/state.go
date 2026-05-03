package easy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// stateBlobV1 is the JSON-encoded shape of an exported encryptor
// state. The schema is documented in the package overview; in
// summary:
//
//   - prf_keys is omitted entirely when the primitive has no fixed
//     PRF key (siphash24).
//   - lock_seed is omitted when the encryptor's dedicated lockSeed
//     is off; when on, the field is encoded as the literal `true`.
//     No other value is canonical, and the v1 reader rejects any
//     non-true encoding.
//   - nonce_bits / barrier_fill / bit_soup / lock_soup carry the
//     encryptor's per-instance configuration overrides. Each is
//     omitted when the encryptor never explicitly set it (cfg
//     sentinel "inherit": NonceBits == 0 / BarrierFill == 0 /
//     BitSoup == -1 / LockSoup == -1). On Import the corresponding
//     setter is called for each present field; missing fields keep
//     the receiver's existing cfg state (legacy mirror-manually
//     behaviour).
//   - seeds inner arrays carry decimal uint64 strings (base 10) so
//     cross-language consumers do not hit the JSON 53-bit number
//     precision limit.
//   - prf_keys entries and mac_key are lowercase hex without any
//     "0x" prefix.
type stateBlobV1 struct {
	Version     int        `json:"v"`
	Kind        string     `json:"kind"`
	Primitive   string     `json:"primitive"`
	KeyBits     int        `json:"key_bits"`
	Mode        string     `json:"mode"`
	MAC         string     `json:"mac"`
	PRFKeys     []string   `json:"prf_keys,omitempty"`
	Seeds       [][]string `json:"seeds"`
	MACKey      string     `json:"mac_key"`
	LockSeed    bool       `json:"lock_seed,omitempty"`
	NonceBits   int        `json:"nonce_bits,omitempty"`
	BarrierFill int        `json:"barrier_fill,omitempty"`
	BitSoup     *int32     `json:"bit_soup,omitempty"`
	LockSoup    *int32     `json:"lock_soup,omitempty"`

	// Mixed signals that the blob carries per-slot primitive names.
	// Encoded as the literal `true` when the encryptor was built via
	// [NewMixed] / [NewMixed3]; omitted (false) for single-primitive
	// encryptors built via [New] / [New3]. The Primitive field on a
	// mixed blob carries [MixedPrimitive] ("mixed") and the
	// per-slot names live in Primitives instead.
	Mixed bool `json:"mixed,omitempty"`

	// Primitives carries one canonical [hashes.Registry] name per
	// seed slot in canonical order: 0 = noiseSeed, then dataSeed
	// (Single) or dataSeed1..3 (Triple), then startSeed (Single)
	// or startSeed1..3 (Triple), with the optional dedicated
	// lockSeed at the trailing slot when LockSeed is true. Length
	// matches len(Seeds). Omitted entirely on single-primitive
	// blobs; readers must treat `Mixed: false` and an empty
	// Primitives slice as the legacy single-primitive shape.
	Primitives []string `json:"primitives,omitempty"`
}

// modeToString maps the integer Mode encoding (1 = Single, 3 =
// Triple) to its JSON string form. Panics on unknown values — the
// internal struct should never carry any other Mode.
func modeToString(m int) string {
	switch m {
	case 1:
		return "single"
	case 3:
		return "triple"
	}
	panic(fmt.Sprintf("itb/easy: invalid Mode %d", m))
}

// modeFromString parses the JSON string form back to its integer
// encoding. Returns (mode, true) on a known value, (0, false) on
// any other string.
func modeFromString(s string) (int, bool) {
	switch s {
	case "single":
		return 1, true
	case "triple":
		return 3, true
	}
	return 0, false
}

// Export returns the encryptor's full state as JSON-encoded bytes.
// The caller saves the bytes to disk / KMS / wire as it sees fit
// and later passes them back to [Encryptor.Import] on a fresh
// encryptor to reconstruct the exact state — same PRF fixed keys,
// same seed components, same MAC key, same dedicated lockSeed
// material if active.
//
// Per-encryptor configuration knobs (NonceBits, BarrierFill,
// BitSoup, LockSoup) are NOT carried in the v1 blob — both sides
// communicate them via deployment config. LockSeed is carried
// because activating it changes the structural seed count.
//
// Infallible — JSON marshal of a validated internal struct cannot
// fail under normal operation; a nil-receiver / closed-encryptor
// surface as a panic.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) Export() []byte {
	if e.closed {
		panic(ErrClosed)
	}

	blob := stateBlobV1{
		Version:   versionV1,
		Kind:      kindEasy,
		Primitive: e.Primitive,
		KeyBits:   e.KeyBits,
		Mode:      modeToString(e.Mode),
		MAC:       e.MACName,
	}

	if e.prfKeys != nil {
		blob.PRFKeys = make([]string, len(e.prfKeys))
		for i, k := range e.prfKeys {
			blob.PRFKeys[i] = hex.EncodeToString(k)
		}
	}

	blob.Seeds = make([][]string, len(e.seeds))
	for i, s := range e.seeds {
		comps := seedComponents(s)
		inner := make([]string, len(comps))
		for j, c := range comps {
			inner[j] = strconv.FormatUint(c, 10)
		}
		blob.Seeds[i] = inner
	}

	blob.MACKey = hex.EncodeToString(e.macKey)
	blob.LockSeed = e.cfg.LockSeed > 0

	// Mixed-mode encryptors carry [MixedPrimitive] in Primitive (set
	// at construction), and the per-slot primitive names ride
	// alongside through the Primitives field. Single-primitive
	// encryptors leave Mixed false and Primitives empty so the blob
	// shape remains identical to the pre-mixed schema for callers
	// that never use [NewMixed] / [NewMixed3].
	if e.primitives != nil {
		blob.Mixed = true
		blob.Primitives = append([]string(nil), e.primitives...)
	}

	// Per-instance configuration overrides — emitted only when the
	// encryptor explicitly set them via the matching Set* method
	// (tracked via the *Explicit flags on the Encryptor). The cfg
	// fields themselves carry [SnapshotGlobals]-pinned values and
	// cannot distinguish "user explicitly set 128" from "snapshot
	// of global default 128"; the flags do. Missing fields tell
	// the receiver to keep its own Set* state on Import — the
	// "deployment config concern" path for callers that ship blobs
	// produced from defaults.
	if e.nonceBitsExplicit {
		blob.NonceBits = e.cfg.NonceBits
	}
	if e.barrierFillExplicit {
		blob.BarrierFill = e.cfg.BarrierFill
	}
	if e.bitSoupExplicit {
		v := e.cfg.BitSoup
		blob.BitSoup = &v
	}
	if e.lockSoupExplicit {
		v := e.cfg.LockSoup
		blob.LockSoup = &v
	}

	out, err := json.Marshal(blob)
	if err != nil {
		panic(fmt.Sprintf("itb/easy: Export json.Marshal: %v", err))
	}
	return out
}

// Import consumes a JSON state blob produced by a prior
// [Encryptor.Export] call and replaces the receiver's PRF keys,
// seed components, MAC key, and (optionally) dedicated lockSeed
// material with the imported state. Returns nil on success or one
// of the package's sentinel errors / [ErrMismatch] on any
// validation failure; on error the encryptor's pre-Import state is
// unchanged.
//
// The blob carries the authoritative LockSeed setting. The
// receiver's pre-Import LockSeed state is silently overridden — a
// blob with lock_seed:true elevates a default-LockSeed=0 receiver
// to LockSeed=1 (and the imported lockSeed material populates the
// 4th/8th seed slot); a blob without lock_seed demotes a pre-Import
// LockSeed=1 receiver to LockSeed=0 (and the receiver's pre-Import
// dedicated-lockSeed material is zeroed and discarded). The four
// other configuration dimensions (primitive, key_bits, mode, mac)
// reject on mismatch because the receiver's hash / MAC factories
// were bound at New / New3 time.
//
// firstEncryptCalled is reset to false on every successful Import —
// the encryptor is conceptually reborn, so [Encryptor.SetLockSeed]
// is allowed again until the next first-Encrypt-on-this-state.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) Import(blobBytes []byte) error {
	if e.closed {
		panic(ErrClosed)
	}

	// First pass — parse into a RawMessage map so kind / version /
	// non-canonical lock_seed values can be diagnosed before any
	// field-level decoding.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(blobBytes, &raw); err != nil {
		return ErrMalformed
	}

	var version int
	if rv, ok := raw["v"]; ok {
		if err := json.Unmarshal(rv, &version); err != nil {
			return ErrMalformed
		}
	} else {
		return ErrMalformed
	}
	if version > versionV1 {
		return ErrVersionTooNew
	}

	var kind string
	if rk, ok := raw["kind"]; ok {
		if err := json.Unmarshal(rk, &kind); err != nil {
			return ErrMalformed
		}
	}
	if kind != kindEasy {
		return ErrMalformed
	}

	// lock_seed canonical-encoding check: absent OR literal true.
	// Any other value (false, null, number, string, ...) is non-
	// canonical and rejected.
	rawLockSeed := false
	if rls, ok := raw["lock_seed"]; ok {
		if string(rls) != "true" {
			return ErrMalformed
		}
		rawLockSeed = true
	}

	// Second pass — full struct unmarshal with DisallowUnknownFields
	// so a tampered blob carrying extra fields is rejected as
	// malformed rather than silently accepted (the encoding/json
	// default ignores unknown fields).
	var blob stateBlobV1
	dec := json.NewDecoder(bytes.NewReader(blobBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&blob); err != nil {
		return ErrMalformed
	}

	// Mixed-mode shape mismatch — the receiver and the blob must
	// agree on whether the encryptor is single-primitive or per-slot
	// mixed. A mixed blob landing on a [New]-built receiver (or
	// vice versa) is rejected as a primitive mismatch; the receiver
	// must be reconstructed via the matching constructor before
	// Import.
	receiverIsMixed := e.primitives != nil
	if blob.Mixed != receiverIsMixed {
		return &ErrMismatch{Field: "primitive"}
	}

	// Resolve the width-pinning [hashes.Spec] and the per-slot
	// primitive name list. For mixed blobs every entry of
	// blob.Primitives must resolve to the registry and share the
	// noiseSeed slot's native width; for single-primitive blobs the
	// noise / data / start slots all share blob.Primitive.
	var spec hashes.Spec
	var slotPrims []string
	if blob.Mixed {
		if blob.Primitive != MixedPrimitive {
			return &ErrMismatch{Field: "primitive"}
		}
		if len(blob.Primitives) == 0 {
			return ErrMalformed
		}
		if len(blob.Primitives) != len(e.primitives) {
			return &ErrMismatch{Field: "primitive"}
		}
		s0, ok := hashes.Find(blob.Primitives[0])
		if !ok {
			return ErrUnknownPrimitive
		}
		spec = s0
		for i, p := range blob.Primitives {
			sp, ok := hashes.Find(p)
			if !ok {
				return ErrUnknownPrimitive
			}
			if int(sp.Width) != int(spec.Width) {
				return ErrMalformed
			}
			if p != e.primitives[i] {
				return &ErrMismatch{Field: "primitive"}
			}
		}
		slotPrims = blob.Primitives
	} else {
		s, ok := hashes.Find(blob.Primitive)
		if !ok {
			return ErrUnknownPrimitive
		}
		spec = s
		if blob.Primitive != e.Primitive {
			return &ErrMismatch{Field: "primitive"}
		}
	}

	switch blob.KeyBits {
	case 512, 1024, 2048:
	default:
		return ErrBadKeyBits
	}
	if blob.KeyBits%int(spec.Width) != 0 {
		return ErrBadKeyBits
	}
	if blob.KeyBits != e.KeyBits {
		return &ErrMismatch{Field: "key_bits"}
	}

	mode, ok := modeFromString(blob.Mode)
	if !ok {
		return ErrMalformed
	}
	if mode != e.Mode {
		return &ErrMismatch{Field: "mode"}
	}

	macSpec, ok := macs.Find(blob.MAC)
	if !ok {
		return ErrUnknownMAC
	}
	if blob.MAC != e.MACName {
		return &ErrMismatch{Field: "mac"}
	}

	nSeeds := 3
	if mode == 3 {
		nSeeds = 7
	}
	if rawLockSeed {
		nSeeds++
	}

	// PRFKeys validation. In single-primitive mode the field is
	// either entirely absent (siphash24) or fully populated. In
	// mixed mode the slice is always present with one entry per
	// slot — empty string for siphash24 slots, hex bytes for the
	// rest. In both modes len(blob.Seeds) must equal nSeeds.
	isSipHashSingle := !blob.Mixed && blob.Primitive == "siphash24"
	if blob.Mixed {
		if len(blob.PRFKeys) != nSeeds {
			return &ErrMismatch{Field: "prf_keys"}
		}
		if len(slotPrims) != nSeeds {
			return &ErrMismatch{Field: "primitive"}
		}
		for i := 0; i < nSeeds; i++ {
			slotIsSip := slotPrims[i] == "siphash24"
			slotKeyEmpty := len(blob.PRFKeys[i]) == 0
			if slotIsSip != slotKeyEmpty {
				return &ErrMismatch{Field: "prf_keys"}
			}
		}
	} else {
		if isSipHashSingle && len(blob.PRFKeys) > 0 {
			return &ErrMismatch{Field: "prf_keys"}
		}
		if !isSipHashSingle && len(blob.PRFKeys) == 0 {
			return &ErrMismatch{Field: "prf_keys"}
		}
		if !isSipHashSingle && len(blob.PRFKeys) != nSeeds {
			return &ErrMismatch{Field: "prf_keys"}
		}
	}

	if len(blob.Seeds) != nSeeds {
		return &ErrMismatch{Field: "seeds"}
	}

	macKey, err := hex.DecodeString(blob.MACKey)
	if err != nil {
		return ErrMalformed
	}
	if len(macKey) < macSpec.MinKeyBytes {
		return &ErrMismatch{Field: "mac_key"}
	}

	// Decode PRFKeys. In mixed mode the slice is always allocated
	// with nSeeds entries (nil for siphash24 slots). In single mode
	// siphash24 leaves prfKeys at nil entirely (legacy shape).
	var prfKeys [][]byte
	if blob.Mixed {
		prfKeys = make([][]byte, nSeeds)
		for i, hx := range blob.PRFKeys {
			if hx == "" {
				continue
			}
			kb, err := hex.DecodeString(hx)
			if err != nil {
				return &ErrMismatch{Field: "prf_keys"}
			}
			prfKeys[i] = kb
		}
	} else if !isSipHashSingle {
		prfKeys = make([][]byte, nSeeds)
		for i, hx := range blob.PRFKeys {
			kb, err := hex.DecodeString(hx)
			if err != nil {
				return &ErrMismatch{Field: "prf_keys"}
			}
			prfKeys[i] = kb
		}
	}

	expectedComponents := blob.KeyBits / 64
	seedCompsArr := make([][]uint64, nSeeds)
	for i, inner := range blob.Seeds {
		if len(inner) != expectedComponents {
			return &ErrMismatch{Field: "seeds"}
		}
		comps := make([]uint64, expectedComponents)
		for j, s := range inner {
			v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return &ErrMismatch{Field: "seeds"}
			}
			comps[j] = v
		}
		seedCompsArr[i] = comps
	}

	// Per-slot reconstruction. In mixed mode each slot resolves to
	// its own primitive name from slotPrims; in single mode every
	// slot uses blob.Primitive. The width is shared across all slots
	// in either mode.
	width := int(spec.Width)
	newSeeds := make([]interface{}, nSeeds)
	for i := 0; i < nSeeds; i++ {
		var slotPrim string
		var key []byte
		if blob.Mixed {
			slotPrim = slotPrims[i]
			key = prfKeys[i] // may be nil for siphash24 slots
		} else {
			slotPrim = blob.Primitive
			if !isSipHashSingle {
				key = prfKeys[i]
			}
		}
		seed, err := reconstructSeed(slotPrim, width, key, seedCompsArr[i])
		if err != nil {
			return &ErrMismatch{Field: "prf_keys"}
		}
		newSeeds[i] = seed
	}

	macFunc, err := macs.Make(blob.MAC, macKey)
	if err != nil {
		return &ErrMismatch{Field: "mac_key"}
	}

	// All validation passed. Zero pre-Import key material before
	// the swap so the discarded state never lingers in memory.
	for _, k := range e.prfKeys {
		clear(k)
	}
	clear(e.macKey)
	for _, s := range e.seeds {
		zeroSeedComponents(s, e.width)
	}

	e.seeds = newSeeds
	switch {
	case blob.Mixed:
		e.prfKeys = prfKeys
		e.primitives = append([]string(nil), slotPrims...)
	case isSipHashSingle:
		e.prfKeys = nil
		e.primitives = nil
	default:
		e.prfKeys = prfKeys
		e.primitives = nil
	}
	e.macKey = macKey
	e.macFunc = macFunc

	// Per-instance configuration overrides — restore each present
	// blob field via the matching cfg slot. Missing fields keep
	// the receiver's existing cfg untouched, preserving the legacy
	// mirror-manually behaviour for callers that ship blobs without
	// the optional knobs (older Export, or sender that never called
	// the corresponding Set*).
	//
	// BarrierFill is asymmetric — receiver does not need the same
	// margin as sender (the container dimensions are stored in the
	// header). When the receiver has already explicitly set
	// BarrierFill > 1, that explicit choice takes priority over
	// the blob value: a deployment that wants a heavier CSPRNG
	// margin on the receive path keeps it across Import. The
	// blob value applies only when the receiver is at the default
	// (cfg.BarrierFill == 0 / 1).
	if blob.NonceBits > 0 {
		e.cfg.NonceBits = blob.NonceBits
		e.nonceBitsExplicit = true
	}
	if blob.BarrierFill > 0 && (!e.barrierFillExplicit || e.cfg.BarrierFill <= 1) {
		e.cfg.BarrierFill = blob.BarrierFill
		e.barrierFillExplicit = true
	}
	if blob.BitSoup != nil {
		e.cfg.BitSoup = *blob.BitSoup
		e.bitSoupExplicit = true
	}
	if blob.LockSoup != nil {
		e.cfg.LockSoup = *blob.LockSoup
		e.lockSoupExplicit = true
	}

	if rawLockSeed {
		e.cfg.LockSeed = 1
		e.cfg.LockSeedHandle = newSeeds[nSeeds-1]
		// Wire the dedicated lockSeed onto the noiseSeed via the
		// width-typed AttachLockSeed mutator, mirroring NewMixed /
		// NewMixed3 construction. Without this attach, post-Import
		// SetLockSeed(0) followed by overlay-off setters would not
		// release the noiseSeed's lockSeed pointer — symmetric with
		// the construction-time path so SetLockSeed lifecycle
		// behaves identically regardless of how the encryptor was
		// born.
		attachNoiseSeedLockSeed(newSeeds[0], newSeeds[nSeeds-1], e.width)
		// Auto-couple Lock Soup + Bit Soup on the on-direction,
		// mirroring [Encryptor.SetLockSeed]'s coupling behaviour: a
		// dedicated lockSeed has no observable effect on the wire
		// output unless the bit-permutation overlay is engaged.
		// Sender reached this state through SetLockSeed(1) which
		// couples both overlays; Import on the receiver must reach
		// the same state or the pre-permuted ciphertext decodes as
		// garbage (MAC verification over the encrypted payload still
		// passes — the key material survives the round-trip — but
		// the recovered plaintext is wrong). The auto-couple runs
		// after the blob's BitSoup / LockSoup fields apply, so a
		// sender that explicitly wrote BitSoup=0 / LockSoup=0 plus
		// lock_seed:true (an inconsistent blob) is normalised to
		// the consistent on-direction state here.
		e.cfg.LockSoup = 1
		e.cfg.BitSoup = 1
		e.lockSoupExplicit = true
		e.bitSoupExplicit = true
	} else {
		e.cfg.LockSeed = 0
		e.cfg.LockSeedHandle = nil
		// Off-direction: do NOT auto-disable the overlay, mirroring
		// SetLockSeed off-direction behaviour. Callers that want to
		// drop only LockSeed but keep the underlying overlay engaged
		// retain their pre-Import LockSoup / BitSoup setting. Detach
		// the noiseSeed's lockSeed pointer (if any) symmetric with
		// the rawLockSeed branch above.
		if len(newSeeds) > 0 {
			detachNoiseSeedLockSeed(newSeeds[0], e.width)
		}
	}

	// Conceptually a fresh encryptor — re-allow SetLockSeed.
	e.firstEncryptCalled = false

	return nil
}

// PeekConfig extracts (primitive, key_bits, mode, mac) from a
// serialized state blob without performing full validation. Useful
// for callers that want to inspect a saved blob's metadata before
// constructing a matching encryptor.
//
// Panics on JSON parse failure, kind mismatch, version too new, or
// unknown mode value — same reasoning as the constructor panic
// policy: callers cannot meaningfully recover from a malformed blob.
func PeekConfig(blob []byte) (primitive string, keyBits, mode int, mac string) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(blob, &raw); err != nil {
		panic(fmt.Sprintf("itb/easy: PeekConfig: %v", err))
	}

	var version int
	if rv, ok := raw["v"]; ok {
		if err := json.Unmarshal(rv, &version); err != nil {
			panic(fmt.Sprintf("itb/easy: PeekConfig: invalid v field"))
		}
	}
	if version > versionV1 {
		panic("itb/easy: PeekConfig: state blob version too new")
	}

	var kind string
	if rk, ok := raw["kind"]; ok {
		_ = json.Unmarshal(rk, &kind)
	}
	if kind != kindEasy {
		panic(fmt.Sprintf("itb/easy: PeekConfig: kind %q is not %q", kind, kindEasy))
	}

	var b stateBlobV1
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		panic(fmt.Sprintf("itb/easy: PeekConfig: %v", err))
	}

	m, ok := modeFromString(b.Mode)
	if !ok {
		panic(fmt.Sprintf("itb/easy: PeekConfig: invalid mode %q", b.Mode))
	}

	return b.Primitive, b.KeyBits, m, b.MAC
}

// reconstructSeed builds a fresh Seed{N} from the given primitive
// name, width, fixed-PRF-key bytes (nil for siphash24), and seed
// components. Used by [Encryptor.Import] to rebuild the seed slots
// from the blob's recorded material.
func reconstructSeed(primitive string, width int, key []byte, components []uint64) (interface{}, error) {
	var keyArgs [][]byte
	if key != nil {
		keyArgs = [][]byte{key}
	}

	switch width {
	case 128:
		single, batched, _, err := hashes.Make128Pair(primitive, keyArgs...)
		if err != nil {
			return nil, err
		}
		s, err := itb.SeedFromComponents128(single, components...)
		if err != nil {
			return nil, err
		}
		s.BatchHash = batched
		return s, nil
	case 256:
		single, batched, _, err := hashes.Make256Pair(primitive, keyArgs...)
		if err != nil {
			return nil, err
		}
		s, err := itb.SeedFromComponents256(single, components...)
		if err != nil {
			return nil, err
		}
		s.BatchHash = batched
		return s, nil
	case 512:
		single, batched, _, err := hashes.Make512Pair(primitive, keyArgs...)
		if err != nil {
			return nil, err
		}
		s, err := itb.SeedFromComponents512(single, components...)
		if err != nil {
			return nil, err
		}
		s.BatchHash = batched
		return s, nil
	}
	return nil, fmt.Errorf("unsupported width %d", width)
}

// seedComponents returns a non-defensive view of the underlying
// Components slice for any of the three width-typed Seed pointers.
// Used by [Encryptor.Export] to read seed material into the JSON
// state blob without an extra copy. Callers that mutate the return
// value also mutate the live encryptor — use the public
// [Encryptor.SeedComponents] getter for defensive copies.
func seedComponents(handle interface{}) []uint64 {
	switch v := handle.(type) {
	case *itb.Seed128:
		return v.Components
	case *itb.Seed256:
		return v.Components
	case *itb.Seed512:
		return v.Components
	}
	panic(fmt.Sprintf("itb/easy: unsupported seed handle %T", handle))
}
