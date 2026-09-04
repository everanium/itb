package itb

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// MaxBlobJSONSize is the upper sanity cap on the total byte length of
// a JSON blob accepted by [Blob128.Import3Cfg] / [Blob256.Import3Cfg]
// / [Blob512.Import3Cfg]. A realistic Triple blob is a few kilobytes;
// the 1 MiB ceiling is roughly two orders of magnitude above that,
// and closes the JSON-array-inflation attack surface transitively —
// no field inside the blob (Components string arrays, hex-encoded
// keys, MAC key) can physically exceed the total, so a per-field cap
// beyond this one is a defence-in-depth check rather than the load-
// bearing bound.
const MaxBlobJSONSize = 1 << 20

// maxMACKeyHexLen is the upper cap on the hex-encoded MAC key string
// inside a Blob{N}. Shipped MAC primitives use keys up to 32 bytes
// (see [github.com/everanium/itb/macs]); the 256-character cap covers
// 128 decoded bytes — twice the largest realistic key — so a hostile
// hex payload cannot inflate the decoded []byte before macs.Make
// rejects an out-of-shape key.
const maxMACKeyHexLen = 256

// maxBlob128KeyHexLen is the upper cap on the hex-encoded variable-
// length key strings on [Blob128] (siphash24 empty, aescmac 16 bytes).
// The 128-character cap covers 64 decoded bytes — matches the 64-byte
// fixed cap enforced by hexToFixed64 for [Blob256] / [Blob512] Key*
// fields — so the [Blob128] variable-length path shares the same
// upper bound as its fixed-length siblings, and no hostile hex
// payload can inflate any Key{N,D1..3,S1..3,L} slice before the
// downstream [hashes.Make128Pair] rejects an out-of-shape key.
const maxBlob128KeyHexLen = 128

// decodeBlobStrict parses a Blob{N} JSON payload into the supplied
// blobV1 receiver with [json.Decoder.DisallowUnknownFields] enabled
// so a tampered blob carrying extra fields is rejected as malformed
// rather than silently accepted (the encoding/json default ignores
// unknown fields). Trailing junk after the JSON value is also
// rejected — json.Decoder.Decode otherwise consumes only the first
// value and leaves the rest unread, allowing a tampered blob to
// smuggle data past the structural check.
//
// A leading len(data) > MaxBlobJSONSize check rejects a hostile
// multi-megabyte input before json.Decoder allocates for a single
// field; a Components / hex-key inflation attack cannot slip past
// this bound since every field lives inside the same byte buffer.
//
// Used by every Blob{128,256,512}.Import3Cfg entry point so
// the strict-shape promise is uniform across widths.
func decodeBlobStrict(data []byte, out *blobV1) error {
	if len(data) > MaxBlobJSONSize {
		return ErrBlobMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	// After the first value, the decoder's stream must be empty.
	// dec.More() reports true if any non-whitespace remains; we
	// reject as malformed in that case.
	if dec.More() {
		return ErrBlobMalformed
	}
	return nil
}

// Blob — native-API session-bundle surface. Three width-specific
// types ([Blob128], [Blob256], [Blob512]) pack the low-level
// encryptor material (hash keys + seed components + dedicated
// lockSeed + optional MAC material) plus the sender's
// process-wide bit-permutation / nonce / barrier configuration into
// one JSON blob. The receiver calls Import3Cfg, which applies
// the captured globals unconditionally and populates the struct's
// public fields.
//
// Hash function closures and BatchHash batched-arm wrappers are
// NOT stored — the caller picks factories at restore time and
// wires Hash / BatchHash from the saved Key* bytes via the
// matching factory (e.g. [MakeAreionSoEM512HashWithKey],
// hashes.BLAKE2b512PairWithKey). This keeps the pluggable-PRF
// philosophy consistent with the rest of the native API.
//
// Cross-reference: the [github.com/everanium/itb/triple] facade is
// the high-level alternative for callers that prefer one
// constructor call + auto-coupling + per-instance Config snapshot.
// The native Blob API trades that convenience for explicit factory
// control and global-Set-based configuration.

// ErrBlobModeMismatch is returned by [Blob128.Import3Cfg] /
// [Blob256.Import3Cfg] / [Blob512.Import3Cfg] when the JSON blob
// carries mode != 3. The shipped Import path accepts Triple blobs
// only; Single-mode blobs from legacy senders are rejected.
var ErrBlobModeMismatch = errors.New("itb: blob mode mismatch (expected mode=3 Triple)")

// ErrBlobMalformed is returned when the JSON blob fails to parse
// or carries fields outside the documented shape (zero-length
// components, bad hex / decimal encoding, key_bits inconsistent
// with components length, etc.).
var ErrBlobMalformed = errors.New("itb: blob malformed")

// ErrBlobVersionTooNew is returned when the blob's "v" field is
// greater than the highest version this build understands.
var ErrBlobVersionTooNew = errors.New("itb: blob version too new")

// ErrBlobTooManyOpts is returned by Export3Cfg when more than
// one [Blob128Opts] / [Blob256Opts] / [Blob512Opts] is supplied to
// the trailing variadic position. Zero or one is accepted.
var ErrBlobTooManyOpts = errors.New("itb: Export accepts at most one options struct")

// blobVersionV1 is the current Blob schema version. Future
// additive fields use omitempty and stay at v=1; incompatible
// shape changes bump the version.
const blobVersionV1 = 1

// blobV1 is the JSON-encoded shape shared by every width. uint64
// components are serialised as decimal strings (avoiding JSON's
// 53-bit number limit); hash keys and MAC key are serialised as
// lowercase hex without a "0x" prefix. Optional fields use
// omitempty; the corresponding struct fields on the public Blob{N}
// types stay zero / nil after Import3Cfg when the blob omits them.
type blobV1 struct {
	Version int    `json:"v"`
	Mode    int    `json:"mode"` // 3 = Triple (only mode emitted)
	KeyBits int    `json:"key_bits"`
	KeyN    string `json:"key_n"`
	KeyL    string `json:"key_l,omitempty"` // dedicated lockSeed
	KeyD1   string `json:"key_d1,omitempty"`
	KeyD2   string `json:"key_d2,omitempty"`
	KeyD3   string `json:"key_d3,omitempty"`
	KeyS1   string `json:"key_s1,omitempty"`
	KeyS2   string `json:"key_s2,omitempty"`
	KeyS3   string `json:"key_s3,omitempty"`

	NS  []string `json:"ns"`
	LS  []string `json:"ls,omitempty"` // dedicated lockSeed
	DS1 []string `json:"ds1,omitempty"`
	DS2 []string `json:"ds2,omitempty"`
	DS3 []string `json:"ds3,omitempty"`
	SS1 []string `json:"ss1,omitempty"`
	SS2 []string `json:"ss2,omitempty"`
	SS3 []string `json:"ss3,omitempty"`

	MACKey  string `json:"mac_key,omitempty"`
	MACName string `json:"mac_name,omitempty"`

	Globals blobGlobalsV1 `json:"globals"`
}

// blobGlobalsV1 captures the sender's per-instance nonce / barrier
// configuration at the moment of Export3Cfg. Import3Cfg copies the
// captured NonceBits / BarrierFill into the caller's *Config. The
// worker cap ([Config.MaxWorkers]) is per-machine performance tuning,
// not wire shape, and has no key here — the strict decoder rejects
// one like any unknown key.
type blobGlobalsV1 struct {
	NonceBits   int `json:"nonce_bits"`
	BarrierFill int `json:"barrier_fill"`
}

// componentsToStrings encodes a uint64 slice as decimal-string
// slice for JSON serialisation. Avoiding the JSON number form
// keeps cross-language consumers unaffected by JSON's 53-bit
// precision limit.
func componentsToStrings(comps []uint64) []string {
	out := make([]string, len(comps))
	for i, c := range comps {
		out[i] = strconv.FormatUint(c, 10)
	}
	return out
}

// componentsFromStrings is the inverse of [componentsToStrings].
// Returns an error wrapping [ErrBlobMalformed] when any element
// fails to parse as a base-10 uint64.
func componentsFromStrings(strs []string) ([]uint64, error) {
	out := make([]uint64, len(strs))
	for i, s := range strs {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, ErrBlobMalformed
		}
		out[i] = v
	}
	return out, nil
}

// hexToFixed64 / hexToFixed32 decode a hex-encoded fixed-width
// hash key. Both flag any length mismatch as [ErrBlobMalformed].
func hexToFixed64(s string) ([64]byte, error) {
	var out [64]byte
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) != 64 {
		return out, ErrBlobMalformed
	}
	copy(out[:], decoded)
	return out, nil
}

func hexToFixed32(s string) ([32]byte, error) {
	var out [32]byte
	decoded, err := hex.DecodeString(s)
	if err != nil || len(decoded) != 32 {
		return out, ErrBlobMalformed
	}
	copy(out[:], decoded)
	return out, nil
}

// hexToBytes is the variable-length variant used by [Blob128] —
// the 128-bit width covers both siphash24 (no fixed key, empty
// bytes) and aescmac (16-byte key). Returns nil for an empty
// input string. Rejects any input longer than [maxBlob128KeyHexLen]
// as [ErrBlobMalformed] so a hostile hex payload cannot force a
// multi-megabyte decoded slice before the downstream key-length
// check in [hashes.Make128Pair] runs.
func hexToBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if len(s) > maxBlob128KeyHexLen {
		return nil, ErrBlobMalformed
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrBlobMalformed
	}
	return decoded, nil
}

// validateSeedComponents{N} checks that a freshly parsed component
// slice has the expected key_bits length and matches the lengths
// of its peers (e.g. all seven Triple-mode seeds carry the same
// component count).
func validateSeedComponentsLen(got, want int) error {
	if got != want {
		return ErrBlobMalformed
	}
	return nil
}

// ───────────────────────────────────────────────────────────────────
// Blob512 — 512-bit native-API state container
// ───────────────────────────────────────────────────────────────────

// Blob512 carries native-API encryptor material (512-bit width)
// across processes. Public fields are populated after
// [Blob512.Import3Cfg]; the caller wires Hash / BatchHash closures
// from the saved Key* bytes through the appropriate 512-bit factory.
//
// [Blob512.Mode] is populated by Import3Cfg / Export3Cfg to 3
// (Triple); no other value is emitted on the shipped surface.
//
// Not safe for concurrent invocation — Export3Cfg / Import3Cfg
// calls on the same Blob512 instance must be serialised by the
// caller.
type Blob512 struct {
	Mode int

	// Hash key bytes.
	KeyN  [64]byte
	KeyL  [64]byte // dedicated lockSeed
	KeyD1 [64]byte
	KeyD2 [64]byte
	KeyD3 [64]byte
	KeyS1 [64]byte
	KeyS2 [64]byte
	KeyS3 [64]byte

	// Seed components — *Seed512 with .Components populated.
	// Hash and BatchHash are nil after Import3Cfg; the caller wires
	// them from the saved Key* bytes.
	NS  *Seed512
	LS  *Seed512 // dedicated lockSeed
	DS1 *Seed512
	DS2 *Seed512
	DS3 *Seed512
	SS1 *Seed512
	SS2 *Seed512
	SS3 *Seed512

	// Optional MAC material. Caller rebuilds the closure with
	// macs.Make(MACName, MACKey).
	MACKey  []byte
	MACName string
}

// Blob512Opts carries the dedicated lockSeed material and optional
// MAC material for [Blob512.Export3Cfg]. Zero-valued MAC fields
// signal "absent" — pass an empty struct, or omit the opts
// argument entirely, when no MAC is in use.
type Blob512Opts struct {
	KeyL    [64]byte // dedicated lockSeed
	LS      *Seed512 // dedicated lockSeed
	MACKey  []byte   // nil / empty if no MAC
	MACName string   // empty if no MAC
}

// ───────────────────────────────────────────────────────────────────
// Blob256 — 256-bit native-API state container
// ───────────────────────────────────────────────────────────────────

// Blob256 is the 256-bit width counterpart of [Blob512]. Hash key
// fields are [32]byte (areion256, blake3, blake2s, blake2b256,
// chacha20 — all 32-byte fixed key). See [Blob512] for the full
// API contract; the surface mirrors symmetrically across widths.
type Blob256 struct {
	Mode int

	// Hash key bytes.
	KeyN  [32]byte
	KeyL  [32]byte // dedicated lockSeed
	KeyD1 [32]byte
	KeyD2 [32]byte
	KeyD3 [32]byte
	KeyS1 [32]byte
	KeyS2 [32]byte
	KeyS3 [32]byte

	// Seed components — *Seed256 with .Components populated.
	// Hash and BatchHash are nil after Import3Cfg; the caller wires
	// them from the saved Key* bytes.
	NS  *Seed256
	LS  *Seed256 // dedicated lockSeed
	DS1 *Seed256
	DS2 *Seed256
	DS3 *Seed256
	SS1 *Seed256
	SS2 *Seed256
	SS3 *Seed256

	// Optional MAC material. Caller rebuilds the closure with
	// macs.Make(MACName, MACKey).
	MACKey  []byte
	MACName string
}

// Blob256Opts is the 256-bit width counterpart of [Blob512Opts].
type Blob256Opts struct {
	KeyL    [32]byte // dedicated lockSeed
	LS      *Seed256 // dedicated lockSeed
	MACKey  []byte   // nil / empty if no MAC
	MACName string   // empty if no MAC
}

// ───────────────────────────────────────────────────────────────────
// Blob128 — 128-bit native-API state container
// ───────────────────────────────────────────────────────────────────

// Blob128 is the 128-bit width counterpart of [Blob512]. Hash key
// fields are []byte (variable length): 16 bytes for aescmac, empty
// for siphash24. See [Blob512] for the full API contract; the
// surface mirrors symmetrically across widths apart from the key
// type.
type Blob128 struct {
	Mode int

	// Hash key bytes.
	KeyN  []byte
	KeyL  []byte // dedicated lockSeed
	KeyD1 []byte
	KeyD2 []byte
	KeyD3 []byte
	KeyS1 []byte
	KeyS2 []byte
	KeyS3 []byte

	// Seed components — *Seed128 with .Components populated.
	// Hash and BatchHash are nil after Import3Cfg; the caller wires
	// them from the saved Key* bytes.
	NS  *Seed128
	LS  *Seed128 // dedicated lockSeed
	DS1 *Seed128
	DS2 *Seed128
	DS3 *Seed128
	SS1 *Seed128
	SS2 *Seed128
	SS3 *Seed128

	// Optional MAC material. Caller rebuilds the closure with
	// macs.Make(MACName, MACKey).
	MACKey  []byte
	MACName string
}

// Blob128Opts is the 128-bit width counterpart of [Blob512Opts].
// KeyL is a variable-length byte slice (empty for siphash24,
// 16 bytes for aescmac).
type Blob128Opts struct {
	KeyL    []byte   // dedicated lockSeed
	LS      *Seed128 // dedicated lockSeed
	MACKey  []byte   // nil / empty if no MAC
	MACName string   // empty if no MAC
}

// ───────────────────────────────────────────────────────────────────
// Cfg-aware Blob Import / Export (per-instance isolation)
// ───────────────────────────────────────────────────────────────────

// ErrBlobNilCfg is returned by [Blob128.Export3Cfg] /
// [Blob256.Export3Cfg] / [Blob512.Export3Cfg] and by their
// Import3Cfg counterparts when a nil *Config is supplied. The
// Cfg-aware entry points require per-instance isolation, so the
// caller must supply a non-nil Config.
var ErrBlobNilCfg = errors.New("itb: blob: Cfg entry point requires non-nil *Config")

// snapshotGlobalsV1FromCfg reads the per-instance nonce / barrier
// configuration from a caller-supplied *Config. The public Export3Cfg
// entry points reject nil before reaching this helper (see
// [ErrBlobNilCfg]). [Config.MaxWorkers] is not snapshotted.
func snapshotGlobalsV1FromCfg(cfg *Config) blobGlobalsV1 {
	return blobGlobalsV1{
		NonceBits:   cfg.NonceBits,
		BarrierFill: cfg.BarrierFill,
	}
}

// applyGlobalsV1ToCfg validates the captured globals and writes them
// into a caller-supplied *Config. No process-wide state is mutated.
//
// Any out-of-range NonceBits / BarrierFill value yields
// [ErrBlobMalformed] before any field is written, so a malformed
// blob does not leave a partially-populated Config behind.
//
// cfg.MaxWorkers is not touched: the blob carries no worker cap, and
// the receiver's own value (0 → runtime.NumCPU at consumption unless
// the caller sets it) applies.
func applyGlobalsV1ToCfg(g blobGlobalsV1, cfg *Config) error {
	if cfg == nil {
		return ErrBlobNilCfg
	}
	switch g.NonceBits {
	case 128, 256, 512:
	default:
		return ErrBlobMalformed
	}
	switch g.BarrierFill {
	case 1, 2, 4, 8, 16, 32:
	default:
		return ErrBlobMalformed
	}
	cfg.NonceBits = g.NonceBits
	cfg.BarrierFill = g.BarrierFill
	return nil
}

// ───────────────────────────────────────────────────────────────────
// Blob512 — Cfg-aware Triple Ouroboros Export / Import
// ───────────────────────────────────────────────────────────────────

// Export3Cfg packs the 8-seed Triple constellation, per-slot hash
// keys, dedicated lockSeed, and optional MAC material into
// a self-describing JSON blob, capturing the per-instance
// NonceBits / BarrierFill from the caller-supplied *Config into the
// blob's globals section. The worker cap is not wire state and is
// not emitted.
//
// A nil cfg returns [ErrBlobNilCfg] — the Cfg-aware entry point
// requires per-instance isolation, so the caller must supply a
// non-nil Config.
func (b *Blob512) Export3Cfg(
	cfg *Config,
	keyN [64]byte,
	keyD1, keyD2, keyD3 [64]byte,
	keyS1, keyS2, keyS3 [64]byte,
	ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed512,
	opts ...Blob512Opts,
) ([]byte, error) {
	if cfg == nil {
		return nil, ErrBlobNilCfg
	}
	if err := validateConfigCfg(cfg); err != nil {
		return nil, err
	}
	if len(opts) > 1 {
		return nil, ErrBlobTooManyOpts
	}
	var o Blob512Opts
	if len(opts) == 1 {
		o = opts[0]
	}
	seeds := [7]*Seed512{ns, ds1, ds2, ds3, ss1, ss2, ss3}
	for i, s := range seeds {
		if s == nil {
			return nil, fmt.Errorf("itb: Blob512.Export3Cfg: nil seed at slot %d", i)
		}
	}
	n := len(ns.Components)
	if n == 0 {
		return nil, fmt.Errorf("itb: Blob512.Export3Cfg: empty noiseSeed components")
	}
	for i, s := range seeds[1:] {
		if len(s.Components) != n {
			return nil, fmt.Errorf("itb: Blob512.Export3Cfg: seed slot %d component count differs from noiseSeed", i+1)
		}
	}

	blob := blobV1{
		Version: blobVersionV1,
		Mode:    3,
		KeyBits: n * 64,
		KeyN:    hex.EncodeToString(keyN[:]),
		KeyD1:   hex.EncodeToString(keyD1[:]),
		KeyD2:   hex.EncodeToString(keyD2[:]),
		KeyD3:   hex.EncodeToString(keyD3[:]),
		KeyS1:   hex.EncodeToString(keyS1[:]),
		KeyS2:   hex.EncodeToString(keyS2[:]),
		KeyS3:   hex.EncodeToString(keyS3[:]),
		NS:      componentsToStrings(ns.Components),
		DS1:     componentsToStrings(ds1.Components),
		DS2:     componentsToStrings(ds2.Components),
		DS3:     componentsToStrings(ds3.Components),
		SS1:     componentsToStrings(ss1.Components),
		SS2:     componentsToStrings(ss2.Components),
		SS3:     componentsToStrings(ss3.Components),
		Globals: snapshotGlobalsV1FromCfg(cfg),
	}

	if o.LS != nil {
		if len(o.LS.Components) != n {
			return nil, fmt.Errorf("itb: Blob512.Export3Cfg: lockSeed component count differs from noiseSeed")
		}
		blob.KeyL = hex.EncodeToString(o.KeyL[:])
		blob.LS = componentsToStrings(o.LS.Components)
	}
	if len(o.MACKey) > 0 {
		blob.MACKey = hex.EncodeToString(o.MACKey)
		blob.MACName = o.MACName
	}
	b.Mode = 3
	return json.Marshal(blob)
}

// Import3Cfg unpacks a Triple blob produced by [Blob512.Export3Cfg]
// and writes the captured globals into the caller-supplied *Config
// via [applyGlobalsV1ToCfg]; no process-wide state is mutated.
// The strict-shape decoder rejects unknown fields and trailing
// junk; the version / mode / key_bits / component-count validation
// runs before any receiver field is written; and the final receiver
// population happens only after every check succeeds.
//
// A nil cfg returns [ErrBlobNilCfg].
func (b *Blob512) Import3Cfg(data []byte, cfg *Config) error {
	if cfg == nil {
		return ErrBlobNilCfg
	}
	var blob blobV1
	if err := decodeBlobStrict(data, &blob); err != nil {
		return ErrBlobMalformed
	}
	if blob.Version > blobVersionV1 {
		return ErrBlobVersionTooNew
	}
	if blob.Mode != 3 {
		return ErrBlobModeMismatch
	}
	// KeyBits pre-validation — mirrors the [NewSeed512] /
	// [SeedFromComponents512] contract at the Import boundary so a
	// malformed blob (KeyBits outside the shipped range, or not a
	// multiple of the width) cannot slip past validateSeedComponentsLen
	// with a small "want" that then indexes past the seed material at
	// first use (Encrypt3x512Cfg → ChainHash512 → Components[0:8]).
	if blob.KeyBits < 512 || blob.KeyBits > MaxKeyBits || blob.KeyBits%512 != 0 {
		return ErrBlobMalformed
	}

	keyN, err := hexToFixed64(blob.KeyN)
	if err != nil {
		return err
	}
	keyD1, err := hexToFixed64(blob.KeyD1)
	if err != nil {
		return err
	}
	keyD2, err := hexToFixed64(blob.KeyD2)
	if err != nil {
		return err
	}
	keyD3, err := hexToFixed64(blob.KeyD3)
	if err != nil {
		return err
	}
	keyS1, err := hexToFixed64(blob.KeyS1)
	if err != nil {
		return err
	}
	keyS2, err := hexToFixed64(blob.KeyS2)
	if err != nil {
		return err
	}
	keyS3, err := hexToFixed64(blob.KeyS3)
	if err != nil {
		return err
	}
	ns, err := componentsFromStrings(blob.NS)
	if err != nil {
		return err
	}
	ds1, err := componentsFromStrings(blob.DS1)
	if err != nil {
		return err
	}
	ds2, err := componentsFromStrings(blob.DS2)
	if err != nil {
		return err
	}
	ds3, err := componentsFromStrings(blob.DS3)
	if err != nil {
		return err
	}
	ss1, err := componentsFromStrings(blob.SS1)
	if err != nil {
		return err
	}
	ss2, err := componentsFromStrings(blob.SS2)
	if err != nil {
		return err
	}
	ss3, err := componentsFromStrings(blob.SS3)
	if err != nil {
		return err
	}
	want := blob.KeyBits / 64
	for _, comps := range [][]uint64{ns, ds1, ds2, ds3, ss1, ss2, ss3} {
		if err := validateSeedComponentsLen(len(comps), want); err != nil {
			return err
		}
	}

	var keyL [64]byte
	var ls []uint64
	hasLS := blob.KeyL != "" || len(blob.LS) > 0
	if hasLS {
		keyL, err = hexToFixed64(blob.KeyL)
		if err != nil {
			return err
		}
		ls, err = componentsFromStrings(blob.LS)
		if err != nil {
			return err
		}
		if err := validateSeedComponentsLen(len(ls), want); err != nil {
			return err
		}
	}

	var macKey []byte
	if blob.MACKey != "" {
		if len(blob.MACKey) > maxMACKeyHexLen {
			return ErrBlobMalformed
		}
		macKey, err = hex.DecodeString(blob.MACKey)
		if err != nil {
			return ErrBlobMalformed
		}
	}

	if err := applyGlobalsV1ToCfg(blob.Globals, cfg); err != nil {
		return err
	}

	*b = Blob512{
		Mode:    3,
		KeyN:    keyN,
		KeyD1:   keyD1,
		KeyD2:   keyD2,
		KeyD3:   keyD3,
		KeyS1:   keyS1,
		KeyS2:   keyS2,
		KeyS3:   keyS3,
		NS:      &Seed512{Components: ns},
		DS1:     &Seed512{Components: ds1},
		DS2:     &Seed512{Components: ds2},
		DS3:     &Seed512{Components: ds3},
		SS1:     &Seed512{Components: ss1},
		SS2:     &Seed512{Components: ss2},
		SS3:     &Seed512{Components: ss3},
		MACKey:  macKey,
		MACName: blob.MACName,
	}
	if hasLS {
		b.KeyL = keyL
		b.LS = &Seed512{Components: ls}
	}
	return nil
}

// ───────────────────────────────────────────────────────────────────
// Blob256 — Cfg-aware Triple Ouroboros Export / Import
// ───────────────────────────────────────────────────────────────────

// Export3Cfg — Triple Ouroboros, 256-bit width. See
// [Blob512.Export3Cfg] for the full contract.
func (b *Blob256) Export3Cfg(
	cfg *Config,
	keyN [32]byte,
	keyD1, keyD2, keyD3 [32]byte,
	keyS1, keyS2, keyS3 [32]byte,
	ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed256,
	opts ...Blob256Opts,
) ([]byte, error) {
	if cfg == nil {
		return nil, ErrBlobNilCfg
	}
	if err := validateConfigCfg(cfg); err != nil {
		return nil, err
	}
	if len(opts) > 1 {
		return nil, ErrBlobTooManyOpts
	}
	var o Blob256Opts
	if len(opts) == 1 {
		o = opts[0]
	}
	seeds := [7]*Seed256{ns, ds1, ds2, ds3, ss1, ss2, ss3}
	for i, s := range seeds {
		if s == nil {
			return nil, fmt.Errorf("itb: Blob256.Export3Cfg: nil seed at slot %d", i)
		}
	}
	n := len(ns.Components)
	if n == 0 {
		return nil, fmt.Errorf("itb: Blob256.Export3Cfg: empty noiseSeed components")
	}
	for i, s := range seeds[1:] {
		if len(s.Components) != n {
			return nil, fmt.Errorf("itb: Blob256.Export3Cfg: seed slot %d component count differs from noiseSeed", i+1)
		}
	}

	blob := blobV1{
		Version: blobVersionV1,
		Mode:    3,
		KeyBits: n * 64,
		KeyN:    hex.EncodeToString(keyN[:]),
		KeyD1:   hex.EncodeToString(keyD1[:]),
		KeyD2:   hex.EncodeToString(keyD2[:]),
		KeyD3:   hex.EncodeToString(keyD3[:]),
		KeyS1:   hex.EncodeToString(keyS1[:]),
		KeyS2:   hex.EncodeToString(keyS2[:]),
		KeyS3:   hex.EncodeToString(keyS3[:]),
		NS:      componentsToStrings(ns.Components),
		DS1:     componentsToStrings(ds1.Components),
		DS2:     componentsToStrings(ds2.Components),
		DS3:     componentsToStrings(ds3.Components),
		SS1:     componentsToStrings(ss1.Components),
		SS2:     componentsToStrings(ss2.Components),
		SS3:     componentsToStrings(ss3.Components),
		Globals: snapshotGlobalsV1FromCfg(cfg),
	}
	if o.LS != nil {
		if len(o.LS.Components) != n {
			return nil, fmt.Errorf("itb: Blob256.Export3Cfg: lockSeed component count differs from noiseSeed")
		}
		blob.KeyL = hex.EncodeToString(o.KeyL[:])
		blob.LS = componentsToStrings(o.LS.Components)
	}
	if len(o.MACKey) > 0 {
		blob.MACKey = hex.EncodeToString(o.MACKey)
		blob.MACName = o.MACName
	}
	b.Mode = 3
	return json.Marshal(blob)
}

// Import3Cfg — Triple Ouroboros, 256-bit width. See
// [Blob512.Import3Cfg] for the full contract.
func (b *Blob256) Import3Cfg(data []byte, cfg *Config) error {
	if cfg == nil {
		return ErrBlobNilCfg
	}
	var blob blobV1
	if err := decodeBlobStrict(data, &blob); err != nil {
		return ErrBlobMalformed
	}
	if blob.Version > blobVersionV1 {
		return ErrBlobVersionTooNew
	}
	if blob.Mode != 3 {
		return ErrBlobModeMismatch
	}
	// KeyBits pre-validation — mirrors the [NewSeed256] /
	// [SeedFromComponents256] contract at the Import boundary so a
	// malformed blob (KeyBits outside the shipped range, or not a
	// multiple of the width) cannot slip past validateSeedComponentsLen
	// with a small "want" that then indexes past the seed material at
	// first use.
	if blob.KeyBits < 512 || blob.KeyBits > MaxKeyBits || blob.KeyBits%256 != 0 {
		return ErrBlobMalformed
	}

	keyN, err := hexToFixed32(blob.KeyN)
	if err != nil {
		return err
	}
	keyD1, err := hexToFixed32(blob.KeyD1)
	if err != nil {
		return err
	}
	keyD2, err := hexToFixed32(blob.KeyD2)
	if err != nil {
		return err
	}
	keyD3, err := hexToFixed32(blob.KeyD3)
	if err != nil {
		return err
	}
	keyS1, err := hexToFixed32(blob.KeyS1)
	if err != nil {
		return err
	}
	keyS2, err := hexToFixed32(blob.KeyS2)
	if err != nil {
		return err
	}
	keyS3, err := hexToFixed32(blob.KeyS3)
	if err != nil {
		return err
	}
	ns, err := componentsFromStrings(blob.NS)
	if err != nil {
		return err
	}
	ds1, err := componentsFromStrings(blob.DS1)
	if err != nil {
		return err
	}
	ds2, err := componentsFromStrings(blob.DS2)
	if err != nil {
		return err
	}
	ds3, err := componentsFromStrings(blob.DS3)
	if err != nil {
		return err
	}
	ss1, err := componentsFromStrings(blob.SS1)
	if err != nil {
		return err
	}
	ss2, err := componentsFromStrings(blob.SS2)
	if err != nil {
		return err
	}
	ss3, err := componentsFromStrings(blob.SS3)
	if err != nil {
		return err
	}
	want := blob.KeyBits / 64
	for _, comps := range [][]uint64{ns, ds1, ds2, ds3, ss1, ss2, ss3} {
		if err := validateSeedComponentsLen(len(comps), want); err != nil {
			return err
		}
	}

	var keyL [32]byte
	var ls []uint64
	hasLS := blob.KeyL != "" || len(blob.LS) > 0
	if hasLS {
		keyL, err = hexToFixed32(blob.KeyL)
		if err != nil {
			return err
		}
		ls, err = componentsFromStrings(blob.LS)
		if err != nil {
			return err
		}
		if err := validateSeedComponentsLen(len(ls), want); err != nil {
			return err
		}
	}

	var macKey []byte
	if blob.MACKey != "" {
		if len(blob.MACKey) > maxMACKeyHexLen {
			return ErrBlobMalformed
		}
		macKey, err = hex.DecodeString(blob.MACKey)
		if err != nil {
			return ErrBlobMalformed
		}
	}

	if err := applyGlobalsV1ToCfg(blob.Globals, cfg); err != nil {
		return err
	}

	*b = Blob256{
		Mode:    3,
		KeyN:    keyN,
		KeyD1:   keyD1,
		KeyD2:   keyD2,
		KeyD3:   keyD3,
		KeyS1:   keyS1,
		KeyS2:   keyS2,
		KeyS3:   keyS3,
		NS:      &Seed256{Components: ns},
		DS1:     &Seed256{Components: ds1},
		DS2:     &Seed256{Components: ds2},
		DS3:     &Seed256{Components: ds3},
		SS1:     &Seed256{Components: ss1},
		SS2:     &Seed256{Components: ss2},
		SS3:     &Seed256{Components: ss3},
		MACKey:  macKey,
		MACName: blob.MACName,
	}
	if hasLS {
		b.KeyL = keyL
		b.LS = &Seed256{Components: ls}
	}
	return nil
}

// ───────────────────────────────────────────────────────────────────
// Blob128 — Cfg-aware Triple Ouroboros Export / Import
// ───────────────────────────────────────────────────────────────────

// Export3Cfg — Triple Ouroboros, 128-bit width. See
// [Blob512.Export3Cfg] for the full contract.
func (b *Blob128) Export3Cfg(
	cfg *Config,
	keyN []byte,
	keyD1, keyD2, keyD3 []byte,
	keyS1, keyS2, keyS3 []byte,
	ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed128,
	opts ...Blob128Opts,
) ([]byte, error) {
	if cfg == nil {
		return nil, ErrBlobNilCfg
	}
	if err := validateConfigCfg(cfg); err != nil {
		return nil, err
	}
	if len(opts) > 1 {
		return nil, ErrBlobTooManyOpts
	}
	var o Blob128Opts
	if len(opts) == 1 {
		o = opts[0]
	}
	seeds := [7]*Seed128{ns, ds1, ds2, ds3, ss1, ss2, ss3}
	for i, s := range seeds {
		if s == nil {
			return nil, fmt.Errorf("itb: Blob128.Export3Cfg: nil seed at slot %d", i)
		}
	}
	n := len(ns.Components)
	if n == 0 {
		return nil, fmt.Errorf("itb: Blob128.Export3Cfg: empty noiseSeed components")
	}
	for i, s := range seeds[1:] {
		if len(s.Components) != n {
			return nil, fmt.Errorf("itb: Blob128.Export3Cfg: seed slot %d component count differs from noiseSeed", i+1)
		}
	}

	blob := blobV1{
		Version: blobVersionV1,
		Mode:    3,
		KeyBits: n * 64,
		KeyN:    hex.EncodeToString(keyN),
		KeyD1:   hex.EncodeToString(keyD1),
		KeyD2:   hex.EncodeToString(keyD2),
		KeyD3:   hex.EncodeToString(keyD3),
		KeyS1:   hex.EncodeToString(keyS1),
		KeyS2:   hex.EncodeToString(keyS2),
		KeyS3:   hex.EncodeToString(keyS3),
		NS:      componentsToStrings(ns.Components),
		DS1:     componentsToStrings(ds1.Components),
		DS2:     componentsToStrings(ds2.Components),
		DS3:     componentsToStrings(ds3.Components),
		SS1:     componentsToStrings(ss1.Components),
		SS2:     componentsToStrings(ss2.Components),
		SS3:     componentsToStrings(ss3.Components),
		Globals: snapshotGlobalsV1FromCfg(cfg),
	}
	if o.LS != nil {
		if len(o.LS.Components) != n {
			return nil, fmt.Errorf("itb: Blob128.Export3Cfg: lockSeed component count differs from noiseSeed")
		}
		blob.KeyL = hex.EncodeToString(o.KeyL)
		blob.LS = componentsToStrings(o.LS.Components)
	}
	if len(o.MACKey) > 0 {
		blob.MACKey = hex.EncodeToString(o.MACKey)
		blob.MACName = o.MACName
	}
	b.Mode = 3
	return json.Marshal(blob)
}

// Import3Cfg — Triple Ouroboros, 128-bit width. See
// [Blob512.Import3Cfg] for the full contract.
func (b *Blob128) Import3Cfg(data []byte, cfg *Config) error {
	if cfg == nil {
		return ErrBlobNilCfg
	}
	var blob blobV1
	if err := decodeBlobStrict(data, &blob); err != nil {
		return ErrBlobMalformed
	}
	if blob.Version > blobVersionV1 {
		return ErrBlobVersionTooNew
	}
	if blob.Mode != 3 {
		return ErrBlobModeMismatch
	}
	// KeyBits pre-validation — mirrors the [NewSeed128] /
	// [SeedFromComponents128] contract at the Import boundary so a
	// malformed blob (KeyBits outside the shipped range, or not a
	// multiple of the width) cannot slip past validateSeedComponentsLen
	// with a small "want" that then indexes past the seed material at
	// first use.
	if blob.KeyBits < 512 || blob.KeyBits > MaxKeyBits || blob.KeyBits%128 != 0 {
		return ErrBlobMalformed
	}

	keyN, err := hexToBytes(blob.KeyN)
	if err != nil {
		return err
	}
	keyD1, err := hexToBytes(blob.KeyD1)
	if err != nil {
		return err
	}
	keyD2, err := hexToBytes(blob.KeyD2)
	if err != nil {
		return err
	}
	keyD3, err := hexToBytes(blob.KeyD3)
	if err != nil {
		return err
	}
	keyS1, err := hexToBytes(blob.KeyS1)
	if err != nil {
		return err
	}
	keyS2, err := hexToBytes(blob.KeyS2)
	if err != nil {
		return err
	}
	keyS3, err := hexToBytes(blob.KeyS3)
	if err != nil {
		return err
	}
	ns, err := componentsFromStrings(blob.NS)
	if err != nil {
		return err
	}
	ds1, err := componentsFromStrings(blob.DS1)
	if err != nil {
		return err
	}
	ds2, err := componentsFromStrings(blob.DS2)
	if err != nil {
		return err
	}
	ds3, err := componentsFromStrings(blob.DS3)
	if err != nil {
		return err
	}
	ss1, err := componentsFromStrings(blob.SS1)
	if err != nil {
		return err
	}
	ss2, err := componentsFromStrings(blob.SS2)
	if err != nil {
		return err
	}
	ss3, err := componentsFromStrings(blob.SS3)
	if err != nil {
		return err
	}
	want := blob.KeyBits / 64
	for _, comps := range [][]uint64{ns, ds1, ds2, ds3, ss1, ss2, ss3} {
		if err := validateSeedComponentsLen(len(comps), want); err != nil {
			return err
		}
	}

	var keyL []byte
	var ls []uint64
	hasLS := blob.KeyL != "" || len(blob.LS) > 0
	if hasLS {
		keyL, err = hexToBytes(blob.KeyL)
		if err != nil {
			return err
		}
		ls, err = componentsFromStrings(blob.LS)
		if err != nil {
			return err
		}
		if err := validateSeedComponentsLen(len(ls), want); err != nil {
			return err
		}
	}

	var macKey []byte
	if blob.MACKey != "" {
		if len(blob.MACKey) > maxMACKeyHexLen {
			return ErrBlobMalformed
		}
		macKey, err = hex.DecodeString(blob.MACKey)
		if err != nil {
			return ErrBlobMalformed
		}
	}

	if err := applyGlobalsV1ToCfg(blob.Globals, cfg); err != nil {
		return err
	}

	*b = Blob128{
		Mode:    3,
		KeyN:    keyN,
		KeyD1:   keyD1,
		KeyD2:   keyD2,
		KeyD3:   keyD3,
		KeyS1:   keyS1,
		KeyS2:   keyS2,
		KeyS3:   keyS3,
		NS:      &Seed128{Components: ns},
		DS1:     &Seed128{Components: ds1},
		DS2:     &Seed128{Components: ds2},
		DS3:     &Seed128{Components: ds3},
		SS1:     &Seed128{Components: ss1},
		SS2:     &Seed128{Components: ss2},
		SS3:     &Seed128{Components: ss3},
		MACKey:  macKey,
		MACName: blob.MACName,
	}
	if hasLS {
		b.KeyL = keyL
		b.LS = &Seed128{Components: ls}
	}
	return nil
}
