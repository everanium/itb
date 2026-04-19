package itb

// Probe 1 (Nonce-reuse attack simulation) corpus generator.
//
// Run with:
//
//   ITB_NONCE_REUSE_HASH=fnv1a \
//   ITB_NONCE_REUSE_N=2 \
//   ITB_NONCE_REUSE_MODE=same \
//   ITB_NONCE_REUSE_SIZE=2097152 \
//   ITB_BARRIER_FILL=1 \
//   go test -run TestRedTeamGenerateNonceReuse -v -timeout 30m
//
// Produces a single-cell corpus under:
//   tmp/attack/nonce_reuse/corpus/<hash>/BF<F>/N<N>/<mode>/
//     ct_0000.bin                  — ciphertext 0
//     ct_0000.plain                — plaintext 0 (known to attacker — Full KPA)
//     ct_0001.bin                  — ciphertext 1
//     ct_0001.plain                — plaintext 1
//     ...
//     cell.meta.json               — cell metadata (hash, keyBits, BF, nonce, mode, seeds)
//     config.truth.json            — per-data-pixel ground-truth config map
//                                    (start_pixel, data_pixels,
//                                     noisePos[p], rotation[p], channelXOR[p][ch])
//
// `config.truth.json` is NEVER read by an attacker simulation. It is read only
// by the Python demasking helper in `--validate` mode to confirm correctness.
//
// Attacker modes:
//   same   — d_0 = d_1 = ... = d_{N-1} — same plaintext forced into every
//            encryption (force-repeat scenario). Enables startPixel recovery
//            via Hamming-weight signature on XOR bytes but NOT rotation
//            recovery.
//   known  — each d_i is a distinct random plaintext, attacker knows them all.
//            Full Layer 1 + Layer 2 demasking recovery in the helper.
//   blind  — each d_i is a distinct random plaintext, attacker does NOT know
//            them. Written to disk for bookkeeping but the helper cannot use
//            them; included for completeness / negative-result documentation.
//
// The fixed nonce is derived deterministically from `ITB_NONCE_REUSE_NONCE_SEED`
// (default: 0xA17B1CE) so repeated runs produce identical nonces — useful for
// debugging. The three cryptographic seeds (noiseSeed, dataSeed, startSeed)
// are always fresh crypto/rand per test invocation (shared across all N
// ciphertexts in the cell).

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// setTestNonce — test-only helper to install a fixed nonce for generateNonce
// ----------------------------------------------------------------------------

// setTestNonce installs `nonce` as the output of generateNonce() for all
// subsequent Encrypt* calls in the current test. Cleanup restores the normal
// crypto/rand path automatically at test end.
//
// The atomic.Pointer variable lives in seed.go; this helper lives in a _test.go
// file so production binaries never link the setter (only the nil-check in
// generateNonce, which is essentially free).
func setTestNonce(t *testing.T, nonce []byte) {
	t.Helper()
	if len(nonce) != currentNonceSize() {
		t.Fatalf("setTestNonce: nonce length %d != current nonce size %d",
			len(nonce), currentNonceSize())
	}
	c := append([]byte(nil), nonce...)
	testNonceOverride.Store(&c)
	t.Cleanup(func() {
		testNonceOverride.Store(nil)
	})
}

// ----------------------------------------------------------------------------
// Env parsers
// ----------------------------------------------------------------------------

// noncerReuseIntEnv reads an integer env var with optional allowed-value
// whitelist; returns default if unset.
func nonceReuseIntEnv(t *testing.T, key string, defaultVal int, allowed []int) int {
	t.Helper()
	raw := os.Getenv(key)
	if raw == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s=%q: must be integer", key, raw)
	}
	if len(allowed) > 0 {
		ok := false
		for _, a := range allowed {
			if v == a {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("%s=%d: must be one of %v", key, v, allowed)
		}
	}
	return v
}

// nonceReuseModeEnv reads the attacker-mode env var; returns default if unset.
// Valid values: "same", "known", "blind", "partial".
func nonceReuseModeEnv(t *testing.T) string {
	t.Helper()
	raw := os.Getenv("ITB_NONCE_REUSE_MODE")
	if raw == "" {
		return "same"
	}
	switch raw {
	case "same", "known", "blind", "partial":
		return raw
	default:
		t.Fatalf("ITB_NONCE_REUSE_MODE=%q: must be one of {same, known, blind, partial}", raw)
		return ""
	}
}

// nonceReusePlaintextKindEnv reads the plaintext-kind env var. Controls how
// the N plaintexts are generated. Valid values:
//
//   - "random" (default): uniform CSPRNG bytes — the original Probe 1 corpus.
//   - "json_structured"  (alias for json_structured_80): ASCII JSON array of
//     records with long repeated field names + 5-byte record-index value +
//     short random values ≈ 83 % attacker-known byte coverage.
//   - "json_structured_{25,50,80}": JSON variants with tuned value lengths
//     targeting the named coverage level.
//   - "html_structured_{25,50,80}": HTML tag-wrapped variants with the same
//     per-record-index design at matching coverage levels.
func nonceReusePlaintextKindEnv(t *testing.T) string {
	t.Helper()
	raw := os.Getenv("ITB_NONCE_REUSE_PLAINTEXT_KIND")
	if raw == "" {
		return "random"
	}
	if raw == "random" {
		return raw
	}
	// "json_structured" alias is accepted by resolveStructuredKind.
	if _, _, ok := resolveStructuredKind(raw); ok {
		return raw
	}
	// random_masked_<coverage%> kinds: random plaintext per sample (no
	// structural framing) + random byte-position mask at target coverage,
	// shared byte-position set across both samples (symmetric coverage).
	if _, ok := resolveRandomMaskedKind(raw); ok {
		return raw
	}
	allowed := []string{"random", "json_structured",
		"random_masked_25", "random_masked_50", "random_masked_80"}
	for k := range structuredPlaintextSpecs {
		allowed = append(allowed, k)
	}
	t.Fatalf("ITB_NONCE_REUSE_PLAINTEXT_KIND=%q: must be one of %v", raw, allowed)
	return ""
}

// resolveRandomMaskedKind parses `random_masked_<N>` and returns the coverage
// percent (25 / 50 / 80). Returns (0, false) if the name does not match.
func resolveRandomMaskedKind(kind string) (int, bool) {
	switch kind {
	case "random_masked_25":
		return 25, true
	case "random_masked_50":
		return 50, true
	case "random_masked_80":
		return 80, true
	}
	return 0, false
}

// ----------------------------------------------------------------------------
// Fixed nonce derivation (deterministic for reproducibility)
// ----------------------------------------------------------------------------

// deriveFixedNonce builds a deterministic nonce of `size` bytes from a seed
// value via a simple xorshift expansion. Not cryptographically meaningful —
// just needs to be non-zero and reproducible across runs.
func deriveFixedNonce(seed uint64, size int) []byte {
	nonce := make([]byte, size)
	x := seed
	if x == 0 {
		x = 0xA17B1CE
	}
	for i := 0; i < size; i++ {
		// xorshift64
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		nonce[i] = byte(x & 0xFF)
	}
	return nonce
}

// ----------------------------------------------------------------------------
// Ground-truth config map — per-data-pixel (noisePos, rotation, channelXOR)
// ----------------------------------------------------------------------------

// pixelConfigEntry matches the per-pixel configuration that processChunk128
// derives at encryption time. One entry per data-carrying pixel.
type pixelConfigEntry struct {
	NoisePos    int   `json:"noise_pos"`       // 0-7, = noiseHash & 7
	Rotation    int   `json:"rotation"`        // 0-6, = dataHash % 7
	ChannelXOR8 []int `json:"channel_xor_8"`   // 8 values, 7-bit each = xorMask slicing
}

// configTruthJSON is the ground-truth configuration written alongside the
// corpus. The demasking helper reads this file in `--validate` mode only.
type configTruthJSON struct {
	Hash        string             `json:"hash"`
	HashWidth   int                `json:"hash_width"`
	Mode        string             `json:"mode"`
	NonceHex    string             `json:"nonce_hex"`
	Width       int                `json:"width"`
	Height      int                `json:"height"`
	TotalPixels int                `json:"total_pixels"`
	StartPixel  int                `json:"start_pixel"`
	DataPixels  int                `json:"data_pixels"`
	PerPixel    []pixelConfigEntry `json:"per_pixel"` // length = data_pixels
}

// configFromHashes builds a single per-pixel config entry from two uint64
// hash outputs (noiseHash, dataHash). All three widths (128/256/512) derive
// config from only the LOW uint64 of ChainHash output — see process_generic.go
// where `noiseHash := noiseH[0]` / `dataHash := dataH[0]` discards the higher
// words. So this helper is width-independent.
func configFromHashes(noiseHash, dataHash uint64) pixelConfigEntry {
	noisePos := int(noiseHash & 7)
	rotation := int(dataHash % 7)
	xorMask := dataHash >> DataRotationBits
	channelXOR := make([]int, Channels)
	for ch := 0; ch < Channels; ch++ {
		channelXOR[ch] = int((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)
	}
	return pixelConfigEntry{
		NoisePos:    noisePos,
		Rotation:    rotation,
		ChannelXOR8: channelXOR,
	}
}

// computeConfigMap128 mirrors process_generic.go:5-54 for the 128-bit family.
func computeConfigMap128(noiseSeed, dataSeed *Seed128, nonce []byte, dataPixels int) []pixelConfigEntry {
	noiseBuf := make([]byte, 4+len(nonce))
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+len(nonce))
	copy(dataBuf[4:], nonce)
	out := make([]pixelConfigEntry, dataPixels)
	for p := 0; p < dataPixels; p++ {
		noiseHash, _ := noiseSeed.blockHash128(noiseBuf, p)
		dataHash, _ := dataSeed.blockHash128(dataBuf, p)
		out[p] = configFromHashes(noiseHash, dataHash)
	}
	return out
}

// computeConfigMap256 mirrors process_generic.go:174-196 for the 256-bit family.
// Only h[0] (the low uint64 of the 4×uint64 ChainHash256 output) contributes
// to the per-pixel config — see processChunk256 where the other 3 uint64s are
// discarded.
func computeConfigMap256(noiseSeed, dataSeed *Seed256, nonce []byte, dataPixels int) []pixelConfigEntry {
	noiseBuf := make([]byte, 4+len(nonce))
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+len(nonce))
	copy(dataBuf[4:], nonce)
	out := make([]pixelConfigEntry, dataPixels)
	for p := 0; p < dataPixels; p++ {
		noiseH := noiseSeed.blockHash256(noiseBuf, p)
		dataH := dataSeed.blockHash256(dataBuf, p)
		out[p] = configFromHashes(noiseH[0], dataH[0])
	}
	return out
}

// computeConfigMap512 mirrors process_generic.go:88-111 for the 512-bit family.
// Same h[0]-only semantics — the other 7 uint64s of ChainHash512 are discarded
// by processChunk512.
func computeConfigMap512(noiseSeed, dataSeed *Seed512, nonce []byte, dataPixels int) []pixelConfigEntry {
	noiseBuf := make([]byte, 4+len(nonce))
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+len(nonce))
	copy(dataBuf[4:], nonce)
	out := make([]pixelConfigEntry, dataPixels)
	for p := 0; p < dataPixels; p++ {
		noiseH := noiseSeed.blockHash512(noiseBuf, p)
		dataH := dataSeed.blockHash512(dataBuf, p)
		out[p] = configFromHashes(noiseH[0], dataH[0])
	}
	return out
}

// ----------------------------------------------------------------------------
// Structured plaintext generator (for Partial KPA runs across JSON and HTML)
// ----------------------------------------------------------------------------

// jsonFieldSpec (historical name, kept for compatibility) defines one field in
// the repeating record.
//
//   - `Name` is the attacker-known protocol token (plus surrounding framing
//     punctuation supplied by the format framing spec).
//   - `ValueLen` bytes of the value are either random-unknown or
//     record-index-known depending on `ValueKind`.
//   - `ValueKind` selects the value generation strategy:
//       - "random": ValueLen random printable ASCII bytes (attacker-unknown)
//       - "record_index_dec": ValueLen digit bytes zero-padded from the record
//         index (attacker-known, varies per record — breaks the record-period
//         symmetry that would otherwise give Layer 2 multiple equivalent sp
//         candidates).
type jsonFieldSpec struct {
	Name      string
	ValueLen  int
	ValueKind string // "random" or "record_index_dec"
}

// structuredFramingSpec captures the per-format record framing text.
// Plaintext layout is:
//
//	openArray + record[0] + recordSep + record[1] + ... + record[N-1] + closeArray
//
// Each record = openRecord + field[0] + fieldSep + field[1] + ... + closeRecord,
// and each field = openField(name) + <valueBytes> + closeField(name).
type structuredFramingSpec struct {
	format      string // "json" or "html"
	openArray   string
	closeArray  string
	openRecord  string
	closeRecord string
	recordSep   string
	openField   func(name string) string
	closeField  func(name string) string
	fieldSep    string
}

var jsonStructuredFraming = structuredFramingSpec{
	format:      "json",
	openArray:   "[",
	closeArray:  "]",
	openRecord:  "{",
	closeRecord: "}",
	recordSep:   ",",
	openField:   func(name string) string { return `"` + name + `":"` },
	closeField:  func(name string) string { return `"` },
	fieldSep:    ",",
}

// HTML framing: records concatenate directly without array wrappers; each
// field is a `<tag>value</tag>` pair where the tag name IS the variant-
// dependent token carrying the `d_xor != 0` info across samples.
var htmlStructuredFraming = structuredFramingSpec{
	format:      "html",
	openArray:   "",
	closeArray:  "",
	openRecord:  "",
	closeRecord: "",
	recordSep:   "",
	openField:   func(name string) string { return "<" + name + ">" },
	closeField:  func(name string) string { return "</" + name + ">" },
	fieldSep:    "",
}

// structuredPlaintextSpec binds a framing to a pair (or more) of variant
// templates plus a target-coverage hint (used for documentation + default-
// tuning in the orchestrator, not for generation logic).
type structuredPlaintextSpec struct {
	framing          structuredFramingSpec
	variants         [][]jsonFieldSpec
	targetCoveragePc int // informational; actual coverage is computed from variant bytes
}

// structuredPlaintextSpecs lists every supported plaintext_kind for Partial
// KPA runs. Keys are the exact env/CLI values accepted by the orchestrator.
//
// Naming convention: `<format>_structured_<coverage>` where format ∈ {json,
// html} and coverage ∈ {25, 50, 80}. The historical `json_structured` name
// is kept as an alias for `json_structured_80` so existing runs/tests do not
// break.
//
// Variant pair design invariant: ALL variants within a kind must have
// identical per-field name LENGTHS, identical ValueLens, and identical
// ValueKinds so the byte-level layout (and hence per-pixel channel mask) is
// structurally identical across samples. Only the NAME CONTENT differs.
// Without that invariant the sample-0 vs sample-1 d_xor would have unequal
// known regions and Layer 1 constraint matching would break.
var structuredPlaintextSpecs = map[string]structuredPlaintextSpec{
	// ----- JSON 80 % known coverage (114 known / 137 total per record) -----
	"json_structured_80": {
		framing:          jsonStructuredFraming,
		targetCoveragePc: 80,
		variants: [][]jsonFieldSpec{
			{
				{Name: "identifier_of_record_in_system", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "the_timestamp_of_the_event_iso", ValueLen: 13, ValueKind: "random"},
				{Name: "the_encrypted_opaque_payload__", ValueLen: 10, ValueKind: "random"},
			},
			{
				{Name: "sender_public_key_receipt_ABCD", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "compressed_receiver_pubkey_DEF", ValueLen: 13, ValueKind: "random"},
				{Name: "compressed_body_trailer_digest", ValueLen: 10, ValueKind: "random"},
			},
		},
	},
	// ----- JSON 50 % known coverage (114 known / 228 total per record) -----
	"json_structured_50": {
		framing:          jsonStructuredFraming,
		targetCoveragePc: 50,
		variants: [][]jsonFieldSpec{
			{
				{Name: "identifier_of_record_in_system", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "the_timestamp_of_the_event_iso", ValueLen: 57, ValueKind: "random"},
				{Name: "the_encrypted_opaque_payload__", ValueLen: 57, ValueKind: "random"},
			},
			{
				{Name: "sender_public_key_receipt_ABCD", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "compressed_receiver_pubkey_DEF", ValueLen: 57, ValueKind: "random"},
				{Name: "compressed_body_trailer_digest", ValueLen: 57, ValueKind: "random"},
			},
		},
	},
	// ----- JSON 25 % known coverage (114 known / 456 total per record) -----
	"json_structured_25": {
		framing:          jsonStructuredFraming,
		targetCoveragePc: 25,
		variants: [][]jsonFieldSpec{
			{
				{Name: "identifier_of_record_in_system", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "the_timestamp_of_the_event_iso", ValueLen: 171, ValueKind: "random"},
				{Name: "the_encrypted_opaque_payload__", ValueLen: 171, ValueKind: "random"},
			},
			{
				{Name: "sender_public_key_receipt_ABCD", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "compressed_receiver_pubkey_DEF", ValueLen: 171, ValueKind: "random"},
				{Name: "compressed_body_trailer_digest", ValueLen: 171, ValueKind: "random"},
			},
		},
	},
	// ----- HTML 80 % known coverage (200 known / 250 total per record) -----
	// Tag names are 30 chars + hyphens to keep valid HTML identifiers.
	"html_structured_80": {
		framing:          htmlStructuredFraming,
		targetCoveragePc: 80,
		variants: [][]jsonFieldSpec{
			{
				{Name: "identifier-of-record-in-system", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "the-timestamp-of-the-event-iso", ValueLen: 25, ValueKind: "random"},
				{Name: "the-encrypted-opaque-payload01", ValueLen: 20, ValueKind: "random"},
			},
			{
				{Name: "sender-public-key-receipt-ABCD", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "compressed-receiver-pubkey-DEF", ValueLen: 25, ValueKind: "random"},
				{Name: "compressed-body-trailer-digest", ValueLen: 20, ValueKind: "random"},
			},
		},
	},
	// ----- HTML 50 % known coverage (200 known / 400 total per record) -----
	"html_structured_50": {
		framing:          htmlStructuredFraming,
		targetCoveragePc: 50,
		variants: [][]jsonFieldSpec{
			{
				{Name: "identifier-of-record-in-system", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "the-timestamp-of-the-event-iso", ValueLen: 100, ValueKind: "random"},
				{Name: "the-encrypted-opaque-payload01", ValueLen: 95, ValueKind: "random"},
			},
			{
				{Name: "sender-public-key-receipt-ABCD", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "compressed-receiver-pubkey-DEF", ValueLen: 100, ValueKind: "random"},
				{Name: "compressed-body-trailer-digest", ValueLen: 95, ValueKind: "random"},
			},
		},
	},
	// ----- HTML 25 % known coverage (200 known / 800 total per record) -----
	"html_structured_25": {
		framing:          htmlStructuredFraming,
		targetCoveragePc: 25,
		variants: [][]jsonFieldSpec{
			{
				{Name: "identifier-of-record-in-system", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "the-timestamp-of-the-event-iso", ValueLen: 300, ValueKind: "random"},
				{Name: "the-encrypted-opaque-payload01", ValueLen: 295, ValueKind: "random"},
			},
			{
				{Name: "sender-public-key-receipt-ABCD", ValueLen: 5, ValueKind: "record_index_dec"},
				{Name: "compressed-receiver-pubkey-DEF", ValueLen: 300, ValueKind: "random"},
				{Name: "compressed-body-trailer-digest", ValueLen: 295, ValueKind: "random"},
			},
		},
	},
}

// jsonStructured alias is resolved at lookup time in generateStructuredPlaintext.

// validateStructuredVariants panics on cross-variant layout mismatch (see
// spec doc above). Called from generateStructuredPlaintext at first use.
func validateStructuredVariants(spec structuredPlaintextSpec) {
	if len(spec.variants) == 0 {
		panic("structured spec has empty variants slice")
	}
	ref := spec.variants[0]
	for vi, v := range spec.variants {
		if len(v) != len(ref) {
			panic(fmt.Sprintf("variant %d has %d fields, reference has %d", vi, len(v), len(ref)))
		}
		for fi, f := range v {
			if len(f.Name) != len(ref[fi].Name) {
				panic(fmt.Sprintf("variant %d field %d name length %d != reference %d",
					vi, fi, len(f.Name), len(ref[fi].Name)))
			}
			if f.ValueLen != ref[fi].ValueLen {
				panic(fmt.Sprintf("variant %d field %d ValueLen %d != reference %d",
					vi, fi, f.ValueLen, ref[fi].ValueLen))
			}
			if f.ValueKind != ref[fi].ValueKind {
				panic(fmt.Sprintf("variant %d field %d ValueKind %q != reference %q",
					vi, fi, f.ValueKind, ref[fi].ValueKind))
			}
		}
	}
}

// structuredRecordLength returns the byte length of one record emitted by
// the given spec using variant 0 (all variants must agree by invariant).
// Used by the orchestrator to auto-tune --n-probe per plaintext kind.
func structuredRecordLength(spec structuredPlaintextSpec) int {
	variant := spec.variants[0]
	total := len(spec.framing.openRecord) + len(spec.framing.closeRecord)
	for i, f := range variant {
		total += len(spec.framing.openField(f.Name)) + f.ValueLen + len(spec.framing.closeField(f.Name))
		if i < len(variant)-1 {
			total += len(spec.framing.fieldSep)
		}
	}
	return total
}

// jsonValueRandomASCII fills `out` with random printable ASCII characters from
// the set `[A-Za-z0-9]`. Never produces 0x00 (so COBS encoding stays 1:1
// structurally), never produces `"` or `\` (so JSON stays well-formed without
// escaping). Deterministic given the rng state.
func jsonValueRandomASCII(rng *rand.Rand, out []byte) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i := range out {
		out[i] = alphabet[rng.Intn(len(alphabet))]
	}
}

// resolveStructuredKind maps the env/CLI-supplied kind name (possibly an
// alias such as "json_structured") to the canonical spec. Returns the
// resolved canonical name alongside the spec for bookkeeping.
func resolveStructuredKind(kind string) (string, structuredPlaintextSpec, bool) {
	if kind == "json_structured" {
		kind = "json_structured_80"
	}
	spec, ok := structuredPlaintextSpecs[kind]
	return kind, spec, ok
}

// generateStructuredPlaintext builds one sample of a structured plaintext
// according to `kind` (e.g. "json_structured_50", "html_structured_25", ...).
// Uses variant `sampleIdx % len(spec.variants)` so consecutive samples in a
// nonce-reuse cell end up on distinct variants (required so known channels
// carry `d_xor != 0` — otherwise the attack degenerates to same-plaintext).
//
// Returns (plaintext, knownMask). `knownMask[i] == 1` iff byte i is
// attacker-derivable from public protocol knowledge (structural framing
// text, variant-dependent field names, or per-record sequence numbers); 0
// iff byte i is a random value the attacker does not know.
func generateStructuredPlaintext(rng *rand.Rand, targetSize, sampleIdx int, kind string) ([]byte, []byte, string) {
	canonicalKind, spec, ok := resolveStructuredKind(kind)
	if !ok {
		panic(fmt.Sprintf("unknown structured plaintext kind %q", kind))
	}
	validateStructuredVariants(spec)
	variant := spec.variants[sampleIdx%len(spec.variants)]
	framing := spec.framing

	// Pre-compute record length once (variant 0 shares length with any variant
	// by the invariant enforced in validateStructuredVariants).
	recordLen := len(framing.openRecord) + len(framing.closeRecord)
	for i, f := range variant {
		recordLen += len(framing.openField(f.Name)) + f.ValueLen + len(framing.closeField(f.Name))
		if i < len(variant)-1 {
			recordLen += len(framing.fieldSep)
		}
	}

	perRecordFootprint := recordLen + len(framing.recordSep)
	arrayOverhead := len(framing.openArray) + len(framing.closeArray)
	nRecords := (targetSize - arrayOverhead) / perRecordFootprint
	if nRecords < 1 {
		nRecords = 1
	}

	capacity := nRecords*perRecordFootprint + arrayOverhead
	plaintext := make([]byte, 0, capacity)
	mask := make([]byte, 0, capacity)

	appendKnown := func(s string) {
		for i := 0; i < len(s); i++ {
			plaintext = append(plaintext, s[i])
			mask = append(mask, 1)
		}
	}

	appendKnown(framing.openArray)
	for r := 0; r < nRecords; r++ {
		appendKnown(framing.openRecord)
		for fi, f := range variant {
			appendKnown(framing.openField(f.Name))
			val := make([]byte, f.ValueLen)
			switch f.ValueKind {
			case "random":
				jsonValueRandomASCII(rng, val)
				plaintext = append(plaintext, val...)
				for range val {
					mask = append(mask, 0) // attacker-unknown
				}
			case "record_index_dec":
				// Zero-padded decimal record index. Attacker-known (protocol
				// sequence numbers are public) AND varying per record — breaks
				// the record-period symmetry that would otherwise give Layer 2
				// multiple equivalent sp candidates (sp_true ± k × record_len).
				s := fmt.Sprintf("%0*d", f.ValueLen, r)
				if len(s) > f.ValueLen {
					// Record index overflowed the digit budget — truncate to
					// the last N digits so byte layout stays constant.
					s = s[len(s)-f.ValueLen:]
				}
				for i := 0; i < f.ValueLen; i++ {
					val[i] = s[i]
				}
				plaintext = append(plaintext, val...)
				for range val {
					mask = append(mask, 1) // attacker-known
				}
			default:
				panic(fmt.Sprintf("unknown ValueKind %q", f.ValueKind))
			}
			appendKnown(framing.closeField(f.Name))
			if fi < len(variant)-1 {
				appendKnown(framing.fieldSep)
			}
		}
		appendKnown(framing.closeRecord)
		if r < nRecords-1 {
			appendKnown(framing.recordSep)
		}
	}
	appendKnown(framing.closeArray)

	if len(plaintext) != len(mask) {
		panic(fmt.Sprintf("generateStructuredPlaintext: length mismatch pt=%d mask=%d",
			len(plaintext), len(mask)))
	}
	return plaintext, mask, canonicalKind
}

// ----------------------------------------------------------------------------
// Cell metadata sidecar
// ----------------------------------------------------------------------------

type cellMetaJSON struct {
	Hash              string   `json:"hash"`
	HashDisplay       string   `json:"hash_display"`
	HashWidth         int      `json:"hash_width"`
	KeyBits           int      `json:"key_bits"`
	BarrierFill       int      `json:"barrier_fill"`
	N                 int      `json:"n_collisions"`
	Mode              string   `json:"mode"`
	ControlMode       string   `json:"control_mode,omitempty"` // "" or "nonce_mismatch"
	PlaintextKind     string   `json:"plaintext_kind"`         // "random" or "json_structured"
	PlaintextSize     int      `json:"plaintext_size"`
	NonceHex          string   `json:"nonce_hex"`              // in control mode: nonce of ct_0000 (per-sample nonces in PerSampleNonces)
	PerSampleNonces   []string `json:"per_sample_nonces,omitempty"` // control_nonce_mismatch only; len == N
	Width             int      `json:"width"`
	Height            int      `json:"height"`
	TotalPixels       int      `json:"total_pixels"`
	StartPixel        int      `json:"start_pixel"`
	DataPixels        int      `json:"data_pixels"`
	KnownBytes        int      `json:"known_bytes"`         // cobs(plaintext) + 1 (null terminator)
	FullyKnownPixels  int      `json:"fully_known_pixels"`  // pixels entirely inside known region
	PartialKnownPixel int      `json:"partial_known_pixel"` // -1 if none, else pixel index with partial overlap
	KnownMaskCoverage float64  `json:"known_mask_coverage"` // partial mode: fraction of plaintext bytes marked known (1.0 for known mode, 0.0 for blind)
	NoiseSeed         []uint64 `json:"noise_seed"`
	DataSeed          []uint64 `json:"data_seed"`
	StartSeed         []uint64 `json:"start_seed"`
	GeneratedAt       string   `json:"generated_at"`
}

// ----------------------------------------------------------------------------
// 128-bit hash dispatch
// ----------------------------------------------------------------------------

// hashWidthForName maps a corpus dirname to the hash output width (128/256/512).
// Matches the ordering in redteam_test.go:buildHashSpecs.
func hashWidthForName(name string) (int, error) {
	switch name {
	case "fnv1a", "md5", "aescmac", "siphash24":
		return 128, nil
	case "chacha20", "areion256", "blake2s", "blake3":
		return 256, nil
	case "blake2b", "areion512":
		return 512, nil
	default:
		return 0, fmt.Errorf("unknown hash %q; supported: fnv1a, md5, aescmac, siphash24, "+
			"chacha20, areion256, blake2s, blake3, blake2b, areion512", name)
	}
}

// hashFunc128ForName returns the 128-bit hash adapter matching the given
// corpus dirname. Errors on unknown names or non-128-bit hashes.
func hashFunc128ForName(name string) (HashFunc128, string, error) {
	switch name {
	case "fnv1a":
		return fnv1a128, "FNV-1a", nil
	case "md5":
		return md5Hash128, "MD5", nil
	case "aescmac":
		return makeAESHash128(), "AES-CMAC", nil
	case "siphash24":
		return sipHash128, "SipHash-2-4", nil
	default:
		return nil, "", fmt.Errorf("hash %q is not in the 128-bit family", name)
	}
}

// hashFunc256ForName returns the 256-bit hash adapter matching the given
// corpus dirname. Errors on unknown names or non-256-bit hashes.
func hashFunc256ForName(name string) (HashFunc256, string, error) {
	switch name {
	case "chacha20":
		return makeChaCha20Hash256(), "ChaCha20", nil
	case "areion256":
		return makeAreionSoEM256(), "AreionSoEM256", nil
	case "blake2s":
		return makeBlake2sHash256(), "BLAKE2s", nil
	case "blake3":
		return makeBlake3Hash256(), "BLAKE3", nil
	default:
		return nil, "", fmt.Errorf("hash %q is not in the 256-bit family", name)
	}
}

// hashFunc512ForName returns the 512-bit hash adapter matching the given
// corpus dirname. Errors on unknown names or non-512-bit hashes.
func hashFunc512ForName(name string) (HashFunc512, string, error) {
	switch name {
	case "blake2b":
		return makeBlake2bHash512(), "BLAKE2b-512", nil
	case "areion512":
		return makeAreionSoEM512(), "AreionSoEM512", nil
	default:
		return nil, "", fmt.Errorf("hash %q is not in the 512-bit family", name)
	}
}

// ----------------------------------------------------------------------------
// Main nonce-reuse corpus generator
// ----------------------------------------------------------------------------

// nonceReuseParams holds the env-parsed + setup state shared by all per-width
// test bodies.
type nonceReuseParams struct {
	hashName        string
	hashDisplay     string
	hashWidth       int
	keyBits         int
	barrierFill     int
	N               int
	mode            string
	plaintextKind   string   // "random" or "json_structured" (partial-mode requires the latter)
	plaintextSize   int
	fixedNonce      []byte
	perSampleNonces [][]byte // populated only in control_nonce_mismatch mode; len == N
	controlMode     string   // "" (nonce reuse — default) or "nonce_mismatch"
	plaintexts      [][]byte
	knownMasks      [][]byte // partial mode only: parallel to plaintexts; byte-level (1=known, 0=unknown)
	outDir          string
}

// nonceReuseWidthAdapter is the per-hash-width interface that the unified
// runNonceReuseBody uses to do encryption + config computation + seed export
// + startPixel derivation. Each of the three width-specific constructors
// (runNonceReuse128/256/512) builds one of these from freshly-generated seeds
// and passes it to the body.
type nonceReuseWidthAdapter struct {
	encrypt            func(plaintext []byte) ([]byte, error)
	decrypt            func(fileData []byte) ([]byte, error)
	computeConfig      func(nonce []byte, dataPixels int) []pixelConfigEntry
	seedComponents     func() (noiseSeed, dataSeed, startSeed []uint64)
	deriveStartPixelFn func(totalPixels int) int
}

// runNonceReuseBody is the width-independent body of the nonce-reuse corpus
// generator. All widths feed it the same adapter; it handles encrypt loop,
// round-trip verification, file writes, config map computation, and sidecar
// emission.
func runNonceReuseBody(t *testing.T, p nonceReuseParams, adapter nonceReuseWidthAdapter) {
	t.Logf("Generating nonce-reuse corpus:")
	t.Logf("  hash      : %s (%s, %d-bit, %d ChainHash rounds at %d-bit key)",
		p.hashName, p.hashDisplay, p.hashWidth, p.keyBits/p.hashWidth, p.keyBits)
	t.Logf("  N         : %d ciphertexts (all with same nonce + same seeds)", p.N)
	t.Logf("  mode      : %s", p.mode)
	t.Logf("  plaintext : %d bytes (%.1f MB)", p.plaintextSize, float64(p.plaintextSize)/(1024*1024))
	t.Logf("  BF        : %d", p.barrierFill)
	t.Logf("  nonce     : %s", hex.EncodeToString(p.fixedNonce))
	t.Logf("  output    : %s", p.outDir)

	t0 := time.Now()
	var firstCt []byte
	var firstWidth, firstHeight, firstTotalPixels, firstStartPixel int

	for i := 0; i < p.N; i++ {
		// In control_nonce_mismatch mode, rotate the installed nonce per
		// ciphertext so each encryption uses a DIFFERENT nonce. This is the
		// sensitivity / negative-control test: two ciphertexts that look like
		// a nonce-reuse pair by construction (same seeds + same plaintext)
		// but differ in nonce, so the helper should refuse to demask.
		expectedNonce := p.fixedNonce
		if p.controlMode == "nonce_mismatch" {
			expectedNonce = p.perSampleNonces[i]
			c := append([]byte(nil), expectedNonce...)
			testNonceOverride.Store(&c)
		}

		ct, err := adapter.encrypt(p.plaintexts[i])
		if err != nil {
			t.Fatalf("encrypt sample %d: %v", i, err)
		}

		actualNonce := ct[:currentNonceSize()]
		if !bytes.Equal(actualNonce, expectedNonce) {
			t.Fatalf("ciphertext %d nonce mismatch: got %x, want %x",
				i, actualNonce, expectedNonce)
		}

		dec, err := adapter.decrypt(ct)
		if err != nil {
			t.Fatalf("decrypt sample %d: %v", i, err)
		}
		if !bytes.Equal(dec, p.plaintexts[i]) {
			t.Fatalf("round-trip mismatch at sample %d (len %d vs %d)",
				i, len(p.plaintexts[i]), len(dec))
		}

		binPath := filepath.Join(p.outDir, fmt.Sprintf("ct_%04d.bin", i))
		plainPath := filepath.Join(p.outDir, fmt.Sprintf("ct_%04d.plain", i))
		if err := os.WriteFile(binPath, ct, 0o644); err != nil {
			t.Fatalf("write %s: %v", binPath, err)
		}
		if err := os.WriteFile(plainPath, p.plaintexts[i], 0o644); err != nil {
			t.Fatalf("write %s: %v", plainPath, err)
		}
		// Partial KPA: write the byte-level known_mask sidecar alongside the
		// plaintext so the Python helper can propagate known/unknown status
		// through COBS encoding and per-channel constraint matching.
		if p.mode == "partial" {
			if i >= len(p.knownMasks) || p.knownMasks[i] == nil {
				t.Fatalf("partial mode: knownMasks[%d] is nil", i)
			}
			if len(p.knownMasks[i]) != len(p.plaintexts[i]) {
				t.Fatalf("partial mode: knownMasks[%d] len %d != plaintext len %d",
					i, len(p.knownMasks[i]), len(p.plaintexts[i]))
			}
			maskPath := filepath.Join(p.outDir, fmt.Sprintf("ct_%04d.known_mask", i))
			if err := os.WriteFile(maskPath, p.knownMasks[i], 0o644); err != nil {
				t.Fatalf("write %s: %v", maskPath, err)
			}
		}

		if i == 0 {
			firstCt = ct
			ns := currentNonceSize()
			firstWidth = int(binary.BigEndian.Uint16(ct[ns:]))
			firstHeight = int(binary.BigEndian.Uint16(ct[ns+2:]))
			firstTotalPixels = firstWidth * firstHeight
		}
	}
	t.Logf("Encryption pass: %d ciphertexts in %s", p.N, time.Since(t0))

	_ = firstCt // retained for potential debugging; not otherwise consumed

	// Compute attacker-knowable region (Full KPA) bounds.
	cobsEncoded := cobsEncode(p.plaintexts[0])
	knownBytes := len(cobsEncoded) + 1
	knownBitsTotal := knownBytes * 8
	fullyKnownPixels := knownBitsTotal / DataBitsPerPixel
	partialKnownPixel := -1
	dataPixels := firstTotalPixels
	if knownBitsTotal%DataBitsPerPixel != 0 && fullyKnownPixels < dataPixels {
		partialKnownPixel = fullyKnownPixels
	}
	t.Logf("Known region under Full KPA: %d bytes = %d fully-known pixels "+
		"(partial pixel %d) of %d total", knownBytes, fullyKnownPixels,
		partialKnownPixel, dataPixels)

	// startPixel is derived from (startSeed, nonce, totalPixels) — we compute it
	// now that firstTotalPixels is known from the first encryption.
	firstStartPixel = adapter.deriveStartPixelFn(firstTotalPixels)

	// Compute ground-truth config map for ALL container pixels.
	t1 := time.Now()
	perPixel := adapter.computeConfig(p.fixedNonce, dataPixels)
	t.Logf("Ground-truth config map: %d pixels in %s", dataPixels, time.Since(t1))

	configTruth := configTruthJSON{
		Hash:        p.hashName,
		HashWidth:   p.hashWidth,
		Mode:        p.mode,
		NonceHex:    hex.EncodeToString(p.fixedNonce),
		Width:       firstWidth,
		Height:      firstHeight,
		TotalPixels: firstTotalPixels,
		StartPixel:  firstStartPixel,
		DataPixels:  dataPixels,
		PerPixel:    perPixel,
	}
	configPath := filepath.Join(p.outDir, "config.truth.json")
	configJSON, err := json.Marshal(configTruth)
	if err != nil {
		t.Fatalf("marshal config.truth: %v", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0o644); err != nil {
		t.Fatalf("write %s: %v", configPath, err)
	}

	noiseComp, dataComp, startComp := adapter.seedComponents()
	var perSampleHex []string
	if p.controlMode == "nonce_mismatch" {
		perSampleHex = make([]string, p.N)
		for i, n := range p.perSampleNonces {
			perSampleHex[i] = hex.EncodeToString(n)
		}
	}
	// Known-mask coverage: fraction of plaintext bytes marked as attacker-known.
	// 1.0 for known / same / blind modes (the full plaintext is either known or
	// irrelevant, with no per-byte mask sidecar); measured from knownMasks[0]
	// under partial mode.
	knownCoverage := 1.0
	if p.mode == "partial" && len(p.knownMasks) > 0 && len(p.knownMasks[0]) > 0 {
		knownBytesCount := 0
		for _, b := range p.knownMasks[0] {
			if b != 0 {
				knownBytesCount++
			}
		}
		knownCoverage = float64(knownBytesCount) / float64(len(p.knownMasks[0]))
		t.Logf("Partial-KPA known-mask coverage: %.2f%% (%d / %d bytes known)",
			knownCoverage*100, knownBytesCount, len(p.knownMasks[0]))
	}
	meta := cellMetaJSON{
		Hash:              p.hashName,
		HashDisplay:       p.hashDisplay,
		HashWidth:         p.hashWidth,
		KeyBits:           p.keyBits,
		BarrierFill:       p.barrierFill,
		N:                 p.N,
		Mode:              p.mode,
		ControlMode:       p.controlMode,
		PlaintextKind:     p.plaintextKind,
		PlaintextSize:     p.plaintextSize,
		NonceHex:          hex.EncodeToString(p.fixedNonce),
		PerSampleNonces:   perSampleHex,
		Width:             firstWidth,
		Height:            firstHeight,
		TotalPixels:       firstTotalPixels,
		StartPixel:        firstStartPixel,
		DataPixels:        dataPixels,
		KnownBytes:        knownBytes,
		FullyKnownPixels:  fullyKnownPixels,
		PartialKnownPixel: partialKnownPixel,
		KnownMaskCoverage: knownCoverage,
		NoiseSeed:         noiseComp,
		DataSeed:          dataComp,
		StartSeed:         startComp,
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	metaPath := filepath.Join(p.outDir, "cell.meta.json")
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal cell.meta: %v", err)
	}
	if err := os.WriteFile(metaPath, metaJSON, 0o644); err != nil {
		t.Fatalf("write %s: %v", metaPath, err)
	}

	t.Logf("Wrote cell artefacts:")
	t.Logf("  %d ciphertexts + %d plaintexts", p.N, p.N)
	t.Logf("  config.truth.json  (%d per-pixel entries, %.1f KB)",
		len(perPixel), float64(len(configJSON))/1024)
	t.Logf("  cell.meta.json")
	t.Logf("Done: %s", p.outDir)
}

// runNonceReuse128 builds seeds + adapter for the 128-bit family and delegates.
func runNonceReuse128(t *testing.T, p *nonceReuseParams, hashFunc HashFunc128) {
	ns, err := NewSeed128(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed128 noise: %v", err)
	}
	ds, err := NewSeed128(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed128 data: %v", err)
	}
	ss, err := NewSeed128(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed128 start: %v", err)
	}
	// startPixel derives from (startSeed, nonce, totalPixels). We need totalPixels
	// from the first encryption, so do a throwaway first encrypt here to capture
	// container dims and compute startPixel.
	//
	// Actually simpler: call encrypt once, parse dims, compute sp, then hand off
	// to body (which re-encrypts — wasteful; but body's first-encrypt pass already
	// captures dims). Let the body compute startPixel itself via a small helper.
	adapter := nonceReuseWidthAdapter{
		deriveStartPixelFn: func(totalPixels int) int {
			return ss.deriveStartPixel(p.fixedNonce, totalPixels)
		},
		encrypt: func(pt []byte) ([]byte, error) { return Encrypt128(ns, ds, ss, pt) },
		decrypt: func(ct []byte) ([]byte, error) { return Decrypt128(ns, ds, ss, ct) },
		computeConfig: func(nonce []byte, dp int) []pixelConfigEntry {
			return computeConfigMap128(ns, ds, nonce, dp)
		},
		seedComponents: func() ([]uint64, []uint64, []uint64) {
			return append([]uint64(nil), ns.Components...),
				append([]uint64(nil), ds.Components...),
				append([]uint64(nil), ss.Components...)
		},
	}
	runNonceReuseBody(t, *p, adapter)
}

// runNonceReuse256 builds seeds + adapter for the 256-bit family and delegates.
func runNonceReuse256(t *testing.T, p *nonceReuseParams, hashFunc HashFunc256) {
	ns, err := NewSeed256(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed256 noise: %v", err)
	}
	ds, err := NewSeed256(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed256 data: %v", err)
	}
	ss, err := NewSeed256(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed256 start: %v", err)
	}
	adapter := nonceReuseWidthAdapter{
		deriveStartPixelFn: func(totalPixels int) int {
			return ss.deriveStartPixel(p.fixedNonce, totalPixels)
		},
		encrypt: func(pt []byte) ([]byte, error) { return Encrypt256(ns, ds, ss, pt) },
		decrypt: func(ct []byte) ([]byte, error) { return Decrypt256(ns, ds, ss, ct) },
		computeConfig: func(nonce []byte, dp int) []pixelConfigEntry {
			return computeConfigMap256(ns, ds, nonce, dp)
		},
		seedComponents: func() ([]uint64, []uint64, []uint64) {
			return append([]uint64(nil), ns.Components...),
				append([]uint64(nil), ds.Components...),
				append([]uint64(nil), ss.Components...)
		},
	}
	runNonceReuseBody(t, *p, adapter)
}

// runNonceReuse512 builds seeds + adapter for the 512-bit family and delegates.
func runNonceReuse512(t *testing.T, p *nonceReuseParams, hashFunc HashFunc512) {
	ns, err := NewSeed512(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed512 noise: %v", err)
	}
	ds, err := NewSeed512(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed512 data: %v", err)
	}
	ss, err := NewSeed512(p.keyBits, hashFunc)
	if err != nil {
		t.Fatalf("NewSeed512 start: %v", err)
	}
	adapter := nonceReuseWidthAdapter{
		deriveStartPixelFn: func(totalPixels int) int {
			return ss.deriveStartPixel(p.fixedNonce, totalPixels)
		},
		encrypt: func(pt []byte) ([]byte, error) { return Encrypt512(ns, ds, ss, pt) },
		decrypt: func(ct []byte) ([]byte, error) { return Decrypt512(ns, ds, ss, ct) },
		computeConfig: func(nonce []byte, dp int) []pixelConfigEntry {
			return computeConfigMap512(ns, ds, nonce, dp)
		},
		seedComponents: func() ([]uint64, []uint64, []uint64) {
			return append([]uint64(nil), ns.Components...),
				append([]uint64(nil), ds.Components...),
				append([]uint64(nil), ss.Components...)
		},
	}
	runNonceReuseBody(t, *p, adapter)
}

func TestRedTeamGenerateNonceReuse(t *testing.T) {
	hashName := os.Getenv("ITB_NONCE_REUSE_HASH")
	if hashName == "" {
		t.Skip("set ITB_NONCE_REUSE_HASH=<hash> to generate nonce-reuse corpus " +
			"(128-bit: fnv1a/md5/aescmac/siphash24; 256-bit: chacha20/areion256/blake2s/blake3; " +
			"512-bit: blake2b/areion512)")
	}

	width, err := hashWidthForName(hashName)
	if err != nil {
		t.Fatalf("%v", err)
	}

	N := nonceReuseIntEnv(t, "ITB_NONCE_REUSE_N", 2, []int{2, 8, 32, 128})
	mode := nonceReuseModeEnv(t)
	plaintextSize := nonceReuseIntEnv(t, "ITB_NONCE_REUSE_SIZE", 2*1024*1024, nil)
	if plaintextSize <= 0 || plaintextSize > maxDataSize {
		t.Fatalf("ITB_NONCE_REUSE_SIZE=%d: must be in (0, %d]", plaintextSize, maxDataSize)
	}
	nonceSeed := uint64(nonceReuseIntEnv(t, "ITB_NONCE_REUSE_NONCE_SEED", 0xA17B1CE, nil))
	barrierFill := redteamBarrierFill(t)
	keyBits := 1024

	// Control-mode env: if set, deviates from the default nonce-reuse setup
	// (see nonceReuseParams.controlMode comment). Currently accepts only
	// "nonce_mismatch" — each ciphertext uses a different nonce (sensitivity
	// test for the demasking helper).
	controlMode := os.Getenv("ITB_NONCE_REUSE_CONTROL")
	if controlMode != "" && controlMode != "nonce_mismatch" {
		t.Fatalf("ITB_NONCE_REUSE_CONTROL=%q: only 'nonce_mismatch' is supported", controlMode)
	}

	SetMaxWorkers(8)
	SetBarrierFill(barrierFill)
	t.Cleanup(func() {
		SetMaxWorkers(0)
		SetBarrierFill(1)
	})

	fixedNonce := deriveFixedNonce(nonceSeed, currentNonceSize())
	setTestNonce(t, fixedNonce)

	// Under control_nonce_mismatch: derive N distinct nonces (one per sample)
	// from nonceSeed + i. runNonceReuseBody rotates the test-nonce override
	// between encrypts using these values.
	var perSampleNonces [][]byte
	if controlMode == "nonce_mismatch" {
		perSampleNonces = make([][]byte, N)
		for i := 0; i < N; i++ {
			// Incorporate i into the seed so each nonce is distinct yet
			// deterministic across reruns.
			perSampleNonces[i] = deriveFixedNonce(nonceSeed+uint64(i*0x1000003D), currentNonceSize())
		}
	}

	// Plaintext generation depends on (mode, plaintext_kind):
	//   - random kind: uniform CSPRNG bytes; used by same / known / blind / partial
	//   - json_structured kind: ASCII JSON array with long repeated field names +
	//     short random values, designed for Partial KPA runs. Emitted alongside
	//     a byte-level known_mask (1 = field-name / punctuation, 0 = value).
	//
	// Known_masks are only meaningful (and only written to disk) under partial
	// mode. Under known-mode the attacker is assumed to know the whole
	// plaintext; under blind-mode the attacker knows nothing; under same-mode
	// the plaintexts are identical and the mask distinction doesn't apply.
	plaintextKind := nonceReusePlaintextKindEnv(t)
	_, _, isStructured := resolveStructuredKind(plaintextKind)
	_, isRandomMasked := resolveRandomMaskedKind(plaintextKind)
	isPartialKind := isStructured || isRandomMasked
	if mode == "partial" && !isPartialKind {
		t.Fatalf("ITB_NONCE_REUSE_MODE=partial requires a structured plaintext kind "+
			"(json_structured_80 / 50 / 25, html_structured_80 / 50 / 25, or the "+
			"alias json_structured) OR a random_masked_{25,50,80} kind — got "+
			"plaintext_kind=%q. Partial KPA needs a known_mask sidecar to carry "+
			"the per-byte attacker-known bit.", plaintextKind)
	}
	if isPartialKind && mode != "partial" {
		t.Fatalf("ITB_NONCE_REUSE_PLAINTEXT_KIND=%q is only supported under "+
			"ITB_NONCE_REUSE_MODE=partial (got mode=%q). Other modes use uniform-random plaintexts.",
			plaintextKind, mode)
	}

	rng := rand.New(rand.NewSource(424242))
	plaintexts := make([][]byte, N)
	var knownMasks [][]byte
	if mode == "partial" {
		knownMasks = make([][]byte, N)
	}
	switch mode {
	case "same":
		base := make([]byte, plaintextSize)
		if _, err := rng.Read(base); err != nil {
			t.Fatalf("rng read base: %v", err)
		}
		for i := 0; i < N; i++ {
			plaintexts[i] = base
		}
	case "known", "blind":
		for i := 0; i < N; i++ {
			plaintexts[i] = make([]byte, plaintextSize)
			if _, err := rng.Read(plaintexts[i]); err != nil {
				t.Fatalf("rng read plaintext %d: %v", i, err)
			}
		}
	case "partial":
		// Partial-KPA corpus — two sub-paths:
		//
		// (a) random_masked_<N>: independent random plaintexts per sample +
		//     a shared random byte-position mask at the target coverage. No
		//     structural framing, no same-plaintext degeneracy on known
		//     channels (d_xor ≠ 0 uniformly on attacker-known bytes). Models
		//     an attacker who happened to observe / guess a uniform random
		//     subset of plaintext bytes in both messages.
		//
		// (b) json_structured_{25,50,80} / html_structured_{25,50,80}: each
		//     sample uses a distinct record-template variant; byte-level
		//     layout is identical across samples but CONTENT of known bytes
		//     differs per variant. Attacker knows protocol framing tokens,
		//     not payload values.
		if coverage, ok := resolveRandomMaskedKind(plaintextKind); ok {
			mask := make([]byte, plaintextSize)
			// Deterministic mask drawn from the same RNG so the corpus
			// regenerates byte-identically. Assign each byte "known" with
			// probability coverage/100 using a uniform uint32 per byte.
			// Shared across all N samples (symmetric coverage).
			draws := make([]byte, plaintextSize*4)
			if _, err := rng.Read(draws); err != nil {
				t.Fatalf("rng read random mask draws: %v", err)
			}
			threshold := uint32(coverage) * ((1 << 32) / 100)
			for j := 0; j < plaintextSize; j++ {
				u := uint32(draws[j*4])<<24 | uint32(draws[j*4+1])<<16 |
					uint32(draws[j*4+2])<<8 | uint32(draws[j*4+3])
				if u < threshold {
					mask[j] = 1
				}
			}
			for i := 0; i < N; i++ {
				plaintexts[i] = make([]byte, plaintextSize)
				if _, err := rng.Read(plaintexts[i]); err != nil {
					t.Fatalf("rng read random_masked plaintext %d: %v", i, err)
				}
				knownMasks[i] = append([]byte(nil), mask...)
			}
		} else {
			for i := 0; i < N; i++ {
				pt, m, _ := generateStructuredPlaintext(rng, plaintextSize, i, plaintextKind)
				plaintexts[i] = pt
				knownMasks[i] = m
			}
		}
	default:
		t.Fatalf("unhandled mode: %s", mode)
	}

	// Output directory — separate tree for control-mode runs so the main
	// corpus is never contaminated by sensitivity-test artefacts. Partial-mode
	// corpora include the plaintext_kind in the path so distinct kinds don't
	// collide under the same (hash, BF, N, mode) coordinates.
	var outDir string
	modeDirSegment := mode
	if mode == "partial" {
		modeDirSegment = "partial_" + plaintextKind
	}
	if controlMode == "nonce_mismatch" {
		outDir, _ = filepath.Abs(filepath.Join(
			"tmp", "attack", "nonce_reuse", "control",
			hashName,
			fmt.Sprintf("BF%d", barrierFill),
			fmt.Sprintf("N%d", N),
			"nonce_mismatch_"+mode,
		))
	} else {
		outDir, _ = filepath.Abs(filepath.Join(
			"tmp", "attack", "nonce_reuse", "corpus",
			hashName,
			fmt.Sprintf("BF%d", barrierFill),
			fmt.Sprintf("N%d", N),
			modeDirSegment,
		))
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	params := &nonceReuseParams{
		hashName:        hashName,
		hashWidth:       width,
		keyBits:         keyBits,
		barrierFill:     barrierFill,
		N:               N,
		mode:            mode,
		controlMode:     controlMode,
		plaintextKind:   plaintextKind,
		plaintextSize:   plaintextSize,
		fixedNonce:      fixedNonce,
		perSampleNonces: perSampleNonces,
		plaintexts:      plaintexts,
		knownMasks:      knownMasks,
		outDir:          outDir,
	}

	switch width {
	case 128:
		hf, display, err := hashFunc128ForName(hashName)
		if err != nil {
			t.Fatalf("%v", err)
		}
		params.hashDisplay = display
		runNonceReuse128(t, params, hf)
	case 256:
		hf, display, err := hashFunc256ForName(hashName)
		if err != nil {
			t.Fatalf("%v", err)
		}
		params.hashDisplay = display
		runNonceReuse256(t, params, hf)
	case 512:
		hf, display, err := hashFunc512ForName(hashName)
		if err != nil {
			t.Fatalf("%v", err)
		}
		params.hashDisplay = display
		runNonceReuse512(t, params, hf)
	default:
		t.Fatalf("unsupported hash width %d for %q", width, hashName)
	}
}
