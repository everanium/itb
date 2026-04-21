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
	"hash/crc64"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/zeebo/blake3"
)

// ----------------------------------------------------------------------------
// CRC128 — test-only primitive for seed-recovery demonstration.
//
// NOT A PRODUCTION HASH. This is a deliberately-below-FNV-1a primitive:
// two independent CRC64 computations with different irreducible polynomials
// (ECMA + ISO), each keyed by one 64-bit half of the (seed0, seed1) input.
// Output is (lo, hi) = (CRC64-ECMA, CRC64-ISO).
//
// Every operation is GF(2)-linear: CRC64 is polynomial division over GF(2)[x],
// the keyed initial-state register XOR is GF(2)-linear, and concatenating two
// GF(2)-linear maps is GF(2)-linear. Wrapping this in ITB's ChainHash (which
// XOR-keys between rounds) keeps the whole chain GF(2)-linear end-to-end —
// so a straightforward Gaussian elimination over GF(2) recovers the 1024-bit
// dataSeed from a few dozen (input, output) observations under a shared
// (seeds, nonce). This is the "worse-than-FNV-1a" control primitive used to
// demonstrate empirically that ITB's mixed-algebra defense (GF(2) XOR +
// Z/2^64 multiplication in FNV-1a's case) is LOAD-BEARING — replace the
// Z/2^64 multiply with a same-algebra operation and the chain collapses.
//
// Placed in this test file (not in ITB's production hash matrix) because
// it has zero cryptographic value and must NEVER be plugged into production.
// ----------------------------------------------------------------------------

var (
	crc64TableECMA = crc64.MakeTable(crc64.ECMA)
	crc64TableISO  = crc64.MakeTable(crc64.ISO)
)

// crc64Keyed runs a standard CRC64 update loop starting from `seed` as the
// initial register state. Returns the final 64-bit register value. The
// per-byte update is `crc = table[byte(crc)^b] ^ (crc >> 8)` — GF(2)-linear.
func crc64Keyed(table *crc64.Table, data []byte, seed uint64) uint64 {
	crc := seed
	for _, b := range data {
		crc = (*table)[byte(crc)^b] ^ (crc >> 8)
	}
	return crc
}

// crc128 is a HashFunc128-compatible adapter. (lo, hi) come from two
// independent CRC64 computations with different polynomials keyed by
// (seed0, seed1) respectively.
func crc128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = crc64Keyed(crc64TableECMA, data, seed0)
	hi = crc64Keyed(crc64TableISO, data, seed1)
	return
}

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
	case "same", "known", "known_ascii", "known_json_structured",
		"known_html_structured", "blind", "partial":
		return raw
	default:
		t.Fatalf("ITB_NONCE_REUSE_MODE=%q: must be one of {same, known, known_ascii, known_json_structured, known_html_structured, blind, partial}", raw)
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
	// Blake3KeyHex is set only when hash=blake3. It is the 32-byte BLAKE3
	// key drawn by makeBlake3Hash256WithKey at corpus generation; the
	// downstream bias probe uses it to mirror Go's keyed BLAKE3 output.
	// LAB-ONLY field — not exposed anywhere else in ITB.
	Blake3KeyHex string `json:"blake3_key_hex,omitempty"`
	GeneratedAt  string `json:"generated_at"`
}

// ----------------------------------------------------------------------------
// 128-bit hash dispatch
// ----------------------------------------------------------------------------

// hashWidthForName maps a corpus dirname to the hash output width (128/256/512).
// Matches the ordering in redteam_test.go:buildHashSpecs.
func hashWidthForName(name string) (int, error) {
	switch name {
	case "fnv1a", "md5", "aescmac", "siphash24", "crc128":
		return 128, nil
	case "chacha20", "areion256", "blake2s", "blake3", "blake2b256":
		return 256, nil
	case "blake2b", "areion512":
		return 512, nil
	default:
		return 0, fmt.Errorf("unknown hash %q; supported: fnv1a, md5, aescmac, siphash24, "+
			"crc128 (test-only), chacha20, areion256, blake2s, blake3, blake2b256, blake2b, areion512", name)
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
	case "crc128":
		return crc128, "CRC128-test", nil
	default:
		return nil, "", fmt.Errorf("hash %q is not in the 128-bit family", name)
	}
}

// redteamBlake3Key is populated when hashFunc256ForName instantiates a
// BLAKE3 adapter. Used by the nonce-reuse corpus-generator body to emit
// the per-corpus BLAKE3 key into cell.meta.json so the Python bias probe
// can mirror Go's keyed BLAKE3 output bit-for-bit. Not part of any
// attacker-visible information — this is a laboratory shortcut.
var redteamBlake3Key [32]byte
var redteamBlake3KeySet bool

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
	case "blake2b256":
		return makeBlake2bHash256(), "BLAKE2b-256", nil
	case "blake3":
		if _, err := rand.Read(redteamBlake3Key[:]); err != nil {
			return nil, "", fmt.Errorf("rand.Read for BLAKE3 key: %w", err)
		}
		redteamBlake3KeySet = true
		return makeBlake3Hash256WithKey(redteamBlake3Key), "BLAKE3", nil
	default:
		return nil, "", fmt.Errorf("hash %q is not in the 256-bit family", name)
	}
}

// makeBlake3Hash256WithKey duplicates makeBlake3Hash256 but takes the
// 32-byte BLAKE3 key as an argument instead of drawing it internally.
// Used only by the redteam nonce-reuse corpus generator so the key can
// be captured and emitted to cell.meta.json for downstream Python
// bias-probe mirroring. Not reachable from any shipped API path.
func makeBlake3Hash256WithKey(key [32]byte) HashFunc256 {
	template, _ := blake3.NewKeyed(key[:])
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}
	return func(data []byte, seed [4]uint64) [4]uint64 {
		h := template.Clone()
		// Ensure mixed is long enough for all 4 seed uint64's (32 bytes),
		// even when data is shorter. See makeBlake3Hash256 in itb_test.go for
		// details on the short-data seed-drop bug this guards against.
		const seedInjectBytes = 32
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		mixedPtr := pool.Get().(*[]byte)
		mixed := *mixedPtr
		if cap(mixed) < payloadLen {
			mixed = make([]byte, payloadLen)
		} else {
			mixed = mixed[:payloadLen]
		}
		for i := len(data); i < payloadLen; i++ {
			mixed[i] = 0
		}
		copy(mixed[:len(data)], data)
		for i := 0; i < 4; i++ {
			off := i * 8
			binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
		}
		h.Write(mixed)
		*mixedPtr = mixed
		pool.Put(mixedPtr)
		var buf [32]byte
		h.Sum(buf[:0])
		return [4]uint64{
			binary.LittleEndian.Uint64(buf[0:]),
			binary.LittleEndian.Uint64(buf[8:]),
			binary.LittleEndian.Uint64(buf[16:]),
			binary.LittleEndian.Uint64(buf[24:]),
		}
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

	// seed.truth.json — ground-truth seed components for the seed-inversion
	// experiment (CRC128 only — other primitives do not have a feasible
	// inversion path at these parameters). Emitted universally so the
	// downstream solver can validate any primitive's recovered output
	// against the expected seed.
	seedTruth := struct {
		KeyBits             int      `json:"key_bits"`
		HashWidth           int      `json:"hash_width"`
		NoiseSeedComponents []uint64 `json:"noise_seed_components"`
		DataSeedComponents  []uint64 `json:"data_seed_components"`
		StartSeedComponents []uint64 `json:"start_seed_components"`
	}{
		KeyBits:             p.keyBits,
		HashWidth:           p.hashWidth,
		NoiseSeedComponents: noiseComp,
		DataSeedComponents:  dataComp,
		StartSeedComponents: startComp,
	}
	seedTruthPath := filepath.Join(p.outDir, "seed.truth.json")
	seedTruthJSON, err := json.Marshal(seedTruth)
	if err != nil {
		t.Fatalf("marshal seed.truth: %v", err)
	}
	if err := os.WriteFile(seedTruthPath, seedTruthJSON, 0o644); err != nil {
		t.Fatalf("write %s: %v", seedTruthPath, err)
	}
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
	if redteamBlake3KeySet {
		meta.Blake3KeyHex = hex.EncodeToString(redteamBlake3Key[:])
		// Reset for the next hashFunc256ForName call in subsequent invocations
		// of this test (ensures we never emit a stale key under hash != blake3).
		redteamBlake3KeySet = false
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
	case "known_ascii":
		// Full KPA, ASCII-only plaintext — a clean testbed for the
		// hash-agnostic raw-mode bias audit (scripts/redteam/phase2_theory/
		// raw_mode_bias_probe.py). No Partial-KPA mask sidecar, no record
		// templating: every byte is drawn uniformly from the printable
		// ASCII alphabet + whitespace. Lets the bias probe measure whether
		// the architecture neutralizes the per-byte ASCII bit-7 = 0 bias
		// for the currently-configured hash primitive. Deterministic from
		// the plaintext-seed RNG so repeated runs produce byte-identical
		// corpora.
		for i := 0; i < N; i++ {
			plaintexts[i] = make([]byte, plaintextSize)
			for j := range plaintexts[i] {
				r := rng.Intn(97)
				switch {
				case r == 95:
					plaintexts[i][j] = 0x09 // tab
				case r == 96:
					plaintexts[i][j] = 0x0A // newline
				default:
					plaintexts[i][j] = byte(0x20 + r) // printable ASCII
				}
			}
		}
	case "known_json_structured", "known_html_structured":
		// Full KPA, structured plaintext — the bias-probe companion to
		// known_ascii, but with record-template structure (JSON array or
		// HTML tag-wrapped document, the same generators used for
		// partial_{json,html}_structured_80). Every byte is known to the
		// attacker (no mask sidecar), but the byte statistics now carry
		// ASCII bit-7 = 0 bias plus framing-token repetition. Used to
		// separate "uniform ASCII bias" from "structural-token bias"
		// contributions in the raw-mode bias audit.
		structuredKind := "json_structured_80"
		if mode == "known_html_structured" {
			structuredKind = "html_structured_80"
		}
		for i := 0; i < N; i++ {
			pt, _, _ := generateStructuredPlaintext(rng, plaintextSize, i, structuredKind)
			plaintexts[i] = pt
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

// ----------------------------------------------------------------------------
// Phase 2e — related-seed differential corpus generator
// ----------------------------------------------------------------------------
//
// Generates ONE pair of ciphertexts (ct_0.bin, ct_1.bin) for a given
// (primitive, seed_axis, delta_kind, plaintext_kind, plaintext_size) cell.
// Both encrypts share the SAME fixed nonce and SAME plaintext; only the
// seed on the requested axis differs by XOR with a known Δ.
//
// The Python analyzer computes D = ct_0 ⊕ ct_1 across the container
// body, then runs distribution + correlation tests to measure whether
// the seed differential Δ leaks into the ciphertext diff D. Under PRF
// assumption D should be uniform random; under a GF(2)-linear primitive
// (CRC128) D should carry a structured pattern related to Δ.
//
// Env vars (all required except defaults noted):
//
//   ITB_REL_HASH          — primitive name (as in hashFunc{128,256,512}ForName)
//   ITB_REL_AXIS          — noise / data / start (which seed gets Δ XOR'd)
//   ITB_REL_DELTA_KIND    — bit0 / bit_mid512 / bit_high1023 / rand_1 /
//                           rand_2 / rand_3 / zero_low_half
//   ITB_REL_PT_KIND       — random / ascii (default: random)
//   ITB_REL_SIZE          — plaintext bytes (default: 524288 = 512 KB)
//   ITB_REL_NONCE_SEED    — PRNG seed for nonce + base seeds + plaintext +
//                           random-Δ derivation (default: 0xA17B1CE; same
//                           nonce_seed across primitives produces
//                           comparable baselines)
//   ITB_REL_CELL_DIR      — output directory (required; attack orchestrator
//                           supplies tmp/attack/related_seed_diff/corpus/...)

const relSeedKeyBits = 1024 // fixed; matches production flagship config

type relSeedParams struct {
	hashName      string
	axis          string
	deltaKind     string
	plaintextKind string
	plaintextSize int
	nonceSeed     uint64
	barrierFill   int
	cellDir       string
}

func relSeedEnv(t *testing.T) relSeedParams {
	t.Helper()
	p := relSeedParams{
		hashName:      os.Getenv("ITB_REL_HASH"),
		axis:          os.Getenv("ITB_REL_AXIS"),
		deltaKind:     os.Getenv("ITB_REL_DELTA_KIND"),
		plaintextKind: os.Getenv("ITB_REL_PT_KIND"),
		cellDir:       os.Getenv("ITB_REL_CELL_DIR"),
	}
	if p.plaintextKind == "" {
		p.plaintextKind = "random"
	}
	if p.hashName == "" || p.axis == "" || p.deltaKind == "" || p.cellDir == "" {
		t.Skip("Phase 2e needs ITB_REL_HASH + ITB_REL_AXIS + ITB_REL_DELTA_KIND + ITB_REL_CELL_DIR")
	}
	switch p.axis {
	case "noise", "data", "start":
	default:
		t.Fatalf("ITB_REL_AXIS=%q: must be noise / data / start", p.axis)
	}
	switch p.deltaKind {
	case "bit0", "bit_mid512", "bit_high1023",
		"rand_1", "rand_2", "rand_3", "zero_low_half":
	default:
		t.Fatalf("ITB_REL_DELTA_KIND=%q: unsupported", p.deltaKind)
	}
	switch p.plaintextKind {
	case "random", "ascii":
	default:
		t.Fatalf("ITB_REL_PT_KIND=%q: must be random / ascii", p.plaintextKind)
	}
	sizeStr := os.Getenv("ITB_REL_SIZE")
	p.plaintextSize = 512 * 1024
	if sizeStr != "" {
		v, err := strconv.Atoi(sizeStr)
		if err != nil || v <= 0 || v > maxDataSize {
			t.Fatalf("ITB_REL_SIZE=%q: must be integer in (0, %d]", sizeStr, maxDataSize)
		}
		p.plaintextSize = v
	}
	seedStr := os.Getenv("ITB_REL_NONCE_SEED")
	p.nonceSeed = 0xA17B1CE
	if seedStr != "" {
		v, err := strconv.ParseUint(seedStr, 0, 64)
		if err != nil {
			t.Fatalf("ITB_REL_NONCE_SEED=%q: %v", seedStr, err)
		}
		p.nonceSeed = v
	}
	bfStr := os.Getenv("ITB_REL_BF")
	p.barrierFill = 1
	if bfStr != "" {
		v, err := strconv.Atoi(bfStr)
		if err != nil {
			t.Fatalf("ITB_REL_BF=%q: %v", bfStr, err)
		}
		switch v {
		case 1, 2, 4, 8, 16, 32:
			p.barrierFill = v
		default:
			t.Fatalf("ITB_REL_BF=%d: must be 1/2/4/8/16/32", v)
		}
	}
	return p
}

// deriveDeltaComponents builds the 16-uint64 Δ for the given kind.
// Deterministic from (nonceSeed, axis, deltaKind) so the matrix is
// reproducible across runs.
//
// For `zero_low_half` Δ is set to the base seed's low-8 components
// (so XOR zeroes them) — must be computed AFTER base seeds are drawn.
func deriveDeltaComponents(kind string, baseLow8 [8]uint64, nonceSeed uint64) [16]uint64 {
	var d [16]uint64
	switch kind {
	case "bit0":
		d[0] = 1
	case "bit_mid512":
		d[8] = 1
	case "bit_high1023":
		d[15] = 1 << 63
	case "rand_1", "rand_2", "rand_3":
		var sub uint64
		switch kind {
		case "rand_1":
			sub = 1
		case "rand_2":
			sub = 2
		case "rand_3":
			sub = 3
		}
		rng := rand.New(rand.NewSource(int64(nonceSeed ^ (0xDEADBEEF00000000 | sub))))
		for i := range d {
			d[i] = rng.Uint64()
		}
	case "zero_low_half":
		for i := 0; i < 8; i++ {
			d[i] = baseLow8[i]
		}
	}
	return d
}

// relSeedGeneratePlaintext returns a deterministic plaintext of the
// requested size and kind.
func relSeedGeneratePlaintext(rng *rand.Rand, size int, kind string) []byte {
	pt := make([]byte, size)
	switch kind {
	case "random":
		if _, err := rng.Read(pt); err != nil {
			panic(err) // math/rand Read never fails
		}
	case "ascii":
		for i := range pt {
			r := rng.Intn(97)
			switch {
			case r == 95:
				pt[i] = 0x09 // tab
			case r == 96:
				pt[i] = 0x0A // newline
			default:
				pt[i] = byte(0x20 + r) // printable ASCII
			}
		}
	}
	return pt
}

func TestRedTeamGenerateRelatedSeedPair(t *testing.T) {
	p := relSeedEnv(t)

	width, err := hashWidthForName(p.hashName)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.MkdirAll(p.cellDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p.cellDir, err)
	}

	SetMaxWorkers(8)
	SetBarrierFill(p.barrierFill)
	t.Cleanup(func() {
		SetMaxWorkers(0)
		SetBarrierFill(1)
	})

	// Fixed nonce so the only diff between ct_0 and ct_1 is the seed Δ.
	fixedNonce := deriveFixedNonce(p.nonceSeed, currentNonceSize())
	setTestNonce(t, fixedNonce)

	// PRNG sequence: nonce-seed keeps determinism reproducible. Four
	// disjoint substreams — one for each of (ns, ds, ss) base components
	// and one for the plaintext bytes — so varying PT_KIND doesn't shift
	// seed values.
	const (
		streamNoise uint64 = 0x1111111111111111
		streamData  uint64 = 0x2222222222222222
		streamStart uint64 = 0x3333333333333333
		streamPT    uint64 = 0x4444444444444444
	)
	draw16 := func(stream uint64) [16]uint64 {
		rng := rand.New(rand.NewSource(int64(p.nonceSeed ^ stream)))
		var out [16]uint64
		for i := range out {
			out[i] = rng.Uint64()
		}
		return out
	}
	noiseBase := draw16(streamNoise)
	dataBase := draw16(streamData)
	startBase := draw16(streamStart)

	// Derive Δ (depends on axis-specific base for zero_low_half).
	var basedelta [8]uint64
	switch p.axis {
	case "noise":
		copy(basedelta[:], noiseBase[:8])
	case "data":
		copy(basedelta[:], dataBase[:8])
	case "start":
		copy(basedelta[:], startBase[:8])
	}
	delta := deriveDeltaComponents(p.deltaKind, basedelta, p.nonceSeed)

	// Apply Δ to the requested axis to get seed_variant.
	var noiseVar, dataVar, startVar [16]uint64
	noiseVar = noiseBase
	dataVar = dataBase
	startVar = startBase
	switch p.axis {
	case "noise":
		for i := range noiseVar {
			noiseVar[i] ^= delta[i]
		}
	case "data":
		for i := range dataVar {
			dataVar[i] ^= delta[i]
		}
	case "start":
		for i := range startVar {
			startVar[i] ^= delta[i]
		}
	}

	// Plaintext (determined from its own stream; does NOT depend on axis/Δ).
	ptRng := rand.New(rand.NewSource(int64(p.nonceSeed ^ streamPT)))
	plaintext := relSeedGeneratePlaintext(ptRng, p.plaintextSize, p.plaintextKind)

	// Create ONE hash-function instance per width and reuse it across both
	// encrypts. Critical: primitives with cached wrappers (AES-CMAC, BLAKE3
	// keyed, ChaCha20, BLAKE2, AreionSoEM) draw an internal random key at
	// factory time; calling hashFunc*ForName twice would give two different
	// keys → ct_0 and ct_1 would be completely unrelated random ciphertexts
	// → D = ct_0 ⊕ ct_1 would look uniform from pure key-randomness, not
	// from architectural security. Reusing one instance exercises the
	// production "same hash function instance, different seed components"
	// setup that ITB actually ships.
	var hf128 HashFunc128
	var hf256 HashFunc256
	var hf512 HashFunc512
	switch width {
	case 128:
		h, _, herr := hashFunc128ForName(p.hashName)
		if herr != nil {
			t.Fatalf("hashFunc128: %v", herr)
		}
		hf128 = h
	case 256:
		h, _, herr := hashFunc256ForName(p.hashName)
		if herr != nil {
			t.Fatalf("hashFunc256: %v", herr)
		}
		hf256 = h
	case 512:
		h, _, herr := hashFunc512ForName(p.hashName)
		if herr != nil {
			t.Fatalf("hashFunc512: %v", herr)
		}
		hf512 = h
	}

	encryptOnce := func(noiseComps, dataComps, startComps [16]uint64) []byte {
		switch width {
		case 128:
			ns, err := SeedFromComponents128(hf128, noiseComps[:]...)
			if err != nil {
				t.Fatalf("ns seed: %v", err)
			}
			ds, err := SeedFromComponents128(hf128, dataComps[:]...)
			if err != nil {
				t.Fatalf("ds seed: %v", err)
			}
			ss, err := SeedFromComponents128(hf128, startComps[:]...)
			if err != nil {
				t.Fatalf("ss seed: %v", err)
			}
			out, err := Encrypt128(ns, ds, ss, plaintext)
			if err != nil {
				t.Fatalf("Encrypt128: %v", err)
			}
			return out
		case 256:
			ns, err := SeedFromComponents256(hf256, noiseComps[:]...)
			if err != nil {
				t.Fatalf("ns seed: %v", err)
			}
			ds, err := SeedFromComponents256(hf256, dataComps[:]...)
			if err != nil {
				t.Fatalf("ds seed: %v", err)
			}
			ss, err := SeedFromComponents256(hf256, startComps[:]...)
			if err != nil {
				t.Fatalf("ss seed: %v", err)
			}
			out, err := Encrypt256(ns, ds, ss, plaintext)
			if err != nil {
				t.Fatalf("Encrypt256: %v", err)
			}
			return out
		case 512:
			ns, err := SeedFromComponents512(hf512, noiseComps[:]...)
			if err != nil {
				t.Fatalf("ns seed: %v", err)
			}
			ds, err := SeedFromComponents512(hf512, dataComps[:]...)
			if err != nil {
				t.Fatalf("ds seed: %v", err)
			}
			ss, err := SeedFromComponents512(hf512, startComps[:]...)
			if err != nil {
				t.Fatalf("ss seed: %v", err)
			}
			out, err := Encrypt512(ns, ds, ss, plaintext)
			if err != nil {
				t.Fatalf("Encrypt512: %v", err)
			}
			return out
		}
		t.Fatalf("unsupported width %d", width)
		return nil
	}

	ct0 := encryptOnce(noiseBase, dataBase, startBase)
	ct1 := encryptOnce(noiseVar, dataVar, startVar)

	if err := os.WriteFile(filepath.Join(p.cellDir, "ct_0.bin"), ct0, 0o644); err != nil {
		t.Fatalf("write ct_0: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.cellDir, "ct_1.bin"), ct1, 0o644); err != nil {
		t.Fatalf("write ct_1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.cellDir, "plaintext.bin"), plaintext, 0o644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}

	meta := struct {
		Hash          string   `json:"hash"`
		HashWidth     int      `json:"hash_width"`
		KeyBits       int      `json:"key_bits"`
		Axis          string   `json:"axis"`
		DeltaKind     string   `json:"delta_kind"`
		DeltaHex      string   `json:"delta_hex"`
		PlaintextKind string   `json:"plaintext_kind"`
		PlaintextSize int      `json:"plaintext_size"`
		NonceHex      string   `json:"nonce_hex"`
		NonceSeed     uint64   `json:"nonce_seed"`
		BarrierFill   int      `json:"barrier_fill"`
		Containers    [2]int   `json:"ciphertext_bytes"`
		NoiseBase     []uint64 `json:"noise_base_components"`
		DataBase      []uint64 `json:"data_base_components"`
		StartBase     []uint64 `json:"start_base_components"`
	}{
		Hash:          p.hashName,
		HashWidth:     width,
		KeyBits:       relSeedKeyBits,
		Axis:          p.axis,
		DeltaKind:     p.deltaKind,
		DeltaHex:      fmt.Sprintf("%x", deltaBytes(delta[:])),
		PlaintextKind: p.plaintextKind,
		PlaintextSize: p.plaintextSize,
		NonceHex:      fmt.Sprintf("%x", fixedNonce),
		NonceSeed:     p.nonceSeed,
		BarrierFill:   currentBarrierFill(),
		Containers:    [2]int{len(ct0), len(ct1)},
		NoiseBase:     noiseBase[:],
		DataBase:      dataBase[:],
		StartBase:     startBase[:],
	}
	metaBytes, err := json.MarshalIndent(&meta, "", "  ")
	if err != nil {
		t.Fatalf("meta json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p.cellDir, "cell.meta.json"), metaBytes, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	t.Logf("related-seed pair generated: hash=%s axis=%s delta=%s pt_kind=%s size=%d → %s",
		p.hashName, p.axis, p.deltaKind, p.plaintextKind, p.plaintextSize, p.cellDir)
}

// deltaBytes flattens the 16-uint64 delta into a byte slice (LE).
func deltaBytes(delta []uint64) []byte {
	out := make([]byte, len(delta)*8)
	for i, v := range delta {
		binary.LittleEndian.PutUint64(out[i*8:], v)
	}
	return out
}

// ----------------------------------------------------------------------------
// Crib-KPA cross-format corpus generator (Phase 2f)
// ----------------------------------------------------------------------------
//
// Produces two ciphertexts under the SAME (noiseSeed, dataSeed, startSeed)
// triple but DIFFERENT nonces. The first encrypts a JSON plaintext (suitable
// as a crib-KPA target — publicly known schema prefix); the second encrypts
// an HTML plaintext (different format, fresh nonce). A compound-key K
// recovered from the JSON ciphertext must decrypt the HTML ciphertext as
// well, since K is a per-dataSeed invariant under ChainHash<CRC128>
// (GF(2)-linear primitive → ChainHash output = K ⊕ c(pixel,nonce), K
// depends only on the seed).
//
// Gated by `ITB_CRIB_CROSS=1`. Always uses CRC128 + keyBits=1024 + BF=1.
// Seeds are deterministic given `ITB_CRIB_CROSS_SEED_SOURCE`; nonces are
// deterministic given `ITB_CRIB_CROSS_NONCE_SEED`. Default size 4 KB.

func TestRedTeamGenerateCribCrossCorpus(t *testing.T) {
	if os.Getenv("ITB_CRIB_CROSS") != "1" {
		t.Skip("set ITB_CRIB_CROSS=1 to generate the crib-cross corpus pair")
	}

	size := 4096
	if s := os.Getenv("ITB_CRIB_CROSS_SIZE"); s != "" {
		sv, err := strconv.Atoi(s)
		if err != nil || sv < 4096 {
			t.Fatalf("ITB_CRIB_CROSS_SIZE=%q: must be integer ≥ 4096", s)
		}
		size = sv
	}
	nonceSeed := uint64(0xDEADBEEFCAFEBABE)
	if s := os.Getenv("ITB_CRIB_CROSS_NONCE_SEED"); s != "" {
		sv, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("ITB_CRIB_CROSS_NONCE_SEED=%q: %v", s, err)
		}
		nonceSeed = sv
	}
	seedSource := uint64(0x1234567890ABCDEF)
	if s := os.Getenv("ITB_CRIB_CROSS_SEED_SOURCE"); s != "" {
		sv, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("ITB_CRIB_CROSS_SEED_SOURCE=%q: %v", s, err)
		}
		seedSource = sv
	}

	const keyBits = 1024

	// Deterministic seed generation from ITB_CRIB_CROSS_SEED_SOURCE.
	seedRng := rand.New(rand.NewSource(int64(seedSource)))
	noiseComps := make([]uint64, 16)
	dataComps := make([]uint64, 16)
	startComps := make([]uint64, 16)
	for i := range noiseComps {
		noiseComps[i] = seedRng.Uint64()
	}
	for i := range dataComps {
		dataComps[i] = seedRng.Uint64()
	}
	for i := range startComps {
		startComps[i] = seedRng.Uint64()
	}

	hashFunc := HashFunc128(crc128)
	nsSeed, err := SeedFromComponents128(hashFunc, noiseComps...)
	if err != nil {
		t.Fatalf("ns seed: %v", err)
	}
	dsSeed, err := SeedFromComponents128(hashFunc, dataComps...)
	if err != nil {
		t.Fatalf("ds seed: %v", err)
	}
	ssSeed, err := SeedFromComponents128(hashFunc, startComps...)
	if err != nil {
		t.Fatalf("ss seed: %v", err)
	}

	// Two distinct nonces, deterministic from nonceSeed.
	nonceRng := rand.New(rand.NewSource(int64(nonceSeed)))
	nonceA := make([]byte, 16)
	nonceB := make([]byte, 16)
	_, _ = nonceRng.Read(nonceA)
	_, _ = nonceRng.Read(nonceB)
	if bytes.Equal(nonceA, nonceB) {
		t.Fatalf("nonceA == nonceB (nonceSeed collision); pick a different ITB_CRIB_CROSS_NONCE_SEED")
	}

	outDir, _ := filepath.Abs(filepath.Join("tmp", "attack", "crib_cross"))
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writeCell := func(cellName string, nonce []byte, ptBytes []byte, kind string) int {
		cellDir := filepath.Join(outDir, cellName)
		if err := os.MkdirAll(cellDir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", cellDir, err)
		}
		setTestNonce(t, nonce)
		ct, err := Encrypt128(nsSeed, dsSeed, ssSeed, ptBytes)
		if err != nil {
			t.Fatalf("Encrypt128 %s: %v", cellName, err)
		}
		// Parse W, H from the 20-byte header (16 nonce + 2 W + 2 H, big-endian).
		if len(ct) < 20 {
			t.Fatalf("ciphertext too short for header: %d", len(ct))
		}
		W := int(uint16(ct[16])<<8 | uint16(ct[17]))
		H := int(uint16(ct[18])<<8 | uint16(ct[19]))
		totalPixels := W * H
		// Recover the ground-truth startPixel from dataSeed.ChainHash on the
		// first data chunk (same derivation as the ITB encoder). Simpler path:
		// parse from the encoder's internal state via a second deterministic
		// encrypt — but we already have the ciphertext. We leave `start_pixel`
		// out; the bias-probe will recover it and the decrypt script will
		// verify against the full-plaintext match instead.
		if err := os.WriteFile(filepath.Join(cellDir, "ct_0000.bin"), ct, 0o644); err != nil {
			t.Fatalf("write ct: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cellDir, "ct_0000.plain"), ptBytes, 0o644); err != nil {
			t.Fatalf("write pt: %v", err)
		}
		meta := struct {
			Hash           string   `json:"hash"`
			HashDisplay    string   `json:"hash_display"`
			HashWidth      int      `json:"hash_width"`
			KeyBits        int      `json:"key_bits"`
			BarrierFill    int      `json:"barrier_fill"`
			Mode           string   `json:"mode"`
			PlaintextKind  string   `json:"plaintext_kind"`
			PlaintextSize  int      `json:"plaintext_size"`
			NonceHex       string   `json:"nonce_hex"`
			CiphertextSize int      `json:"ciphertext_size"`
			Width          int      `json:"width"`
			Height         int      `json:"height"`
			TotalPixels    int      `json:"total_pixels"`
			NoiseSeed      []uint64 `json:"noise_seed"`
			DataSeed       []uint64 `json:"data_seed"`
			StartSeed      []uint64 `json:"start_seed"`
		}{
			Hash:           "crc128",
			HashDisplay:    "CRC128-test",
			HashWidth:      128,
			KeyBits:        keyBits,
			BarrierFill:    currentBarrierFill(),
			Mode:           "crib_cross",
			PlaintextKind:  kind,
			PlaintextSize:  len(ptBytes),
			NonceHex:       hex.EncodeToString(nonce),
			CiphertextSize: len(ct),
			Width:          W,
			Height:         H,
			TotalPixels:    totalPixels,
			NoiseSeed:      noiseComps,
			DataSeed:       dataComps,
			StartSeed:      startComps,
		}
		metaBytes, err := json.MarshalIndent(&meta, "", "  ")
		if err != nil {
			t.Fatalf("meta json: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cellDir, "cell.meta.json"), metaBytes, 0o644); err != nil {
			t.Fatalf("write meta: %v", err)
		}
		t.Logf("  %s: %d B plaintext, %d B ciphertext → %s",
			cellName, len(ptBytes), len(ct), cellDir)
		return len(ct)
	}

	// Corpus A — JSON plaintext (crib-KPA target). Deterministic per seedSource.
	rngA := rand.New(rand.NewSource(int64(seedSource) + 1))
	ptA, _, _ := generateStructuredPlaintext(rngA, size, 0, "json_structured_80")
	ctALen := writeCell("corpus_A_json", nonceA, ptA, "json_structured_80")

	// Corpus B — HTML plaintext under SAME seeds, DIFFERENT nonce. Target of
	// the full-plaintext decrypt script that ingests K recovered from corpus A.
	rngB := rand.New(rand.NewSource(int64(seedSource) + 2))
	ptB, _, _ := generateStructuredPlaintext(rngB, size, 0, "html_structured_80")
	ctBLen := writeCell("corpus_B_html", nonceB, ptB, "html_structured_80")

	// Shared summary for tooling to discover both cells + seeds / nonces.
	summary := struct {
		KeyBits     int      `json:"key_bits"`
		BarrierFill int      `json:"barrier_fill"`
		Hash        string   `json:"hash"`
		NoiseSeed   []uint64 `json:"noise_seed"`
		DataSeed    []uint64 `json:"data_seed"`
		StartSeed   []uint64 `json:"start_seed"`
		NonceAHex   string   `json:"nonce_a_hex"`
		NonceBHex   string   `json:"nonce_b_hex"`
		CorpusA     string   `json:"corpus_a"`
		CorpusB     string   `json:"corpus_b"`
		SizeBytes   int      `json:"plaintext_size_bytes"`
	}{
		KeyBits: keyBits, BarrierFill: currentBarrierFill(), Hash: "crc128",
		NoiseSeed: noiseComps, DataSeed: dataComps, StartSeed: startComps,
		NonceAHex: hex.EncodeToString(nonceA),
		NonceBHex: hex.EncodeToString(nonceB),
		CorpusA:   "corpus_A_json",
		CorpusB:   "corpus_B_html",
		SizeBytes: size,
	}
	summaryBytes, _ := json.MarshalIndent(&summary, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "summary.json"), summaryBytes, 0o644); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	t.Logf("crib-cross corpora generated at %s (A: %d B, B: %d B)", outDir, ctALen, ctBLen)
}
