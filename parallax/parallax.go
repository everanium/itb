package parallax

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"

	"github.com/everanium/itb/ctr"
	"github.com/everanium/itb/kdf"
)

// Wire-format constants.
const (
	// NonceSize is the on-wire per-message nonce width in bytes. The
	// width is independent of palette composition: every Encrypt /
	// EncryptInPlace prepends a 16-byte fresh CSPRNG nonce that each
	// slot's keystream consumes at its own native nonce width via
	// truncation (see worker.go).
	NonceSize = 16

	// MasterKeySize is the minimum byte length of the master keying
	// material accepted by NewCipherset. The 32-byte floor matches the
	// security floor used elsewhere in the project and is sufficient to
	// key every registry primitive. Longer masters are accepted; bytes
	// past the anchor primitive's KDF key length are not consumed (the
	// truncate / expand policy is owned by kdf.Derive).
	MasterKeySize = 32

	// DefaultSegmentSize is the recommended segment size for the
	// single-message API (Encrypt, Decrypt, EncryptInPlace,
	// DecryptInPlace) and for each per-chunk encrypt under the streaming
	// API. The value is the smallest prime above 4000 that is coprime to
	// 504 (the per-mode pipeline period of the surrounding ITB
	// construction) and that delivers steady throughput across the
	// registry primitives.
	DefaultSegmentSize = 4093

	// DefaultChunkSize is the default per-chunk plaintext budget for
	// the streaming API. Mirrors ITB's DefaultChunkSize: the streaming
	// writers accumulate up to DefaultChunkSize plaintext bytes before
	// emitting one wire frame, and the streaming readers pull at most
	// DefaultChunkSize plaintext bytes per upstream Read.
	DefaultChunkSize = 16 << 20

	// MinPaletteSize is the smallest accepted palette size.
	MinPaletteSize = 3

	// MaxPaletteSize is the largest accepted palette size. The cap
	// fits the slot index inside a single byte and keeps the
	// derivation-label suffix bounded.
	MaxPaletteSize = 255

	// MaxCipherNameLen caps a single palette entry's name length. The
	// derivation label is "<name>:<index>" with index up to MaxPaletteSize;
	// the cap leaves the formatted label inside a 16-byte 128-bit-PRF
	// input block budget.
	MaxCipherNameLen = 12

	// MaxSegmentSize is an upper sanity cap on the user-supplied
	// segment size. The cap is 65535 — large enough that throughput
	// already plateaus well before it (per-segment dispatch becomes
	// negligible) and small enough to keep the segment table dense
	// and the worker partitioning meaningful at typical plaintext
	// sizes. The cap itself is rejected by the coprime check
	// (gcd(65535, 504) = 3); the largest accepted value is 65533.
	MaxSegmentSize = 65535

	// MaxChunkSize is the upper sanity cap on the streaming chunk size.
	// The cap is 256 MiB — large enough to accommodate the rare
	// single-message-per-stream workload while keeping the per-chunk
	// wire layout (u32 little-endian length prefix) well inside the
	// u32 range. The cap is independent of the surrounding transport's
	// own chunk-size cap; for parallax composed under an authenticated
	// transport (ITB Easy Mode or Streaming AEAD), the effective
	// ceiling is min(parallax.MaxChunkSize, transport.MaxChunkSize).
	// The two layers exchange a byte stream — parallax frame boundaries
	// are invisible to the outer transport — so the chunk sizes do not
	// need to match.
	MaxChunkSize = 256 << 20

	// scheduleSeedSize is the byte length of the schedule seed
	// extracted from the scheduling keystream and fed to the
	// Fisher-Yates permutation builder. 16 bytes is enough material for
	// every palette size up to MaxPaletteSize.
	scheduleSeedSize = 16
)

// itbPipelinePeriod is the gcd reference used to validate the segment
// size. Coprime segment sizes avoid resonant alignment between segment
// boundaries and the inner ITB pipeline period across every supported
// mode.
const itbPipelinePeriod = 504

// Schedule carries a validated palette, segment size, and streaming
// chunk size. A Schedule is the message-shaped half of the parallax
// configuration; pair it with a Cipherset to encrypt or decrypt. The
// palette is immutable for the lifetime of the Schedule; the segment
// size and chunk size are atomically swappable via SetSegmentSize and
// SetChunkSize.
//
// The segment size drives the single-message API (Encrypt, Decrypt,
// EncryptInPlace, DecryptInPlace) and every per-chunk encrypt under
// the streaming API. The chunk size drives the streaming API only:
// streaming writers accumulate up to chunkSize plaintext bytes before
// emitting one frame, and streaming readers pull at most chunkSize
// plaintext bytes per upstream Read. In-flight calls and in-flight
// streams keep the values observed at the call's start.
type Schedule struct {
	palette     []string
	segmentSize atomic.Int64
	chunkSize   atomic.Int64
}

// Palette returns a copy of the cipher palette in slot order.
func (s *Schedule) Palette() []string {
	out := make([]string, len(s.palette))
	copy(out, s.palette)
	return out
}

// SegmentSize returns the segment size used by every Encrypt / Decrypt
// call routed through this Schedule, including the per-chunk encrypts
// inside the streaming API.
func (s *Schedule) SegmentSize() int {
	return int(s.segmentSize.Load())
}

// ChunkSize returns the per-chunk plaintext budget used by the
// streaming API constructors. Streams already in flight keep the
// value observed at construction time.
func (s *Schedule) ChunkSize() int {
	return int(s.chunkSize.Load())
}

// PaletteSize returns the palette slot count.
func (s *Schedule) PaletteSize() int {
	return len(s.palette)
}

// Cipherset carries per-slot subkeys derived from the master under the
// schedule's palette and the dedicated scheduling subkey used to expand
// the per-message schedule seed. The subkeys are opaque; the only way to
// consume a Cipherset is via Schedule.Encrypt / Schedule.Decrypt.
type Cipherset struct {
	schedule       *Schedule
	subkeys        [][]byte
	scheduleSubkey []byte
}

// NewSchedule validates the palette and segment size and returns a
// Schedule whose single-message and streaming APIs route through the
// supplied segmentSize. A zero or negative segmentSize is rejected;
// pass DefaultSegmentSize to use the package default. The streaming
// chunk size is initialised to DefaultChunkSize and is independently
// adjustable via SetChunkSize.
//
// An error is returned when the palette size falls outside
// [MinPaletteSize, MaxPaletteSize], when any palette entry is empty or
// exceeds MaxCipherNameLen, when any palette entry is not a name the
// ctr registry accepts, when segmentSize is below 1 or above
// MaxSegmentSize, or when segmentSize is not coprime to the per-mode
// pipeline period.
func NewSchedule(palette []string, segmentSize int) (*Schedule, error) {
	if err := validatePalette(palette); err != nil {
		return nil, err
	}
	if err := validateSegmentSize(segmentSize); err != nil {
		return nil, err
	}
	cp := make([]string, len(palette))
	copy(cp, palette)
	s := &Schedule{palette: cp}
	s.segmentSize.Store(int64(segmentSize))
	s.chunkSize.Store(int64(DefaultChunkSize))
	return s, nil
}

// SetSegmentSize replaces the segment size for every subsequent call
// (single-message and per-chunk streaming). The supplied size must be
// a valid segment size (positive, at most MaxSegmentSize, coprime to
// the per-mode pipeline period); invalid values return an error and
// leave the Schedule unchanged. In-flight calls observe the value
// captured at the call's start; in-flight streams keep the value
// captured at construction time.
func (s *Schedule) SetSegmentSize(n int) error {
	if err := validateSegmentSize(n); err != nil {
		return err
	}
	s.segmentSize.Store(int64(n))
	return nil
}

// SetChunkSize replaces the per-chunk plaintext budget used by
// subsequently-constructed streams. In-flight streams keep the chunk
// size observed at construction time. The supplied size must be
// positive and at most MaxChunkSize; invalid values return an error
// and leave the Schedule unchanged.
func (s *Schedule) SetChunkSize(n int) error {
	if err := validateChunkSize(n); err != nil {
		return err
	}
	s.chunkSize.Store(int64(n))
	return nil
}

// GenerateMasterKey draws a fresh MasterKeySize-byte CSPRNG master
// secret suitable for NewCipherset. An error is returned only when
// crypto/rand fails to supply the requested bytes.
func GenerateMasterKey() ([]byte, error) {
	out := make([]byte, MasterKeySize)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

// NewCipherset derives per-slot subkeys and the scheduling subkey from
// master under the schedule's palette. master must be at least
// MasterKeySize bytes; bytes past the anchor primitive's KDF key
// length are not consumed (no additional entropy is mixed in from a
// longer master). The anchor primitive — palette[0] — is the KDF PRF
// for every slot; the derivation label is "<slot-name>:<1-based-index>",
// so identical palette entries in distinct slots produce distinct
// subkeys. A separate scheduling subkey is derived under the dedicated
// label "schedule:0".
//
// An error is returned when schedule is nil, when master is shorter
// than MasterKeySize, when the anchor primitive's key size cannot be
// resolved by the ctr registry, or when KDF derivation fails for the
// scheduling subkey or any per-slot subkey.
func NewCipherset(master []byte, schedule *Schedule) (*Cipherset, error) {
	if schedule == nil {
		return nil, fmt.Errorf("parallax: nil schedule")
	}
	if len(master) < MasterKeySize {
		return nil, fmt.Errorf("parallax: master must be at least %d bytes, got %d", MasterKeySize, len(master))
	}
	anchor := schedule.palette[0]
	anchorKeySize, err := ctr.KeySize(anchor)
	if err != nil {
		return nil, fmt.Errorf("parallax: anchor cipher %q: %w", anchor, err)
	}
	scheduleSubkey, err := kdf.Derive(anchor, master, "schedule:0", anchorKeySize)
	if err != nil {
		return nil, fmt.Errorf("parallax: scheduling subkey derivation: %w", err)
	}
	subkeys := make([][]byte, len(schedule.palette))
	for i, name := range schedule.palette {
		keySize, err := ctr.KeySize(name)
		if err != nil {
			return nil, fmt.Errorf("parallax: slot %d cipher %q: %w", i, name, err)
		}
		label := fmt.Sprintf("%s:%d", name, i+1)
		subkey, err := kdf.Derive(anchor, master, label, keySize)
		if err != nil {
			return nil, fmt.Errorf("parallax: slot %d subkey derivation: %w", i, err)
		}
		subkeys[i] = subkey
	}
	return &Cipherset{
		schedule:       schedule,
		subkeys:        subkeys,
		scheduleSubkey: scheduleSubkey,
	}, nil
}

// Encrypt encrypts plaintext under the cipherset and returns a freshly
// allocated wire of the form `nonce || body`. The 16-byte per-message
// nonce is drawn from crypto/rand. A nil or zero-length plaintext yields
// a nonce-only wire (NonceSize bytes); the round-trip is preserved.
//
// An error is returned when cs is nil or does not match this schedule,
// when crypto/rand fails to supply nonce bytes, or when the per-segment
// keystream construction fails for any palette slot.
func (s *Schedule) Encrypt(plaintext []byte, cs *Cipherset) ([]byte, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	wire := make([]byte, NonceSize+len(plaintext))
	if _, err := rand.Read(wire[:NonceSize]); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return wire, nil
	}
	copy(wire[NonceSize:], plaintext)
	if err := transform(s, cs, wire[:NonceSize], wire[NonceSize:]); err != nil {
		return nil, err
	}
	return wire, nil
}

// Decrypt reverses Encrypt. The 16-byte leading nonce is read from wire
// and the body is decrypted into a freshly allocated buffer. A
// nonce-only wire round-trips as an empty plaintext.
//
// An error is returned when cs is nil or does not match this schedule,
// when ciphertext is shorter than NonceSize, or when the per-segment
// keystream construction fails for any palette slot.
//
// Decrypt performs no integrity check: a wire produced under a
// different palette, segment size, master, or in-flight modification
// returns garbage rather than an error. The single-message wire and
// the streaming wire are both Non-AEAD by design; callers compose
// parallax under ITB's authenticated transport (Easy Mode or Streaming
// AEAD) when wire integrity is required, or wrap the wire in an
// external MAC when parallax is used standalone.
func (s *Schedule) Decrypt(ciphertext []byte, cs *Cipherset) ([]byte, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	if len(ciphertext) < NonceSize {
		return nil, fmt.Errorf("parallax: ciphertext shorter than nonce (%d < %d)", len(ciphertext), NonceSize)
	}
	body := ciphertext[NonceSize:]
	if len(body) == 0 {
		return []byte{}, nil
	}
	out := make([]byte, len(body))
	if err := transformInto(s, cs, ciphertext[:NonceSize], out, body); err != nil {
		return nil, err
	}
	return out, nil
}

// EncryptInPlace encrypts buf under a freshly drawn per-message 16-byte
// nonce and returns a wire of the form `nonce || ciphertext_body`. On
// success buf is overwritten with the ciphertext body, byte-identical
// to wire[NonceSize:]; on error buf is left unchanged. Use this entry
// on hot paths where the caller has just produced a plaintext that need
// not be preserved; Encrypt is the allocate-fresh-output variant.
//
// An error is returned when cs is nil or does not match this schedule,
// when crypto/rand fails to supply nonce bytes, or when the per-segment
// keystream construction fails for any palette slot.
//
// The returned wire is itself a fresh allocation that holds the nonce
// prefix and the ciphertext body in one contiguous buffer. The
// in-place mutation of buf is published only after the wire has been
// fully populated; a transform error therefore propagates without
// partial-mutation on buf.
func (s *Schedule) EncryptInPlace(buf []byte, cs *Cipherset) ([]byte, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	wire := make([]byte, NonceSize+len(buf))
	if _, err := rand.Read(wire[:NonceSize]); err != nil {
		return nil, err
	}
	if len(buf) > 0 {
		if err := transformInto(s, cs, wire[:NonceSize], wire[NonceSize:], buf); err != nil {
			return nil, err
		}
		copy(buf, wire[NonceSize:])
	}
	return wire, nil
}

// DecryptInPlace strips the leading 16-byte nonce from wire and
// decrypts the remainder in place. wire is MUTATED; the returned slice
// is wire[NonceSize:], fully decrypted. A nonce-only wire returns an
// empty (non-nil) slice.
//
// An error is returned when cs is nil or does not match this schedule,
// when wire is shorter than NonceSize, or when the per-segment
// keystream construction fails for any palette slot. On a transform
// error the body region of wire may have been partially decrypted; the
// Non-AEAD contract makes this state observationally equivalent to the
// "wire produced under a different palette or master" failure mode
// described on Decrypt.
func (s *Schedule) DecryptInPlace(wire []byte, cs *Cipherset) ([]byte, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	if len(wire) < NonceSize {
		return nil, fmt.Errorf("parallax: wire shorter than nonce (%d < %d)", len(wire), NonceSize)
	}
	nonce := wire[:NonceSize]
	body := wire[NonceSize:]
	if len(body) == 0 {
		return body, nil
	}
	if err := transform(s, cs, nonce, body); err != nil {
		return nil, err
	}
	return body, nil
}

// checkCipherset verifies that cs is non-nil and bound to s.
func (s *Schedule) checkCipherset(cs *Cipherset) error {
	if cs == nil {
		return fmt.Errorf("parallax: nil cipherset")
	}
	if cs.schedule != s {
		// Allow distinct Schedule instances that carry equivalent
		// state — palette and segment size — so encryptor and
		// decryptor may be constructed independently.
		if !sameSchedule(cs.schedule, s) {
			return fmt.Errorf("parallax: cipherset does not match schedule")
		}
	}
	return nil
}

// sameSchedule returns true when a and b describe identical palette
// and segment size; the comparison ignores pointer identity and the
// streaming-only chunk size.
func sameSchedule(a, b *Schedule) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.SegmentSize() != b.SegmentSize() {
		return false
	}
	if len(a.palette) != len(b.palette) {
		return false
	}
	for i := range a.palette {
		if a.palette[i] != b.palette[i] {
			return false
		}
	}
	return true
}

// transform is the in-place encrypt/decrypt entry consumed by every
// single-message surface helper. It expands the schedule seed via
// cs.scheduleSubkey and the supplied nonce, builds the Fisher-Yates
// permutation, and dispatches the worker loop over buf with buf as
// both source and destination. The XOR is symmetric, so the same call
// decrypts. The segment width is the schedule's segment size observed
// at the call's start.
func transform(s *Schedule, cs *Cipherset, nonce, buf []byte) error {
	return transformInto(s, cs, nonce, buf, buf)
}

// transformInto is the out-of-place counterpart. dst and src may
// alias; when they do, the call is equivalent to transform. The
// segment width is the schedule's segment size observed at the
// call's start.
func transformInto(s *Schedule, cs *Cipherset, nonce, dst, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("parallax: dst/src length mismatch (%d != %d)", len(dst), len(src))
	}
	if len(src) == 0 {
		return nil
	}
	pi, err := buildPermutation(s, cs, nonce)
	if err != nil {
		return err
	}
	segSize := s.SegmentSize()
	return runWorkers(s, cs, pi, nonce, dst, src, segSize)
}

// validatePalette enforces the palette-size and per-name constraints.
func validatePalette(palette []string) error {
	if len(palette) < MinPaletteSize {
		return fmt.Errorf("parallax: palette size %d below minimum %d", len(palette), MinPaletteSize)
	}
	if len(palette) > MaxPaletteSize {
		return fmt.Errorf("parallax: palette size %d above maximum %d", len(palette), MaxPaletteSize)
	}
	for i, name := range palette {
		if len(name) == 0 {
			return fmt.Errorf("parallax: palette[%d] is empty", i)
		}
		if len(name) > MaxCipherNameLen {
			return fmt.Errorf("parallax: palette[%d] %q exceeds %d-char limit", i, name, MaxCipherNameLen)
		}
		if _, err := ctr.KeySize(name); err != nil {
			return fmt.Errorf("parallax: palette[%d]: %w", i, err)
		}
	}
	return nil
}

// validateSegmentSize enforces the bounds and the gcd-coprime rule.
func validateSegmentSize(segmentSize int) error {
	if segmentSize < 1 {
		return fmt.Errorf("parallax: segment size %d below 1", segmentSize)
	}
	if segmentSize > MaxSegmentSize {
		return fmt.Errorf("parallax: segment size %d above maximum %d", segmentSize, MaxSegmentSize)
	}
	if gcd(segmentSize, itbPipelinePeriod) != 1 {
		return fmt.Errorf("parallax: segment size %d not coprime to %d", segmentSize, itbPipelinePeriod)
	}
	return nil
}

// validateChunkSize enforces the bounds on the streaming chunk size.
func validateChunkSize(chunkSize int) error {
	if chunkSize < 1 {
		return fmt.Errorf("parallax: chunk size %d below 1", chunkSize)
	}
	if chunkSize > MaxChunkSize {
		return fmt.Errorf("parallax: chunk size %d above maximum %d", chunkSize, MaxChunkSize)
	}
	return nil
}

// gcd returns the greatest common divisor of |a| and |b|. Both inputs
// are treated as non-negative; a zero argument returns the other.
func gcd(a, b int) int {
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
