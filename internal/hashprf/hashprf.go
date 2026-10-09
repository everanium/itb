// Package hashprf builds keyed pseudo-random functions over hash-based
// ITB registry primitives, exposing each as a fixed-output-width PRF.
//
// The supported primitives split into two families:
//
//   - Areion family ("areion256", "areion512") — keyed via the ITB
//     registry HashFunc factories (hashes.Areion256PairWithKey /
//     hashes.Areion512PairWithKey). The key is the registry fixed key,
//     SoEM's first subkey; the registry seed argument, SoEM's second
//     subkey, is derived from the key once at construction (see
//     areionSeed256).
//     The PRF hashes the input under that secret seed and serialises the
//     resulting uint64 words little-endian.
//   - BLAKE family ("blake2b256", "blake2b512", "blake2s", "blake3") —
//     keyed via the upstream keyed-hash mode. The PRF output is the
//     leading blockSize bytes of the keyed digest over the input.
//
// The Areion family additionally exposes a 4-wide batched PRF via NewBatch:
// it hashes four inputs in one SIMD batch (bit-exact with the single-input
// PRF), which the ctr keystream uses to amortise per-block dispatch. The
// BLAKE family has no batch path, and NewBatch reports none for those names.
//
// The package is a shared dependency of the ctr and kdf packages, which
// import it for their keyed-PRF and SP 800-108 counter-mode constructions
// respectively. It imports the BLAKE upstream packages and the ITB hashes
// package; it does not import ctr or kdf, so no import cycle arises.
package hashprf

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb/hashes"
)

// spec holds the key length and PRF output width of one primitive.
type spec struct {
	keySize   int
	blockSize int
}

// specs maps each supported name to its key and output widths.
var specs = map[string]spec{
	hashes.CipherAreion256:  {keySize: 32, blockSize: 32},
	hashes.CipherAreion512:  {keySize: 64, blockSize: 64},
	hashes.CipherBLAKE2b256: {keySize: 32, blockSize: 32},
	hashes.CipherBLAKE2b512: {keySize: 32, blockSize: 64},
	hashes.CipherBLAKE2s:    {keySize: 32, blockSize: 32},
	hashes.CipherBLAKE3:     {keySize: 32, blockSize: 32},
}

// KeySize returns the byte length of the key for the named primitive.
func KeySize(name string) (int, error) {
	s, ok := specs[name]
	if !ok {
		return 0, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	return s.keySize, nil
}

// BlockSize returns the PRF output width in bytes for the named primitive.
func BlockSize(name string) (int, error) {
	s, ok := specs[name]
	if !ok {
		return 0, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	return s.blockSize, nil
}

// New returns a keyed PRF for one of the hash-based primitives and its
// output block size. The key length must equal the primitive's key size; a
// mismatched length or an unknown name is an error.
//
// The returned prf writes exactly blockSize bytes into dst[:blockSize], so
// dst must have len(dst) >= blockSize. The returned prf is not safe for
// concurrent use; it reuses internal hasher state and is intended for
// serial, single-stream use.
func New(name string, key []byte) (prf func(dst, in []byte), blockSize int, err error) {
	s, ok := specs[name]
	if !ok {
		return nil, 0, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	if len(key) != s.keySize {
		return nil, 0, fmt.Errorf("hashprf: %s key must be %d bytes, got %d", name, s.keySize, len(key))
	}

	switch name {
	case hashes.CipherAreion256:
		return newAreion256PRF(key), s.blockSize, nil
	case hashes.CipherAreion512:
		return newAreion512PRF(key), s.blockSize, nil
	case hashes.CipherBLAKE2b256:
		return newBlake2bPRF(key, 32), s.blockSize, nil
	case hashes.CipherBLAKE2b512:
		return newBlake2bPRF(key, 64), s.blockSize, nil
	case hashes.CipherBLAKE2s:
		return newBlake2sPRF(key), s.blockSize, nil
	case hashes.CipherBLAKE3:
		return newBlake3PRF(key), s.blockSize, nil
	default:
		// Unreachable: specs and the switch are kept in lock-step.
		return nil, 0, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
}

// Domain-separation labels of the Areion second-subkey derivation. Each
// width has its own label, so the two derivations never share an input.
const (
	areion256SubkeyLabel = "itb hashprf areion256 subkey"
	areion512SubkeyLabel = "itb hashprf areion512 subkey"
)

// areionSeed256 derives the secret second SoEM subkey of the areion256 PRF
// from its 32-byte key: seed = SHA-512(areion256SubkeyLabel || key)[:32],
// read as four little-endian uint64 words.
//
// The registry Areion-SoEM round function is SoEM22,
//
//	F(m) = P1(m ^ k1) ^ P2(m ^ k2) ^ k1 ^ k2
//
// with k1 the fixed key, k2 the seed, and P1 / P2 the Areion permutation
// under its first and second round-constant table. Both subkeys must be
// secret: the SoEM22 PRF bound is stated for two independent secret keys,
// and with a public k2 the second term P2(m ^ k2) is computable by anyone,
// which reduces F to a single-key Even-Mansour instance in k1 (the one-
// block inversion is blocked only by the whitening). Deriving k2 from the
// key keeps both subkeys secret while the PRF key length stays the
// registry key length. SHA-512 is used as a standard, domain-separated
// derivation that lives entirely inside this package; modelling it as a
// random oracle, k2 is indistinguishable from a subkey drawn independently
// of k1 by anyone who does not hold the key.
//
// Security. Two secret subkeys restore the SoEM22 key setting. The claim
// is the PRF bound of Chen, Lambooij and Mennink (CRYPTO 2019; ePrint
// 2019/554, Theorem 1): about 2^(2n/3) queries in the state width n, in
// the random-permutation model with P2 modelled as independent of P1 and
// SHA-512 as a random oracle for k2. The CBC-MAC chain over this round
// function, length-tagged in its first block, carries the bound to
// variable-length inputs with the q^2 * l^2 / 2^n term of
// hashes/CONSTRUCTIONS.md, n = 256 for areion256 and n = 512 for
// areion512.
func areionSeed256(key []byte) [4]uint64 {
	h := sha512.New()
	h.Write([]byte(areion256SubkeyLabel))
	h.Write(key)
	var sum [sha512.Size]byte
	h.Sum(sum[:0])
	var seed [4]uint64
	for i := range seed {
		seed[i] = binary.LittleEndian.Uint64(sum[i*8:])
	}
	return seed
}

// areionSeed512 is the areion512 counterpart of areionSeed256:
// seed = SHA-512(areion512SubkeyLabel || key), all 64 bytes, read as eight
// little-endian uint64 words, under the same security statement at
// n = 512.
func areionSeed512(key []byte) [8]uint64 {
	h := sha512.New()
	h.Write([]byte(areion512SubkeyLabel))
	h.Write(key)
	var sum [sha512.Size]byte
	h.Sum(sum[:0])
	var seed [8]uint64
	for i := range seed {
		seed[i] = binary.LittleEndian.Uint64(sum[i*8:])
	}
	return seed
}

// newAreion256PRF builds a keyed Areion-SoEM-256 HashFunc256 and returns
// a PRF that hashes the input under the key-derived seed of areionSeed256
// and serialises the four resulting uint64 words little-endian into 32
// bytes.
func newAreion256PRF(key []byte) func(dst, in []byte) {
	var k [32]byte
	copy(k[:], key)
	hf, _ := hashes.Areion256PairWithKey(k)
	seed := areionSeed256(key)
	return func(dst, in []byte) {
		out := hf(in, seed)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(dst[i*8:], out[i])
		}
	}
}

// newAreion512PRF builds a keyed Areion-SoEM-512 HashFunc512 and returns
// a PRF that hashes the input under the key-derived seed of areionSeed512
// and serialises the eight resulting uint64 words little-endian into 64
// bytes.
func newAreion512PRF(key []byte) func(dst, in []byte) {
	var k [64]byte
	copy(k[:], key)
	hf, _ := hashes.Areion512PairWithKey(k)
	seed := areionSeed512(key)
	return func(dst, in []byte) {
		out := hf(in, seed)
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(dst[i*8:], out[i])
		}
	}
}

// newBlake2bPRF keys a BLAKE2b hasher (output size 32 or 64) and returns
// a PRF that resets and re-hashes the input per call. The keyed hasher is
// created once; each call resets its state, so the hasher is not
// reallocated per call.
func newBlake2bPRF(key []byte, size int) func(dst, in []byte) {
	var h hash.Hash
	var err error
	if size == 32 {
		h, err = blake2b.New256(key)
	} else {
		h, err = blake2b.New512(key)
	}
	if err != nil {
		// A valid 32-byte key never fails for BLAKE2b; New has already
		// validated the key length, so any error here is a bug.
		panic(fmt.Sprintf("hashprf: blake2b keying: %v", err))
	}
	var scratch [64]byte
	return func(dst, in []byte) {
		h.Reset()
		h.Write(in)
		out := h.Sum(scratch[:0])
		copy(dst[:size], out[:size])
	}
}

// newBlake2sPRF keys a BLAKE2s-256 hasher and returns a PRF over the
// reset/re-hash cycle.
func newBlake2sPRF(key []byte) func(dst, in []byte) {
	h, err := blake2s.New256(key)
	if err != nil {
		panic(fmt.Sprintf("hashprf: blake2s keying: %v", err))
	}
	var scratch [32]byte
	return func(dst, in []byte) {
		h.Reset()
		h.Write(in)
		out := h.Sum(scratch[:0])
		copy(dst[:32], out[:32])
	}
}

// newBlake3PRF keys a BLAKE3 hasher once and returns a PRF over the
// reset/re-hash cycle, mirroring the blake2b / blake2s closures above.
//
// The registry HashFunc in hashes/blake3.go clones a shared template per
// call because that closure is shared across the goroutines that process
// ITB pixels in parallel, where Reset() on a shared hasher would race. The
// PRF returned here is bound to one keystream / KDF instance and is driven
// strictly sequentially (the prfHashCTR keystream and the SP 800-108
// counter loop are both single-threaded), so Reset() on a captured hasher
// is safe and avoids the per-call 8 KiB state copy that Clone() incurs.
// zeebo/blake3 Reset() preserves the keyed state — it clears len / chunks /
// stack but not key / flags — so the keystream output is byte-identical to
// the clone path.
func newBlake3PRF(key []byte) func(dst, in []byte) {
	h, err := blake3.NewKeyed(key)
	if err != nil {
		panic(fmt.Sprintf("hashprf: blake3 keying: %v", err))
	}
	var buf [32]byte
	return func(dst, in []byte) {
		h.Reset()
		h.Write(in)
		h.Sum(buf[:0])
		copy(dst[:32], buf[:])
	}
}

// NewBatch returns a 4-wide batched keyed PRF for the primitives that expose a
// SIMD batch path, together with the per-lane output block size. ok reports
// whether a batch path exists for name: only the Areion family does (via the
// registry BatchHashFunc factories, which are bit-exact with the single-input
// HashFunc), so a batched keystream over those primitives produces output
// byte-identical to the single-block PRF. ok is false for the BLAKE family,
// whose registry factories expose no 4-wide batch; callers fall back to New.
//
// The returned batch closure fills dst[0..3] (each at least blockSize bytes)
// from in[0..3]. It is bound to one keystream / KDF instance and driven
// sequentially, like the New closures.
func NewBatch(name string, key []byte) (batch func(dst, in *[4][]byte), blockSize int, ok bool, err error) {
	s, exists := specs[name]
	if !exists {
		return nil, 0, false, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	if len(key) != s.keySize {
		return nil, 0, false, fmt.Errorf("hashprf: %s key must be %d bytes, got %d", name, s.keySize, len(key))
	}
	switch name {
	case hashes.CipherAreion256:
		if b := newAreion256BatchPRF(key); b != nil {
			return b, s.blockSize, true, nil
		}
		// Host lacks a VAES / AVX-512 (or ARM AES-batched) asm path:
		// hashes.Areion256PairWithKey returns a nil batched arm and
		// nothing here to wrap. Report ok=false so callers fall
		// through to the single-block PRF path; the ctr keystream's
		// prfHashCTR variant is bit-exact with the batched keystream.
		return nil, 0, false, nil
	case hashes.CipherAreion512:
		if b := newAreion512BatchPRF(key); b != nil {
			return b, s.blockSize, true, nil
		}
		return nil, 0, false, nil
	default:
		return nil, 0, false, nil
	}
}

// newAreion256BatchPRF builds a keyed Areion-SoEM-256 BatchHashFunc256 and
// returns a 4-wide PRF: it hashes four inputs in one SIMD batch, every lane
// under the key-derived seed of areionSeed256 (the seed of the single-input
// PRF, so the two paths are bit-exact), and serialises each four-word result
// little-endian into 32 bytes.
//
// Returns nil on hosts where hashes.Areion256PairWithKey reports no batched
// arm (non-VAES x86 / non-ARM-AES arm64 / -tags noitbasm builds). Callers
// (NewBatch) treat nil as "no batch path" and route to the single-block PRF.
func newAreion256BatchPRF(key []byte) func(dst, in *[4][]byte) {
	var k [32]byte
	copy(k[:], key)
	_, bhf := hashes.Areion256PairWithKey(k)
	if bhf == nil {
		return nil
	}
	var seeds [4][4]uint64
	s := areionSeed256(key)
	for lane := range seeds {
		seeds[lane] = s
	}
	return func(dst, in *[4][]byte) {
		out := bhf(in, seeds)
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 4; i++ {
				binary.LittleEndian.PutUint64(dst[lane][i*8:], out[lane][i])
			}
		}
	}
}

// newAreion512BatchPRF is the Areion-SoEM-512 counterpart: four inputs per
// SIMD batch, every lane under the key-derived seed of areionSeed512, each
// eight-word result serialised into 64 bytes. Returns nil
// on hosts without a batched arm, per the SoEM-256 rationale above.
func newAreion512BatchPRF(key []byte) func(dst, in *[4][]byte) {
	var k [64]byte
	copy(k[:], key)
	_, bhf := hashes.Areion512PairWithKey(k)
	if bhf == nil {
		return nil
	}
	var seeds [4][8]uint64
	s := areionSeed512(key)
	for lane := range seeds {
		seeds[lane] = s
	}
	return func(dst, in *[4][]byte) {
		out := bhf(in, seeds)
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 8; i++ {
				binary.LittleEndian.PutUint64(dst[lane][i*8:], out[lane][i])
			}
		}
	}
}
