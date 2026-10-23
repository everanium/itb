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
	"runtime"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"

	"github.com/zeebo/blake3"

	"github.com/everanium/areion"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/areionasm"
	"github.com/everanium/itb/internal/wipe"
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
	prf, blockSize, _, err = NewWithClose(name, key)
	return prf, blockSize, err
}

// NewWithClose is [New] paired with a closeFn that zeroes all key material,
// derived subkeys, and internal hasher state captured by the returned PRF
// closure, and scrubs the callee stack frame after each evaluation.
func NewWithClose(name string, key []byte) (prf func(dst, in []byte), blockSize int, closeFn func(), err error) {
	raw, bs, c, err := newPRFWithClose(name, key, true)
	if err != nil {
		return nil, 0, nil, err
	}
	wrapped := func(dst, in []byte) {
		raw(dst, in)
		wipe.CallStack512B()
	}
	return wrapped, bs, c, nil
}

// NewRawWithClose is [NewWithClose] without a per-block stack wipe inside the
// returned closure, intended for callers (such as ctr's block loop and kdf's
// counter loop) that execute many blocks at a fixed stack depth and scrub the
// callee stack frame once at the end of the loop.
func NewRawWithClose(name string, key []byte) (prf func(dst, in []byte), blockSize int, closeFn func(), err error) {
	return newPRFWithClose(name, key, false)
}

func newPRFWithClose(name string, key []byte, scrubPerCall bool) (prf func(dst, in []byte), blockSize int, closeFn func(), err error) {
	s, ok := specs[name]
	if !ok {
		return nil, 0, nil, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	if len(key) != s.keySize {
		return nil, 0, nil, fmt.Errorf("hashprf: %s key must be %d bytes, got %d", name, s.keySize, len(key))
	}

	switch name {
	case hashes.CipherAreion256:
		p, c := newAreion256PRF(key)
		return p, s.blockSize, c, nil
	case hashes.CipherAreion512:
		p, c := newAreion512PRF(key)
		return p, s.blockSize, c, nil
	case hashes.CipherBLAKE2b256:
		p, c := newBlake2bPRF(key, 32, scrubPerCall)
		return p, s.blockSize, c, nil
	case hashes.CipherBLAKE2b512:
		p, c := newBlake2bPRF(key, 64, scrubPerCall)
		return p, s.blockSize, c, nil
	case hashes.CipherBLAKE2s:
		p, c := newBlake2sPRF(key, scrubPerCall)
		return p, s.blockSize, c, nil
	case hashes.CipherBLAKE3:
		p, c := newBlake3PRF(key, scrubPerCall)
		return p, s.blockSize, c, nil
	default:
		// Unreachable: specs and the switch are kept in lock-step.
		return nil, 0, nil, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
}

// Domain-separation labels of the Areion second-subkey derivation. Each
// width has its own label, so the two derivations never share an input.
const (
	areion256SubkeyLabel = "itb hashprf areion256 subkey"
	areion512SubkeyLabel = "itb hashprf areion512 subkey"
)

// areionSeed256 derives the secret second SoEM subkey of the areion256 PRF
// from its 32-byte key into out: seed = SHA-512(areion256SubkeyLabel || key)[:32],
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
func areionSeed256(key []byte, out *[4]uint64) {
	h := sha512.New()
	h.Write([]byte(areion256SubkeyLabel))
	h.Write(key)
	var sum [sha512.Size]byte
	h.Sum(sum[:0])
	wipe.StructPtr(h)
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(sum[i*8:])
	}
	// sum is the derived subkey; zero the stack copy and scrub the SHA-512 frame.
	clear(sum[:])
	runtime.KeepAlive(&sum)
	wipe.CallStack2K([9][8]uint64{})
}

// areionSeed512 is the areion512 counterpart of areionSeed256:
// seed = SHA-512(areion512SubkeyLabel || key), all 64 bytes, read as eight
// little-endian uint64 words into out, under the same security statement at
// n = 512.
func areionSeed512(key []byte, out *[8]uint64) {
	h := sha512.New()
	h.Write([]byte(areion512SubkeyLabel))
	h.Write(key)
	var sum [sha512.Size]byte
	h.Sum(sum[:0])
	wipe.StructPtr(h)
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(sum[i*8:])
	}
	// sum is the derived subkey; zero the stack copy and scrub the SHA-512 frame.
	clear(sum[:])
	runtime.KeepAlive(&sum)
	wipe.CallStack2K([9][8]uint64{})
}

func absorbXOR(dst, src []byte) {
	n := len(dst)
	i := 0
	for ; i+8 <= n; i += 8 {
		d := binary.LittleEndian.Uint64(dst[i:])
		s := binary.LittleEndian.Uint64(src[i:])
		binary.LittleEndian.PutUint64(dst[i:], d^s)
	}
	for ; i < n; i++ {
		dst[i] ^= src[i]
	}
}

//go:noinline
func evalAreion256PRF(dst, in []byte, fullKey *[64]byte) {
	const chunkSize = 24
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(in)))
	if len(in) <= chunkSize {
		copy(state[8:8+len(in)], in)
		state = areion.SoEM256(fullKey, &state)
	} else {
		copy(state[8:8+chunkSize], in[0:chunkSize])
		state = areion.SoEM256(fullKey, &state)
		off := chunkSize
		for off < len(in) {
			end := off + chunkSize
			if end > len(in) {
				end = len(in)
			}
			absorbXOR(state[8:8+(end-off)], in[off:end])
			state = areion.SoEM256(fullKey, &state)
			off = end
		}
	}
	copy(dst[:32], state[:])
	clear(state[:])
	runtime.KeepAlive(&state)
}

// newAreion256PRF builds a keyed Areion-SoEM-256 PRF that hashes the input
// under fixedKey || areionSeed256(key) and writes the 32-byte result into dst.
// Owning the 64-byte fullKey directly in the closure environment lets closeFn
// zero both subkeys in place without leaving an unreachable copy in a nested
// HashFunc256 closure.
func newAreion256PRF(key []byte) (func(dst, in []byte), func()) {
	var fullKey [64]byte
	copy(fullKey[:32], key)
	var seed [4]uint64
	areionSeed256(key, &seed)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(fullKey[32+i*8:], seed[i])
	}
	clear(seed[:])
	runtime.KeepAlive(&seed)
	wipe.CallStack2K([9][8]uint64{})

	prf := func(dst, in []byte) {
		evalAreion256PRF(dst, in, &fullKey)
	}
	closeFn := func() {
		clear(fullKey[:])
		runtime.KeepAlive(&fullKey)
	}
	return prf, closeFn
}

//go:noinline
func evalAreion512PRF(dst, in []byte, fullKey *[128]byte) {
	const chunkSize = 56
	var state [64]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(in)))
	if len(in) <= chunkSize {
		copy(state[8:8+len(in)], in)
		state = areion.SoEM512(fullKey, &state)
	} else {
		copy(state[8:8+chunkSize], in[0:chunkSize])
		state = areion.SoEM512(fullKey, &state)
		off := chunkSize
		for off < len(in) {
			end := off + chunkSize
			if end > len(in) {
				end = len(in)
			}
			absorbXOR(state[8:8+(end-off)], in[off:end])
			state = areion.SoEM512(fullKey, &state)
			off = end
		}
	}
	copy(dst[:64], state[:])
	clear(state[:])
	runtime.KeepAlive(&state)
}

// newAreion512PRF builds a keyed Areion-SoEM-512 PRF that hashes the input
// under fixedKey || areionSeed512(key) and writes the 64-byte result into dst.
func newAreion512PRF(key []byte) (func(dst, in []byte), func()) {
	var fullKey [128]byte
	copy(fullKey[:64], key)
	var seed [8]uint64
	areionSeed512(key, &seed)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(fullKey[64+i*8:], seed[i])
	}
	clear(seed[:])
	runtime.KeepAlive(&seed)
	wipe.CallStack2K([9][8]uint64{})

	prf := func(dst, in []byte) {
		evalAreion512PRF(dst, in, &fullKey)
	}
	closeFn := func() {
		clear(fullKey[:])
		runtime.KeepAlive(&fullKey)
	}
	return prf, closeFn
}

var blake3PRFZeroChunk [1024]byte

//go:noinline
func evalBlakePRF(dst, in []byte, h hash.Hash, scratch []byte, size int, scrubScratch bool) {
	h.Write(in)
	if !scrubScratch && len(dst) >= size {
		h.Sum(dst[:0])
		h.Reset()
		return
	}
	out := h.Sum(scratch[:0])
	for i := 0; i < size && i < len(out); i++ {
		dst[i] = out[i]
	}
	clear(scratch)
	runtime.KeepAlive(scratch)
	h.Reset()
}

// newBlake2bPRF keys a BLAKE2b hasher (output size 32 or 64) and returns
// a PRF that resets and re-hashes the input per call. The keyed hasher is
// created once; each call resets its state, so the hasher is not
// reallocated per call.
func newBlake2bPRF(key []byte, size int, scrubScratch bool) (func(dst, in []byte), func()) {
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
	wipe.CallStack2K([9][8]uint64{})
	var scratch [64]byte
	prf := func(dst, in []byte) {
		evalBlakePRF(dst, in, h, scratch[:], size, scrubScratch)
	}
	closeFn := func() {
		clear(scratch[:])
		runtime.KeepAlive(&scratch)
		wipe.StructPtr(h)
	}
	return prf, closeFn
}

// newBlake2sPRF keys a BLAKE2s-256 hasher and returns a PRF over the
// reset/re-hash cycle.
func newBlake2sPRF(key []byte, scrubScratch bool) (func(dst, in []byte), func()) {
	h, err := blake2s.New256(key)
	if err != nil {
		panic(fmt.Sprintf("hashprf: blake2s keying: %v", err))
	}
	wipe.CallStack2K([9][8]uint64{})
	var scratch [32]byte
	prf := func(dst, in []byte) {
		evalBlakePRF(dst, in, h, scratch[:], 32, scrubScratch)
	}
	closeFn := func() {
		clear(scratch[:])
		runtime.KeepAlive(&scratch)
		wipe.StructPtr(h)
	}
	return prf, closeFn
}

//go:noinline
func evalBlake3PRF(dst, in []byte, h, tmpl *blake3.Hasher, buf *[32]byte, scrubBuf bool) {
	_, _ = h.Write(in)
	if !scrubBuf && len(dst) >= 32 {
		h.Sum(dst[:0])
		h.Reset()
		return
	}
	h.Sum(buf[:0])
	for i := 0; i < 32; i++ {
		dst[i] = buf[i]
	}
	clear(buf[:])
	runtime.KeepAlive(buf)
	if len(in) <= len(blake3PRFZeroChunk) {
		h.Reset()
		if len(in) > 0 {
			_, _ = h.Write(blake3PRFZeroChunk[:len(in)])
			h.Reset()
		}
	} else {
		*h = *tmpl
	}
	runtime.KeepAlive(h)
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
// Restoring *h = *tmpl after each call zeroes all 8 KiB of h.a.buf and
// h.a.stack while preserving the keyed IV.
func newBlake3PRF(key []byte, scrubBuf bool) (func(dst, in []byte), func()) {
	tmpl, err := blake3.NewKeyed(key)
	if err != nil {
		panic(fmt.Sprintf("hashprf: blake3 keying: %v", err))
	}
	h, err := blake3.NewKeyed(key)
	if err != nil {
		panic(fmt.Sprintf("hashprf: blake3 keying: %v", err))
	}
	wipe.CallStack2K([9][8]uint64{})
	var buf [32]byte
	prf := func(dst, in []byte) {
		evalBlake3PRF(dst, in, h, tmpl, &buf, scrubBuf)
	}
	closeFn := func() {
		clear(buf[:])
		runtime.KeepAlive(&buf)
		wipe.StructPtr(h)
		wipe.StructPtr(tmpl)
	}
	return prf, closeFn
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
	batch, blockSize, ok, _, err = NewBatchWithClose(name, key)
	return batch, blockSize, ok, err
}

// NewBatchWithClose is [NewBatch] paired with a closeFn that zeroes all
// captured subkeys in the batched PRF closure, and scrubs the callee stack
// frame after each batch evaluation.
func NewBatchWithClose(name string, key []byte) (batch func(dst, in *[4][]byte), blockSize int, ok bool, closeFn func(), err error) {
	raw, bs, ok, c, err := NewBatchRawWithClose(name, key)
	if err != nil || !ok {
		return nil, bs, ok, c, err
	}
	wrapped := func(dst, in *[4][]byte) {
		raw(dst, in)
		wipe.CallStack2K([9][8]uint64{})
	}
	return wrapped, bs, true, c, nil
}

// NewBatchRawWithClose is [NewBatchWithClose] without a per-batch stack wipe
// inside the returned closure, intended for callers (such as ctr's batched
// keystream loop) that execute many refills at a fixed stack depth and scrub
// the callee stack frame once at the end of the loop.
func NewBatchRawWithClose(name string, key []byte) (batch func(dst, in *[4][]byte), blockSize int, ok bool, closeFn func(), err error) {
	s, exists := specs[name]
	if !exists {
		return nil, 0, false, nil, fmt.Errorf("hashprf: unknown primitive %q", name)
	}
	if len(key) != s.keySize {
		return nil, 0, false, nil, fmt.Errorf("hashprf: %s key must be %d bytes, got %d", name, s.keySize, len(key))
	}
	switch name {
	case hashes.CipherAreion256:
		b, c := newAreion256BatchPRF(key)
		if b != nil {
			return b, s.blockSize, true, c, nil
		}
		return nil, 0, false, nil, nil
	case hashes.CipherAreion512:
		b, c := newAreion512BatchPRF(key)
		if b != nil {
			return b, s.blockSize, true, c, nil
		}
		return nil, 0, false, nil, nil
	default:
		return nil, 0, false, nil, nil
	}
}

//go:noinline
func evalAreion256BatchPRF(dst, in *[4][]byte, fixedKey *[32]byte, seeds *[4][4]uint64, fullKeys *[4][64]byte) {
	const chunkSize = 24
	commonLen := len(in[0])
	for lane := 1; lane < 4; lane++ {
		if len(in[lane]) != commonLen {
			panic("areion: batched arm requires equal lane lengths (ITB contract)")
		}
	}
	if areionasm.FusedAvailable() {
		var out [4][4]uint64
		fused := true
		switch commonLen {
		case 13:
			for lane := range out {
				areionasm.Fused256Chain13x1(fixedKey, seeds[lane][:], &in[lane][0], &out[lane])
			}
		case 20:
			for lane := range out {
				areionasm.Fused256Chain20x1(fixedKey, seeds[lane][:], &in[lane][0], &out[lane])
			}
		case 36:
			for lane := range out {
				areionasm.Fused256Chain36x1(fixedKey, seeds[lane][:], &in[lane][0], &out[lane])
			}
		case 68:
			for lane := range out {
				areionasm.Fused256Chain68x1(fixedKey, seeds[lane][:], &in[lane][0], &out[lane])
			}
		default:
			fused = false
		}
		if fused {
			for lane := 0; lane < 4; lane++ {
				for i := 0; i < 4; i++ {
					binary.LittleEndian.PutUint64(dst[lane][i*8:], out[lane][i])
				}
			}
			clear(out[:])
			runtime.KeepAlive(&out)
			return
		}
	}

	var states [4][32]byte
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(states[lane][:8], uint64(commonLen))
	}
	if commonLen <= chunkSize {
		for lane := 0; lane < 4; lane++ {
			copy(states[lane][8:8+commonLen], in[lane])
		}
		states = itb.AreionSoEM256x4(fullKeys, &states)
	} else {
		for lane := 0; lane < 4; lane++ {
			copy(states[lane][8:8+chunkSize], in[lane][0:chunkSize])
		}
		states = itb.AreionSoEM256x4(fullKeys, &states)
		off := chunkSize
		for off < commonLen {
			end := off + chunkSize
			if end > commonLen {
				end = commonLen
			}
			for lane := 0; lane < 4; lane++ {
				absorbXOR(states[lane][8:8+(end-off)], in[lane][off:end])
			}
			states = itb.AreionSoEM256x4(fullKeys, &states)
			off = end
		}
	}
	for lane := 0; lane < 4; lane++ {
		copy(dst[lane][:32], states[lane][:])
	}
	clear(states[:])
	runtime.KeepAlive(&states)
}

// newAreion256BatchPRF builds a 4-wide Areion-SoEM-256 PRF that hashes four
// equal-length inputs per call under fixedKey || areionSeed256(key) and
// writes each 32-byte result into dst[lane]. Owning fixedKey, seeds, and
// fullKeys directly in the closure environment lets closeFn zero all key
// material in place.
func newAreion256BatchPRF(key []byte) (func(dst, in *[4][]byte), func()) {
	var fixedKey [32]byte
	copy(fixedKey[:], key)
	var seeds [4][4]uint64
	var fullKeys [4][64]byte
	var s [4]uint64
	areionSeed256(key, &s)
	for lane := 0; lane < 4; lane++ {
		seeds[lane] = s
		copy(fullKeys[lane][:32], fixedKey[:])
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(fullKeys[lane][32+i*8:], s[i])
		}
	}
	clear(s[:])
	runtime.KeepAlive(&s)
	wipe.CallStack2K([9][8]uint64{})

	batch := func(dst, in *[4][]byte) {
		evalAreion256BatchPRF(dst, in, &fixedKey, &seeds, &fullKeys)
	}
	closeFn := func() {
		clear(fixedKey[:])
		clear(seeds[:])
		clear(fullKeys[:])
		runtime.KeepAlive(&fixedKey)
		runtime.KeepAlive(&seeds)
		runtime.KeepAlive(&fullKeys)
	}
	return batch, closeFn
}

//go:noinline
func evalAreion512BatchPRF(dst, in *[4][]byte, fixedKey *[64]byte, seeds *[4][8]uint64, fullKeys *[4][128]byte) {
	const chunkSize = 56
	commonLen := len(in[0])
	for lane := 1; lane < 4; lane++ {
		if len(in[lane]) != commonLen {
			panic("areion: batched arm requires equal lane lengths (ITB contract)")
		}
	}
	if areionasm.FusedAvailable() {
		var out [4][8]uint64
		fused := true
		switch commonLen {
		case 13:
			for lane := range out {
				areionasm.Fused512Chain13x1(fixedKey, seeds[lane][:], &in[lane][0], &out[lane])
			}
		case 20:
			for lane := range out {
				areionasm.Fused512Chain20x1(fixedKey, seeds[lane][:], &in[lane][0], &out[lane])
			}
		case 36:
			for lane := range out {
				areionasm.Fused512Chain36x1(fixedKey, seeds[lane][:], &in[lane][0], &out[lane])
			}
		case 68:
			for lane := range out {
				areionasm.Fused512Chain68x1(fixedKey, seeds[lane][:], &in[lane][0], &out[lane])
			}
		default:
			fused = false
		}
		if fused {
			for lane := 0; lane < 4; lane++ {
				for i := 0; i < 8; i++ {
					binary.LittleEndian.PutUint64(dst[lane][i*8:], out[lane][i])
				}
			}
			clear(out[:])
			runtime.KeepAlive(&out)
			return
		}
	}

	var states [4][64]byte
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(states[lane][:8], uint64(commonLen))
	}
	if commonLen <= chunkSize {
		for lane := 0; lane < 4; lane++ {
			copy(states[lane][8:8+commonLen], in[lane])
		}
		states = itb.AreionSoEM512x4(fullKeys, &states)
	} else {
		for lane := 0; lane < 4; lane++ {
			copy(states[lane][8:8+chunkSize], in[lane][0:chunkSize])
		}
		states = itb.AreionSoEM512x4(fullKeys, &states)
		off := chunkSize
		for off < commonLen {
			end := off + chunkSize
			if end > commonLen {
				end = commonLen
			}
			for lane := 0; lane < 4; lane++ {
				absorbXOR(states[lane][8:8+(end-off)], in[lane][off:end])
			}
			states = itb.AreionSoEM512x4(fullKeys, &states)
			off = end
		}
	}
	for lane := 0; lane < 4; lane++ {
		copy(dst[lane][:64], states[lane][:])
	}
	clear(states[:])
	runtime.KeepAlive(&states)
}

// newAreion512BatchPRF is the Areion-SoEM-512 counterpart: four inputs per
// SIMD batch, every lane under the key-derived seed of areionSeed512, each
// 64-byte result written into dst[lane].
func newAreion512BatchPRF(key []byte) (func(dst, in *[4][]byte), func()) {
	var fixedKey [64]byte
	copy(fixedKey[:], key)
	var seeds [4][8]uint64
	var fullKeys [4][128]byte
	var s [8]uint64
	areionSeed512(key, &s)
	for lane := 0; lane < 4; lane++ {
		seeds[lane] = s
		copy(fullKeys[lane][:64], fixedKey[:])
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(fullKeys[lane][64+i*8:], s[i])
		}
	}
	clear(s[:])
	runtime.KeepAlive(&s)
	wipe.CallStack2K([9][8]uint64{})

	batch := func(dst, in *[4][]byte) {
		evalAreion512BatchPRF(dst, in, &fixedKey, &seeds, &fullKeys)
	}
	closeFn := func() {
		clear(fixedKey[:])
		clear(seeds[:])
		clear(fullKeys[:])
		runtime.KeepAlive(&fixedKey)
		runtime.KeepAlive(&seeds)
		runtime.KeepAlive(&fullKeys)
	}
	return batch, closeFn
}
