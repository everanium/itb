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
// The supported primitives — the Areion family and the BLAKE family —
// expose both a single-input PRF via New and a 4-wide batched PRF via
// NewBatch (bit-exact with the single-input PRF), which the ctr keystream
// uses to amortise per-block dispatch.
//
// The package is a shared dependency of the ctr and kdf packages, which
// import it for their keyed-PRF and SP 800-108 counter-mode constructions
// respectively. It imports the BLAKE CTR/PRF packages and the ITB hashes
// package; it does not import ctr or kdf, so no import cycle arises.
package hashprf

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"runtime"

	"github.com/everanium/areion"
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/areionasm"
	"github.com/everanium/itb/internal/blake2bctr"
	"github.com/everanium/itb/internal/blake2sctr"
	"github.com/everanium/itb/internal/blake3ctr"
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
	var in [len(areion256SubkeyLabel) + 32]byte
	copy(in[:len(areion256SubkeyLabel)], areion256SubkeyLabel)
	copy(in[len(areion256SubkeyLabel):], key)
	sum := sha512.Sum512(in[:])
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(sum[i*8:])
	}
	clear(in[:])
	clear(sum[:])
	runtime.KeepAlive(&in)
	runtime.KeepAlive(&sum)
	wipe.CallStack2K([9][8]uint64{})
}

// areionSeed512 is the areion512 counterpart of areionSeed256:
// seed = SHA-512(areion512SubkeyLabel || key), all 64 bytes, read as eight
// little-endian uint64 words into out, under the same security statement at
// n = 512.
func areionSeed512(key []byte, out *[8]uint64) {
	var in [len(areion512SubkeyLabel) + 64]byte
	copy(in[:len(areion512SubkeyLabel)], areion512SubkeyLabel)
	copy(in[len(areion512SubkeyLabel):], key)
	sum := sha512.Sum512(in[:])
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(sum[i*8:])
	}
	clear(in[:])
	clear(sum[:])
	runtime.KeepAlive(&in)
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

// newBlake2bPRF precomputes the RFC 7693 keyed BLAKE2b block-0 chaining
// state (output size 32 or 64) and returns a zero-allocation PRF closure.
func newBlake2bPRF(key []byte, size int, _ bool) (func(dst, in []byte), func()) {
	var hKey [8]uint64
	var keyBlock [4]uint64
	if size == 32 {
		blake2bctr.InitKey256(key, &hKey, &keyBlock)
		wipe.CallStack2K([9][8]uint64{})
		prf := func(dst, in []byte) {
			blake2bctr.Eval256(dst, in, &hKey, &keyBlock)
		}
		closeFn := func() {
			clear(hKey[:])
			clear(keyBlock[:])
			runtime.KeepAlive(&hKey)
			runtime.KeepAlive(&keyBlock)
		}
		return prf, closeFn
	}
	blake2bctr.InitKey512(key, &hKey, &keyBlock)
	wipe.CallStack2K([9][8]uint64{})
	prf := func(dst, in []byte) {
		blake2bctr.Eval512(dst, in, &hKey, &keyBlock)
	}
	closeFn := func() {
		clear(hKey[:])
		clear(keyBlock[:])
		runtime.KeepAlive(&hKey)
		runtime.KeepAlive(&keyBlock)
	}
	return prf, closeFn
}

// newBlake2sPRF precomputes the RFC 7693 keyed BLAKE2s-256 block-0 chaining
// state and returns a zero-allocation PRF closure.
func newBlake2sPRF(key []byte, _ bool) (func(dst, in []byte), func()) {
	var hKey [8]uint32
	var keyWords [8]uint32
	blake2sctr.InitKey(key, &hKey, &keyWords)
	wipe.CallStack2K([9][8]uint64{})
	prf := func(dst, in []byte) {
		blake2sctr.Eval(dst, in, &hKey, &keyWords)
	}
	closeFn := func() {
		clear(hKey[:])
		clear(keyWords[:])
		runtime.KeepAlive(&hKey)
		runtime.KeepAlive(&keyWords)
	}
	return prf, closeFn
}

// newBlake3PRF parses the 32-byte key into key words and returns a keyed
// BLAKE3 PRF closure that evaluates single-block inputs (<= 64 bytes) directly
// without heap allocation.
func newBlake3PRF(key []byte, _ bool) (func(dst, in []byte), func()) {
	var keyWords [8]uint32
	var keyBytes [32]byte
	blake3ctr.InitKey(key, &keyWords)
	copy(keyBytes[:], key)
	wipe.CallStack2K([9][8]uint64{})
	prf := func(dst, in []byte) {
		blake3ctr.Eval(dst, in, &keyWords, &keyBytes)
	}
	closeFn := func() {
		clear(keyWords[:])
		clear(keyBytes[:])
		runtime.KeepAlive(&keyWords)
		runtime.KeepAlive(&keyBytes)
	}
	return prf, closeFn
}

// NewBatch returns a 4-wide batched keyed PRF for the supported primitives,
// together with the per-lane output block size.
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
		wipe.CallStack12K([9][8]uint64{})
		wipe.ClobberRegs()
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
	case hashes.CipherBLAKE2b256:
		b, c := newBlake2b256BatchPRF(key)
		return b, s.blockSize, true, c, nil
	case hashes.CipherBLAKE2b512:
		b, c := newBlake2b512BatchPRF(key)
		return b, s.blockSize, true, c, nil
	case hashes.CipherBLAKE2s:
		b, c := newBlake2sBatchPRF(key)
		return b, s.blockSize, true, c, nil
	case hashes.CipherBLAKE3:
		b, c := newBlake3BatchPRF(key)
		return b, s.blockSize, true, c, nil
	default:
		return nil, 0, false, nil, nil
	}
}

func newBlake2b256BatchPRF(key []byte) (func(dst, in *[4][]byte), func()) {
	var hKey [8]uint64
	var keyBlock [4]uint64
	blake2bctr.InitKey256(key, &hKey, &keyBlock)
	wipe.CallStack2K([9][8]uint64{})
	wipe.ClobberRegs()
	batch := func(dst, in *[4][]byte) {
		blake2bctr.BatchPRF256x4(dst, in, &hKey, &keyBlock)
	}
	closeFn := func() {
		clear(hKey[:])
		clear(keyBlock[:])
		runtime.KeepAlive(&hKey)
		runtime.KeepAlive(&keyBlock)
	}
	return batch, closeFn
}

func newBlake2b512BatchPRF(key []byte) (func(dst, in *[4][]byte), func()) {
	var hKey [8]uint64
	var keyBlock [4]uint64
	blake2bctr.InitKey512(key, &hKey, &keyBlock)
	wipe.CallStack2K([9][8]uint64{})
	wipe.ClobberRegs()
	batch := func(dst, in *[4][]byte) {
		blake2bctr.BatchPRF512x4(dst, in, &hKey, &keyBlock)
	}
	closeFn := func() {
		clear(hKey[:])
		clear(keyBlock[:])
		runtime.KeepAlive(&hKey)
		runtime.KeepAlive(&keyBlock)
	}
	return batch, closeFn
}

func newBlake2sBatchPRF(key []byte) (func(dst, in *[4][]byte), func()) {
	var hKey [8]uint32
	var keyWords [8]uint32
	blake2sctr.InitKey(key, &hKey, &keyWords)
	wipe.CallStack2K([9][8]uint64{})
	wipe.ClobberRegs()
	batch := func(dst, in *[4][]byte) {
		blake2sctr.BatchPRFx4(dst, in, &hKey, &keyWords)
	}
	closeFn := func() {
		clear(hKey[:])
		clear(keyWords[:])
		runtime.KeepAlive(&hKey)
		runtime.KeepAlive(&keyWords)
	}
	return batch, closeFn
}

func newBlake3BatchPRF(key []byte) (func(dst, in *[4][]byte), func()) {
	var keyWords [8]uint32
	var keyBytes [32]byte
	blake3ctr.InitKey(key, &keyWords)
	copy(keyBytes[:], key)
	wipe.CallStack2K([9][8]uint64{})
	wipe.ClobberRegs()
	batch := func(dst, in *[4][]byte) {
		blake3ctr.BatchPRFx4(dst, in, &keyWords, &keyBytes)
	}
	closeFn := func() {
		clear(keyWords[:])
		clear(keyBytes[:])
		runtime.KeepAlive(&keyWords)
		runtime.KeepAlive(&keyBytes)
	}
	return batch, closeFn
}

type areion256SoAKey struct {
	fixedKey   [32]byte
	seed       [4]uint64
	fullKeys   [4][64]byte
	k1b0, k1b1 [8]uint64
	k2b0, k2b1 [8]uint64
	wb0, wb1   [8]uint64
}

type areion512SoAKey struct {
	fixedKey               [64]byte
	seed                   [8]uint64
	fullKeys               [4][128]byte
	k1b0, k1b1, k1b2, k1b3 areion.Block4
	k2b0, k2b1, k2b2, k2b3 areion.Block4
	wb0, wb1, wb2, wb3     [8]uint64
}

func areionSoEMBatchedActive() bool {
	return areionasm.HasVAESAVX512 || areionasm.HasVAESAVX2NoAVX512 || areionasm.HasAVXAESNIBatched || areionasm.HasAESNIBatched || areionasm.HasARMAESBatched
}

func areion256SoEMPermutex4(s1b0, s1b1, s2b0, s2b1 *areion.Block4) {
	switch {
	case areionasm.HasVAESAVX512:
		areionasm.Areion256SoEMPermutex4Interleaved(s1b0, s1b1, s2b0, s2b1)
	case areionasm.HasVAESAVX2NoAVX512:
		areionasm.Areion256SoEMPermutex4VaesAvx2(s1b0, s1b1, s2b0, s2b1)
	case areionasm.HasAVXAESNIBatched:
		areionasm.Areion256SoEMPermutex4Vex(s1b0, s1b1, s2b0, s2b1)
	case areionasm.HasAESNIBatched:
		areionasm.Areion256SoEMPermutex4AesNi(s1b0, s1b1, s2b0, s2b1)
	case areionasm.HasARMAESBatched:
		areionasm.Areion256SoEMPermutex4NEON(s1b0, s1b1, s2b0, s2b1)
	}
}

func areion512SoEMPermutex4(a1, b1, c1, d1, a2, b2, c2, d2 *areion.Block4) {
	switch {
	case areionasm.HasVAESAVX512:
		areionasm.Areion512SoEMPermutex4Interleaved(a1, b1, c1, d1, a2, b2, c2, d2)
	case areionasm.HasVAESAVX2NoAVX512:
		areionasm.Areion512SoEMPermutex4VaesAvx2(a1, b1, c1, d1, a2, b2, c2, d2)
	case areionasm.HasAVXAESNIBatched:
		areionasm.Areion512SoEMPermutex4Vex(a1, b1, c1, d1, a2, b2, c2, d2)
	case areionasm.HasAESNIBatched:
		areionasm.Areion512SoEMPermutex4AesNi(a1, b1, c1, d1, a2, b2, c2, d2)
	case areionasm.HasARMAESBatched:
		areionasm.Areion512SoEMPermutex4NEON(a1, b1, c1, d1, a2, b2, c2, d2)
	}
}

//go:noinline
func evalAreion256BatchPRFSlow(dst, in *[4][]byte, soa *areion256SoAKey, commonLen int) {
	const chunkSize = 24
	if areionasm.FusedAvailable() {
		var out [4][4]uint64
		fused := true
		switch commonLen {
		case 13:
			ptrs := [4]*byte{&in[0][0], &in[1][0], &in[2][0], &in[3][0]}
			areionasm.Fused256Chain13x4(&soa.fixedKey, soa.seed[:], &ptrs, &out)
		case 20:
			ptrs := [4]*byte{&in[0][0], &in[1][0], &in[2][0], &in[3][0]}
			areionasm.Fused256Chain20x4(&soa.fixedKey, soa.seed[:], &ptrs, &out)
		case 36:
			ptrs := [4]*byte{&in[0][0], &in[1][0], &in[2][0], &in[3][0]}
			areionasm.Fused256Chain36x4(&soa.fixedKey, soa.seed[:], &ptrs, &out)
		case 68:
			ptrs := [4]*byte{&in[0][0], &in[1][0], &in[2][0], &in[3][0]}
			areionasm.Fused256Chain68x4(&soa.fixedKey, soa.seed[:], &ptrs, &out)
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
		states = itb.AreionSoEM256x4(&soa.fullKeys, &states)
	} else {
		for lane := 0; lane < 4; lane++ {
			copy(states[lane][8:8+chunkSize], in[lane][0:chunkSize])
		}
		states = itb.AreionSoEM256x4(&soa.fullKeys, &states)
		off := chunkSize
		for off < commonLen {
			end := off + chunkSize
			if end > commonLen {
				end = commonLen
			}
			for lane := 0; lane < 4; lane++ {
				absorbXOR(states[lane][8:8+(end-off)], in[lane][off:end])
			}
			states = itb.AreionSoEM256x4(&soa.fullKeys, &states)
			off = end
		}
	}
	for lane := 0; lane < 4; lane++ {
		copy(dst[lane][:32], states[lane][:])
	}
	clear(states[:])
	runtime.KeepAlive(&states)
}

//go:noinline
func evalAreion256BatchPRF(dst, in *[4][]byte, soa *areion256SoAKey) {
	commonLen := len(in[0])
	for lane := 1; lane < 4; lane++ {
		if len(in[lane]) != commonLen {
			panic("areion: batched arm requires equal lane lengths (ITB contract)")
		}
	}
	if commonLen != 24 || !areionSoEMBatchedActive() {
		evalAreion256BatchPRFSlow(dst, in, soa, commonLen)
		return
	}
	var s1b0, s1b1, s2b0, s2b1 areion.Block4
	for lane := 0; lane < 4; lane++ {
		inp := in[lane]
		m0 := uint64(24)
		m1 := binary.LittleEndian.Uint64(inp[0:8])
		m2 := binary.LittleEndian.Uint64(inp[8:16])
		m3 := binary.LittleEndian.Uint64(inp[16:24])
		w := lane * 2
		o := lane * 16
		binary.LittleEndian.PutUint64(s1b0[o:o+8], m0^soa.k1b0[w])
		binary.LittleEndian.PutUint64(s1b0[o+8:o+16], m1^soa.k1b0[w+1])
		binary.LittleEndian.PutUint64(s1b1[o:o+8], m2^soa.k1b1[w])
		binary.LittleEndian.PutUint64(s1b1[o+8:o+16], m3^soa.k1b1[w+1])
		binary.LittleEndian.PutUint64(s2b0[o:o+8], m0^soa.k2b0[w])
		binary.LittleEndian.PutUint64(s2b0[o+8:o+16], m1^soa.k2b0[w+1])
		binary.LittleEndian.PutUint64(s2b1[o:o+8], m2^soa.k2b1[w])
		binary.LittleEndian.PutUint64(s2b1[o+8:o+16], m3^soa.k2b1[w+1])
	}
	areion256SoEMPermutex4(&s1b0, &s1b1, &s2b0, &s2b1)
	for lane := 0; lane < 4; lane++ {
		d := dst[lane]
		w := lane * 2
		o := lane * 16
		binary.LittleEndian.PutUint64(d[0:8], binary.LittleEndian.Uint64(s1b0[o:o+8])^soa.wb0[w])
		binary.LittleEndian.PutUint64(d[8:16], binary.LittleEndian.Uint64(s1b0[o+8:o+16])^soa.wb0[w+1])
		binary.LittleEndian.PutUint64(d[16:24], binary.LittleEndian.Uint64(s1b1[o:o+8])^soa.wb1[w])
		binary.LittleEndian.PutUint64(d[24:32], binary.LittleEndian.Uint64(s1b1[o+8:o+16])^soa.wb1[w+1])
	}
	clear(s1b0[:])
	clear(s1b1[:])
	clear(s2b0[:])
	clear(s2b1[:])
	runtime.KeepAlive(&s1b0)
	runtime.KeepAlive(&s1b1)
	runtime.KeepAlive(&s2b0)
	runtime.KeepAlive(&s2b1)
}

//go:noinline
func initAreion256SoAKey(soa *areion256SoAKey, key []byte) {
	copy(soa.fixedKey[:], key)
	areionSeed256(key, &soa.seed)
	k1w0 := binary.LittleEndian.Uint64(soa.fixedKey[0:8])
	k1w1 := binary.LittleEndian.Uint64(soa.fixedKey[8:16])
	k1w2 := binary.LittleEndian.Uint64(soa.fixedKey[16:24])
	k1w3 := binary.LittleEndian.Uint64(soa.fixedKey[24:32])
	for lane := 0; lane < 4; lane++ {
		copy(soa.fullKeys[lane][:32], soa.fixedKey[:])
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(soa.fullKeys[lane][32+i*8:], soa.seed[i])
		}
		w := lane * 2
		soa.k1b0[w], soa.k1b0[w+1] = k1w0, k1w1
		soa.k1b1[w], soa.k1b1[w+1] = k1w2, k1w3
		soa.k2b0[w], soa.k2b0[w+1] = soa.seed[0], soa.seed[1]
		soa.k2b1[w], soa.k2b1[w+1] = soa.seed[2], soa.seed[3]
		soa.wb0[w], soa.wb0[w+1] = k1w0^soa.seed[0], k1w1^soa.seed[1]
		soa.wb1[w], soa.wb1[w+1] = k1w2^soa.seed[2], k1w3^soa.seed[3]
	}
	wipe.ClobberRegs()
}

// newAreion256BatchPRF builds a 4-wide Areion-SoEM-256 PRF that hashes four
// equal-length inputs per call under fixedKey || areionSeed256(key) and
// writes each 32-byte result into dst[lane]. Owning fixedKey, seeds, and
// fullKeys directly in the closure environment lets closeFn zero all key
// material in place.
func newAreion256BatchPRF(key []byte) (func(dst, in *[4][]byte), func()) {
	var soa areion256SoAKey
	initAreion256SoAKey(&soa, key)

	batch := func(dst, in *[4][]byte) {
		evalAreion256BatchPRF(dst, in, &soa)
	}
	closeFn := func() {
		soa = areion256SoAKey{}
		runtime.KeepAlive(&soa)
	}
	return batch, closeFn
}

//go:noinline
func evalAreion512BatchPRFSlow(dst, in *[4][]byte, soa *areion512SoAKey, commonLen int) {
	const chunkSize = 56
	if areionasm.FusedAvailable() {
		var out [4][8]uint64
		fused := true
		switch commonLen {
		case 13:
			ptrs := [4]*byte{&in[0][0], &in[1][0], &in[2][0], &in[3][0]}
			areionasm.Fused512Chain13x4(&soa.fixedKey, soa.seed[:], &ptrs, &out)
		case 20:
			ptrs := [4]*byte{&in[0][0], &in[1][0], &in[2][0], &in[3][0]}
			areionasm.Fused512Chain20x4(&soa.fixedKey, soa.seed[:], &ptrs, &out)
		case 36:
			ptrs := [4]*byte{&in[0][0], &in[1][0], &in[2][0], &in[3][0]}
			areionasm.Fused512Chain36x4(&soa.fixedKey, soa.seed[:], &ptrs, &out)
		case 68:
			ptrs := [4]*byte{&in[0][0], &in[1][0], &in[2][0], &in[3][0]}
			areionasm.Fused512Chain68x4(&soa.fixedKey, soa.seed[:], &ptrs, &out)
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
		states = itb.AreionSoEM512x4(&soa.fullKeys, &states)
	} else {
		for lane := 0; lane < 4; lane++ {
			copy(states[lane][8:8+chunkSize], in[lane][0:chunkSize])
		}
		states = itb.AreionSoEM512x4(&soa.fullKeys, &states)
		off := chunkSize
		for off < commonLen {
			end := off + chunkSize
			if end > commonLen {
				end = commonLen
			}
			for lane := 0; lane < 4; lane++ {
				absorbXOR(states[lane][8:8+(end-off)], in[lane][off:end])
			}
			states = itb.AreionSoEM512x4(&soa.fullKeys, &states)
			off = end
		}
	}
	for lane := 0; lane < 4; lane++ {
		copy(dst[lane][:64], states[lane][:])
	}
	clear(states[:])
	runtime.KeepAlive(&states)
}

//go:noinline
func evalAreion512BatchPRF(dst, in *[4][]byte, soa *areion512SoAKey) {
	commonLen := len(in[0])
	for lane := 1; lane < 4; lane++ {
		if len(in[lane]) != commonLen {
			panic("areion: batched arm requires equal lane lengths (ITB contract)")
		}
	}
	if commonLen != 24 || !areionSoEMBatchedActive() {
		evalAreion512BatchPRFSlow(dst, in, soa, commonLen)
		return
	}
	var s1b0, s1b1, s1b2, s1b3, s2b0, s2b1, s2b2, s2b3 areion.Block4
	copy(s1b2[:], soa.k1b2[:])
	copy(s1b3[:], soa.k1b3[:])
	copy(s2b2[:], soa.k2b2[:])
	copy(s2b3[:], soa.k2b3[:])
	for lane := 0; lane < 4; lane++ {
		inp := in[lane]
		m0 := uint64(24)
		m1 := binary.LittleEndian.Uint64(inp[0:8])
		m2 := binary.LittleEndian.Uint64(inp[8:16])
		m3 := binary.LittleEndian.Uint64(inp[16:24])
		o := lane * 16
		binary.LittleEndian.PutUint64(s1b0[o:o+8], m0^binary.LittleEndian.Uint64(soa.k1b0[o:o+8]))
		binary.LittleEndian.PutUint64(s1b0[o+8:o+16], m1^binary.LittleEndian.Uint64(soa.k1b0[o+8:o+16]))
		binary.LittleEndian.PutUint64(s1b1[o:o+8], m2^binary.LittleEndian.Uint64(soa.k1b1[o:o+8]))
		binary.LittleEndian.PutUint64(s1b1[o+8:o+16], m3^binary.LittleEndian.Uint64(soa.k1b1[o+8:o+16]))
		binary.LittleEndian.PutUint64(s2b0[o:o+8], m0^binary.LittleEndian.Uint64(soa.k2b0[o:o+8]))
		binary.LittleEndian.PutUint64(s2b0[o+8:o+16], m1^binary.LittleEndian.Uint64(soa.k2b0[o+8:o+16]))
		binary.LittleEndian.PutUint64(s2b1[o:o+8], m2^binary.LittleEndian.Uint64(soa.k2b1[o:o+8]))
		binary.LittleEndian.PutUint64(s2b1[o+8:o+16], m3^binary.LittleEndian.Uint64(soa.k2b1[o+8:o+16]))
	}
	areion512SoEMPermutex4(&s1b0, &s1b1, &s1b2, &s1b3, &s2b0, &s2b1, &s2b2, &s2b3)
	for lane := 0; lane < 4; lane++ {
		d := dst[lane]
		w := lane * 2
		o := lane * 16
		binary.LittleEndian.PutUint64(d[0:8], binary.LittleEndian.Uint64(s1b0[o:o+8])^soa.wb0[w])
		binary.LittleEndian.PutUint64(d[8:16], binary.LittleEndian.Uint64(s1b0[o+8:o+16])^soa.wb0[w+1])
		binary.LittleEndian.PutUint64(d[16:24], binary.LittleEndian.Uint64(s1b1[o:o+8])^soa.wb1[w])
		binary.LittleEndian.PutUint64(d[24:32], binary.LittleEndian.Uint64(s1b1[o+8:o+16])^soa.wb1[w+1])
		binary.LittleEndian.PutUint64(d[32:40], binary.LittleEndian.Uint64(s1b2[o:o+8])^soa.wb2[w])
		binary.LittleEndian.PutUint64(d[40:48], binary.LittleEndian.Uint64(s1b2[o+8:o+16])^soa.wb2[w+1])
		binary.LittleEndian.PutUint64(d[48:56], binary.LittleEndian.Uint64(s1b3[o:o+8])^soa.wb3[w])
		binary.LittleEndian.PutUint64(d[56:64], binary.LittleEndian.Uint64(s1b3[o+8:o+16])^soa.wb3[w+1])
	}
	clear(s1b0[:])
	clear(s1b1[:])
	clear(s1b2[:])
	clear(s1b3[:])
	clear(s2b0[:])
	clear(s2b1[:])
	clear(s2b2[:])
	clear(s2b3[:])
	runtime.KeepAlive(&s1b0)
	runtime.KeepAlive(&s1b1)
	runtime.KeepAlive(&s1b2)
	runtime.KeepAlive(&s1b3)
	runtime.KeepAlive(&s2b0)
	runtime.KeepAlive(&s2b1)
	runtime.KeepAlive(&s2b2)
	runtime.KeepAlive(&s2b3)
}

//go:noinline
func initAreion512SoAKey(soa *areion512SoAKey, key []byte) {
	copy(soa.fixedKey[:], key)
	areionSeed512(key, &soa.seed)
	for lane := 0; lane < 4; lane++ {
		copy(soa.fullKeys[lane][:64], soa.fixedKey[:])
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(soa.fullKeys[lane][64+i*8:], soa.seed[i])
		}
		o := lane * 16
		copy(soa.k1b0[o:o+16], soa.fixedKey[0:16])
		copy(soa.k1b1[o:o+16], soa.fixedKey[16:32])
		copy(soa.k1b2[o:o+16], soa.fixedKey[32:48])
		copy(soa.k1b3[o:o+16], soa.fixedKey[48:64])
		copy(soa.k2b0[o:o+16], soa.fullKeys[lane][64:80])
		copy(soa.k2b1[o:o+16], soa.fullKeys[lane][80:96])
		copy(soa.k2b2[o:o+16], soa.fullKeys[lane][96:112])
		copy(soa.k2b3[o:o+16], soa.fullKeys[lane][112:128])
		w := lane * 2
		soa.wb0[w] = binary.LittleEndian.Uint64(soa.fixedKey[0:8]) ^ soa.seed[0]
		soa.wb0[w+1] = binary.LittleEndian.Uint64(soa.fixedKey[8:16]) ^ soa.seed[1]
		soa.wb1[w] = binary.LittleEndian.Uint64(soa.fixedKey[16:24]) ^ soa.seed[2]
		soa.wb1[w+1] = binary.LittleEndian.Uint64(soa.fixedKey[24:32]) ^ soa.seed[3]
		soa.wb2[w] = binary.LittleEndian.Uint64(soa.fixedKey[32:40]) ^ soa.seed[4]
		soa.wb2[w+1] = binary.LittleEndian.Uint64(soa.fixedKey[40:48]) ^ soa.seed[5]
		soa.wb3[w] = binary.LittleEndian.Uint64(soa.fixedKey[48:56]) ^ soa.seed[6]
		soa.wb3[w+1] = binary.LittleEndian.Uint64(soa.fixedKey[56:64]) ^ soa.seed[7]
	}
	wipe.ClobberRegs()
}

// newAreion512BatchPRF is the Areion-SoEM-512 counterpart: four inputs per
// SIMD batch, every lane under the key-derived seed of areionSeed512, each
// 64-byte result written into dst[lane].
func newAreion512BatchPRF(key []byte) (func(dst, in *[4][]byte), func()) {
	var soa areion512SoAKey
	initAreion512SoAKey(&soa, key)

	batch := func(dst, in *[4][]byte) {
		evalAreion512BatchPRF(dst, in, &soa)
	}
	closeFn := func() {
		soa = areion512SoAKey{}
		runtime.KeepAlive(&soa)
	}
	return batch, closeFn
}
