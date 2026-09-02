package macs

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"sync"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// HMACSpec parameterises [BuildHMAC]. Only Name is required; zero
// size fields take the documented defaults.
type HMACSpec struct {
	// Name is the MAC name the returned Spec registers under —
	// lowercase letters, digits, underscores, at most [MaxNameLen]
	// bytes (validated at [Register] time).
	Name string

	// KeySize is the recommended key size in bytes; the key length
	// triple session initialisation generates for the primitive.
	// Zero defaults to 32. HMAC accepts keys of arbitrary length
	// (RFC 2104).
	KeySize int

	// TagSize is the tag length in bytes. Zero defaults to the
	// underlying hash's output size; a non-zero value must equal it
	// (no truncation).
	TagSize int

	// MinKeyBytes is the minimum acceptable key length in bytes.
	// Zero defaults to 16 (the [Register] floor).
	MinKeyBytes int
}

// KeyedHashSpec parameterises [BuildKeyedHash]. Only Name is
// required; zero size fields take per-primitive defaults.
type KeyedHashSpec struct {
	// Name is the MAC name the returned Spec registers under —
	// lowercase letters, digits, underscores, at most [MaxNameLen]
	// bytes (validated at [Register] time).
	Name string

	// KeySize is the recommended key size in bytes. Zero defaults to
	// the primitive's native recommendation; primitives with an
	// exact-length key contract (BLAKE3's 32, SipHash-2-4's 16)
	// reject any other value.
	KeySize int

	// TagSize is the tag length in bytes. Zero defaults to the
	// primitive's native output size; a non-zero value must equal it
	// (no truncation).
	TagSize int

	// MinKeyBytes is the minimum acceptable key length in bytes.
	// Zero defaults to the primitive's floor; exact-length key
	// primitives pin it to the key length.
	MinKeyBytes int
}

// keyProbeLengths is the key-length ladder [BuildKeyedHash] walks to
// discover a KeySize default when KeyedHashSpec.KeySize is zero: the
// first length the primitive's keyed constructor accepts becomes the
// default. The ladder covers the shipped keyed-hash geometries; a
// custom primitive whose constructor rejects every ladder length must
// set KeyedHashSpec.KeySize explicitly.
var keyProbeLengths = [...]int{32, 16, 64}

// BuildHMAC returns a [Spec] ready for [Register] that wraps the
// named hash-registry primitive in the HMAC construction (RFC 2104 /
// FIPS 198-1). hashName resolves through [hashes.Find], so shipped
// primitives and user-registered custom primitives added via
// [hashes.Register] qualify uniformly. The resolved [hashes.Spec]
// must carry a non-nil HashHash field — the primitive's
// general-purpose unkeyed hash.Hash form the HMAC envelope wraps;
// when the field is nil (no such form exists — the Areion SoEM
// constructions, AES-CMAC, SipHash-2-4, ChaCha20, and any custom
// primitive registered without it), BuildHMAC returns an error and
// the hand-rolled [Register] path with a caller-written MakeMAC
// factory applies instead.
//
// The produced factories honour every [Register] closure contract by
// construction: both arms share one pre-keyed construction (a
// sync.Pool of pre-keyed hmac.Hash instances, reset to the post-ipad
// state per call), so cross-arm equivalence, determinism, constant
// tag length, parallel-safety, and fresh-slice output all hold, and
// per-call invocation carries no key-derivation overhead.
func BuildHMAC(hashName string, spec HMACSpec) (Spec, error) {
	hspec, ok := hashes.Find(hashName)
	if !ok {
		return Spec{}, fmt.Errorf("macs: BuildHMAC: unknown hash primitive %q", hashName)
	}
	if hspec.HashHash == nil {
		return Spec{}, fmt.Errorf("macs: BuildHMAC: primitive %q has no unkeyed hash.Hash form (populate hashes.Spec.HashHash, or register a hand-rolled Spec via macs.Register)", hashName)
	}
	newHash := hspec.HashHash
	size := newHash().Size()
	out := Spec{
		Name:        spec.Name,
		KeySize:     spec.KeySize,
		TagSize:     spec.TagSize,
		MinKeyBytes: spec.MinKeyBytes,
	}
	if out.KeySize == 0 {
		out.KeySize = 32
	}
	if out.MinKeyBytes == 0 {
		out.MinKeyBytes = 16
	}
	if out.TagSize == 0 {
		out.TagSize = size
	}
	if out.TagSize != size {
		return Spec{}, fmt.Errorf("macs: BuildHMAC: TagSize %d != %s output size %d (truncation unsupported)",
			out.TagSize, hashName, size)
	}
	newKeyed := func(key []byte) (hash.Hash, error) {
		if len(key) == 0 {
			return nil, fmt.Errorf("key must not be empty")
		}
		return hmac.New(newHash, key), nil
	}
	out.MakeMAC, out.MakeIncrementalMAC = pooledFactoryPair(spec.Name, size, newKeyed)
	return out, nil
}

// BuildKeyedHash returns a [Spec] ready for [Register] that uses the
// named primitive's native keyed mode directly as the MAC. hashName
// resolves through [hashes.Find], so shipped primitives and
// user-registered custom primitives added via [hashes.Register]
// qualify uniformly. The resolved [hashes.Spec] must carry a non-nil
// KeyedHash field — the primitive's native keyed hash.Hash mode;
// when the field is nil (no native keyed mode exists, or a custom
// primitive was registered without it), BuildKeyedHash returns an
// error and the hand-rolled [Register] path applies instead. For the
// shipped keyed-form primitives (the BLAKE2 variants, BLAKE3,
// SipHash-2-4) the keyed mode is itself a sound PRF, so the
// double-invocation HMAC envelope is unnecessary; the keyed-mode
// soundness of a custom primitive is the registrant's responsibility.
//
// The primitive's keyed constructor is the single source of truth
// for key geometry. A zero KeySize defaults to the first
// [keyProbeLengths] entry the constructor accepts; a zero
// MinKeyBytes defaults to 16 (the [Register] floor) when the
// constructor accepts a 16-byte key and to KeySize otherwise
// (exact-length key contracts — BLAKE3's 32, SipHash-2-4's 16).
// Explicit KeySize / MinKeyBytes values the constructor rejects fail
// eagerly at build time. TagSize defaults to the primitive's native
// output size; truncation is unsupported.
//
// The produced factories honour every [Register] closure contract by
// construction — same pooled pre-keyed strategy as [BuildHMAC].
func BuildKeyedHash(hashName string, spec KeyedHashSpec) (Spec, error) {
	hspec, ok := hashes.Find(hashName)
	if !ok {
		return Spec{}, fmt.Errorf("macs: BuildKeyedHash: unknown hash primitive %q", hashName)
	}
	if hspec.KeyedHash == nil {
		return Spec{}, fmt.Errorf("macs: BuildKeyedHash: primitive %q has no native keyed-hash form (populate hashes.Spec.KeyedHash, or register a hand-rolled Spec via macs.Register)", hashName)
	}
	newKeyed := hspec.KeyedHash
	out := Spec{
		Name:        spec.Name,
		KeySize:     spec.KeySize,
		TagSize:     spec.TagSize,
		MinKeyBytes: spec.MinKeyBytes,
	}
	if out.KeySize == 0 {
		for _, n := range keyProbeLengths {
			if h, err := newKeyed(make([]byte, n)); err == nil && h != nil {
				out.KeySize = n
				break
			}
		}
		if out.KeySize == 0 {
			return Spec{}, fmt.Errorf("macs: BuildKeyedHash: %s accepts none of the probe key lengths %v; set KeyedHashSpec.KeySize explicitly",
				hashName, keyProbeLengths)
		}
	}
	probe, err := newKeyed(make([]byte, out.KeySize))
	if err != nil {
		return Spec{}, fmt.Errorf("macs: BuildKeyedHash: %s rejects a %d-byte key (KeySize): %w",
			hashName, out.KeySize, err)
	}
	if probe == nil {
		return Spec{}, fmt.Errorf("macs: BuildKeyedHash: %s constructor returned a nil hash.Hash for a %d-byte key",
			hashName, out.KeySize)
	}
	size := probe.Size()
	if out.MinKeyBytes == 0 {
		if _, err := newKeyed(make([]byte, 16)); err == nil {
			out.MinKeyBytes = 16
		} else {
			out.MinKeyBytes = out.KeySize
		}
	} else if out.MinKeyBytes != out.KeySize {
		if _, err := newKeyed(make([]byte, out.MinKeyBytes)); err != nil {
			return Spec{}, fmt.Errorf("macs: BuildKeyedHash: %s rejects a %d-byte key (MinKeyBytes): %w",
				hashName, out.MinKeyBytes, err)
		}
	}
	if out.TagSize == 0 {
		out.TagSize = size
	}
	if out.TagSize != size {
		return Spec{}, fmt.Errorf("macs: BuildKeyedHash: TagSize %d != %s output size %d (truncation unsupported)",
			out.TagSize, hashName, size)
	}
	out.MakeMAC, out.MakeIncrementalMAC = pooledFactoryPair(spec.Name, out.TagSize, newKeyed)
	return out, nil
}

// pooledFactoryPair derives both Spec factory arms from a single
// pre-keyed hash.Hash constructor. Each built closure owns a
// sync.Pool of pre-keyed hasher instances: a call takes one, resets
// it to its keyed initial state, absorbs the input, finalises into a
// fresh tagSize-byte slice, and returns the hasher to the pool — no
// per-call key-derivation cost, parallel-safe by pool discipline.
// Both arms sharing one constructor makes cross-arm equivalence hold
// by construction.
func pooledFactoryPair(name string, tagSize int, newKeyed func(key []byte) (hash.Hash, error)) (
	func(key []byte) (itb.MACFunc, error),
	func(key []byte) (itb.MACIncrementalFunc, error),
) {
	makeMAC := func(key []byte) (itb.MACFunc, error) {
		pool, err := newKeyedPool(name, key, newKeyed)
		if err != nil {
			return nil, err
		}
		return func(data []byte) []byte {
			h := pool.Get().(hash.Hash)
			h.Reset()
			h.Write(data)
			out := h.Sum(make([]byte, 0, tagSize))
			pool.Put(h)
			return out
		}, nil
	}
	makeIncremental := func(key []byte) (itb.MACIncrementalFunc, error) {
		pool, err := newKeyedPool(name, key, newKeyed)
		if err != nil {
			return nil, err
		}
		return func(chunks ...[]byte) []byte {
			h := pool.Get().(hash.Hash)
			h.Reset()
			for _, c := range chunks {
				h.Write(c)
			}
			out := h.Sum(make([]byte, 0, tagSize))
			pool.Put(h)
			return out
		}, nil
	}
	return makeMAC, makeIncremental
}

// newKeyedPool validates the (constructor, key) pairing eagerly by
// building one instance, then returns a sync.Pool seeded with it.
// Construction is deterministic in the key, so pool refills cannot
// fail once the eager build succeeded.
func newKeyedPool(name string, key []byte, newKeyed func(key []byte) (hash.Hash, error)) (*sync.Pool, error) {
	keyCopy := append([]byte(nil), key...)
	first, err := newKeyed(keyCopy)
	if err != nil {
		return nil, fmt.Errorf("macs: %s: %w", name, err)
	}
	pool := &sync.Pool{
		New: func() any {
			h, _ := newKeyed(keyCopy)
			return h
		},
	}
	pool.Put(first)
	return pool, nil
}
