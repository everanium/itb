package hashes

import "github.com/everanium/itb"

// newseed.go — name-keyed seed constructors, the constructor path of
// every shipped seed: the triple package's seed builders and the C ABI
// seed constructors call them. Each builds a seed of the named registry
// primitive with every performance hook the primitive offers: the
// (single, batched) arms from the width's Make<W>Pair, keyBits random
// components from the itb constructor, then the fused ChainHash cascade
// hooks and the Interlocked Barrier fill hooks from the width's attach
// steps. The
// hooks are performance paths only — a seed built on the arms alone
// through itb.NewSeed<W> produces and decrypts the same wire — so
// itb.NewSeed<W> remains the constructor for callers who supply their
// own HashFunc<W> outside the registry.

// NewSeed128 builds a width-128 seed of the named primitive with
// keyBits bits of random components and every hook the primitive
// offers. The returned key is the fixed key the arms were built with:
// generated through crypto/rand when key is omitted, the supplied key
// otherwise, nil for primitives keyed by their seed components alone
// (siphash24). Save it beside the seed's Components for a cross-process
// restore through [SeedFromComponents128].
//
// Errors: an unknown name, a name of another width, a key the primitive
// rejects, or keyBits the itb constructor rejects.
func NewSeed128(name string, keyBits int, key ...[]byte) (*itb.Seed128, []byte, error) {
	single, batched, fixedKey, err := Make128Pair(name, key...)
	if err != nil {
		return nil, nil, err
	}
	s, err := itb.NewSeed128(keyBits, single)
	if err != nil {
		return nil, nil, err
	}
	s.BatchHash = batched
	if err := attachFused128(s, name, fixedKey); err != nil {
		return nil, nil, err
	}
	if err := attachInterlockBatch16(s, name, fixedKey); err != nil {
		return nil, nil, err
	}
	return s, fixedKey, nil
}

// NewSeed256 is the width-256 form of [NewSeed128]: the arms of
// [Make256Pair], the fused cascade, batch-16 and batch-32 hooks of the
// entry, the fixed key of the arms as the second return value.
func NewSeed256(name string, keyBits int, key ...[]byte) (*itb.Seed256, []byte, error) {
	single, batched, fixedKey, err := Make256Pair(name, key...)
	if err != nil {
		return nil, nil, err
	}
	s, err := itb.NewSeed256(keyBits, single)
	if err != nil {
		return nil, nil, err
	}
	s.BatchHash = batched
	if err := attachFused256(s, name, fixedKey); err != nil {
		return nil, nil, err
	}
	if err := attachInterlockBatch16x256(s, name, fixedKey); err != nil {
		return nil, nil, err
	}
	if err := attachInterlockBatch32x256(s, name, fixedKey); err != nil {
		return nil, nil, err
	}
	return s, fixedKey, nil
}

// NewSeed512 is the width-512 form of [NewSeed128]: the arms of
// [Make512Pair], the fused cascade, batch-16 and batch-32 hooks of the
// entry, the fixed key of the arms as the second return value.
func NewSeed512(name string, keyBits int, key ...[]byte) (*itb.Seed512, []byte, error) {
	single, batched, fixedKey, err := Make512Pair(name, key...)
	if err != nil {
		return nil, nil, err
	}
	s, err := itb.NewSeed512(keyBits, single)
	if err != nil {
		return nil, nil, err
	}
	s.BatchHash = batched
	if err := attachFused512(s, name, fixedKey); err != nil {
		return nil, nil, err
	}
	if err := attachInterlockBatch16x512(s, name, fixedKey); err != nil {
		return nil, nil, err
	}
	if err := attachInterlockBatch32x512(s, name, fixedKey); err != nil {
		return nil, nil, err
	}
	return s, fixedKey, nil
}

// SeedFromComponents128 rebuilds a width-128 seed of the named primitive
// from saved components with every hook the primitive offers — the
// restore counterpart of [NewSeed128]: key is the fixed key NewSeed128
// returned (nil for a primitive keyed by its seed components alone), and
// components are the seed's Components. The arms of [Make128Pair] are
// rebuilt under that key, [itb.SeedFromComponents128] installs the
// components, and the entry's factories attach the hooks. A seed
// restored this way is indistinguishable on the wire from
// one restored through [itb.SeedFromComponents128] on the arms alone.
func SeedFromComponents128(name string, key []byte, components ...uint64) (*itb.Seed128, error) {
	var keyArg [][]byte
	if len(key) > 0 {
		keyArg = [][]byte{key}
	}
	single, batched, fixedKey, err := Make128Pair(name, keyArg...)
	if err != nil {
		return nil, err
	}
	s, err := itb.SeedFromComponents128(single, components...)
	if err != nil {
		return nil, err
	}
	s.BatchHash = batched
	if err := attachFused128(s, name, fixedKey); err != nil {
		return nil, err
	}
	if err := attachInterlockBatch16(s, name, fixedKey); err != nil {
		return nil, err
	}
	return s, nil
}

// SeedFromComponents256 is the width-256 form of [SeedFromComponents128].
func SeedFromComponents256(name string, key []byte, components ...uint64) (*itb.Seed256, error) {
	var keyArg [][]byte
	if len(key) > 0 {
		keyArg = [][]byte{key}
	}
	single, batched, fixedKey, err := Make256Pair(name, keyArg...)
	if err != nil {
		return nil, err
	}
	s, err := itb.SeedFromComponents256(single, components...)
	if err != nil {
		return nil, err
	}
	s.BatchHash = batched
	if err := attachFused256(s, name, fixedKey); err != nil {
		return nil, err
	}
	if err := attachInterlockBatch16x256(s, name, fixedKey); err != nil {
		return nil, err
	}
	if err := attachInterlockBatch32x256(s, name, fixedKey); err != nil {
		return nil, err
	}
	return s, nil
}

// SeedFromComponents512 is the width-512 form of [SeedFromComponents128].
func SeedFromComponents512(name string, key []byte, components ...uint64) (*itb.Seed512, error) {
	var keyArg [][]byte
	if len(key) > 0 {
		keyArg = [][]byte{key}
	}
	single, batched, fixedKey, err := Make512Pair(name, keyArg...)
	if err != nil {
		return nil, err
	}
	s, err := itb.SeedFromComponents512(single, components...)
	if err != nil {
		return nil, err
	}
	s.BatchHash = batched
	if err := attachFused512(s, name, fixedKey); err != nil {
		return nil, err
	}
	if err := attachInterlockBatch16x512(s, name, fixedKey); err != nil {
		return nil, err
	}
	if err := attachInterlockBatch32x512(s, name, fixedKey); err != nil {
		return nil, err
	}
	return s, nil
}
