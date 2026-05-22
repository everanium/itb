package hashes

import (
	"crypto/cipher"
	"encoding/binary"
	"sync"

	"github.com/everanium/itb"
)

// newScratchPool returns a sync.Pool of reusable byte buffers, each
// initialized to size bytes. Buffers are boxed as *[]byte so that
// Get / Put move a pointer rather than re-boxing a []byte header into
// an interface on every call (storing []byte directly in a sync.Pool
// allocates the interface box per Put). Each builder closure owns its
// own pool, so the buffer size matches that closure's fixed state /
// scratch width and there is no cross-instance contention beyond the
// per-P sharding sync.Pool already provides.
func newScratchPool(size int) *sync.Pool {
	return &sync.Pool{New: func() any {
		b := make([]byte, size)
		return &b
	}}
}

// scratchAtLeast borrows a buffer from pool and guarantees its capacity
// is at least need bytes, growing (and replacing the pooled buffer) only
// when the current one is too small. For ITB's fixed nonce widths the
// initial pool size covers every call, so the grow path is taken at most
// once per pool. Returns the boxed pointer (to Put back) and a slice of
// exactly need bytes.
func scratchAtLeast(pool *sync.Pool, need int) (*[]byte, []byte) {
	bp := pool.Get().(*[]byte)
	if cap(*bp) < need {
		nb := make([]byte, need)
		*bp = nb
	}
	return bp, (*bp)[:need]
}

// builders.go — safe pluggable PRF construction helpers for user primitives.
//
// The eight built-in primitives in this package (areion256, areion512,
// blake2b256, blake2b512, blake2s, blake3, aescmac, siphash24, chacha20)
// each implement chain-absorb or native variable-length absorb directly in
// their closure body, with primitive-specific stack-allocated state arrays,
// inlined permutation calls, and unsafe.Pointer escape-analysis tricks for
// hot-path performance.
//
// The helpers in this file expose three generic patterns —
// BuildCBCMACChainAbsorb, BuildSpongeChainAbsorb, BuildARXChainAbsorb —
// that wrap a user-supplied primitive (cipher.Block, unkeyed permutation,
// or full hash function) into an itb.HashFunc{128,256,512} closure with
// correct ITB-nonce-width preservation across all SetNonceBits
// configurations.
//
// THESE BUILDERS ARE FOR USER-SUPPLIED PRIMITIVES, NOT REPLACEMENTS FOR
// THE BUILT-IN CLOSURES. The built-in closures stay primitive-specific
// for performance — they use stack-allocated fixed-size state arrays
// (e.g. `var state [32]byte`), inlined permutation calls, and fast paths
// for common ITB input lengths {20, 36, 68}. A generic builder taking
// `cipher.Block` / `Permute` callbacks goes through interface dispatch
// and `[]byte` state buffers that escape to heap; benchmarks of generic
// vs inline for the chain-absorb pattern show 5-15% throughput loss.
// The built-in closures remain optimized; these builders are for "user
// brings their own primitive and wants correct nonce-width preservation
// without writing the chain-absorb pattern themselves" use cases.
//
// Why these matter for ITB security
//
// ITB supports nonce widths of 128, 256, or 512 bits via SetNonceBits.
// The per-call buffer presented to a HashFunc closure carries a domain-
// tag byte plus the configured nonce material — 20, 36, or 68 bytes for
// the three nonce widths respectively. Every byte of the data parameter
// must reach the digest for ITB's advertised nonce strength to hold.
//
// A naive user-written wrapper can silently truncate the ITB nonce in
// several ways:
//
//   - Wrapping `crypto/sha256.Sum256(data)` directly into HashFunc512:
//     SHA-256 output is 32 bytes, so the upper 32 bytes of any returned
//     [8]uint64 get zero-padded by naive repacking. ChainHash's per-call
//     XOR-chain in ITB consumes the full 64-byte intermediate state, so
//     a constant upper half across calls destroys half the entropy of
//     the intermediate seed-mix state.
//
//   - Wrapping `aes.NewCipher(key).Encrypt(iv, plaintext)` with the ITB
//     nonce as `iv`: AES IV is 16 bytes regardless of how long the ITB
//     nonce is. SetNonceBits(512) → effective 128-bit nonce. The PRF
//     property still holds at the reduced width, but the advertised
//     property is broken silently.
//
//   - Wrapping `chacha20.NewUnauthenticatedCipher(key, nonce)` with the
//     ITB nonce as `nonce`: ChaCha20 nonce slot is 12 bytes. Same trap.
//
// These builders sidestep all three traps by construction. The user
// supplies the primitive in its natural form (block cipher already
// keyed, unkeyed permutation, or full hash function); the builder
// absorbs the full data parameter via the appropriate chain pattern,
// folding the seed and length-tag through the state to break trailing-
// zero collision class. The resulting closure preserves the full ITB
// nonce width by construction; no caller-side knowledge of the chain-
// absorb pattern is required.
//
// Performance note
//
// The chain-absorb state / scratch buffer escapes to the heap in every
// family because it is passed to an indirect call the escape analyzer
// cannot see through (cipher.Block.Encrypt, Permute, Hash256Fn /
// Hash512Fn). Rather than allocate that buffer per call, each builder
// closure owns a sync.Pool of reusable buffers (newScratchPool /
// scratchAtLeast) sized to its fixed state width; after warm-up the
// per-call allocation count is zero. Built-in primitives instead use
// stack-allocated `var state [N]byte` arrays kept off the heap via
// unsafe.Pointer noescape tricks — marginally faster than a pool Get /
// Put but unsafe, so the generic builders take the pool route. The
// remaining per-call cost is dominated by the underlying primitive.

// ============================================================================
// CBC-MAC Chain-Absorb builders — for caller-keyed block ciphers
// ============================================================================

// BuildCBCMACChainAbsorb128 wraps a keyed block cipher into an
// itb.HashFunc128 closure that absorbs arbitrary-length data via
// CBC-MAC chain. The full ITB nonce reaches the digest with no silent
// truncation: data is absorbed in BlockSize()-byte chunks via XOR
// followed by block.Encrypt; a length tag is folded into the initial
// state to break the trailing-zero collision class.
//
// The block cipher must have BlockSize() >= 16. AES-128 / AES-192 /
// AES-256, Camellia, ARIA, SM4 — all qualify. The cipher's key is
// embedded inside the cipher.Block; the builder does not see the key
// material.
//
// Construction:
//
//   - state := zeros(BlockSize())
//   - state[0:8]  = seed0 ^ len(data)
//   - state[8:16] = seed1 ^ len(data)
//   - state[0:firstChunkLen] ^= data[:firstChunkLen]
//   - state = block.Encrypt(state)
//   - For each subsequent BlockSize()-byte chunk of data:
//   - state[0:chunkLen] ^= data[offset:offset+chunkLen]
//   - state = block.Encrypt(state)
//   - Output: (uint64_le(state[0:8]), uint64_le(state[8:16]))
//
// The closure runs at least one block.Encrypt call (even for empty
// data) so the length-tagged initial state is always permuted before
// output extraction.
func BuildCBCMACChainAbsorb128(block cipher.Block) itb.HashFunc128 {
	bs := block.BlockSize()
	if bs < 16 {
		panic("hashes: BuildCBCMACChainAbsorb128 requires block size >= 16 bytes")
	}
	pool := newScratchPool(bs)
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		bp := pool.Get().(*[]byte)
		lo, hi := cbcMACChainAbsorbOne(block, (*bp)[:bs], data, seed0, seed1, 0x01)
		pool.Put(bp)
		return lo, hi
	}
}

// BuildCBCMACChainAbsorb256 wraps a keyed block cipher into an
// itb.HashFunc256 closure. Internally runs two independent CBC-MAC
// chain-absorb passes over the same data, each domain-separated by a
// distinct constant XOR'd into the initial state, and concatenates the
// 16-byte halves into a 32-byte digest. The construction inherits the
// full nonce absorption property of BuildCBCMACChainAbsorb128 and adds
// a 2x throughput cost.
func BuildCBCMACChainAbsorb256(block cipher.Block) itb.HashFunc256 {
	bs := block.BlockSize()
	if bs < 16 {
		panic("hashes: BuildCBCMACChainAbsorb256 requires block size >= 16 bytes")
	}
	pool := newScratchPool(bs)
	return func(data []byte, seed [4]uint64) [4]uint64 {
		bp := pool.Get().(*[]byte)
		st := (*bp)[:bs]
		lo0, hi0 := cbcMACChainAbsorbOne(block, st, data, seed[0], seed[1], 0x02)
		lo1, hi1 := cbcMACChainAbsorbOne(block, st, data, seed[2], seed[3], 0x03)
		pool.Put(bp)
		return [4]uint64{lo0, hi0, lo1, hi1}
	}
}

// BuildCBCMACChainAbsorb512 wraps a keyed block cipher into an
// itb.HashFunc512 closure. Internally runs four independent CBC-MAC
// chain-absorb passes over the same data, each domain-separated by a
// distinct constant XOR'd into the initial state, and concatenates the
// 16-byte quarters into a 64-byte digest. The construction inherits
// the full nonce absorption property of BuildCBCMACChainAbsorb128 and
// adds a 4x throughput cost.
//
// For 64-byte ITB nonce (SetNonceBits(512)) configurations, this
// closure runs 4 * ceil(68 / BlockSize()) block.Encrypt calls per
// HashFunc512 invocation. For AES-128 (BlockSize=16) this is 20
// Encrypt calls; for a hypothetical 32-byte block cipher 12 Encrypt
// calls.
func BuildCBCMACChainAbsorb512(block cipher.Block) itb.HashFunc512 {
	bs := block.BlockSize()
	if bs < 16 {
		panic("hashes: BuildCBCMACChainAbsorb512 requires block size >= 16 bytes")
	}
	pool := newScratchPool(bs)
	return func(data []byte, seed [8]uint64) [8]uint64 {
		bp := pool.Get().(*[]byte)
		st := (*bp)[:bs]
		lo0, hi0 := cbcMACChainAbsorbOne(block, st, data, seed[0], seed[1], 0x04)
		lo1, hi1 := cbcMACChainAbsorbOne(block, st, data, seed[2], seed[3], 0x05)
		lo2, hi2 := cbcMACChainAbsorbOne(block, st, data, seed[4], seed[5], 0x06)
		lo3, hi3 := cbcMACChainAbsorbOne(block, st, data, seed[6], seed[7], 0x07)
		pool.Put(bp)
		return [8]uint64{lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3}
	}
}

// cbcMACChainAbsorbOne runs one CBC-MAC chain over data and returns
// the first 16 bytes of the final state as a (lo, hi) uint64 pair.
// The domain byte is OR'd into the high byte of the seed0 word in
// the initial state to differentiate parallel chains in the 256/512
// width builders. seed1 is XOR'd with length-tag in the high word.
func cbcMACChainAbsorbOne(block cipher.Block, state []byte, data []byte, seed0, seed1 uint64, domain byte) (uint64, uint64) {
	bs := len(state)
	for i := range state {
		state[i] = 0
	}
	lenTag := uint64(len(data))
	binary.LittleEndian.PutUint64(state[0:], seed0^lenTag^(uint64(domain)<<56))
	binary.LittleEndian.PutUint64(state[8:], seed1^lenTag)

	firstChunkLen := len(data)
	if firstChunkLen > bs {
		firstChunkLen = bs
	}
	for i := 0; i < firstChunkLen; i++ {
		state[i] ^= data[i]
	}
	block.Encrypt(state, state)

	for off := bs; off < len(data); off += bs {
		end := off + bs
		if end > len(data) {
			end = len(data)
		}
		for i := off; i < end; i++ {
			state[i-off] ^= data[i]
		}
		block.Encrypt(state, state)
	}

	return binary.LittleEndian.Uint64(state[0:8]), binary.LittleEndian.Uint64(state[8:16])
}

// ============================================================================
// Sponge Chain-Absorb builders — for unkeyed permutations
// ============================================================================

// Permute is the type for an unkeyed permutation operating on a state
// buffer. The implementation must mutate state in place; state length
// is always rate + capacity bytes. Standard sponge permutations like
// Keccak-f[1600] or Ascon-p match this signature trivially.
type Permute func(state []byte)

// BuildSpongeChainAbsorb128 wraps an unkeyed permutation into a keyed-
// sponge itb.HashFunc128 closure. The permutation is invoked on a
// (rate + capacity)-byte state buffer. The fixedKey is XOR'd into the
// capacity region for keying (standard keyed-sponge pattern). Data is
// absorbed in rate-byte chunks; output is extracted from the first
// 16 bytes of the rate region.
//
// Requirements:
//   - rate >= 16 (so output extraction is direct, no squeeze loop)
//   - capacity >= 16 (so the seed components fit in the capacity slot
//     after fixedKey injection)
//   - len(fixedKey) <= capacity
//
// Construction:
//
//   - state := zeros(rate + capacity)
//   - copy(state[rate:rate+len(fixedKey)], fixedKey)
//   - state[rate:rate+8]   ^= LE(seed0)
//   - state[rate+8:rate+16] ^= LE(seed1)
//   - state[0:8] = LE(len(data) ^ domain)
//   - permute(state)
//   - For each rate-byte chunk of data:
//   - state[0:chunkLen] ^= data[offset:offset+chunkLen]
//   - permute(state)
//   - Output: (uint64_le(state[0:8]), uint64_le(state[8:16]))
//
// The permutation runs at least once (over the initialized state)
// even for empty data, so the length-tagged state is always mixed
// before output.
func BuildSpongeChainAbsorb128(permute Permute, rate, capacity int, fixedKey []byte) itb.HashFunc128 {
	if rate < 16 {
		panic("hashes: BuildSpongeChainAbsorb128 requires rate >= 16 bytes")
	}
	if capacity < 16 {
		panic("hashes: BuildSpongeChainAbsorb128 requires capacity >= 16 bytes")
	}
	if len(fixedKey) > capacity {
		panic("hashes: fixedKey must fit in capacity region")
	}
	pool := newScratchPool(rate + capacity)
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		bp := pool.Get().(*[]byte)
		lo, hi := spongeChainAbsorbOne(permute, (*bp)[:rate+capacity], rate, capacity, fixedKey, data, seed0, seed1, 0x11)
		pool.Put(bp)
		return lo, hi
	}
}

// BuildSpongeChainAbsorb256 wraps an unkeyed permutation into a keyed-
// sponge itb.HashFunc256 closure. Internally runs two domain-separated
// sponge chain-absorb passes and concatenates 16-byte halves. Same
// guarantees as BuildSpongeChainAbsorb128 at 2x cost.
func BuildSpongeChainAbsorb256(permute Permute, rate, capacity int, fixedKey []byte) itb.HashFunc256 {
	if rate < 16 {
		panic("hashes: BuildSpongeChainAbsorb256 requires rate >= 16 bytes")
	}
	if capacity < 16 {
		panic("hashes: BuildSpongeChainAbsorb256 requires capacity >= 16 bytes")
	}
	if len(fixedKey) > capacity {
		panic("hashes: fixedKey must fit in capacity region")
	}
	pool := newScratchPool(rate + capacity)
	return func(data []byte, seed [4]uint64) [4]uint64 {
		bp := pool.Get().(*[]byte)
		st := (*bp)[:rate+capacity]
		lo0, hi0 := spongeChainAbsorbOne(permute, st, rate, capacity, fixedKey, data, seed[0], seed[1], 0x12)
		lo1, hi1 := spongeChainAbsorbOne(permute, st, rate, capacity, fixedKey, data, seed[2], seed[3], 0x13)
		pool.Put(bp)
		return [4]uint64{lo0, hi0, lo1, hi1}
	}
}

// BuildSpongeChainAbsorb512 wraps an unkeyed permutation into a keyed-
// sponge itb.HashFunc512 closure. Internally runs four domain-separated
// sponge chain-absorb passes and concatenates 16-byte quarters. Same
// guarantees as BuildSpongeChainAbsorb128 at 4x cost.
func BuildSpongeChainAbsorb512(permute Permute, rate, capacity int, fixedKey []byte) itb.HashFunc512 {
	if rate < 16 {
		panic("hashes: BuildSpongeChainAbsorb512 requires rate >= 16 bytes")
	}
	if capacity < 16 {
		panic("hashes: BuildSpongeChainAbsorb512 requires capacity >= 16 bytes")
	}
	if len(fixedKey) > capacity {
		panic("hashes: fixedKey must fit in capacity region")
	}
	pool := newScratchPool(rate + capacity)
	return func(data []byte, seed [8]uint64) [8]uint64 {
		bp := pool.Get().(*[]byte)
		st := (*bp)[:rate+capacity]
		lo0, hi0 := spongeChainAbsorbOne(permute, st, rate, capacity, fixedKey, data, seed[0], seed[1], 0x14)
		lo1, hi1 := spongeChainAbsorbOne(permute, st, rate, capacity, fixedKey, data, seed[2], seed[3], 0x15)
		lo2, hi2 := spongeChainAbsorbOne(permute, st, rate, capacity, fixedKey, data, seed[4], seed[5], 0x16)
		lo3, hi3 := spongeChainAbsorbOne(permute, st, rate, capacity, fixedKey, data, seed[6], seed[7], 0x17)
		pool.Put(bp)
		return [8]uint64{lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3}
	}
}

// spongeChainAbsorbOne runs one keyed-sponge chain over data and
// returns the first 16 bytes of the rate region as a (lo, hi) uint64
// pair. fixedKey + seed components occupy the capacity region; the
// length tag and domain byte initialize the rate region's leading
// uint64.
func spongeChainAbsorbOne(permute Permute, state []byte, rate, capacity int, fixedKey []byte, data []byte, seed0, seed1 uint64, domain byte) (uint64, uint64) {
	for i := range state {
		state[i] = 0
	}

	// Capacity region: copy fixedKey, then XOR seed components into
	// the first 16 bytes of the capacity slot. seed material reaches
	// every byte of capacity[0:16] before the first permute call.
	copy(state[rate:], fixedKey)
	if capacity >= 16 {
		for i := 0; i < 8; i++ {
			state[rate+i] ^= byte(seed0 >> (8 * i))
			state[rate+8+i] ^= byte(seed1 >> (8 * i))
		}
	}

	// Rate region: length tag + domain byte for collision-class
	// disambiguation. Length tag occupies the leading uint64; domain
	// byte is folded into the high byte.
	lenTag := uint64(len(data))
	binary.LittleEndian.PutUint64(state[0:], lenTag^(uint64(domain)<<56))

	permute(state)

	// Absorb data in rate-byte chunks via XOR over the rate region.
	for off := 0; off < len(data); off += rate {
		end := off + rate
		if end > len(data) {
			end = len(data)
		}
		for i := off; i < end; i++ {
			state[i-off] ^= data[i]
		}
		permute(state)
	}

	return binary.LittleEndian.Uint64(state[0:8]), binary.LittleEndian.Uint64(state[8:16])
}

// ============================================================================
// ARX / Full-Hash Chain-Absorb builders — for Merkle-Damgard / tree hashes
// ============================================================================

// Hash256Fn represents a full hash function with 32-byte output, such
// as crypto/sha256.Sum256. The function must compute the full hash
// over the input byte slice in one call; it must not retain a
// reference to the input slice after returning.
type Hash256Fn func(data []byte) [32]byte

// Hash512Fn represents a full hash function with 64-byte output, such
// as crypto/sha512.Sum512.
type Hash512Fn func(data []byte) [64]byte

// BuildARXChainAbsorb128 wraps a 32-byte full hash function into an
// itb.HashFunc128 closure. The closure constructs a single absorb
// buffer of the form:
//
//	buf = fixedKey || lenTag(8) || seed0(8) || seed1(8) || domain(1) || data
//
// then computes hashFn(buf) and returns the first 16 bytes of the
// digest as a (lo, hi) uint64 pair. The full ITB nonce is part of the
// data segment and reaches the hash through the underlying hash
// function's native variable-length absorption.
//
// fixedKey is hashed into the prefix as a long-lived keying source;
// seed0/seed1 are the per-call PRF key supplied by ITB's ChainHash.
// Length tag and domain byte protect against length-extension and
// cross-call collision attacks within the construction.
//
// For SHA-256 wrappers this is the canonical safe usage. The hash
// function does its own MD chaining internally, so no chain-absorb
// loop is needed at the builder level — the builder's role is to
// arrange the buffer correctly so all of {fixedKey, seed, length,
// domain, data} reach the digest with no silent truncation.
func BuildARXChainAbsorb128(hashFn Hash256Fn, fixedKey []byte) itb.HashFunc128 {
	if hashFn == nil {
		panic("hashes: BuildARXChainAbsorb128 requires non-nil hashFn")
	}
	prefixLen := len(fixedKey) + 8 + 8 + 8 + 1
	pool := newScratchPool(prefixLen + 256)
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		bp, buf := scratchAtLeast(pool, prefixLen+len(data))
		out := arxAbsorbHash256(hashFn, buf, fixedKey, data, seed0, seed1, 0x21)
		pool.Put(bp)
		return binary.LittleEndian.Uint64(out[0:8]), binary.LittleEndian.Uint64(out[8:16])
	}
}

// BuildARXChainAbsorb256 wraps a 32-byte full hash function into an
// itb.HashFunc256 closure. Same construction as BuildARXChainAbsorb128
// but returns the full 32-byte digest as [4]uint64.
func BuildARXChainAbsorb256(hashFn Hash256Fn, fixedKey []byte) itb.HashFunc256 {
	if hashFn == nil {
		panic("hashes: BuildARXChainAbsorb256 requires non-nil hashFn")
	}
	prefixLen := len(fixedKey) + 8 + 8 + 8 + 1
	pool := newScratchPool(prefixLen + 256)
	return func(data []byte, seed [4]uint64) [4]uint64 {
		bp, buf := scratchAtLeast(pool, prefixLen+len(data))
		out := arxAbsorbHash256(hashFn, buf, fixedKey, data, seed[0], seed[1], 0x22)
		// Second call with different domain + remaining seed components
		// to fill the second half of the 32-byte output. The two halves
		// are independent under the random-oracle / PRF assumption on
		// hashFn. The scratch buffer is fully overwritten on each call,
		// so it is reused across both passes.
		out2 := arxAbsorbHash256(hashFn, buf, fixedKey, data, seed[2], seed[3], 0x23)
		pool.Put(bp)
		return [4]uint64{
			binary.LittleEndian.Uint64(out[0:8]),
			binary.LittleEndian.Uint64(out[8:16]),
			binary.LittleEndian.Uint64(out2[0:8]),
			binary.LittleEndian.Uint64(out2[8:16]),
		}
	}
}

// BuildARXChainAbsorb512 wraps a 64-byte full hash function into an
// itb.HashFunc512 closure. Same construction as BuildARXChainAbsorb128
// but uses a Hash512Fn (e.g. crypto/sha512.Sum512) so the full 64-byte
// digest comes from a single hash call. The fixedKey + seed (4 of 8
// components) + length + domain prefix is built once; the remaining
// 4 seed components are mixed via a second hash call with a different
// domain marker, and the two 32-byte halves are concatenated.
func BuildARXChainAbsorb512(hashFn Hash512Fn, fixedKey []byte) itb.HashFunc512 {
	if hashFn == nil {
		panic("hashes: BuildARXChainAbsorb512 requires non-nil hashFn")
	}
	prefixLen := len(fixedKey) + 8 + 8*8 + 1
	pool := newScratchPool(prefixLen + 256)
	return func(data []byte, seed [8]uint64) [8]uint64 {
		// Single hash call carries all 8 seed components: 4 in the
		// first half via arxAbsorbHash512First, 4 in the second half
		// via the seed-tail injection inside the prefix. Single hashFn
		// call returns 64 bytes which we marshal directly.
		bp, buf := scratchAtLeast(pool, prefixLen+len(data))
		out := arxAbsorbHash512(hashFn, buf, fixedKey, data, seed, 0x24)
		pool.Put(bp)
		return [8]uint64{
			binary.LittleEndian.Uint64(out[0:8]),
			binary.LittleEndian.Uint64(out[8:16]),
			binary.LittleEndian.Uint64(out[16:24]),
			binary.LittleEndian.Uint64(out[24:32]),
			binary.LittleEndian.Uint64(out[32:40]),
			binary.LittleEndian.Uint64(out[40:48]),
			binary.LittleEndian.Uint64(out[48:56]),
			binary.LittleEndian.Uint64(out[56:64]),
		}
	}
}

// arxAbsorbHash256 builds the canonical absorb buffer
// (fixedKey || lenTag || seed0 || seed1 || domain || data) and feeds
// it to the supplied 32-byte hash function. Returns the 32-byte digest.
func arxAbsorbHash256(hashFn Hash256Fn, scratch []byte, fixedKey []byte, data []byte, seed0, seed1 uint64, domain byte) [32]byte {
	prefixLen := len(fixedKey) + 8 + 8 + 8 + 1 // key + lenTag + seed0 + seed1 + domain
	buf := scratch[:prefixLen+len(data)]
	off := 0
	copy(buf[off:], fixedKey)
	off += len(fixedKey)
	binary.LittleEndian.PutUint64(buf[off:], uint64(len(data)))
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], seed0)
	off += 8
	binary.LittleEndian.PutUint64(buf[off:], seed1)
	off += 8
	buf[off] = domain
	off++
	copy(buf[off:], data)
	return hashFn(buf)
}

// arxAbsorbHash512 builds the canonical absorb buffer with all 8 seed
// components and feeds it to the supplied 64-byte hash function.
// Returns the 64-byte digest.
func arxAbsorbHash512(hashFn Hash512Fn, scratch []byte, fixedKey []byte, data []byte, seed [8]uint64, domain byte) [64]byte {
	prefixLen := len(fixedKey) + 8 + 8*8 + 1 // key + lenTag + 8 seed words + domain
	buf := scratch[:prefixLen+len(data)]
	off := 0
	copy(buf[off:], fixedKey)
	off += len(fixedKey)
	binary.LittleEndian.PutUint64(buf[off:], uint64(len(data)))
	off += 8
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(buf[off:], seed[i])
		off += 8
	}
	buf[off] = domain
	off++
	copy(buf[off:], data)
	return hashFn(buf)
}
