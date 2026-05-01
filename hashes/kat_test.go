// Pair-level Known-Answer Tests (KAT) for every PRF-grade hash
// primitive in the registry. Each primitive's closure construction
// is independently re-executed in this file using only the upstream
// library imports (golang.org/x/crypto/blake2b, blake2s, chacha20;
// github.com/zeebo/blake3; github.com/dchest/siphash;
// github.com/jedisct1/go-aes for Areion-SoEM; crypto/aes for the
// AES round on AES-CMAC) — bypassing the closure's pool, template-
// clone caching, and per-call-amortisation paths. The closure's
// public single arm and the ZMM-batched arm (when present) must
// produce bit-identical output to the in-test reference for a fixed
// matrix of (key, data, seed) tuples.
//
// Compared with the existing kernel-layer parity tests in
// hashes/internal/<primitive>asm/, this file pins the Pair-public-
// API contract: any drift in the buffer construction, the pool
// reuse, the template.Clone() behaviour, the per-call key
// derivation, or the lenTag fold would surface here as a digest
// mismatch even when the underlying primitive itself is intact.
package hashes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	stdaes "github.com/jedisct1/go-aes"
	"github.com/dchest/siphash"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
)

// -----------------------------------------------------------------------------
// Shared test scaffolding.
// -----------------------------------------------------------------------------

// canonicalData synthesises a deterministic per-byte test pattern:
// byte i = byte(i mod 251). The same convention is used by the
// upstream BLAKE3 spec test vectors and gives every length a
// distinct, reproducible buffer.
func canonicalData(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i % 251)
	}
	return buf
}

// canonicalSeed4 returns one of four reproducible 4 × uint64 seed
// flavours, parameterised by `flavor`. Each flavour stresses a
// different state-init region (zero / ascending / high-bit /
// pseudo-random fixed).
func canonicalSeed4(flavor int) [4]uint64 {
	switch flavor {
	case 0:
		return [4]uint64{}
	case 1:
		return [4]uint64{1, 2, 3, 4}
	case 2:
		return [4]uint64{0x8000000000000001, 0x8000000000000002, 0x8000000000000003, 0x8000000000000004}
	default:
		return [4]uint64{0xdeadbeefcafebabe, 0x0123456789abcdef, 0xfedcba9876543210, 0x1337c0debaadf00d}
	}
}

// canonicalSeed2 returns a 2 × uint64 seed flavour (W128 primitives).
func canonicalSeed2(flavor int) [2]uint64 {
	s := canonicalSeed4(flavor)
	return [2]uint64{s[0], s[1]}
}

// canonicalSeed8 returns an 8 × uint64 seed flavour (W512 primitives).
// Each flavour stresses every state slot with a deterministic pattern
// derived from canonicalSeed4 and a per-half offset.
func canonicalSeed8(flavor int) [8]uint64 {
	a := canonicalSeed4(flavor)
	b := canonicalSeed4((flavor + 1) & 3)
	return [8]uint64{a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]}
}

// canonicalKey32 builds a deterministic 32-byte key with a single
// non-zero seed byte at position `flavor`, for catching state-init
// regressions tied to specific key layouts.
func canonicalKey32() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(0x40 | (i & 0x3f))
	}
	return k
}

// canonicalKey64 — 64-byte counterpart for BLAKE2b-512 / Areion-SoEM-512.
func canonicalKey64() [64]byte {
	var k [64]byte
	for i := range k {
		k[i] = byte(0x40 | (i & 0x3f))
	}
	return k
}

// canonicalKey16 — 16-byte counterpart for AES-CMAC.
func canonicalKey16() [16]byte {
	var k [16]byte
	for i := range k {
		k[i] = byte(0x40 | (i & 0x3f))
	}
	return k
}

// expectAndAssertEqual4 fails the test when actual ≠ expected on
// any of the 4 uint64 lanes, printing a hex-formatted diff.
func expectAndAssertEqual4(t *testing.T, label string, actual, expected [4]uint64) {
	t.Helper()
	if actual != expected {
		t.Errorf("%s: digest mismatch\n  got  = %016x %016x %016x %016x\n  want = %016x %016x %016x %016x",
			label,
			actual[0], actual[1], actual[2], actual[3],
			expected[0], expected[1], expected[2], expected[3])
	}
}

// expectAndAssertEqual2 — W128 counterpart.
func expectAndAssertEqual2(t *testing.T, label string, gotLo, gotHi, wantLo, wantHi uint64) {
	t.Helper()
	if gotLo != wantLo || gotHi != wantHi {
		t.Errorf("%s: digest mismatch\n  got  = %016x %016x\n  want = %016x %016x",
			label, gotLo, gotHi, wantLo, wantHi)
	}
}

// expectAndAssertEqual8 — W512 counterpart for BLAKE2b-512 / Areion-SoEM-512.
func expectAndAssertEqual8(t *testing.T, label string, actual, expected [8]uint64) {
	t.Helper()
	if actual != expected {
		t.Errorf("%s: digest mismatch\n  got  = %016x %016x %016x %016x %016x %016x %016x %016x\n  want = %016x %016x %016x %016x %016x %016x %016x %016x",
			label,
			actual[0], actual[1], actual[2], actual[3], actual[4], actual[5], actual[6], actual[7],
			expected[0], expected[1], expected[2], expected[3], expected[4], expected[5], expected[6], expected[7])
	}
}

// katLengths covers the closure single-arm test surface — a mix of
// short-tail / chunk-boundary / multi-chunk inputs that exercise
// every code path of the buffer-construction body.
var katLengths = []int{0, 1, 7, 16, 20, 24, 36, 64, 68, 100, 256, 1024}

// katBatchedLengths covers only the lengths where the public batched
// arm dispatches to a ZMM kernel. Other lengths fall through to the
// per-lane scalar arm and are already covered by the single-arm tests.
var katBatchedLengths = []int{20, 36, 68}

// -----------------------------------------------------------------------------
// BLAKE2b-256 KAT.
// -----------------------------------------------------------------------------

// blake2b256RefClosure rebuilds the hashes.BLAKE2b256 closure body
// using golang.org/x/crypto/blake2b directly. Mirrors the closure's
// buf-construction byte-for-byte: key prefix (32 bytes), data (zero-
// padded to >= 32 bytes), seed XOR'd into buf[32:64] as 4 LE uint64.
func blake2b256RefClosure(key [32]byte, data []byte, seed [4]uint64) [4]uint64 {
	const keyLen = 32
	const seedInjectBytes = 32
	payloadLen := len(data)
	if payloadLen < seedInjectBytes {
		payloadLen = seedInjectBytes
	}
	buf := make([]byte, keyLen+payloadLen)
	copy(buf[:keyLen], key[:])
	copy(buf[keyLen:keyLen+len(data)], data)
	for i := 0; i < 4; i++ {
		off := keyLen + i*8
		v := binary.LittleEndian.Uint64(buf[off:]) ^ seed[i]
		binary.LittleEndian.PutUint64(buf[off:], v)
	}
	digest := blake2b.Sum256(buf)
	return [4]uint64{
		binary.LittleEndian.Uint64(digest[0:]),
		binary.LittleEndian.Uint64(digest[8:]),
		binary.LittleEndian.Uint64(digest[16:]),
		binary.LittleEndian.Uint64(digest[24:]),
	}
}

func TestKAT_BLAKE2b256(t *testing.T) {
	key := canonicalKey32()
	single, batched, retKey := BLAKE2b256Pair(key)
	if !bytes.Equal(retKey[:], key[:]) {
		t.Fatalf("Pair returned key %x, want %x", retKey[:], key[:])
	}

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed4(flavor)
			want := blake2b256RefClosure(key, data, seed)
			got := single(data, seed)
			expectAndAssertEqual4(t, label("BLAKE2b256 single", n, flavor), got, want)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][4]uint64
			var wants [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed4(lane)
				wants[lane] = blake2b256RefClosure(key, data4[lane], seeds4[lane])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual4(t, labelLane("BLAKE2b256 batched", n, lane), gots[lane], wants[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// BLAKE2b-512 KAT.
// -----------------------------------------------------------------------------

// blake2b512RefClosure rebuilds the hashes.BLAKE2b512 closure body:
// key prefix (64 bytes), data zero-padded to >= 64 bytes, seed XOR'd
// into buf[64:128] as 8 LE uint64. Output is 8 LE uint64 (64-byte
// digest of blake2b.Sum512).
func blake2b512RefClosure(key [64]byte, data []byte, seed [8]uint64) [8]uint64 {
	const keyLen = 64
	const seedInjectBytes = 64
	payloadLen := len(data)
	if payloadLen < seedInjectBytes {
		payloadLen = seedInjectBytes
	}
	buf := make([]byte, keyLen+payloadLen)
	copy(buf[:keyLen], key[:])
	copy(buf[keyLen:keyLen+len(data)], data)
	for i := 0; i < 8; i++ {
		off := keyLen + i*8
		v := binary.LittleEndian.Uint64(buf[off:]) ^ seed[i]
		binary.LittleEndian.PutUint64(buf[off:], v)
	}
	digest := blake2b.Sum512(buf)
	var out [8]uint64
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint64(digest[i*8:])
	}
	return out
}

func TestKAT_BLAKE2b512(t *testing.T) {
	key := canonicalKey64()
	single, batched, retKey := BLAKE2b512Pair(key)
	if !bytes.Equal(retKey[:], key[:]) {
		t.Fatalf("Pair returned key %x, want %x", retKey[:], key[:])
	}

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed8(flavor)
			want := blake2b512RefClosure(key, data, seed)
			got := single(data, seed)
			expectAndAssertEqual8(t, label("BLAKE2b512 single", n, flavor), got, want)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][8]uint64
			var wants [4][8]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed8(lane)
				wants[lane] = blake2b512RefClosure(key, data4[lane], seeds4[lane])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual8(t, labelLane("BLAKE2b512 batched", n, lane), gots[lane], wants[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// BLAKE2s-256 KAT.
// -----------------------------------------------------------------------------

// blake2sRefClosure rebuilds the hashes.BLAKE2s closure body using
// golang.org/x/crypto/blake2s directly. Same shape as BLAKE2b-256
// but with the BLAKE2s primitive (32-bit state, 64-byte block).
func blake2sRefClosure(key [32]byte, data []byte, seed [4]uint64) [4]uint64 {
	const keyLen = 32
	const seedInjectBytes = 32
	payloadLen := len(data)
	if payloadLen < seedInjectBytes {
		payloadLen = seedInjectBytes
	}
	buf := make([]byte, keyLen+payloadLen)
	copy(buf[:keyLen], key[:])
	copy(buf[keyLen:keyLen+len(data)], data)
	for i := 0; i < 4; i++ {
		off := keyLen + i*8
		v := binary.LittleEndian.Uint64(buf[off:]) ^ seed[i]
		binary.LittleEndian.PutUint64(buf[off:], v)
	}
	digest := blake2s.Sum256(buf)
	return [4]uint64{
		binary.LittleEndian.Uint64(digest[0:]),
		binary.LittleEndian.Uint64(digest[8:]),
		binary.LittleEndian.Uint64(digest[16:]),
		binary.LittleEndian.Uint64(digest[24:]),
	}
}

func TestKAT_BLAKE2s(t *testing.T) {
	key := canonicalKey32()
	single, batched, retKey := BLAKE2s256Pair(key)
	if !bytes.Equal(retKey[:], key[:]) {
		t.Fatalf("Pair returned key %x, want %x", retKey[:], key[:])
	}

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed4(flavor)
			want := blake2sRefClosure(key, data, seed)
			got := single(data, seed)
			expectAndAssertEqual4(t, label("BLAKE2s single", n, flavor), got, want)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][4]uint64
			var wants [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed4(lane)
				wants[lane] = blake2sRefClosure(key, data4[lane], seeds4[lane])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual4(t, labelLane("BLAKE2s batched", n, lane), gots[lane], wants[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// BLAKE3 KAT.
// -----------------------------------------------------------------------------

// blake3RefClosure rebuilds the hashes.BLAKE3 closure body using
// github.com/zeebo/blake3 in keyed mode WITHOUT the template.Clone()
// per-call optimisation — calling NewKeyed fresh on every invocation
// pins the closure's caching path against the canonical
// "fresh hasher per call" reference.
func blake3RefClosure(key [32]byte, data []byte, seed [4]uint64) [4]uint64 {
	const seedInjectBytes = 32
	payloadLen := len(data)
	if payloadLen < seedInjectBytes {
		payloadLen = seedInjectBytes
	}
	mixed := make([]byte, payloadLen)
	copy(mixed, data)
	for i := 0; i < 4; i++ {
		off := i * 8
		v := binary.LittleEndian.Uint64(mixed[off:]) ^ seed[i]
		binary.LittleEndian.PutUint64(mixed[off:], v)
	}
	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic(err)
	}
	if _, err := h.Write(mixed); err != nil {
		panic(err)
	}
	var digest [32]byte
	h.Sum(digest[:0])
	return [4]uint64{
		binary.LittleEndian.Uint64(digest[0:]),
		binary.LittleEndian.Uint64(digest[8:]),
		binary.LittleEndian.Uint64(digest[16:]),
		binary.LittleEndian.Uint64(digest[24:]),
	}
}

func TestKAT_BLAKE3(t *testing.T) {
	key := canonicalKey32()
	single, batched, retKey := BLAKE3256Pair(key)
	if !bytes.Equal(retKey[:], key[:]) {
		t.Fatalf("Pair returned key %x, want %x", retKey[:], key[:])
	}

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed4(flavor)
			want := blake3RefClosure(key, data, seed)
			got := single(data, seed)
			expectAndAssertEqual4(t, label("BLAKE3 single", n, flavor), got, want)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][4]uint64
			var wants [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed4(lane)
				wants[lane] = blake3RefClosure(key, data4[lane], seeds4[lane])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual4(t, labelLane("BLAKE3 batched", n, lane), gots[lane], wants[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// ChaCha20 KAT.
// -----------------------------------------------------------------------------

// chacha20RefClosure rebuilds the hashes.ChaCha20 closure body:
// per-call key = fixedKey ^ seed (LE uint64 over 4 components),
// chacha20.NewUnauthenticatedCipher with zero nonce, then a CBC-MAC-
// style absorb where state[0..8] holds the lenTag, state[8..32]
// absorbs `data` in 24-byte chunks, with c.XORKeyStream applied after
// each chunk's XOR-into-state.
func chacha20RefClosure(fixedKey [32]byte, data []byte, seed [4]uint64) [4]uint64 {
	var key [32]byte
	copy(key[:], fixedKey[:])
	for i := 0; i < 4; i++ {
		off := i * 8
		v := binary.LittleEndian.Uint64(key[off:]) ^ seed[i]
		binary.LittleEndian.PutUint64(key[off:], v)
	}
	var nonce [12]byte
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		panic(err)
	}
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	const chunkSize = 24
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		c.XORKeyStream(state[:], state[:])
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		c.XORKeyStream(state[:], state[:])
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			for i := 0; i < end-off; i++ {
				state[8+i] ^= data[off+i]
			}
			c.XORKeyStream(state[:], state[:])
			off = end
		}
	}
	return [4]uint64{
		binary.LittleEndian.Uint64(state[0:]),
		binary.LittleEndian.Uint64(state[8:]),
		binary.LittleEndian.Uint64(state[16:]),
		binary.LittleEndian.Uint64(state[24:]),
	}
}

func TestKAT_ChaCha20(t *testing.T) {
	key := canonicalKey32()
	single, batched, retKey := ChaCha20256Pair(key)
	if !bytes.Equal(retKey[:], key[:]) {
		t.Fatalf("Pair returned key %x, want %x", retKey[:], key[:])
	}

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed4(flavor)
			want := chacha20RefClosure(key, data, seed)
			got := single(data, seed)
			expectAndAssertEqual4(t, label("ChaCha20 single", n, flavor), got, want)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][4]uint64
			var wants [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed4(lane)
				wants[lane] = chacha20RefClosure(key, data4[lane], seeds4[lane])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual4(t, labelLane("ChaCha20 batched", n, lane), gots[lane], wants[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// AES-CMAC KAT.
// -----------------------------------------------------------------------------

// aescmacRefClosure rebuilds the hashes.AESCMAC closure body using
// crypto/aes directly. State init: state[0:8] = seed0 ^ lenTag,
// state[8:16] = seed1 ^ lenTag (folds the input length into both
// halves of the seed prefix). Absorb XOR pattern: first block XORs
// data[0:min(16, len)] into state, encrypts; subsequent blocks XOR
// data[off:off+16] (or a tail) and encrypt again.
func aescmacRefClosure(aesKey [16]byte, data []byte, seed0, seed1 uint64) (uint64, uint64) {
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		panic(err)
	}
	lenTag := uint64(len(data))
	var b1 [16]byte
	binary.LittleEndian.PutUint64(b1[0:], seed0^lenTag)
	binary.LittleEndian.PutUint64(b1[8:], seed1^lenTag)
	firstBlockLen := len(data)
	if firstBlockLen > 16 {
		firstBlockLen = 16
	}
	for i := 0; i < firstBlockLen; i++ {
		b1[i] ^= data[i]
	}
	aescmacEncrypt(block, &b1)
	for off := 16; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		for i := 0; i < end-off; i++ {
			b1[i] ^= data[off+i]
		}
		aescmacEncrypt(block, &b1)
	}
	return binary.LittleEndian.Uint64(b1[:8]), binary.LittleEndian.Uint64(b1[8:])
}

// aescmacEncrypt applies a single AES-128 block encryption in-place.
func aescmacEncrypt(block cipher.Block, buf *[16]byte) {
	block.Encrypt(buf[:], buf[:])
}

func TestKAT_AESCMAC(t *testing.T) {
	key := canonicalKey16()
	single, batched, retKey := AESCMACPair(key)
	if !bytes.Equal(retKey[:], key[:]) {
		t.Fatalf("Pair returned key %x, want %x", retKey[:], key[:])
	}

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed2(flavor)
			wantLo, wantHi := aescmacRefClosure(key, data, seed[0], seed[1])
			gotLo, gotHi := single(data, seed[0], seed[1])
			expectAndAssertEqual2(t, label("AESCMAC single", n, flavor), gotLo, gotHi, wantLo, wantHi)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][2]uint64
			var wantLos, wantHis [4]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed2(lane)
				wantLos[lane], wantHis[lane] = aescmacRefClosure(key, data4[lane], seeds4[lane][0], seeds4[lane][1])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual2(t, labelLane("AESCMAC batched", n, lane), gots[lane][0], gots[lane][1], wantLos[lane], wantHis[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// SipHash-2-4 KAT.
// -----------------------------------------------------------------------------

// siphashRefClosure rebuilds the hashes.SipHash24 closure body —
// a direct call into github.com/dchest/siphash with the per-call
// (seed0, seed1) acting as the entire SipHash-128 key. No fixed-key
// prefix, no buffer construction — the closure is structurally a
// thin wrapper, so the reference is the wrapper itself.
func siphashRefClosure(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	return siphash.Hash128(seed0, seed1, data)
}

func TestKAT_SipHash24(t *testing.T) {
	single, batched := SipHash24Pair()

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed2(flavor)
			wantLo, wantHi := siphashRefClosure(data, seed[0], seed[1])
			gotLo, gotHi := single(data, seed[0], seed[1])
			expectAndAssertEqual2(t, label("SipHash24 single", n, flavor), gotLo, gotHi, wantLo, wantHi)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][2]uint64
			var wantLos, wantHis [4]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed2(lane)
				wantLos[lane], wantHis[lane] = siphashRefClosure(data4[lane], seeds4[lane][0], seeds4[lane][1])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual2(t, labelLane("SipHash24 batched", n, lane), gots[lane][0], gots[lane][1], wantLos[lane], wantHis[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Areion-SoEM-256 KAT.
// -----------------------------------------------------------------------------

// areion256RefClosure rebuilds the hashes.Areion256 closure body
// using github.com/jedisct1/go-aes's exported AreionSoEM256 directly.
// Construction: 64-byte SoEM key = fixedKey || seed_packed (4 LE
// uint64); 32-byte state with state[0:8] = lenTag, state[8:32]
// absorbs `data` in 24-byte chunks via state[8:8+r] ^= chunk;
// state = AreionSoEM256(key, state) between rounds.
func areion256RefClosure(fixedKey [32]byte, data []byte, seed [4]uint64) [4]uint64 {
	var key [64]byte
	copy(key[:32], fixedKey[:])
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(key[32+i*8:], seed[i])
	}
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	const chunkSize = 24
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		state = stdaes.AreionSoEM256(&key, &state)
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		state = stdaes.AreionSoEM256(&key, &state)
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			for i := 0; i < end-off; i++ {
				state[8+i] ^= data[off+i]
			}
			state = stdaes.AreionSoEM256(&key, &state)
			off = end
		}
	}
	return [4]uint64{
		binary.LittleEndian.Uint64(state[0:]),
		binary.LittleEndian.Uint64(state[8:]),
		binary.LittleEndian.Uint64(state[16:]),
		binary.LittleEndian.Uint64(state[24:]),
	}
}

func TestKAT_Areion256(t *testing.T) {
	key := canonicalKey32()
	single, batched, retKey := Areion256Pair(key)
	if !bytes.Equal(retKey[:], key[:]) {
		t.Fatalf("Pair returned key %x, want %x", retKey[:], key[:])
	}

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed4(flavor)
			want := areion256RefClosure(key, data, seed)
			got := single(data, seed)
			expectAndAssertEqual4(t, label("Areion256 single", n, flavor), got, want)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][4]uint64
			var wants [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed4(lane)
				wants[lane] = areion256RefClosure(key, data4[lane], seeds4[lane])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual4(t, labelLane("Areion256 batched", n, lane), gots[lane], wants[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Areion-SoEM-512 KAT.
// -----------------------------------------------------------------------------

// areion512RefClosure rebuilds the hashes.Areion512 closure body
// using github.com/jedisct1/go-aes's exported AreionSoEM512 directly.
// Construction is structurally identical to AreionSoEM256 but scaled
// to a 128-byte SoEM key (64-byte fixedKey || 64-byte seed_packed,
// where seed_packed = 8 LE uint64) and a 64-byte state absorbing
// 56-byte chunks per round.
func areion512RefClosure(fixedKey [64]byte, data []byte, seed [8]uint64) [8]uint64 {
	var key [128]byte
	copy(key[:64], fixedKey[:])
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(key[64+i*8:], seed[i])
	}
	var state [64]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	const chunkSize = 56
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		state = stdaes.AreionSoEM512(&key, &state)
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		state = stdaes.AreionSoEM512(&key, &state)
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			for i := 0; i < end-off; i++ {
				state[8+i] ^= data[off+i]
			}
			state = stdaes.AreionSoEM512(&key, &state)
			off = end
		}
	}
	var out [8]uint64
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint64(state[i*8:])
	}
	return out
}

func TestKAT_Areion512(t *testing.T) {
	key := canonicalKey64()
	single, batched, retKey := Areion512Pair(key)
	if !bytes.Equal(retKey[:], key[:]) {
		t.Fatalf("Pair returned key %x, want %x", retKey[:], key[:])
	}

	for _, n := range katLengths {
		for flavor := 0; flavor < 4; flavor++ {
			data := canonicalData(n)
			seed := canonicalSeed8(flavor)
			want := areion512RefClosure(key, data, seed)
			got := single(data, seed)
			expectAndAssertEqual8(t, label("Areion512 single", n, flavor), got, want)
		}
	}

	if batched != nil {
		for _, n := range katBatchedLengths {
			var data4 [4][]byte
			var seeds4 [4][8]uint64
			var wants [4][8]uint64
			for lane := 0; lane < 4; lane++ {
				data4[lane] = canonicalData(n + lane)[:n]
				seeds4[lane] = canonicalSeed8(lane)
				wants[lane] = areion512RefClosure(key, data4[lane], seeds4[lane])
			}
			gots := batched(&data4, seeds4)
			for lane := 0; lane < 4; lane++ {
				expectAndAssertEqual8(t, labelLane("Areion512 batched", n, lane), gots[lane], wants[lane])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Helpers.
// -----------------------------------------------------------------------------

func label(name string, n, flavor int) string {
	return name + " len=" + itoaShort(n) + " flavor=" + itoaShort(flavor)
}

func labelLane(name string, n, lane int) string {
	return name + " len=" + itoaShort(n) + " lane=" + itoaShort(lane)
}

func itoaShort(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
