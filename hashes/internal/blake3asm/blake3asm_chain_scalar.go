package blake3asm

import (
	"encoding/binary"
	"unsafe"

	"github.com/zeebo/blake3"
)

// scalar256ChainAbsorb20 is the pure-Go reference implementation of
// the BLAKE3-256 20-byte chain-absorb kernel. The construction
// matches the existing hashes.BLAKE3 closure bit-exactly:
//
//	mixed[0:32] = (data[0:20] || zero-pad to 32) ⊕ seed (LE uint64
//	                                              over four 8-byte
//	                                              chunks)
//	digest      = blake3.NewKeyed(key).Write(mixed).Sum256()
//
// Unlike BLAKE2{b,s}, the key does NOT enter the hashed payload —
// it lives in BLAKE3's keyed-hash state init (KEYED_HASH flag).
// Mixed is a single block of ≤32 bytes; the BLAKE3 single-chunk
// compression is therefore one block with flags
// = KEYED_HASH | CHUNK_START | CHUNK_END | ROOT and block_len = 32.
//
// On non-amd64 / purego builds and on amd64 hosts without
// AVX-512+VL, this serves as the production fallback. On AVX-512+VL
// hosts it is the parity baseline for the
// blake3_chain256_20_amd64.s ASM kernel — divergence between them
// would observably change the digest emitted by hashes.BLAKE3256.
func scalar256ChainAbsorb20(
	key *[32]byte,
	data *[20]byte,
	seed *[4]uint64,
	out *[8]uint32,
) {
	var mixed [32]byte
	pack256Buf(mixed[:], data[:], seed)
	var digest [32]byte
	blake3KeyedSum(key, mixed[:], digest[:])
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
}

// scalar256ChainAbsorb36 — 36-byte counterpart for BLAKE3-256.
// mixed is 36 bytes; still single-block (36 ≤ 64-byte BLAKE3 block
// size), with the same single-block flag set as the 20-byte case
// but block_len = 36.
//
// This is structurally different from BLAKE2s at the same data
// length: BLAKE2s 36-byte buf is 68 bytes (key prefix + data) and
// requires two compression blocks. BLAKE3 32-byte key lives in the
// initial state, so no key prefix in the buffer — 36 bytes fits
// in one BLAKE3 block.
func scalar256ChainAbsorb36(
	key *[32]byte,
	data *[36]byte,
	seed *[4]uint64,
	out *[8]uint32,
) {
	var mixed [36]byte
	pack256Buf(mixed[:], data[:], seed)
	var digest [32]byte
	blake3KeyedSum(key, mixed[:], digest[:])
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
}

// scalar256ChainAbsorb68 — 68-byte counterpart for BLAKE3-256.
// mixed is 68 bytes; this exceeds BLAKE3's 64-byte block size, so
// the chunk runs as TWO blocks:
//
//	Block 1: data[0:64], block_len=64, flags=KEYED_HASH|CHUNK_START
//	         — produces an intermediate 32-byte chaining value (cv1)
//	Block 2: data[64:68], block_len=4, flags=KEYED_HASH|CHUNK_END|ROOT
//	         — uses cv1 as v[0..7] (NOT the original key — chunk-
//	           internal blocks chain), produces the root output
func scalar256ChainAbsorb68(
	key *[32]byte,
	data *[68]byte,
	seed *[4]uint64,
	out *[8]uint32,
) {
	var mixed [68]byte
	pack256Buf(mixed[:], data[:], seed)
	var digest [32]byte
	blake3KeyedSum(key, mixed[:], digest[:])
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
}

// pack256Buf lays out the BLAKE3-256 chain-absorb mixed buffer for
// any caller data length. Unlike the BLAKE2{b,s} pack helpers, no
// key prefix is written into the buffer (the key is consumed by the
// keyed-hash state init upstream). The seed XOR covers
// mixed[0:32]; for short data the unfilled bytes in that region
// become seed bytes after XOR. For data length > 32 the bytes past
// position 32 are not seed-XOR'd.
func pack256Buf(mixed []byte, data []byte, seed *[4]uint64) {
	copy(mixed[:len(data)], data)
	// Zero-pad mixed[len(data):min(32, len(mixed))] is implicit since
	// the caller's mixed array starts zero-initialised when stack-
	// allocated; the seed XOR's into that region produce seed bytes.
	for i := 0; i < 4; i++ {
		off := i * 8
		if off+8 > len(mixed) {
			break
		}
		binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
	}
}

// blake3KeyedSum runs the upstream zeebo/blake3 keyed-hash path on
// the mixed buffer using the supplied 32-byte key. Bit-exact
// equivalent to the hashes.BLAKE3 closure's
// `blake3.NewKeyed(key).Write(mixed).Sum(...)` sequence.
func blake3KeyedSum(key *[32]byte, mixed []byte, out []byte) {
	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic(err)
	}
	if _, err := h.Write(mixed); err != nil {
		panic(err)
	}
	h.Sum(out[:0])
}

// scalarBatch256ChainAbsorb20 is the scalar 4-lane reference for
// the BLAKE3-256 batched chain-absorb at the 20-byte data shape.
// Loops the per-lane scalar reference; each lane is bit-exact
// equivalent to the public hashes.BLAKE3 closure on the same input.
// Used as the production fallback on hosts without AVX-512+VL and
// as the parity baseline for the ZMM-batched ASM kernel.
func scalarBatch256ChainAbsorb20(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[20]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint32
		scalar256ChainAbsorb20(key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch256ChainAbsorb36 — 36-byte counterpart.
func scalarBatch256ChainAbsorb36(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[36]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint32
		scalar256ChainAbsorb36(key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch256ChainAbsorb68 — 68-byte counterpart.
func scalarBatch256ChainAbsorb68(
	key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[68]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint32
		scalar256ChainAbsorb68(key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}
