package blake2sasm

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/crypto/blake2s"
)

// scalar256ChainAbsorb20 is the pure-Go reference implementation of the
// BLAKE2s-256 20-byte chain-absorb kernel. It builds the 64-byte
// BLAKE2s compression buffer ([b2key:32][data:20][zero-pad:12], with
// seed[0..3] XOR'd into buf[32:64] across four uint64 lanes — each
// straddling two BLAKE2s 32-bit message words) and runs the upstream
// blake2s.Sum256 path on it.
//
// On non-amd64 / purego builds and on amd64 hosts without
// AVX-512+VL, this serves as the production fallback path. On AVX-
// 512+VL hosts it serves as the parity baseline for the
// blake2s_chain256_20_amd64.s ASM kernel — any divergence between the
// two would surface as a different digest from the public
// hashes.BLAKE2s256 factory, which the porting work explicitly forbids.
func scalar256ChainAbsorb20(
	h0 *[8]uint32,
	b2key *[32]byte,
	data *[20]byte,
	seed *[4]uint64,
	out *[8]uint32,
) {
	_ = h0 // dispatch is implicit in blake2s.Sum256 (digestLength=32)
	var buf [64]byte
	pack256Buf(buf[:], b2key, data[:], seed)
	digest := blake2s.Sum256(buf[:])
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
}

// scalar256ChainAbsorb36 — 36-byte counterpart for BLAKE2s-256. buf
// is 68 bytes (key 32 + data 36, no zero-pad needed since data > 32).
// blake2s.Sum256 internally pads to a 128-byte two-block compression
// (block size 64); the second block carries 4 bytes of data + 60
// bytes of zero pad. Block 1 has t=64, f=0; block 2 has t=68, f=^0.
func scalar256ChainAbsorb36(
	h0 *[8]uint32,
	b2key *[32]byte,
	data *[36]byte,
	seed *[4]uint64,
	out *[8]uint32,
) {
	_ = h0
	var buf [68]byte
	pack256Buf(buf[:], b2key, data[:], seed)
	digest := blake2s.Sum256(buf[:])
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
}

// scalar256ChainAbsorb68 — 68-byte counterpart for BLAKE2s-256. buf
// is 100 bytes (key 32 + data 68). Two-block BLAKE2s compression
// (100 > 64-byte block size): block 1 carries the key + data[0:32]
// XOR'd with seed; block 2 carries data[32:68] + 28 zero pad. Block 1
// has t=64, f=0; block 2 has t=100, f=^0.
func scalar256ChainAbsorb68(
	h0 *[8]uint32,
	b2key *[32]byte,
	data *[68]byte,
	seed *[4]uint64,
	out *[8]uint32,
) {
	_ = h0
	var buf [100]byte
	pack256Buf(buf[:], b2key, data[:], seed)
	digest := blake2s.Sum256(buf[:])
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
}

// pack256Buf lays out the BLAKE2s-256 chain-absorb buffer for any
// caller data length. The data region starts at offset 32 (after the
// 32-byte key prefix); the seed XOR covers buf[32:64] regardless of
// data length, so any unfilled bytes in that region become seed bytes.
//
// Each seed[i] is a uint64 (8 bytes); applied LE it straddles two
// consecutive BLAKE2s 32-bit message words. The ASM kernel must split
// the seed into _lo32 / _hi32 halves and XOR them into m[2*i+8] and
// m[2*i+9] respectively.
func pack256Buf(buf []byte, b2key *[32]byte, data []byte, seed *[4]uint64) {
	copy(buf[0:32], b2key[:])
	copy(buf[32:32+len(data)], data)
	for i := 0; i < 4; i++ {
		off := 32 + i*8
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
}

// scalarBatch256ChainAbsorb20 is the scalar 4-lane reference for the
// BLAKE2s-256 batched chain-absorb at the 20-byte data shape. Loops
// the existing scalar single-pixel reference (scalar256ChainAbsorb20)
// over the four lanes; each lane is bit-exact equivalent to the
// public hashes.BLAKE2s256 closure on the same input. Used as the
// production fallback on hosts without AVX-512+VL and as the parity
// baseline for the ZMM-batched ASM kernel.
func scalarBatch256ChainAbsorb20(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[20]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint32
		scalar256ChainAbsorb20(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch256ChainAbsorb36 — 36-byte counterpart. Each lane is the
// two-compression-block path through the upstream blake2s.Sum256.
func scalarBatch256ChainAbsorb36(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[36]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint32
		scalar256ChainAbsorb36(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch256ChainAbsorb68 — 68-byte counterpart. Each lane is the
// two-compression-block path through the upstream blake2s.Sum256.
func scalarBatch256ChainAbsorb68(
	h0 *[8]uint32,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint32,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[68]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint32
		scalar256ChainAbsorb68(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}
