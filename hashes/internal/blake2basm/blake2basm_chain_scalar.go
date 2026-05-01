package blake2basm

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/crypto/blake2b"
)

// scalar512ChainAbsorb20 is the pure-Go reference implementation of the
// 20-byte chain-absorb kernel. It builds the 128-byte BLAKE2b
// compression buffer ([b2key:64][data:20][zero-pad:44], with
// seed[0..7] XOR'd into buf[64:128]) and runs the upstream
// blake2b.Sum{256,512} path on it, dispatching by the digestLength
// encoded in h0[0].
//
// On non-amd64 / purego builds and on amd64 hosts without
// AVX-512+VL, this serves as the production fallback path. On AVX-
// 512+VL hosts it serves as the parity baseline for the
// blake2b_chain_20_amd64.s ASM kernel — any divergence between the
// two would surface as a different digest from the public
// hashes.BLAKE2b{256,512} factories, which the porting work
// explicitly forbids.
func scalar512ChainAbsorb20(
	h0 *[8]uint64,
	b2key *[64]byte,
	data *[20]byte,
	seed *[8]uint64,
	out *[8]uint64,
) {
	var buf [128]byte
	packBuf128(&buf, b2key, data[:], seed)
	scalarSum(buf[:], h0, out)
}

// scalar512ChainAbsorb36 — 36-byte counterpart. Same single-compression
// shape as the 20-byte path; only the data length region in the
// 128-byte buf differs.
func scalar512ChainAbsorb36(
	h0 *[8]uint64,
	b2key *[64]byte,
	data *[36]byte,
	seed *[8]uint64,
	out *[8]uint64,
) {
	var buf [128]byte
	packBuf128(&buf, b2key, data[:], seed)
	scalarSum(buf[:], h0, out)
}

// scalar512ChainAbsorb68 — 68-byte counterpart. Two compression blocks:
//
//	Block 1 (t=128, f=0): buf[0:128]   = b2key + (data[0:64] ⊕ seed)
//	Block 2 (t=132, f=1): buf[128:132] = data[64:68] + 124 zero pad
//
// On the AVX-512 fused path the BLAKE2b state is held in ZMM
// registers across both compressions. The scalar reference
// delegates to the upstream blake2b.Sum* driver, which iterates
// blocks naturally.
func scalar512ChainAbsorb68(
	h0 *[8]uint64,
	b2key *[64]byte,
	data *[68]byte,
	seed *[8]uint64,
	out *[8]uint64,
) {
	var buf [132]byte
	packBuf132(&buf, b2key, data, seed)
	scalarSum(buf[:], h0, out)
}

// packBuf128 lays out the 128-byte BLAKE2b compression buffer for
// the 20-byte and 36-byte input shapes. The data region (64..64+L)
// is followed by zero padding to byte 128; the seed XOR loop covers
// buf[64:128] regardless of L, so any zero-pad bytes become seed
// bytes after XOR.
func packBuf128(buf *[128]byte, b2key *[64]byte, data []byte, seed *[8]uint64) {
	copy(buf[0:64], b2key[:])
	copy(buf[64:64+len(data)], data)
	for i := 0; i < 8; i++ {
		off := 64 + i*8
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
}

// packBuf132 lays out the 132-byte buffer for the 68-byte input
// shape. The seed XOR overlaps only the first 64 bytes of data
// (buf[64:128]); data[64:68] at buf[128:132] is unmodified.
func packBuf132(buf *[132]byte, b2key *[64]byte, data *[68]byte, seed *[8]uint64) {
	copy(buf[0:64], b2key[:])
	copy(buf[64:132], data[:])
	for i := 0; i < 8; i++ {
		off := 64 + i*8
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
}

// scalarSum runs the upstream blake2b.Sum256 / Sum512 path on buf,
// dispatching by the digestLength encoded in h0[0]. The result is
// written to out as 8 × uint64 (LE). For -256 dispatch (32-byte
// digest), out[4:8] is zero-filled; for -512, all 8 uint64 carry
// digest bytes.
//
// The dispatch matches the choice of blake2b.Sum256 / Sum512 used
// by the existing hashes.BLAKE2b{256,512} closures, so this function
// is bit-exact equivalent to running those closures on the same
// inputs.
func scalarSum(buf []byte, h0 *[8]uint64, out *[8]uint64) {
	var digest []byte
	if h0[0] == Blake2bIV256Param[0] {
		d := blake2b.Sum256(buf)
		digest = d[:]
	} else {
		d := blake2b.Sum512(buf)
		digest = d[:]
	}
	for i := 0; i < 8; i++ {
		if i*8+8 <= len(digest) {
			out[i] = binary.LittleEndian.Uint64(digest[i*8:])
		} else {
			out[i] = 0
		}
	}
}

// scalar256ChainAbsorb20 is the pure-Go reference for the BLAKE2b-256
// chain-absorb at the 20-byte data shape. Buffer is constructed
// exactly as the existing hashes.BLAKE2b256 closure does:
//
//	buf[0:32]   = b2key
//	buf[32:52]  = data
//	buf[52:64]  = zero (will receive seed bytes via XOR)
//	then for i in 0..3: buf[32+i*8 : 40+i*8] ^= seed[i]
//
// The buf is then passed to blake2b.Sum256 (which internally pads
// to a 128-byte block and runs one compression with t=64, f=^0).
// Output is written to out[0:4]; out[4:8] is zeroed.
func scalar256ChainAbsorb20(
	h0 *[8]uint64,
	b2key *[32]byte,
	data *[20]byte,
	seed *[4]uint64,
	out *[8]uint64,
) {
	_ = h0 // dispatch is implicit in blake2b.Sum256 (digestLength=32)
	var buf [64]byte
	pack256Buf(buf[:], b2key, data[:], seed)
	digest := blake2b.Sum256(buf[:])
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint64(digest[i*8:])
	}
	out[4], out[5], out[6], out[7] = 0, 0, 0, 0
}

// scalar256ChainAbsorb36 — 36-byte counterpart for BLAKE2b-256. buf
// is 68 bytes (key 32 + data 36, no zero-pad needed since data > 32).
// Single 128-byte BLAKE2b compression with t=68, f=^0.
func scalar256ChainAbsorb36(
	h0 *[8]uint64,
	b2key *[32]byte,
	data *[36]byte,
	seed *[4]uint64,
	out *[8]uint64,
) {
	_ = h0
	var buf [68]byte
	pack256Buf(buf[:], b2key, data[:], seed)
	digest := blake2b.Sum256(buf[:])
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint64(digest[i*8:])
	}
	out[4], out[5], out[6], out[7] = 0, 0, 0, 0
}

// scalar256ChainAbsorb68 — 68-byte counterpart for BLAKE2b-256. buf
// is 100 bytes (key 32 + data 68). Single 128-byte BLAKE2b
// compression with t=100, f=^0 (still under the 128-byte block size,
// no inter-block fold).
func scalar256ChainAbsorb68(
	h0 *[8]uint64,
	b2key *[32]byte,
	data *[68]byte,
	seed *[4]uint64,
	out *[8]uint64,
) {
	_ = h0
	var buf [100]byte
	pack256Buf(buf[:], b2key, data[:], seed)
	digest := blake2b.Sum256(buf[:])
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint64(digest[i*8:])
	}
	out[4], out[5], out[6], out[7] = 0, 0, 0, 0
}

// pack256Buf lays out the BLAKE2b-256 chain-absorb buffer for any
// caller data length. The data region starts at offset 32 (after the
// 32-byte key prefix); the seed XOR covers buf[32:64] regardless of
// data length, so any unfilled bytes in that region become seed bytes.
func pack256Buf(buf []byte, b2key *[32]byte, data []byte, seed *[4]uint64) {
	copy(buf[0:32], b2key[:])
	copy(buf[32:32+len(data)], data)
	for i := 0; i < 4; i++ {
		off := 32 + i*8
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
}

// scalarBatch512ChainAbsorb20 is the scalar 4-lane reference for the
// BLAKE2b-512 batched chain-absorb at the 20-byte data shape. Loops
// the existing scalar single-pixel reference (scalar512ChainAbsorb20)
// over the four lanes; each lane is bit-exact equivalent to the
// public hashes.BLAKE2b512 closure on the same input. Used as the
// production fallback on hosts without AVX-512+VL and as the parity
// baseline for the ZMM-batched ASM kernel.
func scalarBatch512ChainAbsorb20(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[20]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint64
		scalar512ChainAbsorb20(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch512ChainAbsorb36 — 36-byte counterpart.
func scalarBatch512ChainAbsorb36(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[36]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint64
		scalar512ChainAbsorb36(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch512ChainAbsorb68 — 68-byte counterpart. Each lane is the
// two-compression-block path through the upstream blake2b.Sum512.
func scalarBatch512ChainAbsorb68(
	h0 *[8]uint64,
	b2key *[64]byte,
	seeds *[4][8]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[68]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint64
		scalar512ChainAbsorb68(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch256ChainAbsorb20 is the scalar 4-lane reference for the
// BLAKE2b-256 batched chain-absorb at the 20-byte data shape. Each
// lane is bit-exact equivalent to the public hashes.BLAKE2b256
// closure. Output occupies out[lane][0:4]; out[lane][4:8] is zero.
func scalarBatch256ChainAbsorb20(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[20]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint64
		scalar256ChainAbsorb20(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch256ChainAbsorb36 — 36-byte counterpart for BLAKE2b-256.
func scalarBatch256ChainAbsorb36(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[36]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint64
		scalar256ChainAbsorb36(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}

// scalarBatch256ChainAbsorb68 — 68-byte counterpart for BLAKE2b-256.
func scalarBatch256ChainAbsorb68(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[68]byte)(unsafe.Pointer(dataPtrs[lane]))
		var laneOut [8]uint64
		scalar256ChainAbsorb68(h0, b2key, data, &seeds[lane], &laneOut)
		out[lane] = laneOut
	}
}
