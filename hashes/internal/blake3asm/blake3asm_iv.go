package blake3asm

// Blake3IV is the BLAKE3 initialization vector (RFC §2.4). The
// constants are bit-identical to BLAKE2s IV (and the SHA-256 IV);
// BLAKE3 reuses these values for v[8..11] of the compression state
// init, with the remaining four IV slots replaced by (t_lo, t_hi,
// block_len, flags) per BLAKE3's compression contract.
//
// Unlike BLAKE2{b,s}, BLAKE3 has no parameter-block XOR'd into h[0]
// — the digest length is not encoded in the chaining value at init
// time. So no Blake3IV256Param companion variable is needed.
var Blake3IV = [8]uint32{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}

// BLAKE3 domain-separation flags (RFC §2.1).
const (
	FlagChunkStart = 0x01
	FlagChunkEnd   = 0x02
	FlagRoot       = 0x08
	FlagKeyedHash  = 0x10
)

// FlagsSingleBlock — set by the 20- and 36-byte kernels (where the
// keyed-hash chunk is a single block, and that block is
// simultaneously chunk-start, chunk-end, and root).
const FlagsSingleBlock = FlagKeyedHash | FlagChunkStart | FlagChunkEnd | FlagRoot

// FlagsTwoBlockFirst — set by block 1 of the 68-byte kernel (chunk
// start, but neither chunk end nor root yet).
const FlagsTwoBlockFirst = FlagKeyedHash | FlagChunkStart

// FlagsTwoBlockFinal — set by block 2 of the 68-byte kernel (chunk
// end and root, but no longer chunk start).
const FlagsTwoBlockFinal = FlagKeyedHash | FlagChunkEnd | FlagRoot
