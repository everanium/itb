package blake2sasm

// Blake2sIV is the BLAKE2s initialization vector from RFC 7693 §3.2.
// The 32-bit word constants are the same as the upper 32 bits of the
// corresponding BLAKE2b IV entries. The compression function's initial
// state for BLAKE2s-256 derives from this IV with the parameter block
// XOR'd into h[0]; h[1..7] remain equal to IV[1..7].
var Blake2sIV = [8]uint32{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}

// Blake2sIV256Param is the precomputed initial state for the
// hashes.BLAKE2s256 prefix-MAC construction:
//
//	paramBlock = digestLength=32, fanout=1, depth=1, keylen=0
//	           = 0x01010020 (LE uint32)
//	h[0]       = IV[0] ⊕ paramBlock = 0x6b08e647
//	h[1..7]    = IV[1..7] (unchanged)
//
// The hashes.BLAKE2s256 closure passes a pointer to this array as the
// h0 parameter of the chain-absorb kernels. Caller-side IV setup keeps
// the ASM kernel digest-width-agnostic — though BLAKE2s ships only
// at 32-byte digest width in this repo, the same shape leaves room
// for a future -224 parameter set to slot in without a kernel rewrite.
var Blake2sIV256Param = [8]uint32{
	0x6b08e647, // IV[0] ⊕ 0x01010020
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}
