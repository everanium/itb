package blake2basm

// Blake2bIV is the BLAKE2b initialization vector from RFC 7693 §3.2.
// The compression function's initial state for both BLAKE2b-256 and
// BLAKE2b-512 derives from this IV with the parameter block XOR'd
// into h[0]; h[1..7] remain equal to IV[1..7].
var Blake2bIV = [8]uint64{
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
}

// Blake2bIV512Param is the precomputed initial state for the
// hashes.BLAKE2b512 prefix-MAC construction:
//
//	paramBlock = digestLength=64, fanout=1, depth=1, keylen=0
//	           = 0x0000_0000_0101_0040 (LE uint64)
//	h[0]       = IV[0] ⊕ paramBlock = 0x6a09e667f2bdc948
//	h[1..7]    = IV[1..7] (unchanged)
//
// The hashes.BLAKE2b512 closure passes a pointer to this array as the
// h0 parameter of the chain-absorb kernels. Caller-side IV setup keeps
// the ASM kernel digest-width-agnostic (one kernel set serves both
// -256 and -512 factories).
var Blake2bIV512Param = [8]uint64{
	0x6a09e667f2bdc948, // IV[0] ⊕ 0x01010040
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
}

// Blake2bIV256Param — analogous initial state for hashes.BLAKE2b256:
//
//	paramBlock = digestLength=32, fanout=1, depth=1, keylen=0
//	           = 0x0000_0000_0101_0020 (LE uint64)
//	h[0]       = IV[0] ⊕ paramBlock = 0x6a09e667f2bdc928
//	h[1..7]    = IV[1..7] (unchanged)
//
// For -256 callers the ASM kernel still computes the full 64-byte
// state; the BLAKE2b256 closure truncates the result to out[0:4]
// (32 bytes) before returning.
var Blake2bIV256Param = [8]uint64{
	0x6a09e667f2bdc928, // IV[0] ⊕ 0x01010020
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
}
