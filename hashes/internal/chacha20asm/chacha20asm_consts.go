package chacha20asm

// ChaCha20 sigma constants — the four 32-bit words "expa", "nd 3",
// "2-by", "te k" placed at v[0..3] of the 16-dword ChaCha20 state at
// the start of every compression (RFC 7539 §2.3). Stored as the
// little-endian uint32 representation of the ASCII bytes; the
// compression block uses VPBROADCASTD over each entry to fan one
// constant across all 16 dword lanes of a ZMM (lanes 4..15 are
// ignored downstream — the kernel only writes back lanes 0..3 to
// out[]).
var ChaCha20Sigma = [4]uint32{
	0x61707865, // "expa"
	0x3320646e, // "nd 3"
	0x79622d32, // "2-by"
	0x6b206574, // "te k"
}
