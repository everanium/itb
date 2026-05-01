package siphashasm

// SipHash initialization constants per Aumasson & Bernstein 2012
// §2.1 — the four 64-bit words "somepseu", "dorandom", "lygenera",
// "tedbytes" treated as little-endian uint64. State init folds
// these into the per-lane (seed0, seed1) key:
//
//	v0 = K0 ⊕ Const0
//	v1 = K1 ⊕ Const1
//	v2 = K0 ⊕ Const2
//	v3 = K1 ⊕ Const3
//
// The kernels load each constant as a 64-bit immediate via
// MOVQ $imm, scratch + VPBROADCASTQ rather than touching this
// table — the constants are duplicated here for parity-test
// readability and as a single source of truth that the kernels'
// hard-coded immediates can be cross-referenced against.
const (
	SipConst0 uint64 = 0x736f6d6570736575
	SipConst1 uint64 = 0x646f72616e646f6d
	SipConst2 uint64 = 0x6c7967656e657261
	SipConst3 uint64 = 0x7465646279746573

	// SipConst1XorEE is Const1 ⊕ 0xee, the v1 init constant for
	// SipHash-128 (the 128-bit output variant folds 0xee into v1
	// at init time per Aumasson & Bernstein 2012 §2.4). The
	// kernels load this value directly to avoid a separate XOR.
	SipConst1XorEE uint64 = SipConst1 ^ 0xee // = 0x646f72616e646f83
)
