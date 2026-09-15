// Package aesitb is an audit-oriented pure-Go reference implementation of
// the AES-ITB primitive. It is not used by the production ITB path — the
// shipping implementation lives in the itb root package (aesitb.go),
// which wires the nonce-free generic hash (HashGeneric here) into the
// ChainHash dispatch and the per-architecture SIMD kernels of
// internal/aesitbasm. The session-keyed shapes (SessionInit, HashPixel)
// are reference-only and have no shipped counterpart. This package
// exists to cross-check the shipping implementation via KAT vectors and
// the root prod-vs-reference parity tests.
package aesitb
