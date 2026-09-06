// Package aesitb is an audit-oriented pure-Go reference implementation of
// the AES-ITB primitive. It is not used by the production ITB path — the
// shipping implementation lives in the itb root package (aesitb.go) and
// wires session-aware hot paths and per-architecture SIMD dispatchers.
// This reference package exists to cross-check the shipping implementation
// via KAT vectors and future prod-vs-reference parity tests.
package aesitb
