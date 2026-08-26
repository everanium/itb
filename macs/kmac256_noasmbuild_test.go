//go:build !amd64 || purego || noitbasm

package macs

// isASMBuild reports whether this test build compiled the vendored
// AVX-512 Keccak-f[1600] kernel in.
func isASMBuild() bool { return false }
