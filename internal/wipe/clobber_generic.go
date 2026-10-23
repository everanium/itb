//go:build (!amd64 && !arm64) || purego

package wipe

// ClobberRegs zeroes integer argument registers on targets without a
// dedicated assembly register-clobber routine.
func ClobberRegs() {
	_ = clobberIntArgRegs(0, 0, 0, 0, 0, 0, 0, 0, 0)
}
