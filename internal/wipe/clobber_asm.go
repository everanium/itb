//go:build (amd64 || arm64) && !purego

package wipe

// ClobberRegs zeroes all caller-saved GPR and XMM/NEON registers.
func ClobberRegs()
