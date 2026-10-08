//go:build !amd64 && !arm64

package cpuid

import "golang.org/x/sys/cpu"

func init() {
	AESNI = cpu.X86.HasAES
	ARMAES = cpu.ARM64.HasAES
}
