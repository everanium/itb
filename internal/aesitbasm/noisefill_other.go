//go:build (!amd64 && !arm64) || purego || noitbasm

package aesitbasm

// noiseFillGran reports 0: no assembly tier applies on this build, and
// the Go path over go-aes's single round runs the whole fill.
func noiseFillGran() int { return 0 }

// noiseFillKernel is never reached on this build (noiseFillGran is 0).
func noiseFillKernel(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64) {}
