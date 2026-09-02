package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
)

// Payload mode selector values for the --payload-mode flag.
//
//   - fixed: one CSPRNG-generated buffer per worker, held unchanged
//     for the whole run (the default).
//   - rotating: the buffer is regenerated before every iteration, so
//     no two encrypt calls see the same plaintext.
//   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
//     all 0xFF) probing minimum-entropy plaintext handling.
//   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
//     structured text.
const (
	payloadFixed        = "fixed"
	payloadRotating     = "rotating"
	payloadPatternZero  = "pattern-zero"
	payloadPatternFF    = "pattern-ff"
	payloadPatternASCII = "pattern-ascii"
)

// newWorkerRNG builds the deterministic per-worker plaintext source
// for seeded runs. Returns nil when seed is zero — the crypto/rand
// path. Each worker's stream is domain-separated by its id so seeded
// workers still hold pairwise-distinct buffers under the fixed and
// rotating modes.
func newWorkerRNG(seed uint64, workerID int) *mrand.ChaCha8 {
	if seed == 0 {
		return nil
	}
	var s [32]byte
	binary.LittleEndian.PutUint64(s[0:8], seed)
	s[8] = byte(workerID)
	return mrand.NewChaCha8(s)
}

// fillPayload writes one plaintext buffer according to the payload
// mode. The fixed and rotating modes draw from rng when non-nil
// (seeded run) and from crypto/rand otherwise; the pattern modes are
// deterministic regardless of rng.
func fillPayload(mode string, rng *mrand.ChaCha8, buf []byte) error {
	switch mode {
	case payloadFixed, payloadRotating:
		if rng != nil {
			rng.Read(buf) // ChaCha8.Read never fails
			return nil
		}
		if _, err := crand.Read(buf); err != nil {
			return fmt.Errorf("crypto/rand: %w", err)
		}
	case payloadPatternZero:
		clear(buf)
	case payloadPatternFF:
		for i := range buf {
			buf[i] = 0xFF
		}
	case payloadPatternASCII:
		for i := range buf {
			buf[i] = 'A' + byte(i%26)
		}
	default:
		return fmt.Errorf("unknown payload mode %q", mode)
	}
	return nil
}
