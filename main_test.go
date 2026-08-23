package itb

import (
	"fmt"
	"os"
	"testing"
)

// TestMain honours the ITB_NONCE_BITS environment variable. When set,
// the value flips the SetNonceBits process-global setter on the itb
// root package before any test or benchmark runs; subsequent test
// bodies observe the requested nonce width via the normal
// process-global read path.
//
//	go test ./                          # default config
//	ITB_NONCE_BITS=128 go test ./       # 128-bit nonces
//	ITB_NONCE_BITS=256 go test ./       # 256-bit nonces
//	ITB_NONCE_BITS=512 go test ./       # 512-bit nonces
//
// Values other than 128 / 256 / 512 print a stderr note and are
// ignored (the run continues under the compiled-in default).
func TestMain(m *testing.M) {
	if v := os.Getenv("ITB_NONCE_BITS"); v != "" {
		switch v {
		case "128":
			SetNonceBits(128)
		case "256":
			SetNonceBits(256)
		case "512":
			SetNonceBits(512)
		default:
			fmt.Fprintf(os.Stderr,
				"ITB_NONCE_BITS=%q invalid (expected 128/256/512); ignoring\n", v)
		}
	}
	os.Exit(m.Run())
}
