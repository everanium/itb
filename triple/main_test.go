package triple

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
)

// TestMain honours the ITB_NONCE_BITS environment variable. When set,
// the value flips the itb.SetNonceBits process-global setter before
// any test or benchmark in the triple package runs; subsequent
// triple.Init calls whose Opts leave NonceBits at zero pick up the
// requested nonce width via the standard process-global fallback.
//
//	go test ./triple/                          # default config
//	ITB_NONCE_BITS=128 go test ./triple/       # 128-bit nonces
//	ITB_NONCE_BITS=256 go test ./triple/       # 256-bit nonces
//	ITB_NONCE_BITS=512 go test ./triple/       # 512-bit nonces
//
// Values other than 128 / 256 / 512 print a stderr note and are
// ignored (the run continues under the compiled-in default).
func TestMain(m *testing.M) {
	if v := os.Getenv("ITB_NONCE_BITS"); v != "" {
		switch v {
		case "128":
			itb.SetNonceBits(128)
		case "256":
			itb.SetNonceBits(256)
		case "512":
			itb.SetNonceBits(512)
		default:
			fmt.Fprintf(os.Stderr,
				"ITB_NONCE_BITS=%q invalid (expected 128/256/512); ignoring\n", v)
		}
	}
	os.Exit(m.Run())
}
