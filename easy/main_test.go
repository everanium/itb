package easy_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
)

// TestMain honours the ITB_NONCE_BITS environment variable. A
// non-empty value flips the process-global nonce-size setter on
// the itb root package before any test or benchmark runs;
// subsequent easy.New3 / easy.NewMixed3 calls in this suite
// snapshot the global state into their per-encryptor [itb.Config],
// so the env-driven configuration flows uniformly into every
// encryptor produced here.
//
//	go test ./easy/                    # default config
//	ITB_NONCE_BITS=512 go test ./easy/ # 512-bit nonces
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
