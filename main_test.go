package itb

import (
	"fmt"
	"os"
	"testing"
)

// testNonceBitsOverride carries the value of the ITB_NONCE_BITS
// environment variable when set by TestMain. Zero means the variable
// was not set (or held an invalid value) and tests fall back to the
// compile-in [DefaultNonceBits]. Test-only, never observed by
// production code.
var testNonceBitsOverride int

// TestMain honours the ITB_NONCE_BITS environment variable. When set
// to 128 / 256 / 512, subsequent tests that read
// [testNonceBitsOverride] and build their [Config] from it observe the
// requested nonce width; tests that pass nil keep using
// [DefaultNonceBits].
//
//	go test ./                          # default config (DefaultNonceBits)
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
			testNonceBitsOverride = 128
		case "256":
			testNonceBitsOverride = 256
		case "512":
			testNonceBitsOverride = 512
		default:
			fmt.Fprintf(os.Stderr,
				"ITB_NONCE_BITS=%q invalid (expected 128/256/512); ignoring\n", v)
		}
	}
	os.Exit(m.Run())
}
