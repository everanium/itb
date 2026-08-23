package triple

import (
	"fmt"
	"os"
	"testing"
)

// testNonceBitsOverride carries the value of the ITB_NONCE_BITS
// environment variable when set by TestMain. Zero means the variable
// was not set (or held an invalid value) and tests fall back to the
// compile-in default nonce width. Test-only, never observed by
// production code.
var testNonceBitsOverride int

// testOpts returns an [Opts] with NonceBits populated from
// [testNonceBitsOverride] when the ITB_NONCE_BITS environment variable
// selected a specific width, or a zero-value Opts otherwise. Tests
// threading nonce width through [Init] call testOpts() where they used
// to rely on the retired process-global; tests that pass a plain
// zero-value Opts inherit the compile-in default.
func testOpts() Opts {
	if testNonceBitsOverride == 0 {
		return Opts{}
	}
	return Opts{NonceBits: testNonceBitsOverride}
}

// TestMain honours the ITB_NONCE_BITS environment variable. When set
// to 128 / 256 / 512, subsequent triple tests that build their Opts
// via [testOpts] observe the requested nonce width; tests that pass a
// zero-value Opts keep using the compile-in default.
//
//	go test ./triple/                          # default config
//	ITB_NONCE_BITS=128 go test ./triple/       # 128-bit nonces via testOpts()
//	ITB_NONCE_BITS=256 go test ./triple/       # 256-bit nonces via testOpts()
//	ITB_NONCE_BITS=512 go test ./triple/       # 512-bit nonces via testOpts()
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
