package easy_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb"
)

// TestMain honours the ITB_BITSOUP / ITB_LOCKSOUP / ITB_LOCKSEED /
// ITB_NONCE_BITS environment variables. Each non-empty / non-"0"
// value flips the corresponding process-global setter on the itb
// root package before any test or benchmark runs; subsequent
// easy.New / easy.New3 calls in this suite snapshot the global
// state into their per-encryptor [itb.Config], so the env-driven
// configuration flows uniformly into every encryptor produced
// here. The pattern mirrors itb's own bitbyte_test.go TestMain.
//
//	go test ./easy/                    # default config
//	ITB_BITSOUP=1 go test ./easy/      # bit-soup overlay engaged
//	ITB_LOCKSOUP=1 go test ./easy/     # Lock Soup overlay engaged
//	ITB_LOCKSEED=1 go test ./easy/     # dedicated lockSeed allocated by
//	                                   # every easy.New / easy.New3
//	ITB_NONCE_BITS=512 go test ./easy/ # 512-bit nonces
//
// Combinations work — e.g. ITB_LOCKSOUP=1 ITB_LOCKSEED=1
// go test -bench=. ./easy/ runs the throughput cohort with the
// full bit-permutation overlay routed through a dedicated
// lockSeed.
func TestMain(m *testing.M) {
	if v := os.Getenv("ITB_BITSOUP"); v != "" && v != "0" {
		itb.SetBitSoup(1)
	}
	if v := os.Getenv("ITB_LOCKSOUP"); v != "" && v != "0" {
		itb.SetLockSoup(1)
	}
	if v := os.Getenv("ITB_LOCKSEED"); v != "" && v != "0" {
		itb.SetLockSeed(1)
	}
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
