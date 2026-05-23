package kdf

import (
	"fmt"

	"github.com/everanium/itb/internal/hashprf"
)

// Registry names for the six hash-based SP 800-108 Counter Mode KDFs.
const (
	hashAreion256  = "areion256"
	hashAreion512  = "areion512"
	hashBLAKE2b256 = "blake2b256"
	hashBLAKE2b512 = "blake2b512"
	hashBLAKE2s    = "blake2s"
	hashBLAKE3     = "blake3"
)

// hashKDFMasterMin is the minimum master length accepted by every
// hash-based derivation. The five 32-byte-keyed primitives take
// master[:32] directly; areion512 stretches master[:32] to its 64-byte
// key. ML-KEM shared secrets are 32 bytes, which this bound admits.
const hashKDFMasterMin = 32

// deriveHashPRF implements SP 800-108 Counter Mode with PRF = the named
// hash-based keyed PRF from internal/hashprf, keyed by the leading 32
// bytes of master. A master shorter than 32 bytes is an error.
//
// areion512 needs a 64-byte PRF key; that path runs through
// deriveAreion512 instead of this helper.
func deriveHashPRF(name string, master []byte, label string, outLen int) ([]byte, error) {
	if len(master) < hashKDFMasterMin {
		return nil, fmt.Errorf("kdf: %s master must be at least %d bytes, got %d", name, hashKDFMasterMin, len(master))
	}
	prf, prfLen, err := hashprf.New(name, master[:hashKDFMasterMin])
	if err != nil {
		return nil, fmt.Errorf("kdf: %w", err)
	}
	wrap := func(in []byte) []byte {
		out := make([]byte, prfLen)
		prf(out, in)
		return out
	}
	return sp800108CounterMode(wrap, prfLen, []byte(label), outLen), nil
}

// deriveAreion512 implements SP 800-108 Counter Mode with PRF =
// Areion-SoEM-512 keyed by a 64-byte family key. ML-KEM masters are 32
// bytes while areion512 needs a 64-byte key, so the master is first
// stretched to 64 bytes via stretchAreion512Key before the areion512 PRF
// is keyed. A master shorter than 32 bytes is an error.
func deriveAreion512(master []byte, label string, outLen int) ([]byte, error) {
	key64, err := stretchAreion512Key(master)
	if err != nil {
		return nil, err
	}
	prf, prfLen, err := hashprf.New(hashAreion512, key64)
	if err != nil {
		return nil, fmt.Errorf("kdf: %w", err)
	}
	wrap := func(in []byte) []byte {
		out := make([]byte, prfLen)
		prf(out, in)
		return out
	}
	return sp800108CounterMode(wrap, prfLen, []byte(label), outLen), nil
}

// stretchAreion512Key deterministically expands master[:32] into the
// 64-byte key for the areion512 PRF. The expansion is SP 800-108 Counter
// Mode over the areion256 keyed PRF (key = master[:32]) under a fixed
// family-internal label, producing 64 bytes. This is an internal key
// schedule, not a user-facing derivation; the fixed label keeps it
// isolated from any caller-chosen label. A master shorter than 32 bytes
// is an error.
func stretchAreion512Key(master []byte) ([]byte, error) {
	if len(master) < hashKDFMasterMin {
		return nil, fmt.Errorf("kdf: %s master must be at least %d bytes, got %d", hashAreion512, hashKDFMasterMin, len(master))
	}
	prf, prfLen, err := hashprf.New(hashAreion256, master[:hashKDFMasterMin])
	if err != nil {
		return nil, fmt.Errorf("kdf: %w", err)
	}
	wrap := func(in []byte) []byte {
		out := make([]byte, prfLen)
		prf(out, in)
		return out
	}
	return sp800108CounterMode(wrap, prfLen, []byte("kdf:areion512-key-stretch"), 64), nil
}
