package itb

import (
	"bytes"
	"testing"
)

// TestInterlockPRFFillSeqEnvVarToggle verifies that ITB_FORCE_INTERLOCK_PRF_FILL_SEQ
// environment variable properly toggles the batch-16 path nil/non-nil state in
// buildLockBatchPRF48_128. When SEQ=1, fillRanksSuper is nil (sequential fallback);
// when SEQ is unset, fillRanksSuper is populated (batch-16 active).
func TestInterlockPRFFillSeqEnvVarToggle(t *testing.T) {
	// Create a seed with AES-ITB-128 hash for testing
	seedKey := [16]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	hash128, _, _ := MakeAESITB128Hash(seedKey)

	seed, err := NewSeed128(512, hash128)
	if err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}

	// Attach the batch-16 hook (normally done by triple pipeline in allocOneSeed)
	// The hook is a dummy function; we're testing that buildLockBatchPRF48_128
	// correctly checks InterlockFillX16() and toggles fillRanksSuper based on the env-var
	seed.SetInterlockBatch16(func(groupIdxBase, seed0, seed1 uint64, out *[16][2]uint64) {
		// Placeholder: real implementation dispatches to x16 kernel
	})

	nonce := bytes.Repeat([]byte{0xAA}, 16)

	// Test 1: SEQ=1 → fillRanksSuper must be nil (sequential path forced)
	t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "1")
	bp1 := buildLockBatchPRF48_128(seed, nonce)
	if bp1.fillRanksSuper != nil {
		t.Error("SEQ=1: fillRanksSuper should be nil, got non-nil")
	}

	// Test 2: SEQ unset → fillRanksSuper must be populated (batch-16 active)
	t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "")
	bp2 := buildLockBatchPRF48_128(seed, nonce)
	if bp2.fillRanksSuper == nil {
		t.Error("SEQ unset: fillRanksSuper should be populated, got nil")
	}

	// Test 3: Verify env-var is consulted per call (toggle again)
	t.Setenv("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "1")
	bp3 := buildLockBatchPRF48_128(seed, nonce)
	if bp3.fillRanksSuper != nil {
		t.Error("SEQ=1 after toggle: fillRanksSuper should be nil")
	}
}
