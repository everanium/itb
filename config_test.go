package itb

import (
	"bytes"
	"sync"
	"testing"
)

// TestConfigCurrentNonceSizeCfg covers the three resolution paths of
// currentNonceSizeCfg: nil cfg (inherits global), cfg with sentinel 0
// (inherits global), and cfg with explicit non-zero NonceBits
// (overrides global).
func TestConfigCurrentNonceSizeCfg(t *testing.T) {
	// Save and restore the global so this test does not leak state.
	origBits := GetNonceBits()
	t.Cleanup(func() { SetNonceBits(origBits) })

	SetNonceBits(256) // 32-byte nonce globally

	t.Run("nil_fallback", func(t *testing.T) {
		if got := currentNonceSizeCfg(nil); got != 32 {
			t.Errorf("nil cfg: got %d bytes, want 32 (256-bit global)", got)
		}
	})

	t.Run("sentinel_fallback", func(t *testing.T) {
		cfg := &Config{NonceBits: 0}
		if got := currentNonceSizeCfg(cfg); got != 32 {
			t.Errorf("sentinel cfg: got %d bytes, want 32 (256-bit global)", got)
		}
	})

	t.Run("explicit_overrides_global", func(t *testing.T) {
		cases := []struct {
			nonceBits int
			wantBytes int
		}{
			{128, 16},
			{256, 32},
			{512, 64},
		}
		for _, c := range cases {
			cfg := &Config{NonceBits: c.nonceBits}
			if got := currentNonceSizeCfg(cfg); got != c.wantBytes {
				t.Errorf("explicit cfg NonceBits=%d: got %d, want %d",
					c.nonceBits, got, c.wantBytes)
			}
		}
	})
}

// TestConfigCurrentBarrierFillCfg covers the three resolution paths of
// currentBarrierFillCfg.
func TestConfigCurrentBarrierFillCfg(t *testing.T) {
	origFill := GetBarrierFill()
	t.Cleanup(func() { SetBarrierFill(origFill) })

	SetBarrierFill(8)

	t.Run("nil_fallback", func(t *testing.T) {
		if got := currentBarrierFillCfg(nil); got != 8 {
			t.Errorf("nil cfg: got %d, want 8 (global)", got)
		}
	})

	t.Run("sentinel_fallback", func(t *testing.T) {
		cfg := &Config{BarrierFill: 0}
		if got := currentBarrierFillCfg(cfg); got != 8 {
			t.Errorf("sentinel cfg: got %d, want 8 (global)", got)
		}
	})

	t.Run("explicit_overrides_global", func(t *testing.T) {
		for _, want := range []int{1, 2, 4, 8, 16, 32} {
			cfg := &Config{BarrierFill: want}
			if got := currentBarrierFillCfg(cfg); got != want {
				t.Errorf("explicit cfg BarrierFill=%d: got %d", want, got)
			}
		}
	})
}

// TestConfigGenerateNonceCfg verifies that generateNonceCfg honours
// the cfg-side NonceBits override and falls back to the global when
// cfg is nil or the field is the inherit sentinel.
func TestConfigGenerateNonceCfg(t *testing.T) {
	origBits := GetNonceBits()
	t.Cleanup(func() { SetNonceBits(origBits) })

	SetNonceBits(128) // global = 16-byte nonce

	t.Run("nil_inherits_global_size", func(t *testing.T) {
		nonce, err := generateNonceCfg(nil)
		if err != nil {
			t.Fatalf("generateNonceCfg(nil): %v", err)
		}
		if len(nonce) != 16 {
			t.Errorf("nil cfg: got %d-byte nonce, want 16", len(nonce))
		}
	})

	t.Run("explicit_overrides_global_size", func(t *testing.T) {
		cases := []struct {
			nonceBits int
			wantBytes int
		}{
			{128, 16},
			{256, 32},
			{512, 64},
		}
		for _, c := range cases {
			cfg := &Config{NonceBits: c.nonceBits}
			nonce, err := generateNonceCfg(cfg)
			if err != nil {
				t.Fatalf("generateNonceCfg(NonceBits=%d): %v", c.nonceBits, err)
			}
			if len(nonce) != c.wantBytes {
				t.Errorf("cfg NonceBits=%d: got %d-byte nonce, want %d",
					c.nonceBits, len(nonce), c.wantBytes)
			}
		}
	})
}

// TestConfigSnapshotGlobals verifies that SnapshotGlobals captures
// the current global state into a config object whose fields then do
// not drift when the globals are subsequently mutated. This is the
// per-encryptor isolation guarantee the constructor path depends on.
func TestConfigSnapshotGlobals(t *testing.T) {
	origNonce := GetNonceBits()
	origBarrier := GetBarrierFill()
	t.Cleanup(func() {
		SetNonceBits(origNonce)
		SetBarrierFill(origBarrier)
	})

	SetNonceBits(256)
	SetBarrierFill(8)

	cfg := SnapshotGlobals()

	if cfg.NonceBits != 256 {
		t.Errorf("NonceBits: got %d, want 256", cfg.NonceBits)
	}
	if cfg.BarrierFill != 8 {
		t.Errorf("BarrierFill: got %d, want 8", cfg.BarrierFill)
	}

	// Mutate globals after snapshot — the snapshot must not drift.
	SetNonceBits(512)
	SetBarrierFill(32)

	if cfg.NonceBits != 256 {
		t.Errorf("post-mutation drift: NonceBits = %d, want 256", cfg.NonceBits)
	}
	if cfg.BarrierFill != 8 {
		t.Errorf("post-mutation drift: BarrierFill = %d, want 8", cfg.BarrierFill)
	}

	// Symmetric direction — mutating the snapshot must not affect
	// globals (no shared backing state — config is a value type
	// returned by pointer, fully owned by the caller).
	cfg.NonceBits = 128
	if got := GetNonceBits(); got != 512 {
		t.Errorf("snapshot mutation leaked into global: got %d, want 512", got)
	}
}

// TestConfigMaxWorkersOverride verifies the per-encryptor MaxWorkers
// field flows through the *Cfg entry points into effectiveWorkersCfg
// without touching the process-global set via [SetMaxWorkers]. This is
// the per-Pipeline isolation guarantee the triple package depends on
// for its concurrent-instance construction.
//
// The test:
//  1. Snapshots the process-global via [GetMaxWorkers] and asserts it
//     is not perturbed after 8 concurrent goroutines each encrypt +
//     decrypt through the authenticated Cfg entry point with
//     cfg.MaxWorkers = 2.
//  2. Confirms every round-trip matches the input byte-exact.
//  3. Confirms decrypt-side worker-count invariance: the same
//     ciphertext decrypted under cfg.MaxWorkers ∈ {1, 2, 4, 8, nil}
//     produces bit-identical plaintext. Encrypt-side ciphertext
//     equality across independent calls is not testable — every
//     Triple encrypt injects fresh crypto/rand into the container
//     background and the payload tail-fill, so two independent
//     encrypts always diverge byte-wise regardless of worker count
//     (this is Proof 10 material, not a worker-count artefact).
func TestConfigMaxWorkersOverride(t *testing.T) {
	prevGlobal := GetMaxWorkers()
	t.Cleanup(func() { SetMaxWorkers(prevGlobal) })
	// Pin the process-global to a distinct value so a bleed from the
	// per-encryptor cfg into the global would be visible after the
	// concurrent batch completes.
	SetMaxWorkers(7)

	cfg := &Config{MaxWorkers: 2}
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	plaintext := generateData(4 << 20) // 4 MiB
	mac := macFuncForTest([32]byte{0x11, 0x22, 0x33, 0x44})

	const workers = 8
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ct, err := EncryptAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, mac)
			if err != nil {
				errs[idx] = err
				return
			}
			pt, err := DecryptAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, mac)
			if err != nil {
				errs[idx] = err
				return
			}
			if !bytes.Equal(plaintext, pt) {
				errs[idx] = errRoundTripMismatch
				return
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d: %v", i, err)
		}
	}

	// Assertion (b): per-Pipeline cap must not bleed into the global.
	if got := GetMaxWorkers(); got != 7 {
		t.Errorf("cfg.MaxWorkers=2 leaked into process-global: GetMaxWorkers()=%d, want 7", got)
	}

	// Assertion (c): decrypt-side worker-count invariance. One
	// reference ciphertext, N decrypts under a sweep of MaxWorkers
	// values — every recovered plaintext must be bit-identical.
	refCT, err := EncryptAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, mac)
	if err != nil {
		t.Fatalf("reference encrypt: %v", err)
	}
	sweep := []*Config{
		{MaxWorkers: 1},
		{MaxWorkers: 2},
		{MaxWorkers: 4},
		{MaxWorkers: 8},
		nil, // inherits process-global (7 for this test's scope)
	}
	for _, sweepCfg := range sweep {
		pt, err := DecryptAuthenticated3x256Cfg(sweepCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, refCT, mac)
		if err != nil {
			t.Errorf("decrypt cfg=%+v: %v", sweepCfg, err)
			continue
		}
		if !bytes.Equal(plaintext, pt) {
			t.Errorf("decrypt cfg=%+v: recovered plaintext differs from input", sweepCfg)
		}
	}

	// Final global-pinning assertion after the sweep, in case a decrypt
	// path bled the per-Pipeline cap into the global.
	if got := GetMaxWorkers(); got != 7 {
		t.Errorf("post-sweep global drift: GetMaxWorkers()=%d, want 7", got)
	}
}

// errRoundTripMismatch is a package-scoped sentinel used by
// [TestConfigMaxWorkersOverride]'s per-worker error slot so the
// worker goroutines can flag a plaintext mismatch without allocating
// a fresh error per goroutine.
var errRoundTripMismatch = errRoundTripMismatchType{}

type errRoundTripMismatchType struct{}

func (errRoundTripMismatchType) Error() string {
	return "recovered plaintext differs from input"
}
