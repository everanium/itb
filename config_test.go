package itb

import (
	"bytes"
	"sync"
	"testing"
)

// TestConfigCurrentNonceSizeCfg covers the three resolution paths of
// currentNonceSizeCfg: nil cfg (inherits default), cfg with sentinel 0
// (inherits default), and cfg with explicit non-zero NonceBits.
func TestConfigCurrentNonceSizeCfg(t *testing.T) {
	t.Run("nil_fallback", func(t *testing.T) {
		if got := currentNonceSizeCfg(nil); got != DefaultNonceBits/8 {
			t.Errorf("nil cfg: got %d bytes, want %d", got, DefaultNonceBits/8)
		}
	})

	t.Run("sentinel_fallback", func(t *testing.T) {
		cfg := &Config{NonceBits: 0}
		if got := currentNonceSizeCfg(cfg); got != DefaultNonceBits/8 {
			t.Errorf("sentinel cfg: got %d bytes, want %d", got, DefaultNonceBits/8)
		}
	})

	t.Run("explicit_overrides_default", func(t *testing.T) {
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
	t.Run("nil_fallback", func(t *testing.T) {
		if got := currentBarrierFillCfg(nil); got != DefaultBarrierFill {
			t.Errorf("nil cfg: got %d, want %d", got, DefaultBarrierFill)
		}
	})

	t.Run("sentinel_fallback", func(t *testing.T) {
		cfg := &Config{BarrierFill: 0}
		if got := currentBarrierFillCfg(cfg); got != DefaultBarrierFill {
			t.Errorf("sentinel cfg: got %d, want %d", got, DefaultBarrierFill)
		}
	})

	t.Run("explicit_overrides_default", func(t *testing.T) {
		for _, want := range []int{1, 2, 4, 8, 16, 32} {
			cfg := &Config{BarrierFill: want}
			if got := currentBarrierFillCfg(cfg); got != want {
				t.Errorf("explicit cfg BarrierFill=%d: got %d", want, got)
			}
		}
	})
}

// TestConfigGenerateNonceCfg verifies that generateNonceCfg honours
// the cfg-side NonceBits override and falls back to the compile-in
// default when cfg is nil or the field is the inherit sentinel.
func TestConfigGenerateNonceCfg(t *testing.T) {
	t.Run("nil_inherits_default_size", func(t *testing.T) {
		nonce, err := generateNonceCfg(nil)
		if err != nil {
			t.Fatalf("generateNonceCfg(nil): %v", err)
		}
		if len(nonce) != DefaultNonceBits/8 {
			t.Errorf("nil cfg: got %d-byte nonce, want %d", len(nonce), DefaultNonceBits/8)
		}
	})

	t.Run("explicit_overrides_default_size", func(t *testing.T) {
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

// TestConfigZeroDefaultsToDefaultConstants ratifies the fallback-via-
// constant path: a zero-value *Config passed to a Cfg-suffixed entry
// point encrypts and round-trips cleanly using [DefaultNonceBits] /
// [DefaultBarrierFill] / runtime.NumCPU.
func TestConfigZeroDefaultsToDefaultConstants(t *testing.T) {
	cfg := &Config{}
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	plaintext := []byte("zero cfg round-trip")
	ct, err := Encrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x256Cfg(zero cfg): %v", err)
	}
	pt, err := Decrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256Cfg(zero cfg): %v", err)
	}
	if !bytes.Equal(plaintext, pt) {
		t.Fatalf("zero cfg round-trip mismatch")
	}
}

// TestConfigMaxWorkersOverride verifies the per-encryptor MaxWorkers
// field flows through the *Cfg entry points into effectiveWorkersCfg.
// Confirms every round-trip matches the input byte-exact and that a
// decrypt-side sweep of MaxWorkers values recovers bit-identical
// plaintext.
func TestConfigMaxWorkersOverride(t *testing.T) {
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

	// Decrypt-side worker-count invariance. One reference ciphertext,
	// N decrypts under a sweep of MaxWorkers values — every recovered
	// plaintext must be bit-identical.
	refCT, err := EncryptAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, mac)
	if err != nil {
		t.Fatalf("reference encrypt: %v", err)
	}
	sweep := []*Config{
		{MaxWorkers: 1},
		{MaxWorkers: 2},
		{MaxWorkers: 4},
		{MaxWorkers: 8},
		nil, // inherits runtime.NumCPU
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
