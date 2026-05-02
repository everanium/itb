package itb

import (
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

// TestConfigIsBitSoupEnabledCfg covers the three resolution paths of
// isBitSoupEnabledCfg. The BitSoup sentinel is -1 (not 0) — value 0
// means "explicitly off", which is distinct from "inherit".
func TestConfigIsBitSoupEnabledCfg(t *testing.T) {
	origBitSoup := GetBitSoup()
	t.Cleanup(func() { SetBitSoup(origBitSoup) })

	SetBitSoup(1) // global = on

	t.Run("nil_fallback_inherits_on", func(t *testing.T) {
		if !isBitSoupEnabledCfg(nil) {
			t.Errorf("nil cfg: got false, want true (global on)")
		}
	})

	t.Run("sentinel_fallback_inherits_on", func(t *testing.T) {
		cfg := &Config{BitSoup: -1}
		if !isBitSoupEnabledCfg(cfg) {
			t.Errorf("sentinel cfg: got false, want true (global on)")
		}
	})

	t.Run("explicit_off_overrides_global_on", func(t *testing.T) {
		cfg := &Config{BitSoup: 0}
		if isBitSoupEnabledCfg(cfg) {
			t.Errorf("explicit cfg BitSoup=0: got true, want false (override)")
		}
	})

	t.Run("explicit_on_overrides_global_off", func(t *testing.T) {
		SetBitSoup(0) // global flips to off
		cfg := &Config{BitSoup: 1}
		if !isBitSoupEnabledCfg(cfg) {
			t.Errorf("explicit cfg BitSoup=1: got false, want true (override)")
		}
	})
}

// TestConfigIsLockSoupEnabledCfg covers the three resolution paths of
// isLockSoupEnabledCfg. Same sentinel rule as BitSoup: -1 = inherit,
// 0 = explicit off, non-zero = explicit on.
func TestConfigIsLockSoupEnabledCfg(t *testing.T) {
	origBitSoup := GetBitSoup()
	origLockSoup := GetLockSoup()
	t.Cleanup(func() {
		SetBitSoup(origBitSoup)
		SetLockSoup(origLockSoup)
	})

	SetLockSoup(1) // global on; SetLockSoup(1) also coerces SetBitSoup(1)

	t.Run("nil_fallback_inherits_on", func(t *testing.T) {
		if !isLockSoupEnabledCfg(nil) {
			t.Errorf("nil cfg: got false, want true (global on)")
		}
	})

	t.Run("sentinel_fallback_inherits_on", func(t *testing.T) {
		cfg := &Config{LockSoup: -1}
		if !isLockSoupEnabledCfg(cfg) {
			t.Errorf("sentinel cfg: got false, want true (global on)")
		}
	})

	t.Run("explicit_off_overrides_global_on", func(t *testing.T) {
		cfg := &Config{LockSoup: 0}
		if isLockSoupEnabledCfg(cfg) {
			t.Errorf("explicit cfg LockSoup=0: got true, want false")
		}
	})

	t.Run("explicit_on_overrides_global_off", func(t *testing.T) {
		SetLockSoup(0)
		cfg := &Config{LockSoup: 1}
		if !isLockSoupEnabledCfg(cfg) {
			t.Errorf("explicit cfg LockSoup=1: got false, want true")
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
	origBitSoup := GetBitSoup()
	origLockSoup := GetLockSoup()
	origLockSeed := GetLockSeed()
	t.Cleanup(func() {
		SetNonceBits(origNonce)
		SetBarrierFill(origBarrier)
		SetBitSoup(origBitSoup)
		SetLockSoup(origLockSoup)
		SetLockSeed(int(origLockSeed))
	})

	SetNonceBits(256)
	SetBarrierFill(8)
	SetBitSoup(0) // explicit off so the snapshot pin is observable
	SetLockSoup(0)
	SetLockSeed(0)

	cfg := SnapshotGlobals()

	if cfg.NonceBits != 256 {
		t.Errorf("NonceBits: got %d, want 256", cfg.NonceBits)
	}
	if cfg.BarrierFill != 8 {
		t.Errorf("BarrierFill: got %d, want 8", cfg.BarrierFill)
	}
	if cfg.BitSoup != 0 {
		t.Errorf("BitSoup: got %d, want 0", cfg.BitSoup)
	}
	if cfg.LockSoup != 0 {
		t.Errorf("LockSoup: got %d, want 0", cfg.LockSoup)
	}
	if cfg.LockSeed != 0 {
		t.Errorf("LockSeed: got %d, want 0 (snapshot of global)", cfg.LockSeed)
	}
	if cfg.LockSeedHandle != nil {
		t.Errorf("LockSeedHandle: got %v, want nil", cfg.LockSeedHandle)
	}

	// Mutate globals after snapshot — the snapshot must not drift.
	SetNonceBits(512)
	SetBarrierFill(32)
	SetBitSoup(1)
	SetLockSoup(1)
	SetLockSeed(1)

	if cfg.NonceBits != 256 {
		t.Errorf("post-mutation drift: NonceBits = %d, want 256", cfg.NonceBits)
	}
	if cfg.BarrierFill != 8 {
		t.Errorf("post-mutation drift: BarrierFill = %d, want 8", cfg.BarrierFill)
	}
	if cfg.BitSoup != 0 {
		t.Errorf("post-mutation drift: BitSoup = %d, want 0", cfg.BitSoup)
	}
	if cfg.LockSoup != 0 {
		t.Errorf("post-mutation drift: LockSoup = %d, want 0", cfg.LockSoup)
	}
	if cfg.LockSeed != 0 {
		t.Errorf("post-mutation drift: LockSeed = %d, want 0", cfg.LockSeed)
	}

	// Symmetric direction — mutating the snapshot must not affect
	// globals (no shared backing state — config is a value type
	// returned by pointer, fully owned by the caller).
	cfg.NonceBits = 128
	if got := GetNonceBits(); got != 512 {
		t.Errorf("snapshot mutation leaked into global: got %d, want 512", got)
	}
}

// TestConfigSnapshotGlobalsLockSeedOn complements
// TestConfigSnapshotGlobals by exercising the LockSeed=1 snapshot
// path: the snapshot captures global LockSeed=1 and pins it across a
// subsequent global mutation back to 0.
func TestConfigSnapshotGlobalsLockSeedOn(t *testing.T) {
	origLockSeed := GetLockSeed()
	t.Cleanup(func() { SetLockSeed(int(origLockSeed)) })

	SetLockSeed(1)
	cfg := SnapshotGlobals()

	if cfg.LockSeed != 1 {
		t.Errorf("LockSeed: got %d, want 1 (snapshot of global on)", cfg.LockSeed)
	}

	SetLockSeed(0) // global flips off

	if cfg.LockSeed != 1 {
		t.Errorf("post-mutation drift: LockSeed = %d, want 1", cfg.LockSeed)
	}
}

// TestConfigIsLockSeedActiveCfg covers the three resolution paths of
// isLockSeedActiveCfg. Same sentinel rule as BitSoup / LockSoup:
// -1 = inherit, 0 = explicit off, non-zero = explicit on.
func TestConfigIsLockSeedActiveCfg(t *testing.T) {
	origLockSeed := GetLockSeed()
	t.Cleanup(func() { SetLockSeed(int(origLockSeed)) })

	SetLockSeed(1) // global on

	t.Run("nil_fallback_inherits_on", func(t *testing.T) {
		if !isLockSeedActiveCfg(nil) {
			t.Errorf("nil cfg: got false, want true (global on)")
		}
	})

	t.Run("sentinel_fallback_inherits_on", func(t *testing.T) {
		cfg := &Config{LockSeed: -1}
		if !isLockSeedActiveCfg(cfg) {
			t.Errorf("sentinel cfg: got false, want true (global on)")
		}
	})

	t.Run("explicit_off_overrides_global_on", func(t *testing.T) {
		cfg := &Config{LockSeed: 0}
		if isLockSeedActiveCfg(cfg) {
			t.Errorf("explicit cfg LockSeed=0: got true, want false")
		}
	})

	t.Run("explicit_on_overrides_global_off", func(t *testing.T) {
		SetLockSeed(0)
		cfg := &Config{LockSeed: 1}
		if !isLockSeedActiveCfg(cfg) {
			t.Errorf("explicit cfg LockSeed=1: got false, want true")
		}
	})
}
