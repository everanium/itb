package itb

import (
	"bytes"
	"fmt"
	"testing"
)

// TestTagStubSizeCfgResolution pins the resolution contract of
// nomacTagStubSizeCfg: nil cfg and a zero-value field fall back to
// the 32-byte default (32 + 1 = 33 reserved), and a positive
// Config.TagStubSize overrides the tag-size portion while the
// +1 flag-slot mirror is always appended. The override arm is the
// Low-Level explicit-control surface: a No MAC caller pairing with a
// custom-tag-size authenticated peer forces the reservation to any
// value, independent of what any MAC closure would probe to.
func TestTagStubSizeCfgResolution(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want int
	}{
		{"nil-cfg", nil, 33},
		{"zero-field", &Config{}, 33},
		{"tag16", &Config{TagStubSize: 16}, 17},
		{"tag20", &Config{TagStubSize: 20}, 21},
		{"tag32-explicit", &Config{TagStubSize: 32}, 33},
		{"tag48", &Config{TagStubSize: 48}, 49},
		{"tag64", &Config{TagStubSize: 64}, 65},
	}
	for _, tc := range cases {
		if got := nomacTagStubSizeCfg(tc.cfg); got != tc.want {
			t.Errorf("%s: nomacTagStubSizeCfg = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// makeTagMAC returns a deterministic MACFunc emitting a zero tag of
// the given length, so envelope byte counts depend only on the chunk
// sizing arithmetic — the same convention dummy32MAC uses for the
// shipped-32 parity tests.
func makeTagMAC(tagSize int) MACFunc {
	return func(_ []byte) []byte { return make([]byte, tagSize) }
}

// TestSingleMessageParityCustomTagSizes verifies the Single Message
// envelope-size parity between the No MAC path (Encrypt3xNCfg with
// Config.TagStubSize set to the peer's tag length) and the
// MAC Authenticated path (EncryptAuthenticated3xNCfg with a MAC of
// that tag length) across tag sizes beyond the shipped 32. A fixed
// nonce is injected via testNonceOverride so the mask-driven byte
// distribution across the three snakes is identical on both paths;
// with equal reservations (tagSize + 1 on both sides) the container
// arithmetic then yields byte-count-equal envelopes. Both envelopes
// are round-tripped to confirm the pair is wire-compatible
// end-to-end, not only length-equal.
func TestSingleMessageParityCustomTagSizes(t *testing.T) {
	tagSizes := []int{16, 20, 32, 64}
	sizes := []int{777, 64 * 1024}

	t.Run("w512", func(t *testing.T) {
		installTestNonce(t, nonceFixture(currentNonceSizeCfg(nil)))
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
		for _, ts := range tagSizes {
			for _, sz := range sizes {
				t.Run(fmt.Sprintf("tag=%d/plaintext=%d", ts, sz), func(t *testing.T) {
					data := randomPlaintext(t, sz)
					cfg := &Config{TagStubSize: ts}
					macF := makeTagMAC(ts)

					ctNoMAC, err := Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
					if err != nil {
						t.Fatalf("Encrypt3x512Cfg: %v", err)
					}
					ctMAC, err := EncryptAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, macF)
					if err != nil {
						t.Fatalf("EncryptAuthenticated3x512Cfg: %v", err)
					}
					if len(ctMAC) != len(ctNoMAC) {
						t.Fatalf("envelope size drift (tag=%d): MAC=%d No MAC=%d", ts, len(ctMAC), len(ctNoMAC))
					}

					ptNoMAC, err := Decrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctNoMAC)
					if err != nil {
						t.Fatalf("Decrypt3x512Cfg: %v", err)
					}
					if !bytes.Equal(ptNoMAC, data) {
						t.Fatal("No MAC round-trip mismatch")
					}
					ptMAC, err := DecryptAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctMAC, macF)
					if err != nil {
						t.Fatalf("DecryptAuthenticated3x512Cfg: %v", err)
					}
					if !bytes.Equal(ptMAC, data) {
						t.Fatal("MAC Authenticated round-trip mismatch")
					}
				})
			}
		}
	})

	// The 128- and 256-bit width files carry the same reservation
	// call sites; one non-32 tag size each guards them against drift.
	t.Run("w128", func(t *testing.T) {
		installTestNonce(t, nonceFixture(currentNonceSizeCfg(nil)))
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)
		data := randomPlaintext(t, 4096)
		cfg := &Config{TagStubSize: 16}
		macF := makeTagMAC(16)
		ctNoMAC, err := Encrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
		if err != nil {
			t.Fatalf("Encrypt3x128Cfg: %v", err)
		}
		ctMAC, err := EncryptAuthenticated3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, macF)
		if err != nil {
			t.Fatalf("EncryptAuthenticated3x128Cfg: %v", err)
		}
		if len(ctMAC) != len(ctNoMAC) {
			t.Fatalf("envelope size drift (tag=16): MAC=%d No MAC=%d", len(ctMAC), len(ctNoMAC))
		}
	})
	t.Run("w256", func(t *testing.T) {
		installTestNonce(t, nonceFixture(currentNonceSizeCfg(nil)))
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures256(t, 512)
		data := randomPlaintext(t, 4096)
		cfg := &Config{TagStubSize: 64}
		macF := makeTagMAC(64)
		ctNoMAC, err := Encrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
		if err != nil {
			t.Fatalf("Encrypt3x256Cfg: %v", err)
		}
		ctMAC, err := EncryptAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, macF)
		if err != nil {
			t.Fatalf("EncryptAuthenticated3x256Cfg: %v", err)
		}
		if len(ctMAC) != len(ctNoMAC) {
			t.Fatalf("envelope size drift (tag=64): MAC=%d No MAC=%d", len(ctMAC), len(ctNoMAC))
		}
	})
}

// TestStreamingParityCustomTagSizes verifies the streaming
// envelope-size parity between the No MAC stream (EncryptStream3xNCfg
// with Config.TagStubSize set to the peer's tag length) and the
// Streaming AEAD stream (EncryptStreamAuth3xNCfg with a MAC of that
// tag length): identical chunk counts and identical total wire byte
// counts under a fixed nonce, for tag sizes beyond the shipped 32.
// The No MAC 32-byte CSPRNG dummy prefix and the AEAD streamID prefix
// are the same length by construction, so per-chunk parity carries
// through to the full-stream envelope.
func TestStreamingParityCustomTagSizes(t *testing.T) {
	installTestNonce(t, nonceFixture(currentNonceSizeCfg(nil)))
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
	const chunkSize = 8192
	data := randomPlaintext(t, 20000) // 3 chunks: 8192 + 8192 + 3616

	for _, ts := range []int{16, 64} {
		t.Run(fmt.Sprintf("tag=%d", ts), func(t *testing.T) {
			cfg := &Config{TagStubSize: ts}
			macF := makeTagMAC(ts)

			var noMACTotal, aeadTotal int
			var noMACChunks, aeadChunks int
			err := EncryptStream3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, func(chunk []byte) error {
				noMACTotal += len(chunk)
				noMACChunks++
				return nil
			})
			if err != nil {
				t.Fatalf("EncryptStream3x512Cfg: %v", err)
			}
			err = EncryptStreamAuth3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, macF, func(chunk []byte) error {
				aeadTotal += len(chunk)
				aeadChunks++
				return nil
			})
			if err != nil {
				t.Fatalf("EncryptStreamAuth3x512Cfg: %v", err)
			}
			if noMACChunks != aeadChunks {
				t.Fatalf("chunk count drift (tag=%d): No MAC=%d AEAD=%d", ts, noMACChunks, aeadChunks)
			}
			if noMACTotal != aeadTotal {
				t.Fatalf("stream envelope size drift (tag=%d): No MAC=%d AEAD=%d", ts, noMACTotal, aeadTotal)
			}
		})
	}
}

// TestTagStubSizeRangeRejectedLowLevel pins the Low-Level entry-point
// validation of Config.TagStubSize: the No MAC encrypt entries
// (Single Message and Streaming) reject values outside {0} ∪ [16, 64]
// before any wire is produced, and the boundary values pass. The
// Streaming arm is checked before the envelope prefix is emitted, so
// a rejected stream produces zero output bytes.
func TestTagStubSizeRangeRejectedLowLevel(t *testing.T) {
	installTestNonce(t, nonceFixture(currentNonceSizeCfg(nil)))
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
	data := randomPlaintext(t, 256)

	for _, stub := range []int{-1, 1, 15, 65, 128} {
		cfg := &Config{TagStubSize: stub}
		if _, err := Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data); err == nil {
			t.Errorf("Encrypt3x512Cfg accepted TagStubSize=%d, want rejection", stub)
		}
		emitted := 0
		err := EncryptStream3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, 128, func(chunk []byte) error {
			emitted += len(chunk)
			return nil
		})
		if err == nil {
			t.Errorf("EncryptStream3x512Cfg accepted TagStubSize=%d, want rejection", stub)
		}
		if emitted != 0 {
			t.Errorf("EncryptStream3x512Cfg TagStubSize=%d emitted %d bytes before rejection", stub, emitted)
		}
	}

	for _, stub := range []int{0, 16, 64} {
		cfg := &Config{TagStubSize: stub}
		if _, err := Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data); err != nil {
			t.Errorf("Encrypt3x512Cfg rejected TagStubSize=%d: %v", stub, err)
		}
	}
}

// TestConfigNonceBitsRangeRejectedLowLevel pins the Low-Level
// [validateConfigCfg] rejection of every out-of-enum
// [Config.NonceBits] value at every Cfg-aware Encrypt entry point.
// The sentinel 0 and the three shipped widths (128 / 256 / 512) pass;
// any other value would let the sender emit a nonce width the
// receiver's [Blob512.Import3Cfg] would refuse, so the check fires
// fail-fast at the entry point.
func TestConfigNonceBitsRangeRejectedLowLevel(t *testing.T) {
	installTestNonce(t, nonceFixture(currentNonceSizeCfg(nil)))
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
	data := randomPlaintext(t, 256)
	mac := makeTagMAC(32)

	for _, nb := range []int{-1, 1, 64, 129, 255, 384, 511, 513, 999, 1024} {
		cfg := &Config{NonceBits: nb}
		if _, err := Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data); err == nil {
			t.Errorf("Encrypt3x512Cfg accepted NonceBits=%d, want rejection", nb)
		}
		if _, err := EncryptAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, mac); err == nil {
			t.Errorf("EncryptAuthenticated3x512Cfg accepted NonceBits=%d, want rejection", nb)
		}
		emitted := 0
		err := EncryptStream3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, 128, func(chunk []byte) error {
			emitted += len(chunk)
			return nil
		})
		if err == nil {
			t.Errorf("EncryptStream3x512Cfg accepted NonceBits=%d, want rejection", nb)
		}
		if emitted != 0 {
			t.Errorf("EncryptStream3x512Cfg NonceBits=%d emitted %d bytes before rejection", nb, emitted)
		}
	}
}

// TestConfigBarrierFillRangeRejectedLowLevel pins the same fail-fast
// rejection for [Config.BarrierFill] — sentinel 0 and the shipped
// {1, 2, 4, 8, 16, 32} pass; every other value (off-schedule,
// negative, or huge enough to overflow the side*side*8 container
// arithmetic in [calcContainerSize3Cfg]) is rejected before any wire
// is produced.
func TestConfigBarrierFillRangeRejectedLowLevel(t *testing.T) {
	installTestNonce(t, nonceFixture(currentNonceSizeCfg(nil)))
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
	data := randomPlaintext(t, 256)
	mac := makeTagMAC(32)

	for _, bf := range []int{-1, 3, 5, 6, 7, 9, 15, 17, 33, 100, 1_000_000_000} {
		cfg := &Config{BarrierFill: bf}
		if _, err := Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data); err == nil {
			t.Errorf("Encrypt3x512Cfg accepted BarrierFill=%d, want rejection", bf)
		}
		if _, err := EncryptAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, mac); err == nil {
			t.Errorf("EncryptAuthenticated3x512Cfg accepted BarrierFill=%d, want rejection", bf)
		}
	}
}

// TestConfigMaxWorkersRejectsNegative pins the fail-fast rejection of
// a negative [Config.MaxWorkers]. Zero remains the "defer to
// runtime.NumCPU" sentinel; positive values are clamped at consumption.
func TestConfigMaxWorkersRejectsNegative(t *testing.T) {
	installTestNonce(t, nonceFixture(currentNonceSizeCfg(nil)))
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
	data := randomPlaintext(t, 256)

	for _, mw := range []int{-1, -2, -1024} {
		cfg := &Config{MaxWorkers: mw}
		if _, err := Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data); err == nil {
			t.Errorf("Encrypt3x512Cfg accepted MaxWorkers=%d, want rejection", mw)
		}
	}
}
