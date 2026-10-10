package itb

import (
	"crypto/rand"
	"fmt"

	"github.com/everanium/itb/internal/drbg"
)

// nomacTagStubSizeCfg returns the number of bytes the No MAC Encrypt3x
// pipeline reserves at the tail of the third region's container capacity
// so its on-wire envelope matches the paired authenticated envelope
// (payload || MAC tag || 1-byte flag) bit-for-bit in shape, across
// both the Single Message and Streaming pipelines. The bytes carry
// pure DRBG dummy content on the No MAC path; the decrypt side
// ignores them (the COBS terminator lands strictly before this region,
// so the null-search stops well ahead of the stub).
//
// [Config.TagStubSize] sets the tag-size portion of the
// reservation; zero (and a nil cfg) falls back to 32, which aligns
// with each shipped MAC in macs/ (each emits a 32-byte tag). User-pluggable
// custom MACs registered via
// [github.com/everanium/itb/macs.Register] accept TagSize in
// [16, 64] and therefore may emit tags of a different length; the
// Low-Level authenticated paths probe the closure's tag length at
// construction and reserve the payload precisely, so correctness is
// preserved for any tag size. A Low-Level No MAC caller pairing with a
// custom-tag-size authenticated peer sets Config.TagStubSize to
// the peer's MAC tag length so the envelope shapes stay matched; a
// MAC-carrying triple.Pipeline populates the field from its profile's
// MAC automatically.
//
// The +1 mirrors the streamFlagByte position AEAD chunks occupy for
// the finalFlag indicator.
func nomacTagStubSizeCfg(cfg *Config) int {
	tagSize := 32
	if cfg != nil && cfg.TagStubSize > 0 {
		tagSize = cfg.TagStubSize
	}
	return tagSize + 1
}

// validateTagStubSizeCfg rejects an out-of-range [Config.TagStubSize]
// before any wire is produced. Accepted values: 0 (defer to the
// 32-byte default) or 16..64 inclusive — the floor matches the
// macs.Register TagSize >= 16 contract so the whole MAC-related API
// shares one floor, and the ceiling covers the longest realistic MAC
// tag (64 bytes, e.g. HMAC-SHA-512); values beyond it indicate
// misconfiguration. Consulted by the No MAC encrypt entry points
// ([Encrypt3x128Cfg] / [Encrypt3x256Cfg] / [Encrypt3x512Cfg] and
// their EncryptStream counterparts) ahead of nonce generation and
// prefix emission; the decrypt side never consumes the stub.
func validateTagStubSizeCfg(cfg *Config) error {
	if cfg != nil && cfg.TagStubSize != 0 && (cfg.TagStubSize < 16 || cfg.TagStubSize > 64) {
		return fmt.Errorf("itb: cfg.TagStubSize=%d must be 0 or in [16, 64]", cfg.TagStubSize)
	}
	return nil
}

// validateConfigCfg rejects an out-of-range [Config.NonceBits],
// [Config.BarrierFill], or [Config.MaxWorkers] before any wire is
// produced or persisted. Accepted values:
//
//   - NonceBits: 0 (defer to [DefaultNonceBits]) or 128 / 256 / 512.
//     Any other value would let a sender emit a nonce width the
//     receiver's Blob-import decoder rejects with [ErrBlobMalformed],
//     silently corrupting the on-wire nonce material.
//   - BarrierFill: 0 (defer to [DefaultBarrierFill]) or one of
//     {1, 2, 4, 8, 16, 32}. Off-schedule values produce the same
//     Blob-import mismatch; huge positive values would overflow the
//     `side * side * 8` container-size arithmetic in
//     [calcContainerSize3Cfg].
//   - MaxWorkers: non-negative. Zero defers to runtime.NumCPU; a
//     positive value is clamped at 256 at consumption. The field is
//     per-machine tuning and never travels in a blob; the guard keeps
//     a negative value out of the Cfg-aware entry points.
//   - Mode: 0 (defer to the per-region floor) or 1 / 2. Any other
//     value is reported as [ErrBlobModeMismatch], the sentinel the
//     Export3Cfg entries raise for an out-of-range Opts.Mode and the
//     Import3Cfg entries raise for an out-of-range blob mode, so one
//     condition carries one error identity whichever side set it.
//
// Consulted by every Cfg-aware Encrypt entry point in the itb-root
// package and by every [Blob128.Export3Cfg] / [Blob256.Export3Cfg] /
// [Blob512.Export3Cfg] call ahead of the wire-producing step; the
// receiver's import path uses [applyGlobalsV1ToCfg] for the same
// enum checks so a poisoned blob never lands.
func validateConfigCfg(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	switch cfg.NonceBits {
	case 0, 128, 256, 512:
	default:
		return fmt.Errorf("itb: cfg.NonceBits=%d must be 0 or one of {128, 256, 512}", cfg.NonceBits)
	}
	switch cfg.BarrierFill {
	case 0, 1, 2, 4, 8, 16, 32:
	default:
		return fmt.Errorf("itb: cfg.BarrierFill=%d must be 0 or one of {1, 2, 4, 8, 16, 32}", cfg.BarrierFill)
	}
	if cfg.MaxWorkers < 0 {
		return fmt.Errorf("itb: cfg.MaxWorkers=%d must be >= 0", cfg.MaxWorkers)
	}
	switch cfg.Mode {
	case 0, 1, 2:
	default:
		return fmt.Errorf("%w (cfg.Mode=%d)", ErrBlobModeMismatch, cfg.Mode)
	}
	if !drbg.Known(cfg.DRBG) {
		return fmt.Errorf("itb: cfg.DRBG=%q is not an installed DRBG fill primitive (want \"\" or one of %v)", cfg.DRBG, drbg.Names())
	}
	return nil
}

// fillNomacPrefix draws the No MAC dummy prefix straight into dst —
// the reserved lead bytes of the wire [Encrypt3x128Cfg] /
// [Encrypt3x256Cfg] / [Encrypt3x512Cfg] return, and of every chunk
// record the No MAC streaming encoders emit — from crypto/rand, the
// same source as the streamID and chunk prefixes of the MAC arm, so a
// wire observer cannot tell the No MAC prefix from the MAC arm's.
// The bytes are never re-consumed; the decoder skips the same-length
// window.
func fillNomacPrefix(dst []byte) error {
	if _, err := rand.Read(dst); err != nil {
		return fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return nil
}
