package itb

import (
	"crypto/rand"
	"fmt"
)

// nomacStreamPrefix draws a fresh CSPRNG dummy stream anchor for the
// No MAC streaming path. Length matches [streamIDPrefixLen] so a wire
// observer cannot distinguish the No MAC envelope prefix from the
// AEAD streamID prefix. The bytes are never re-consumed on either
// side — the decoder just skips the same-length window.
func nomacStreamPrefix() ([]byte, error) {
	buf := make([]byte, streamIDPrefixLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return buf, nil
}

// nomacTagStubSizeCfg returns the number of bytes the No MAC Encrypt3x
// pipeline reserves at the tail of the third snake's container capacity
// so its on-wire envelope matches the paired authenticated envelope
// (payload || MAC tag || 1-byte flag) bit-for-bit in shape, across
// both the Single Message and Streaming pipelines. The bytes carry
// pure CSPRNG dummy content on the No MAC path; the decrypt side
// ignores them (the COBS terminator lands strictly before this region,
// so the null-search stops well ahead of the stub).
//
// [Config.TagStubSize] sets the tag-size portion of the
// reservation; zero (and a nil cfg) falls back to 32, which aligns
// with every shipped MAC in macs/: HMAC-BLAKE3, HMAC-SHA256, KMAC-256
// all emit 32-byte tags. User-pluggable custom MACs registered via
// [github.com/everanium/itb/macs.Register] accept TagSize in
// [16, 64] and therefore may emit tags of a different length; the
// Low-Level
// authenticated paths probe the closure's tag length at construction
// and reserve the payload precisely, so correctness is preserved for
// any tag size. A Low-Level No MAC caller pairing with a
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
