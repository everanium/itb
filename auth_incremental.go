package itb

// MACIncrementalFunc is the optional multi-slice arm of the pluggable
// MAC interface. Where [MACFunc] receives the MAC input as one
// contiguous slice — forcing the authenticated entry points to
// concatenate the three per-third payloads (plus the streaming
// trailer) into a pooled scratch buffer first — a MACIncrementalFunc
// absorbs the chunks in order and returns the tag directly. The
// contract is byte-for-byte equivalence:
//
//	inc(a, b, c) == mac(concat(a, b, c))
//
// for every chunk split, where mac is the [MACFunc] built from the
// same primitive and key. The authenticated entry points consult
// [Config.MACIncremental] and use it when non-nil, skipping the
// concatenation copy entirely; a nil field keeps the legacy
// concatenate-then-MAC path. MACFunc remains the primary type —
// MACIncrementalFunc is additive.
type MACIncrementalFunc func(chunks ...[]byte) []byte

// macTagCfg computes the MAC tag over the logical concatenation of
// parts: via cfg.MACIncremental when present (no concatenation copy),
// via macFunc over a pooled scratch concatenation otherwise. Both
// arms return the same tag byte-for-byte per the
// [MACIncrementalFunc] contract.
func macTagCfg(cfg *Config, macFunc MACFunc, parts ...[]byte) []byte {
	if cfg != nil && cfg.MACIncremental != nil {
		return cfg.MACIncremental(parts...)
	}
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	bufPtr, buf := acquireBuffer(total)
	defer releaseBuffer(bufPtr, buf)
	off := 0
	for _, p := range parts {
		off += copy(buf[off:], p)
	}
	return macFunc(buf[:total])
}
