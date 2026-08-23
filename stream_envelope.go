package itb

import (
	"crypto/rand"
	"fmt"
)

// nomacStreamPrefix draws a fresh CSPRNG dummy stream anchor for the
// No-MAC streaming path. Length matches [streamIDPrefixLen] so a wire
// observer cannot distinguish the No-MAC envelope prefix from the
// AEAD streamID prefix. The bytes are never re-consumed on either
// side — the decoder just skips the same-length window.
func nomacStreamPrefix() ([]byte, error) {
	buf := make([]byte, streamIDPrefixLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return buf, nil
}

// nomacTagStubSize is the number of bytes the No-MAC Encrypt3x pipeline
// reserves at the tail of the third snake's container capacity so its
// on-wire envelope matches the Streaming AEAD chunk envelope
// (payload || 32-byte MAC tag || 1-byte finalFlag) bit-for-bit in
// shape. The bytes carry pure CSPRNG dummy content on the No-MAC path;
// the decrypt side ignores them (the COBS terminator lands strictly
// before this region, so the null-search stops well ahead of the stub).
//
// The 32 aligns with every shipped MAC in macs/: HMAC-BLAKE3,
// HMAC-SHA256, KMAC-256 all emit 32-byte tags. Adding a MAC that emits
// a different tag length would turn MAC-primitive choice into an
// on-wire length leak; the registry enforces the invariant.
//
// The +1 mirrors the streamFlagByte position AEAD chunks occupy for
// the finalFlag indicator.
const nomacTagStubSize = 32 + 1
