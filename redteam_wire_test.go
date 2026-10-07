//go:build redteam

package itb

import "encoding/binary"

// Single Message wire layout, as the red-team probes parse it in memory
// and as every corpus file they write holds it:
//
//	[prefix 32][main nonce N][W 2 BE][H 2 BE][container W·H·Channels]
//
// The prefix is a CSPRNG dummy on the No MAC arm and the MAC-bound
// streamID on the MAC arm. It is derived from no seed and carries no
// information about the plaintext, so the probes read past it; it is
// attacker-visible public bytes like the rest of the wire. Corpus files
// hold the whole wire. Their metadata records the two leading lengths
// as `prefix_size` (32) and `header_size` (N + 4), so a consumer finds
// the main nonce at `prefix_size` and the container at
// `prefix_size + header_size`.

// smPrefixLen is the length of the Single Message prefix.
const smPrefixLen = streamIDPrefixLen

// smWire holds the parts of one Single Message wire. Every slice
// aliases the wire.
type smWire struct {
	prefix    []byte // 32 bytes
	mainNonce []byte // N bytes
	width     int
	height    int
	container []byte // width·height·Channels bytes
}

// smContainerOffset is the byte offset of the container inside a
// Single Message wire whose main nonce is nonceLen bytes long —
// prefix, nonce and the two 16-bit dimensions.
func smContainerOffset(nonceLen int) int { return smPrefixLen + nonceLen + 4 }

// parseSMWire splits a Single Message wire into its parts; nonceLen is
// the main-nonce length of the Config that produced it. Panics on a
// wire shorter than its header plus the container the header
// announces — the probes hand it fresh Encrypt output or a corpus file
// written from one.
func parseSMWire(wire []byte, nonceLen int) smWire {
	hdr := wire[smPrefixLen : smPrefixLen+nonceLen+4]
	w := int(binary.BigEndian.Uint16(hdr[nonceLen:]))
	h := int(binary.BigEndian.Uint16(hdr[nonceLen+2:]))
	off := smContainerOffset(nonceLen)
	return smWire{
		prefix:    wire[:smPrefixLen],
		mainNonce: hdr[:nonceLen],
		width:     w,
		height:    h,
		container: wire[off : off+w*h*Channels],
	}
}
