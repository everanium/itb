//go:build redteam

package itb

// Attacker-side handling of the interlock nonce after it left the wire
// header.
//
// The interlock nonce is no longer a header field: it is split into three
// fragments sized by [nonceSplit] and prepended to the three interlocked
// lanes ahead of the COBS stage, inside the Pixel Barrier's coverage. A
// passive observer can therefore no longer transcribe it off the wire, so
// a red-team harness that reads `interlock_nonce_hex` out of the fixture
// metadata and feeds it to a candidate derivation is consuming secret
// material the lab handed it — the same class of lab peek as reading a
// true seed component. The helpers here replace that grant with the three
// things an attacker can actually do:
//
//  1. Measure, entirely on attacker-chosen material, whether the interlock
//     nonce reaches the Rank Barrier at all under the primitive in hand
//     ([probeInterlockNonceInvariance128]). Under a primitive whose
//     ChainHash output collapses, the barrier lanes do not depend on the
//     nonce, and the grant costs the attack nothing to give up.
//  2. Step over the fragment by its public length. The fragment's length
//     follows from the configured nonce width alone, and COBS places the
//     first barrier byte at a fixed output offset regardless of what the
//     fragment contains ([laneStreamWithUnknownFragment]).
//  3. Enumerate the derived interlock key rather than the nonce
//     ([mirrorLockBatchPRF48_128]). At 128-bit hash width the nonce's
//     entire influence on the Rank Barrier is the pair
//     [Seed128.deriveInterLockSeed] returns, so under a primitive whose
//     output is one byte per lane that influence is 16 bits wide however
//     long the nonce is.
//
// Nothing here reads victim material. Every routine takes either
// attacker-chosen constants or values the caller has already established
// as its own reference, and the callers state which.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// nonceInvarianceReport is the outcome of [probeInterlockNonceInvariance128].
type nonceInvarianceReport struct {
	seeds        int  // attacker-chosen seeds tried
	nonces       int  // attacker-chosen nonces tried per seed
	distinctKeys int  // distinct deriveInterLockSeed outputs observed
	laneTrials   int  // lane comparisons performed
	laneMatches  int  // comparisons that came out byte-identical
	invariant    bool // every comparison matched
}

// probeInterlockNonceInvariance128 measures whether the interlock nonce
// reaches the Rank Barrier's lane output under a given 128-bit primitive.
//
// This is an offline attacker capability, not a lab peek: every input is
// attacker-chosen (seeds drawn by the caller's own CSPRNG, nonces drawn
// the same way, a probe plaintext of the attacker's choosing), and the
// primitive is public. An attacker holding the ITB source and knowing
// which primitive the target runs reproduces this measurement without
// observing a single victim byte.
//
// Two quantities are reported because they can disagree, and the
// disagreement is the interesting case. distinctKeys counts how many
// distinct values [Seed128.deriveInterLockSeed] takes across the probed
// nonces — a primitive can spread that derivation widely and still lose
// it downstream, because the cascade fill re-hashes the derived key
// together with the lockSeed components over the 13-byte group block.
// laneMatches counts how often the barrier lanes themselves came out
// byte-identical under different nonces, which is what an attack
// reconstructing candidate lanes actually depends on.
//
// The verdict is bounded by the sample: `invariant` means no
// nonce-dependence was observed over seeds × nonces comparisons, not that
// none exists.
func probeInterlockNonceInvariance128(cfg *Config, h HashFunc128, keyBits, seeds, nonces int) nonceInvarianceReport {
	rep := nonceInvarianceReport{seeds: seeds, nonces: nonces, invariant: true}
	probe := make([]byte, 96)
	if _, err := rand.Read(probe); err != nil {
		return rep
	}
	nonceLen := currentNonceSizeCfg(cfg)
	keys := map[[2]uint64]struct{}{}
	n := tripleLaneLen(len(probe))
	lanes := func(s *Seed128, nonce []byte) [3][]byte {
		bp := buildLockBatchPRF48_128Cfg(cfg, s, nonce)
		a, b, c := make([]byte, n), make([]byte, n), make([]byte, n)
		splitForTriple48LockedInto(cfg, probe, bp, a, b, c)
		return [3][]byte{a, b, c}
	}
	for si := 0; si < seeds; si++ {
		s, err := NewSeed128(keyBits, h)
		if err != nil {
			return rep
		}
		var ref [3][]byte
		for ni := 0; ni < nonces; ni++ {
			nonce := make([]byte, nonceLen)
			if _, err := rand.Read(nonce); err != nil {
				return rep
			}
			lo, hi := s.deriveInterLockSeed(nonce)
			keys[[2]uint64{lo, hi}] = struct{}{}
			cur := lanes(s, nonce)
			if ni == 0 {
				ref = cur
				continue
			}
			rep.laneTrials++
			if bytes.Equal(ref[0], cur[0]) && bytes.Equal(ref[1], cur[1]) && bytes.Equal(ref[2], cur[2]) {
				rep.laneMatches++
			} else {
				rep.invariant = false
			}
		}
	}
	rep.distinctKeys = len(keys)
	return rep
}

// laneStreamWithUnknownFragment builds the COBS stream a region carries
// when the interlock-nonce fragment at the front of the lane is unknown.
//
// The encoder COBS-encodes `fragment ‖ barrier` as one buffer. COBS emits
// one code byte per zero-delimited group and elides the zeros themselves,
// so an fragLen-byte prefix always costs exactly fragLen extra output
// bytes and always leaves the first barrier byte at output offset
// fragLen+1 — whatever the fragment contains, zero bytes included. The
// group that carries the first barrier byte opens at offset fragLen, and
// every output byte from fragLen+1 onward is bit-identical to
// cobsEncode(barrier) from offset 1 onward.
//
// The returned stream therefore holds the attacker-computable tail in its
// correct absolute position, a zero-filled placeholder over
// [0, fragLen+1) where the code byte and the fragment sit, and the 0x00
// terminator the encoder appends. knownFrom is fragLen+1: a caller must
// not read a verdict out of any byte below it.
//
// The offset identity assumes the lane stays inside a single COBS
// 254-byte group boundary run, which holds for every geometry these
// harnesses build; callers pass lanes of a few hundred bytes.
func laneStreamWithUnknownFragment(barrier []byte, fragLen int) (stream []byte, knownFrom int) {
	enc := cobsEncode(barrier)
	stream = make([]byte, fragLen+len(enc)+1)
	copy(stream[fragLen+1:], enc[1:])
	stream[len(stream)-1] = 0x00
	return stream, fragLen + 1
}

// unmaskPixelWindow reconstructs the 56-bit lane window one pixel carries
// under a candidate (noisePos, dataHash) pair. It mirrors the decode body
// of [processChunk128] (process_generic.go, the serial tail loop): strip
// the noise bit, reverse the 7-bit rotation, undo the per-channel XOR,
// pack the eight 7-bit channels little-endian. Byte j of the window is
// `byte(packed >> (8*j))`, matching the encoder's byte order.
//
// The caller supplies dataHash rather than a (rotation, xorMask) pair
// because the pipeline derives both from that one value: rotation is
// dataHash % 7 and the per-channel masks are slices of
// dataHash >> DataRotationBits. Enumerating dataHash therefore enumerates
// a consistent pair, which enumerating them separately would not.
func unmaskPixelWindow(pix []byte, noisePos uint, dataHash uint64) uint64 {
	rot := uint(dataHash % 7)
	xorMask := dataHash >> DataRotationBits
	noiseMask := byte(1) << noisePos
	var packed uint64
	for ch := 0; ch < Channels; ch++ {
		channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)
		b := pix[ch]
		low := b & (noiseMask - 1)
		high := b >> (noisePos + 1)
		d := low | (high << noisePos)
		d = rotateBits7(d, 7-rot)
		d ^= channelXOR
		packed |= uint64(d) << uint(ch*DataBitsPerChannel)
	}
	return packed
}

// recoverLaneFragments enumerates the interlock-nonce fragment a region's
// first walked pixel can be carrying.
//
// Premise: the barrier lane bytes are known — the caller has either
// established the Rank Barrier output as its reference or recovered the
// derived interlock key first. Everything else comes off the wire.
//
// Under a primitive whose ChainHash128 output is one byte per lane the
// per-channel XOR masks occupy only the low bits of `dataHash >> 3`, so
// seven of the eight channels carry their lane bits unmasked and the
// per-pixel configuration space is 8 noise positions × 256 dataHash
// values = 2048. The first walked pixel covers stream bytes [0, 7), which
// is exactly the span the unknown fragment occupies. Each of the 2048
// readings is accepted only when splicing it in front of the known tail
// COBS-decodes to a buffer whose content past the fragment reproduces the
// barrier lane byte for byte — a public structural check that needs no
// plaintext knowledge and that handles a fragment containing 0x00 bytes
// without a special case, since the decode follows whatever group
// structure the candidate prefix declares.
//
// The survivor set is the result. A region whose constraint span is one
// byte (fragLen 6 against a 7-byte pixel window) leaves several readings
// consistent; a region with two spare bytes usually resolves to one. The
// caller reports the counts rather than assuming a unique answer.
func recoverLaneFragments(region []byte, width, startPixel, fragLen int, barrier []byte) [][]byte {
	if fragLen <= 0 || fragLen >= 7 {
		return nil
	}
	enc := cobsEncode(barrier)
	// The candidate window supplies stream bytes [0,7); the known tail
	// resumes at stream offset 7, which is enc offset 7-fragLen.
	tail := enc[7-fragLen:]
	pixelOffset := (startPixel % width) * Channels
	pix := region[pixelOffset : pixelOffset+Channels]
	seen := map[string]struct{}{}
	var out [][]byte
	cand := make([]byte, 7+len(tail))
	copy(cand[7:], tail)
	decBuf := make([]byte, len(cand))
	for np := uint(0); np < 8; np++ {
		for dh := uint64(0); dh < 256; dh++ {
			packed := unmaskPixelWindow(pix, np, dh)
			for j := 0; j < 7; j++ {
				cand[j] = byte(packed >> uint(8*j))
			}
			if bytes.IndexByte(cand[:7], 0x00) >= 0 {
				continue // COBS output never contains 0x00
			}
			dec := cobsDecodeInto(decBuf, cand)
			if len(dec) < fragLen+len(barrier) {
				continue
			}
			if !bytes.Equal(dec[fragLen:fragLen+len(barrier)], barrier) {
				continue
			}
			frag := append([]byte(nil), dec[:fragLen]...)
			if _, dup := seen[string(frag)]; dup {
				continue
			}
			seen[string(frag)] = struct{}{}
			out = append(out, frag)
		}
	}
	return out
}

// laneLeakPixelMatches counts how many of a region's walked pixels admit
// at least one (noisePos, rotation) reading consistent with the expected
// COBS stream, over the seven channels a below-floor primitive leaves
// without an XOR mask.
//
// The walk starts at firstPixel rather than at the head of the region:
// the caller passes 1 when the stream's leading bytes are the unknown
// interlock-nonce fragment, so no verdict is drawn from a byte the
// attacker cannot predict. Channel 0 is skipped for the same reason the
// per-pixel leak measurement skips it — it is the one channel the 8-bit
// hash output still masks.
//
// This is the scoring signal a candidate search uses: a candidate that
// reproduces the true lane bytes matches on nearly every pixel, and one
// that does not sits near zero.
func laneLeakPixelMatches(region []byte, width, startPixel int, stream []byte) int {
	totalBits := len(stream) * 8
	matched := 0
	bitIndex := DataBitsPerPixel
	for pp := 1; pp < width && bitIndex < totalBits; pp++ {
		linearIdx := (startPixel + pp) % width
		pixelOffset := linearIdx * Channels
		found := false
		for np := uint(0); np < 8 && !found; np++ {
			noiseMask := byte(1 << np)
			for rot := uint(0); rot < 7 && !found; rot++ {
				allMatch := true
				bi := bitIndex
				for ch := 0; ch < Channels; ch++ {
					if bi+DataBitsPerChannel > totalBits {
						break
					}
					pixByte := region[pixelOffset+ch]
					low := pixByte & (noiseMask - 1)
					high := pixByte >> (np + 1)
					recovered := low | (high << np)
					if ch != 0 {
						dataBits := rotateBits7(recovered, 7-rot)
						byteIdx := bi / 8
						bitOff := uint(bi % 8)
						raw := uint16(stream[byteIdx])
						if byteIdx+1 < len(stream) {
							raw |= uint16(stream[byteIdx+1]) << 8
						}
						expected := byte((raw >> bitOff) & 0x7F)
						if dataBits != expected {
							allMatch = false
							break
						}
					}
					bi += DataBitsPerChannel
				}
				if allMatch {
					found = true
				}
			}
		}
		if found {
			matched++
		}
		bitIndex += DataBitsPerPixel
	}
	return matched
}

// mirrorLockBatchPRF48_128 rebuilds the batched 128-bit Rank Barrier PRF
// around a caller-supplied derived interlock key instead of deriving that
// key from a nonce.
//
// It mirrors [buildLockBatchPRF48_128] (interlock48_cascade.go:57-77)
// with one substitution: the shipped builder opens with
// `lockLo, lockHi := lockSeed.deriveInterLockSeed(nonce)` and prepends the
// pair to the component slice, while this form takes the pair directly.
// Everything downstream — the 13-byte group block `[0x03 ‖ LE64(groupIdx)
// ‖ 4×0x00]`, the cascade call, the mask fill — is the shipped code path.
//
// The optional batched arms the shipped builder attaches when the
// lockSeed carries BatchHash / InterlockFillX16 hooks are left off. The
// cascade-fill invariant makes every arm bit-exact with the sequential
// one, so the omission is a dispatch choice and not a wire choice;
// [assertMirrorLockBatchParity128] checks that on attacker-chosen
// material rather than taking it on trust.
//
// This exists so a harness can enumerate the 16-bit derived key an 8-bit
// primitive produces instead of enumerating a 128-bit nonce it does not
// hold.
func mirrorLockBatchPRF48_128(lockSeed *Seed128, keyLo, keyHi uint64) lockBatchPRF48 {
	lockComps := make([]uint64, 2+len(lockSeed.Components))
	lockComps[0], lockComps[1] = keyLo, keyHi
	copy(lockComps[2:], lockSeed.Components)
	return lockBatchPRF48{
		factor: lockBatchFactor48_128,
		fill: func(buf []byte, groupIdx uint64, masks *[lockBatchFactor48Max][3]uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			lo, hi := lockSeed.chainHash128With(lockComps, buf)
			var prf [8]uint64
			prf[0], prf[1] = lo, hi
			fillLockMasksTriple48(&prf, lockBatchFactor48_128, masks)
		},
		fillRanks: func(buf []byte, groupIdx uint64, prf []uint64) {
			buf[0] = 0x03
			binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
			prf[0], prf[1] = lockSeed.chainHash128With(lockComps, buf)
		},
	}
}

// assertMirrorLockBatchParity128 verifies that [mirrorLockBatchPRF48_128]
// fed the key a nonce derives reproduces the lanes the shipped builder
// produces for that nonce. Attacker-chosen seed, attacker-chosen nonce,
// attacker-chosen probe plaintext: no victim material, and a drift
// between the mirror and the shipped builder surfaces here rather than as
// an enumeration that mysteriously fails to converge.
func assertMirrorLockBatchParity128(t *testing.T, cfg *Config, h HashFunc128, keyBits int) {
	t.Helper()
	s, err := NewSeed128(keyBits, h)
	if err != nil {
		t.Fatalf("mirror parity: NewSeed128: %v", err)
	}
	probe := make([]byte, 96)
	nonce := make([]byte, currentNonceSizeCfg(cfg))
	if _, err := rand.Read(probe); err != nil {
		t.Fatalf("mirror parity: rand probe: %v", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("mirror parity: rand nonce: %v", err)
	}
	n := tripleLaneLen(len(probe))
	run := func(bp lockBatchPRF48) [3][]byte {
		a, b, c := make([]byte, n), make([]byte, n), make([]byte, n)
		splitForTriple48LockedInto(cfg, probe, bp, a, b, c)
		return [3][]byte{a, b, c}
	}
	keyLo, keyHi := s.deriveInterLockSeed(nonce)
	want := run(buildLockBatchPRF48_128Cfg(cfg, s, nonce))
	got := run(mirrorLockBatchPRF48_128(s, keyLo, keyHi))
	for i := 0; i < 3; i++ {
		if !bytes.Equal(want[i], got[i]) {
			t.Fatalf("mirror parity: lane %d differs from the shipped builder", i)
		}
	}
}
