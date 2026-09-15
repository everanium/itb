package itb

// Interlock-nonce placement inside the three interlocked lanes.
//
// The interlock nonce is not a wire header field. It is split into
// three fragments — one per interlocked lane — and prepended to the
// lane bytes the Rank Barrier produces, ahead of the COBS stage. Every
// downstream stage is agnostic to the fragment: COBS encodes the lane
// whole, the terminator scan and the tail DRBG fill see one longer
// byte array, and the Pixel Barrier walks the resulting payload
// unchanged. Because COBS eliminates zero bytes from its output by
// construction, zeros inside a fragment are absorbed and the
// terminator scan needs no offset.
//
// On the decode side the fragments are stripped off the COBS-decoded
// lanes and reassembled immediately before the final interleave, the
// single point at which the interlock nonce is consumed. Nothing
// between the Pixel Barrier strip and that call needs it, the MAC
// included, so the fragments are always available in time: the batched
// interleave splits its workers over chunk groups and reads all three
// lanes simultaneously, which means it cannot begin until every lane is
// fully materialised.
//
// Both sides derive the split from the configured nonce size alone, so
// no length information travels on the wire. Placing the fragments
// inside the payload also brings the interlock nonce under the MAC on
// the authenticated shapes, whose input is the three COBS-framed lane
// buffers.
//
// Why this depth and no deeper. The fragments sit ahead of COBS and
// under the Pixel Barrier, but outside the Rank Barrier, and both
// halves of that are forced rather than chosen.
//
// They cannot go deeper: inverting the Rank Barrier requires the
// per-chunk mask triple, which is keyed by the interlock nonce, so a
// nonce hidden behind that permutation could never be recovered to
// undo it. The dependency is circular by construction.
//
// They need not go deeper: the fragment carries CSPRNG bytes, so the
// derivable offsets expose no anchor. A known-plaintext attacker needs
// known values to constrain, and there are none at those positions;
// the positions that do carry predictable content are the ones the
// Rank Barrier permutes. The Pixel Barrier's per-pixel rotation, noise
// insertion and channelXOR are therefore what the fragment needs, and
// all it needs.

// nonceSplit returns the per-lane fragment lengths of an nonceLen-byte
// interlock nonce spread across the three interlocked lanes, together
// with each fragment's starting offset inside the nonce. Remainder
// bytes go to the lowest-indexed lanes, which holds the three lanes
// within one byte of each other: container sizing takes the maximum
// over the thirds and the container is three such thirds, so an
// unbalanced split would cost roughly three times the wire growth of a
// balanced one.
func nonceSplit(nonceLen int) (lens [3]int, offs [3]int) {
	base, rem := nonceLen/3, nonceLen%3
	off := 0
	for i := 0; i < 3; i++ {
		lens[i] = base
		if i < rem {
			lens[i]++
		}
		offs[i] = off
		off += lens[i]
	}
	return lens, offs
}

// recoverInterlockNonce strips the interlock-nonce fragment off the
// front of each COBS-decoded lane and reassembles the nonce. lanes[i]
// carries whatever follows the fragment in parts[i] and is handed
// straight to the interleave.
//
// Plausible-decryption invariant: never errors, never panics.
// Wrong-seed brute-force feeds in lanes whose COBS decode truncated at
// whatever spurious 0x00 the garbage bytes contained, so parts[i] can
// be shorter than its own fragment. The take is clamped to the bytes
// that exist, the rest of the fragment stays zero, and the lane keeps
// the remainder — possibly empty. One code path covers both cases;
// [padLanesToEqualEven] absorbs the resulting length mismatch exactly
// as it absorbs a wrong-seed truncation on any other lane.
func recoverInterlockNonce(nonceLen int, parts [3][]byte) (ilNonce []byte, lanes [3][]byte) {
	lens, offs := nonceSplit(nonceLen)
	ilNonce = make([]byte, nonceLen)
	for i := 0; i < 3; i++ {
		take := lens[i]
		if take > len(parts[i]) {
			take = len(parts[i])
		}
		copy(ilNonce[offs[i]:offs[i]+lens[i]], parts[i][:take])
		lanes[i] = parts[i][take:]
	}
	return ilNonce, lanes
}
