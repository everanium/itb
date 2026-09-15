package itb

// laneScratch holds the per-worker hash-input buffers of the pixel
// pipeline: one contiguous block sliced into eight noise lanes and eight
// data lanes, each laid out as [pixelIndex:4][nonce] with the nonce
// pre-copied at offset 4 (the pixel-index slot is written per call).
// Lane 0 of each family doubles as the serial single-call buffer; the
// four-lane and eight-lane views alias the same storage so the batched
// hash paths see one set of bytes.
//
// One allocation per worker replaces the per-lane make calls and the
// checkouts of sub-100-byte lanes from the megabyte-class bufferPool —
// checkouts that displaced the pool's large payload items and forced
// fresh full-size allocations on the next payload acquire.
type laneScratch struct {
	block  []byte
	noise  [8][]byte
	data   [8][]byte
	noise4 [4][]byte
	data4  [4][]byte
}

// newLaneScratch allocates the lane block for a nonce of nonceLen bytes
// and copies nonce into every lane at offset 4. Every lane is a
// capacity-limited sub-slice so an out-of-bounds append inside a hash
// implementation cannot spill into the neighbouring lane.
func newLaneScratch(nonce []byte, nonceLen int) *laneScratch {
	stride := 4 + nonceLen
	ls := &laneScratch{block: make([]byte, 16*stride)}
	for lane := 0; lane < 8; lane++ {
		off := lane * stride
		ls.noise[lane] = ls.block[off : off+stride : off+stride]
		copy(ls.noise[lane][4:], nonce)
		off = (8 + lane) * stride
		ls.data[lane] = ls.block[off : off+stride : off+stride]
		copy(ls.data[lane][4:], nonce)
	}
	copy(ls.noise4[:], ls.noise[:4])
	copy(ls.data4[:], ls.data[:4])
	return ls
}

// wipe zeroes the lane block; deferred by every worker so the hash
// inputs do not outlive the call.
func (ls *laneScratch) wipe() {
	secureWipe(ls.block)
}
