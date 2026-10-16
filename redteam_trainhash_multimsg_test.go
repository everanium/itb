//go:build redteam

package itb

// Universal multi-message 25% Crib KPA solver for the 8-bit-per-lane bijective
// affine T-function trainHash under the shipped Triple Ouroboros barrier.
//
// Primitive definition:
//
//	l = ((l + b)*3 + 1) & 0xFF
//	h = ((h + b)*5 + 7) & 0xFF
//
// Over any buffer B of length n, trainHash is affine in the low byte of each
// seed word:
//
//	lo(B, s0) = (3^n * (s0 & 0xFF) + cLo(B)) mod 256
//	hi(B, s1) = (5^n * (s1 & 0xFF) + cHi(B)) mod 256
//
// Because 3^n and 5^n are odd, each round is a bijection on Z/256Z and does not
// collapse to a constant attractor. However:
//  1. Every seed component is truncated to 8 bits (& 0xFF), reducing each
//     4-round ChainHash128 lane from 256 bits to 32 bits.
//  2. In every cascade round s_{r+1} = a * (k_{r+1} ^ s_r) + c (mod 256) with
//     odd a, flipping bit 7 (0x80) of k_r shifts s_r by 128 mod 256 (also
//     flipping bit 7 of s_r), which cancels if bit 7 of k_{r+1} is flipped at
//     the same time. That 2^3 = 8-fold MSB gauge symmetry reduces every 4-byte
//     lane key to 29 effective bits.
//  3. Because dataHash is 8 bits wide, 7 of the 8 pixel channels carry zero
//     XOR mask (rotation + 1 noise bit only). Cross-region band joining across
//     the 25% crib resolves startPixel_0..2, per-chunk 16-bit barrier ranks,
//     lockSeed, and dataSeed_0..2 in 2..4 messages, and cHi-collision
//     correlation across the 50-message session recovers noiseSeed without any
//     plaintext model.
//
// Passing the 8 recovered *Seed128 instances to Decrypt3x128Cfg decrypts all
// 50 messages of the session across ascii, json, and uniform random binary
// corpora with 100% SHA-256 verification.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"sort"
	"sync"
	"testing"
	"time"
)

func trainHash(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	l := seed0 & 0xFF
	h := seed1 & 0xFF
	for _, b := range data {
		l = ((l+uint64(b))*3 + 1) & 0xFF
		h = ((h+uint64(b))*5 + 7) & 0xFF
	}
	return l, h
}

func tcLaneConsts(buf []byte) (aLo, cLo, aHi, cHi byte) {
	l0, h0 := trainHash(buf, 0, 0)
	l1, h1 := trainHash(buf, 1, 1)
	cLo, cHi = byte(l0), byte(h0)
	aLo, aHi = byte(l1)-cLo, byte(h1)-cHi
	return
}

func tcInv256(a byte) byte {
	for x := 0; x < 256; x++ {
		if a*byte(x) == 1 {
			return byte(x)
		}
	}
	return 0
}

func tcLockBuf(groupIdx uint64, fold [4]byte) []byte {
	buf := make([]byte, 13)
	buf[0] = 0x03
	binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
	copy(buf[9:13], fold[:])
	return buf
}

func tcPixelBuf(p int, mainNonce []byte) []byte {
	buf := make([]byte, 4+len(mainNonce))
	binary.LittleEndian.PutUint32(buf, uint32(p))
	copy(buf[4:], mainNonce)
	return buf
}

func tcCascade(k []byte, a, c byte) byte {
	s := a*k[0] + c
	for j := 1; j < len(k); j++ {
		s = a*(k[j]^s) + c
	}
	return s
}

func tcCanonicalKey4(k [4]byte) [4]byte {
	parity := (k[0] & 0x80) ^ (k[1] & 0x80) ^ (k[2] & 0x80)
	return [4]byte{
		k[0] & 0x7F,
		k[1] & 0x7F,
		k[2] & 0x7F,
		k[3] ^ parity,
	}
}

func tcCanonicalFunc4(k [4]byte, a byte) [256]byte {
	var tab [256]byte
	for c := 0; c < 256; c++ {
		tab[c] = tcCascade(k[:], a, byte(c))
	}
	return tab
}

func tcAllMasks() *[65536][3]uint64 {
	m := new([65536][3]uint64)
	for lo := 0; lo < 256; lo++ {
		for hi := 0; hi < 256; hi++ {
			a, b, c := rankToMaskTriple48(uint64(lo), uint64(hi))
			m[lo|hi<<8] = [3]uint64{a, b, c}
		}
	}
	return m
}

func tcReadPixel(region []byte, linearIdx int, np, rot, xor uint) [7]byte {
	var packed uint64
	noiseMask := byte(1) << np
	for ch := 0; ch < Channels; ch++ {
		b := region[linearIdx*Channels+ch]
		low := b & (noiseMask - 1)
		high := b >> (np + 1)
		d := low | (high << np)
		d = rotateBits7(d, 7-rot)
		if ch == 0 {
			d ^= byte(xor)
		}
		packed |= uint64(d) << uint(ch*DataBitsPerChannel)
	}
	var out [7]byte
	for j := 0; j < 7; j++ {
		out[j] = byte(packed >> uint(8*j))
	}
	return out
}

type tcVictimSession struct {
	cfg      *Config
	ns, ls   *Seed128
	d        [3]*Seed128
	s        [3]*Seed128
	messages []tcVictimMsg
}

type tcVictimMsg struct {
	idx       int
	plaintext []byte
	wire      []byte
	mainNonce []byte
}

func generateTrainHashVictimSession(t *testing.T, corpus string, keyBits, ptSize, numMsgs int) *tcVictimSession {
	t.Helper()
	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	mk := func() *Seed128 {
		s, err := NewSeed128(keyBits, trainHash)
		if err != nil {
			t.Fatalf("NewSeed128: %v", err)
		}
		return s
	}
	sess := &tcVictimSession{
		cfg: cfg,
		ns:  mk(),
		ls:  mk(),
		d:   [3]*Seed128{mk(), mk(), mk()},
		s:   [3]*Seed128{mk(), mk(), mk()},
	}
	nonceLen := currentNonceSizeCfg(cfg)
	for m := 0; m < numMsgs; m++ {
		pt := qhMakePlaintext(corpus, ptSize, m)
		ct, err := Encrypt3x128Cfg(cfg, sess.ns, sess.ls, sess.d[0], sess.d[1], sess.d[2], sess.s[0], sess.s[1], sess.s[2], pt)
		if err != nil {
			t.Fatalf("Encrypt3x128Cfg: %v", err)
		}
		sm := parseSMWire(ct, nonceLen)
		sess.messages = append(sess.messages, tcVictimMsg{
			idx:       m,
			plaintext: pt,
			wire:      ct,
			mainNonce: sm.mainNonce,
		})
	}
	return sess
}

type tcAttackerPacket struct {
	idx  int
	wire []byte
	crib []byte
}

type tcPixCfg struct {
	np, rot, xor uint
	ok           bool
	xorOK        bool
}

type tcBandSolution struct {
	sp  [3]int
	np  [3]uint
	rot [3]uint
}

type tcAttack struct {
	idx           int
	mainNonce     []byte
	regions       [3][]byte
	widths        [3]int
	third         int
	base          [3]int
	startPixel    [3]int
	pix           [3][]tcPixCfg
	bandsResolved int
	crib          []byte
	ptSize        int
	masks         *[65536][3]uint64
	allScheds     [][]int
}

func newTCAttack(pkt tcAttackerPacket, ptSize int, masks *[65536][3]uint64) *tcAttack {
	sm := parseSMWire(pkt.wire, 16)
	totalPixels := sm.width * sm.height
	third, third2, _ := tripleThirdCaps(totalPixels)
	lens, _ := nonceSplit(16)
	a := &tcAttack{
		idx:       pkt.idx,
		mainNonce: sm.mainNonce,
		widths:    [3]int{third, third, third2},
		third:     third,
		regions: [3][]byte{
			sm.container[0 : third*Channels],
			sm.container[third*Channels : 2*third*Channels],
			sm.container[2*third*Channels : totalPixels*Channels],
		},
		base:   [3]int{lens[0] + 1, lens[1] + 1, lens[2] + 1},
		crib:   pkt.crib,
		ptSize: ptSize,
		masks:  masks,
	}
	for r := 0; r < 3; r++ {
		a.pix[r] = make([]tcPixCfg, a.widths[r])
	}
	return a
}

func (a *tcAttack) chunkX(k int) (uint64, bool) {
	if k < 1 || 6*k+6-4 > len(a.crib) {
		return 0, false
	}
	var x uint64
	for i := 0; i < 6; i++ {
		x |= uint64(a.crib[6*k+i-4]) << uint(8*i)
	}
	return x, true
}

func (a *tcAttack) chunkXPartial(k int) (x, known uint64) {
	for i := 0; i < 6; i++ {
		fi := 6*k + i
		if fi < 4 || fi-4 >= len(a.crib) {
			continue
		}
		x |= uint64(a.crib[fi-4]) << uint(8*i)
		known |= uint64(0xFF) << uint(8*i)
	}
	return x, known
}

func (a *tcAttack) laneBytes(k int, rank int) (l0, l1, l2 uint16, ok bool) {
	x, ok := a.chunkX(k)
	if !ok {
		return
	}
	m := a.masks[rank]
	l0, l1, l2 = chunk48lock(x, m[0], m[1], m[2])
	return l0, l1, l2, true
}

func (a *tcAttack) readLaneByte(r, j int) (val, bits byte, ok bool) {
	s := a.base[r] + j
	w, off := s/7, s%7
	if w >= a.widths[r] || w >= len(a.pix[r]) || !a.pix[r][w].ok {
		return 0, 0, false
	}
	c := a.pix[r][w]
	lin := (a.startPixel[r] + w) % a.widths[r]
	win := tcReadPixel(a.regions[r], lin, c.np, c.rot, c.xor)
	if off == 0 && !c.xorOK {
		return win[off], 0xE0, true
	}
	return win[off], 0xFF, true
}

func (a *tcAttack) pinRank(k int) []int {
	type obs struct {
		r, j    int
		v, bits byte
	}
	var o []obs
	for r := 0; r < 3; r++ {
		for _, j := range [2]int{2 * k, 2*k + 1} {
			if v, bits, ok := a.readLaneByte(r, j); ok {
				o = append(o, obs{r, j, v, bits})
			}
		}
	}
	if len(o) == 0 {
		return nil
	}
	var out []int
	for rank := 0; rank < 65536; rank++ {
		l0, l1, l2, ok := a.laneBytes(k, rank)
		if !ok {
			return nil
		}
		lv := [3]uint16{l0, l1, l2}
		good := true
		for _, c := range o {
			var want byte
			if c.j == 2*k {
				want = byte(lv[c.r])
			} else {
				want = byte(lv[c.r] >> 8)
			}
			if want == 0 {
				continue
			}
			if (want^c.v)&c.bits != 0 {
				good = false
				break
			}
		}
		if good {
			out = append(out, rank)
		}
	}
	return out
}

func (a *tcAttack) tcJoinBand(w int, anchors [2]int, spKnown bool) []tcBandSolution {
	type rankInfo struct{ l [3]uint16 }
	var tab [2][]rankInfo
	var byL0 [2]map[uint16][]int
	for i, k := range anchors {
		tab[i] = make([]rankInfo, 65536)
		byL0[i] = make(map[uint16][]int, 65536)
		for rank := 0; rank < 65536; rank++ {
			l0, l1, l2, ok := a.laneBytes(k, rank)
			if !ok {
				return nil
			}
			tab[i][rank] = rankInfo{[3]uint16{l0, l1, l2}}
			byL0[i][l0] = append(byL0[i][l0], rank)
		}
	}
	type slot struct{ off [4]int }
	var slots [3]slot
	for r := 0; r < 3; r++ {
		for i, k := range anchors {
			slots[r].off[2*i] = a.base[r] + 2*k - 7*w
			slots[r].off[2*i+1] = a.base[r] + 2*k + 1 - 7*w
		}
		for _, o := range slots[r].off {
			if o < 1 || o > 6 {
				return nil
			}
		}
	}
	type cand struct {
		sp      int
		np, rot uint
		lA, lB  uint16
	}
	var cands [3][]cand
	for r := 0; r < 3; r++ {
		spLo, spHi := 0, a.widths[r]
		if spKnown {
			spLo, spHi = a.startPixel[r], a.startPixel[r]+1
		}
		for sp := spLo; sp < spHi; sp++ {
			lin := (sp + w) % a.widths[r]
			for np := uint(0); np < 8; np++ {
				for rot := uint(0); rot < 7; rot++ {
					win := tcReadPixel(a.regions[r], lin, np, rot, 0)
					lA := uint16(win[slots[r].off[0]]) | uint16(win[slots[r].off[1]])<<8
					lB := uint16(win[slots[r].off[2]]) | uint16(win[slots[r].off[3]])<<8
					cands[r] = append(cands[r], cand{sp, np, rot, lA, lB})
				}
			}
		}
	}
	idx := [2]map[[2]uint16][]int{}
	for r := 1; r < 3; r++ {
		m := make(map[[2]uint16][]int, len(cands[r]))
		for i, c := range cands[r] {
			m[[2]uint16{c.lA, c.lB}] = append(m[[2]uint16{c.lA, c.lB}], i)
		}
		idx[r-1] = m
	}
	seen := map[tcBandSolution]struct{}{}
	var out []tcBandSolution
	for _, c0 := range cands[0] {
		for _, rA := range byL0[0][c0.lA] {
			for _, rB := range byL0[1][c0.lB] {
				k1 := [2]uint16{tab[0][rA].l[1], tab[1][rB].l[1]}
				k2 := [2]uint16{tab[0][rA].l[2], tab[1][rB].l[2]}
				for _, i1 := range idx[0][k1] {
					for _, i2 := range idx[1][k2] {
						s := tcBandSolution{
							sp:  [3]int{c0.sp, cands[1][i1].sp, cands[2][i2].sp},
							np:  [3]uint{c0.np, cands[1][i1].np, cands[2][i2].np},
							rot: [3]uint{c0.rot, cands[1][i1].rot, cands[2][i2].rot},
						}
						if _, dup := seen[s]; !dup {
							seen[s] = struct{}{}
							out = append(out, s)
						}
					}
				}
			}
		}
	}
	return out
}

func (a *tcAttack) tcXorFromCribChunk(r, w, k, rank int) (uint, bool) {
	x, known := a.chunkXPartial(k)
	if known == 0 {
		return 0, false
	}
	m := a.masks[rank]
	v0, v1, v2 := chunk48lock(x, m[0], m[1], m[2])
	kb0, kb1, kb2 := chunk48lock(known, m[0], m[1], m[2])
	want := [3]uint16{v0, v1, v2}[r]
	valid := [3]uint16{kb0, kb1, kb2}[r]
	for bi, j := range [2]int{2 * k, 2*k + 1} {
		st := a.base[r] + j
		if st/7 != w || st%7 != 0 {
			continue
		}
		if byte(valid>>uint(8*bi)) != 0xFF {
			return 0, false
		}
		ev := byte(want >> uint(8*bi))
		if ev == 0 {
			return 0, false
		}
		c := a.pix[r][w]
		lin := (a.startPixel[r] + w) % a.widths[r]
		got := tcReadPixel(a.regions[r], lin, c.np, c.rot, 0)[0]
		if (got^ev)&0xE0 != 0 {
			return 0, false
		}
		return uint((got ^ ev) & 0x1F), true
	}
	return 0, false
}

func tcDataHashCandidates(rot, xor uint) []byte {
	var out []byte
	for t := uint(0); t < 8; t++ {
		v := 8*xor + t
		if v < 256 && v%7 == rot {
			out = append(out, byte(v))
		}
	}
	return out
}

func tcSolveLane4Canonical(a, c []byte, sets [][]byte) [][4]byte {
	n := len(sets)
	if n < 2 {
		return nil
	}
	ainv := make([]byte, n)
	for i := range a {
		ainv[i] = tcInv256(a[i])
	}
	type sig [8]byte
	fwd := make(map[sig][][2]byte, 1<<14)
	for k0 := 0; k0 < 128; k0++ {
		for k1 := 0; k1 < 128; k1++ {
			var g sig
			for i := 0; i < n; i++ {
				s1 := a[i]*byte(k0) + c[i]
				g[i] = a[i]*(byte(k1)^s1) + c[i]
			}
			fwd[g] = append(fwd[g], [2]byte{byte(k0), byte(k1)})
		}
	}
	seen := map[[4]byte]struct{}{}
	var out [][4]byte
	idx := make([]int, n)
	for k2 := 0; k2 < 128; k2++ {
		for k3 := 0; k3 < 256; k3++ {
			for i := range idx {
				idx[i] = 0
			}
			for {
				var g sig
				for i := 0; i < n; i++ {
					s3 := ainv[i]*(sets[i][idx[i]]-c[i]) ^ byte(k3)
					g[i] = ainv[i]*(s3-c[i]) ^ byte(k2)
				}
				for _, fk := range fwd[g] {
					key := [4]byte{fk[0], fk[1], byte(k2), byte(k3)}
					if _, dup := seen[key]; !dup {
						seen[key] = struct{}{}
						out = append(out, key)
					}
				}
				i := 0
				for ; i < n; i++ {
					if idx[i]++; idx[i] < len(sets[i]) {
						break
					}
					idx[i] = 0
				}
				if i == n {
					break
				}
			}
		}
	}
	return out
}

type tcLaneKey struct {
	k     [5]byte
	delta byte
}

type tcDiffMITMScratch struct {
	head  []int32
	dirty []uint32
	next  [65536]int32
	k01   [65536]uint16
	l0    [65536]byte
}

func newTCDiffMITMScratch() *tcDiffMITMScratch {
	head := make([]int32, 1<<24)
	for i := range head {
		head[i] = -1
	}
	return &tcDiffMITMScratch{
		head:  head,
		dirty: make([]uint32, 0, 65536),
	}
}

func tcSolveLaneOneDeltaCanonical(a, c []byte, sets [][]byte, ord []int, allowMask *[32][4]uint64, ainv *[32]byte, ws *tcDiffMITMScratch) [][5]byte {
	n := len(sets)
	if n < 4 {
		return nil
	}
	p0, p1, p2, p3 := ord[0], ord[1], ord[2], ord[3]
	a0, c0, ai0 := a[p0], c[p0], ainv[p0]
	a1, c1, ai1 := a[p1], c[p1], ainv[p1]
	a2, c2, ai2 := a[p2], c[p2], ainv[p2]
	a3, c3, ai3 := a[p3], c[p3], ainv[p3]
	set0, set1, set2, set3 := sets[p0], sets[p1], sets[p2], sets[p3]

	for _, sig := range ws.dirty {
		ws.head[sig] = -1
	}
	ws.dirty = ws.dirty[:0]

	idx := int32(0)
	for k0 := 0; k0 < 256; k0++ {
		b0 := byte(k0)
		s1_0 := a0*b0 + c0
		s1_1 := a1*b0 + c1
		s1_2 := a2*b0 + c2
		s1_3 := a3*b0 + c3
		for k1 := 0; k1 < 128; k1++ {
			b1 := byte(k1)
			L0 := a0*(b1^s1_0) + c0
			L1 := a1*(b1^s1_1) + c1
			L2 := a2*(b1^s1_2) + c2
			L3 := a3*(b1^s1_3) + c3
			sig := uint32(L1^L0) | uint32(L2^L0)<<8 | uint32(L3^L0)<<16
			if ws.head[sig] == -1 {
				ws.dirty = append(ws.dirty, sig)
			}
			ws.next[idx] = ws.head[sig]
			ws.k01[idx] = uint16(k0) | uint16(k1)<<8
			ws.l0[idx] = L0
			ws.head[sig] = idx
			idx++
		}
	}

	seen := map[[5]byte]struct{}{}
	var found [][5]byte
	var r0Arr, r1Arr, r2Arr, r3Arr [256]byte
	n0, n1, n2, n3 := len(set0), len(set1), len(set2), len(set3)

	for k3 := 0; k3 < 128; k3++ {
		b3 := byte(k3)
		for k4 := 0; k4 < 256; k4++ {
			b4 := byte(k4)
			for i, v := range set0 {
				s4 := ai0*(v-c0) ^ b4
				s3 := ai0*(s4-c0) ^ b3
				r0Arr[i] = ai0 * (s3 - c0)
			}
			for i, v := range set1 {
				s4 := ai1*(v-c1) ^ b4
				s3 := ai1*(s4-c1) ^ b3
				r1Arr[i] = ai1 * (s3 - c1)
			}
			for i, v := range set2 {
				s4 := ai2*(v-c2) ^ b4
				s3 := ai2*(s4-c2) ^ b3
				r2Arr[i] = ai2 * (s3 - c2)
			}
			for i, v := range set3 {
				s4 := ai3*(v-c3) ^ b4
				s3 := ai3*(s4-c3) ^ b3
				r3Arr[i] = ai3 * (s3 - c3)
			}
			for i0 := 0; i0 < n0; i0++ {
				R0 := r0Arr[i0]
				for i1 := 0; i1 < n1; i1++ {
					d1 := uint32(r1Arr[i1] ^ R0)
					for i2 := 0; i2 < n2; i2++ {
						d12 := d1 | uint32(r2Arr[i2]^R0)<<8
						for i3 := 0; i3 < n3; i3++ {
							sig := d12 | uint32(r3Arr[i3]^R0)<<16
							for e := ws.head[sig]; e >= 0; e = ws.next[e] {
								b2 := ws.l0[e] ^ R0
								if b2 >= 128 {
									continue
								}
								kv := ws.k01[e]
								key := [5]byte{byte(kv), byte(kv >> 8), b2, b3, b4}
								ok := true
								for i := 0; i < n; i++ {
									out := tcCascade(key[:], a[i], c[i])
									if allowMask[i][out>>6]&(uint64(1)<<(out&63)) == 0 {
										ok = false
										break
									}
								}
								if ok {
									if _, dup := seen[key]; !dup {
										seen[key] = struct{}{}
										found = append(found, key)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return found
}

func tcSolveLaneFoldParallel(a, c []byte, sets [][]byte, numWorkers int) []tcLaneKey {
	n := len(sets)
	if n < 4 {
		return nil
	}
	var ainv [32]byte
	var allowMask [32][4]uint64
	for i := 0; i < n; i++ {
		ainv[i] = tcInv256(a[i])
		for _, v := range sets[i] {
			allowMask[i][v>>6] |= uint64(1) << (v & 63)
		}
	}
	ord := make([]int, n)
	for i := range ord {
		ord[i] = i
	}
	sort.SliceStable(ord, func(x, y int) bool { return len(sets[ord[x]]) < len(sets[ord[y]]) })

	var mu sync.Mutex
	var allFound []tcLaneKey
	var wg sync.WaitGroup
	ch := make(chan int, 256)
	for d := 0; d < 256; d++ {
		ch <- d
	}
	close(ch)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ws := newTCDiffMITMScratch()
			shifted := make([]byte, n)
			var local []tcLaneKey
			for d := range ch {
				for i := range c {
					shifted[i] = c[i] + byte(d)
				}
				for _, k := range tcSolveLaneOneDeltaCanonical(a, shifted, sets, ord, &allowMask, &ainv, ws) {
					local = append(local, tcLaneKey{k: k, delta: byte(d)})
				}
			}
			mu.Lock()
			allFound = append(allFound, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return allFound
}

func tcSolveLaneWithSuffixes(suffixes [][4]byte, a, c []byte, sets [][]byte) []tcLaneKey {
	n := len(sets)
	var allowMask [32][4]uint64
	for i := 0; i < n; i++ {
		for _, v := range sets[i] {
			allowMask[i][v>>6] |= uint64(1) << (v & 63)
		}
	}
	var found []tcLaneKey
	for _, suf := range suffixes {
		for d := 0; d < 256; d++ {
			delta := byte(d)
			for k0 := 0; k0 < 256; k0++ {
				key := [5]byte{byte(k0), suf[0], suf[1], suf[2], suf[3]}
				ok := true
				for i := 0; i < n; i++ {
					out := tcCascade(key[:], a[i], c[i]+delta)
					if allowMask[i][out>>6]&(uint64(1)<<(out&63)) == 0 {
						ok = false
						break
					}
				}
				if ok {
					found = append(found, tcLaneKey{k: key, delta: delta})
				}
			}
		}
	}
	return found
}

type tcNoiseObs struct {
	cLo, cHi byte
	npMask   byte
}

type tcNoiseHiBin struct {
	cHi   byte
	obs   []tcNoiseObs
	masks [][256][4]uint64
}

type tcNoiseSeedPair struct {
	lo, hi [4]byte
}

func tcSolveNoiseSeedFromBins(allObs []tcNoiseObs, numWorkers int) []tcNoiseSeedPair {
	aLo, _, aHi, _ := tcLaneConsts(make([]byte, 20))

	byHi := make(map[byte]map[byte]byte)
	var uniqueObs []tcNoiseObs
	seenPair := make(map[uint16]int)

	for _, o := range allObs {
		key := uint16(o.cLo) | uint16(o.cHi)<<8
		if idx, exists := seenPair[key]; !exists {
			seenPair[key] = len(uniqueObs)
			uniqueObs = append(uniqueObs, o)
		} else {
			uniqueObs[idx].npMask &= o.npMask
		}
		if byHi[o.cHi] == nil {
			byHi[o.cHi] = make(map[byte]byte)
		}
		if prev, exists := byHi[o.cHi][o.cLo]; exists {
			byHi[o.cHi][o.cLo] = prev & o.npMask
		} else {
			byHi[o.cHi][o.cLo] = o.npMask
		}
	}

	var bins []tcNoiseHiBin
	for cHi, m := range byHi {
		if len(m) < 3 {
			continue
		}
		var b tcNoiseHiBin
		b.cHi = cHi
		for cLo, npMask := range m {
			b.obs = append(b.obs, tcNoiseObs{cLo: cLo, cHi: cHi, npMask: npMask})
		}
		sort.Slice(b.obs, func(i, j int) bool {
			ci, cj := bits.OnesCount8(b.obs[i].npMask), bits.OnesCount8(b.obs[j].npMask)
			if ci != cj {
				return ci < cj
			}
			return b.obs[i].cLo < b.obs[j].cLo
		})
		b.masks = make([][256][4]uint64, len(b.obs))
		for r, o := range b.obs {
			for u := 0; u < 256; u++ {
				lVal := uint64(aLo*byte(u) + o.cLo)
				var mask [4]uint64
				for h := uint64(0); h < 256; h++ {
					np := noiseFold3(lVal + 2*h)
					if (o.npMask>>np)&1 != 0 {
						mask[h>>6] |= uint64(1) << (h & 63)
					}
				}
				b.masks[r][u] = mask
			}
		}
		bins = append(bins, b)
	}

	sort.Slice(bins, func(i, j int) bool {
		if len(bins[i].obs) != len(bins[j].obs) {
			return len(bins[i].obs) > len(bins[j].obs)
		}
		return bins[i].cHi < bins[j].cHi
	})

	if len(bins) < 4 || len(bins[0].obs) < 4 {
		return nil
	}

	b0 := bins[0]
	idx4 := 4
	if len(b0.obs) < 5 {
		idx4 = len(b0.obs) - 1
	}
	x0, x1, x2, x3, x4 := b0.obs[0].cLo, b0.obs[1].cLo, b0.obs[2].cLo, b0.obs[3].cLo, b0.obs[idx4].cLo
	m0Tab, m1Tab, m2Tab, m3Tab, m4Tab := &b0.masks[0], &b0.masks[1], &b0.masks[2], &b0.masks[3], &b0.masks[idx4]

	checkAllBins := func(key [4]byte) bool {
		for bi := range bins {
			b := &bins[bi]
			var w0, w1, w2, w3 uint64 = ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)
			for r, o := range b.obs {
				s1 := aLo*key[0] + o.cLo
				s2 := aLo*(key[1]^s1) + o.cLo
				s3 := aLo*(key[2]^s2) + o.cLo
				u := key[3] ^ s3
				mk := &b.masks[r][u]
				w0 &= mk[0]
				w1 &= mk[1]
				w2 &= mk[2]
				w3 &= mk[3]
				if (w0 | w1 | w2 | w3) == 0 {
					return false
				}
			}
		}
		return true
	}

	var mu sync.Mutex
	var candKLo [][4]byte
	var wg sync.WaitGroup
	ch := make(chan int, 128)
	for k0 := 0; k0 < 128; k0++ {
		ch <- k0
	}
	close(ch)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local [][4]byte
			for k0 := range ch {
				b0k := byte(k0)
				s1_0 := aLo*b0k + x0
				s1_1 := aLo*b0k + x1
				s1_2 := aLo*b0k + x2
				s1_3 := aLo*b0k + x3
				s1_4 := aLo*b0k + x4
				for k1 := 0; k1 < 128; k1++ {
					b1k := byte(k1)
					s2_0 := aLo*(b1k^s1_0) + x0
					s2_1 := aLo*(b1k^s1_1) + x1
					s2_2 := aLo*(b1k^s1_2) + x2
					s2_3 := aLo*(b1k^s1_3) + x3
					s2_4 := aLo*(b1k^s1_4) + x4
					for k2 := 0; k2 < 128; k2++ {
						b2k := byte(k2)
						s3_0 := aLo*(b2k^s2_0) + x0
						s3_1 := aLo*(b2k^s2_1) + x1
						s3_2 := aLo*(b2k^s2_2) + x2
						s3_3 := aLo*(b2k^s2_3) + x3
						s3_4 := aLo*(b2k^s2_4) + x4
						for k3 := 0; k3 < 256; k3++ {
							b3k := byte(k3)
							mk0 := &m0Tab[b3k^s3_0]
							mk1 := &m1Tab[b3k^s3_1]
							mk2 := &m2Tab[b3k^s3_2]
							mk3 := &m3Tab[b3k^s3_3]
							mk4 := &m4Tab[b3k^s3_4]
							if ((mk0[0]&mk1[0]&mk2[0]&mk3[0]&mk4[0]) |
								(mk0[1]&mk1[1]&mk2[1]&mk3[1]&mk4[1]) |
								(mk0[2]&mk1[2]&mk2[2]&mk3[2]&mk4[2]) |
								(mk0[3]&mk1[3]&mk2[3]&mk3[3]&mk4[3])) == 0 {
								continue
							}
							cand := [4]byte{b0k, b1k, b2k, b3k}
							if checkAllBins(cand) {
								local = append(local, cand)
							}
						}
					}
				}
			}
			mu.Lock()
			candKLo = append(candKLo, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	seenLoFn := make(map[[256]byte][4]byte)
	for _, kl := range candKLo {
		seenLoFn[tcCanonicalFunc4(kl, aLo)] = kl
	}

	var outPairs []tcNoiseSeedPair
	for _, kl := range seenLoFn {
		var aa, cc []byte
		var sets [][]byte
		for bi := 0; bi < 4 && bi < len(bins); bi++ {
			b := &bins[bi]
			var w0, w1, w2, w3 uint64 = ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)
			for r, o := range b.obs {
				s1 := aLo*kl[0] + o.cLo
				s2 := aLo*(kl[1]^s1) + o.cLo
				s3 := aLo*(kl[2]^s2) + o.cLo
				u := kl[3] ^ s3
				mk := &b.masks[r][u]
				w0 &= mk[0]
				w1 &= mk[1]
				w2 &= mk[2]
				w3 &= mk[3]
			}
			mask := [4]uint64{w0, w1, w2, w3}
			var hSet []byte
			for h := 0; h < 256; h++ {
				if mask[h>>6]&(uint64(1)<<(h&63)) != 0 {
					hSet = append(hSet, byte(h))
				}
			}
			aa = append(aa, aHi)
			cc = append(cc, b.cHi)
			sets = append(sets, hSet)
		}
		hiCands := tcSolveLane4Canonical(aa, cc, sets)
		seenHiFn := make(map[[256]byte][4]byte)
		for _, kh := range hiCands {
			seenHiFn[tcCanonicalFunc4(kh, aHi)] = kh
		}
		for _, kh := range seenHiFn {
			allMatch := true
			for _, o := range uniqueObs {
				loVal := uint64(tcCascade(kl[:], aLo, o.cLo))
				hiVal := uint64(tcCascade(kh[:], aHi, o.cHi))
				np := noiseFold3(loVal + 2*hiVal)
				if (o.npMask>>np)&1 == 0 {
					allMatch = false
					break
				}
			}
			if allMatch {
				outPairs = append(outPairs, tcNoiseSeedPair{lo: kl, hi: kh})
			}
		}
	}
	return outPairs
}

// tcMakeEquivSeed builds a 512-bit *Seed128 for slot in 0..7 from 4-byte lo and
// hi component arrays. Setting (uint64(slot) << 8) on Components[0] does not
// alter any byte modulo 256 (which is all trainHash reads) while ensuring
// pairwise distinctness across all 8 seeds for checkEightSeeds128.
func tcMakeEquivSeed(slot int, lo, hi [4]byte) *Seed128 {
	s, err := SeedFromComponents128(trainHash,
		uint64(lo[0])|(uint64(slot)<<8), uint64(hi[0]),
		uint64(lo[1]), uint64(hi[1]),
		uint64(lo[2]), uint64(hi[2]),
		uint64(lo[3]), uint64(hi[3]),
	)
	if err != nil {
		panic(err)
	}
	return s
}

func runTrainHashMultiMsgSession(t *testing.T, corpus string, cribLen, numMsgs int) {
	t.Helper()
	t0 := time.Now()
	masks := tcAllMasks()
	sess := generateTrainHashVictimSession(t, corpus, 512, 512, numMsgs)

	maxChunks := 90
	type laneConst struct{ aL, cL, aH, cH byte }
	lc := make([]laneConst, maxChunks)
	for k := 0; k < maxChunks; k++ {
		al, cl, ah, ch := tcLaneConsts(tcLockBuf(uint64(k), [4]byte{}))
		lc[k] = laneConst{al, cl, ah, ch}
	}

	var candSufLo, candSufHi [][4]byte
	bootstrapped := false

	var regionFuncCounts [3]map[[256]byte]int
	var regionFuncRep [3]map[[256]byte][4]byte
	for r := 0; r < 3; r++ {
		regionFuncCounts[r] = map[[256]byte]int{}
		regionFuncRep[r] = map[[256]byte][4]byte{}
	}
	dataSeedSamples := [3]int{}
	aPixelLo, _, aPixelHi, _ := tcLaneConsts(make([]byte, 20))

	var resolvedAttacks []*tcAttack
	maxAnchorBand := 6

	for m, vm := range sess.messages {
		pkt := tcAttackerPacket{
			idx:  m,
			wire: vm.wire,
			crib: append([]byte(nil), vm.plaintext[:cribLen]...),
		}
		att := newTCAttack(pkt, 512, masks)
		sols1 := att.tcJoinBand(1, [2]int{1, 2}, false)
		if len(sols1) == 0 {
			continue
		}
		var bestAtt *tcAttack
		for _, s1 := range sols1 {
			candAtt := newTCAttack(pkt, 512, masks)
			for r := 0; r < 3; r++ {
				candAtt.startPixel[r] = s1.sp[r]
				candAtt.pix[r][1] = tcPixCfg{np: s1.np[r], rot: s1.rot[r], ok: true}
			}
			sols2 := candAtt.tcJoinBand(2, [2]int{5, 6}, true)
			if len(sols2) == 0 {
				continue
			}
			for r := 0; r < 3; r++ {
				candAtt.pix[r][2] = tcPixCfg{np: sols2[0].np[r], rot: sols2[0].rot[r], ok: true}
			}
			bandsResolved := 2
			for _, ap := range [][3]int{{3, 8, 9}, {4, 12, 13}, {5, 15, 16}, {6, 19, 20}} {
				if ap[0] > maxAnchorBand {
					break
				}
				sw := candAtt.tcJoinBand(ap[0], [2]int{ap[1], ap[2]}, true)
				if len(sw) == 1 {
					for r := 0; r < 3; r++ {
						candAtt.pix[r][ap[0]] = tcPixCfg{np: sw[0].np[r], rot: sw[0].rot[r], ok: true}
					}
					bandsResolved = ap[0]
				} else {
					break
				}
			}
			candAtt.bandsResolved = bandsResolved
			if bestAtt == nil || candAtt.bandsResolved > bestAtt.bandsResolved {
				bestAtt = candAtt
				if bestAtt.bandsResolved == maxAnchorBand {
					break
				}
			}
		}
		if bestAtt != nil {
			resolvedAttacks = append(resolvedAttacks, bestAtt)
		}
	}

	sort.SliceStable(resolvedAttacks, func(i, j int) bool {
		return resolvedAttacks[i].bandsResolved > resolvedAttacks[j].bandsResolved
	})

	aStartLo, _, _, _ := tcLaneConsts(make([]byte, 17))
	var candSS [3][][4]byte
	for r := 0; r < 3; r++ {
		var aa, cc []byte
		var sets [][]byte
		for _, att := range resolvedAttacks {
			buf := make([]byte, 1+len(att.mainNonce))
			buf[0] = 0x02
			copy(buf[1:], att.mainNonce)
			al, cl, _, _ := tcLaneConsts(buf)
			var cand []byte
			for h := 0; h < 256; h++ {
				if h%att.widths[r] == att.startPixel[r] {
					cand = append(cand, byte(h))
				}
			}
			aa = append(aa, al)
			cc = append(cc, cl)
			sets = append(sets, cand)
		}
		if len(sets) >= 3 {
			rawCands := tcSolveLane4Canonical(aa[:3], cc[:3], sets[:3])
			if len(sets) >= 6 {
				rawCands = append(rawCands, tcSolveLane4Canonical(aa[3:6], cc[3:6], sets[3:6])...)
			}
			seenFn := map[[256]byte][4]byte{}
			fnHits := map[[256]byte]int{}
			maxHits := -1
			for _, ck := range rawCands {
				fn := tcCanonicalFunc4(ck, aStartLo)
				if _, seen := seenFn[fn]; seen {
					continue
				}
				hits := 0
				for i := 0; i < len(sets); i++ {
					out := tcCascade(ck[:], aa[i], cc[i])
					for _, v := range sets[i] {
						if v == out {
							hits++
							break
						}
					}
				}
				seenFn[fn] = ck
				fnHits[fn] = hits
				if hits > maxHits {
					maxHits = hits
				}
			}
			for fn, ck := range seenFn {
				if fnHits[fn] == maxHits {
					candSS[r] = append(candSS[r], ck)
				}
			}
		}
	}

	for _, att := range resolvedAttacks {
		bandsResolved := att.bandsResolved
		var aL, cL, aH, cH []byte
		var loSets, hiSets [][]byte
		safeBands := bandsResolved
		if bandsResolved < maxAnchorBand && bandsResolved > 2 {
			safeBands = bandsResolved - 1
		}
		maxSafeK := (7*(safeBands+1) - att.base[0] - 1) / 2
		if maxSafeK > (cribLen+4)/6 {
			maxSafeK = (cribLen + 4) / 6
		}
		for k := 1; k <= maxSafeK; k++ {
			c := att.pinRank(k)
			if len(c) == 0 || len(c) > 4096 {
				continue
			}
			ls, hs := map[byte]bool{}, map[byte]bool{}
			for _, rk := range c {
				ls[byte(rk&0xFF)] = true
				hs[byte(rk>>8)] = true
			}
			var lv, hv []byte
			for v := range ls {
				lv = append(lv, v)
			}
			for v := range hs {
				hv = append(hv, v)
			}
			aL, cL, aH, cH = append(aL, lc[k].aL), append(cL, lc[k].cL), append(aH, lc[k].aH), append(cH, lc[k].cH)
			loSets, hiSets = append(loSets, lv), append(hiSets, hv)
		}
		if len(loSets) < 5 {
			continue
		}
		var keysLo, keysHi []tcLaneKey
		if !bootstrapped {
			keysLo = tcSolveLaneFoldParallel(aL, cL, loSets, 8)
			keysHi = tcSolveLaneFoldParallel(aH, cH, hiSets, 8)
		} else {
			keysLo = tcSolveLaneWithSuffixes(candSufLo, aL, cL, loSets)
			keysHi = tcSolveLaneWithSuffixes(candSufHi, aH, cH, hiSets)
		}
		sufLoMap := map[[4]byte]bool{}
		for _, kl := range keysLo {
			sufLoMap[[4]byte{kl.k[1], kl.k[2], kl.k[3], kl.k[4]}] = true
		}
		sufHiMap := map[[4]byte]bool{}
		for _, kh := range keysHi {
			sufHiMap[[4]byte{kh.k[1], kh.k[2], kh.k[3], kh.k[4]}] = true
		}
		if len(sufLoMap) == 0 || len(sufHiMap) == 0 {
			continue
		}
		candSufLo = candSufLo[:0]
		for s := range sufLoMap {
			candSufLo = append(candSufLo, s)
		}
		candSufHi = candSufHi[:0]
		for s := range sufHiMap {
			candSufHi = append(candSufHi, s)
		}
		bootstrapped = true

		seenSched := map[string]bool{}
		var msgScheds [][]int
		for _, kl := range keysLo {
			for _, kh := range keysHi {
				if (kl.delta & 1) != (kh.delta & 1) {
					continue
				}
				rk := make([]int, maxChunks)
				var sig [90 * 2]byte
				for k := 0; k < maxChunks; k++ {
					lo := tcCascade(kl.k[:], lc[k].aL, lc[k].cL+kl.delta)
					hi := tcCascade(kh.k[:], lc[k].aH, lc[k].cH+kh.delta)
					rk[k] = int(lo) | int(hi)<<8
					sig[2*k] = lo
					sig[2*k+1] = hi
				}
				if !seenSched[string(sig[:])] {
					seenSched[string(sig[:])] = true
					msgScheds = append(msgScheds, rk)
				}
			}
		}

		if safeBands >= 3 && dataSeedSamples[0] < 8 {
			for r := 0; r < 3; r++ {
				seenFn := map[[256]byte]bool{}
				contributed := false
				for _, rk := range msgScheds {
					var aa, cc []byte
					var sets [][]byte
					for w := 2; w <= safeBands; w++ {
						for k := 1; k <= maxSafeK; k++ {
							if xVal, ok := att.tcXorFromCribChunk(r, w, k, rk[k]); ok {
								al, cl, _, _ := tcLaneConsts(tcPixelBuf(w, att.mainNonce))
								cand := tcDataHashCandidates(att.pix[r][w].rot, xVal)
								if len(cand) > 0 {
									aa = append(aa, al)
									cc = append(cc, cl)
									sets = append(sets, cand)
								}
								break
							}
						}
					}
					if len(sets) >= 2 {
						contributed = true
						cands := tcSolveLane4Canonical(aa, cc, sets)
						for _, ck := range cands {
							fn := tcCanonicalFunc4(ck, aPixelLo)
							if !seenFn[fn] {
								seenFn[fn] = true
								regionFuncCounts[r][fn]++
								regionFuncRep[r][fn] = ck
							}
						}
					}
				}
				if contributed {
					dataSeedSamples[r]++
				}
			}
		}
		att.allScheds = msgScheds
	}

	var pinnedDS [3][4]byte
	for r := 0; r < 3; r++ {
		bestCnt := -1
		for fn, cnt := range regionFuncCounts[r] {
			if cnt > bestCnt {
				bestCnt = cnt
				pinnedDS[r] = regionFuncRep[r][fn]
			}
		}
	}

	var allNoiseObs []tcNoiseObs
	for _, att := range resolvedAttacks {
		if len(att.allScheds) != 1 {
			continue
		}
		rk := att.allScheds[0]
		safeBands := att.bandsResolved
		if att.bandsResolved < maxAnchorBand && att.bandsResolved > 2 {
			safeBands = att.bandsResolved - 1
		}
		for r := 0; r < 3; r++ {
			for w := 1; w <= safeBands; w++ {
				if !att.pix[r][w].ok {
					continue
				}
				al, cl, _, _ := tcLaneConsts(tcPixelBuf(w, att.mainNonce))
				dh := uint(tcCascade(pinnedDS[r][:], al, cl))
				rot, xor := dh%7, dh>>DataRotationBits
				lin := (att.startPixel[r] + w) % att.widths[r]

				var npMask byte
				for np := uint(0); np < 8; np++ {
					win := tcReadPixel(att.regions[r], lin, np, rot, xor)
					good := true
					for off := 0; off < 7; off++ {
						st := 7*w + off
						j := st - att.base[r]
						if j < 2 {
							continue
						}
						k, bi := j/2, j%2
						if k < 1 || k > 20 {
							continue
						}
						l0, l1, l2, ok := att.laneBytes(k, rk[k])
						if !ok {
							continue
						}
						want := byte([3]uint16{l0, l1, l2}[r] >> uint(8*bi))
						if want == 0 {
							continue
						}
						if win[off] != want {
							good = false
							break
						}
					}
					if good {
						npMask |= byte(1) << np
					}
				}
				if npMask != 0 {
					nbuf := tcPixelBuf(r*att.widths[0]+w, att.mainNonce)
					_, nCLo, _, nCHi := tcLaneConsts(nbuf)
					allNoiseObs = append(allNoiseObs, tcNoiseObs{cLo: nCLo, cHi: nCHi, npMask: npMask})
				}
			}
		}
	}

	candNS := tcSolveNoiseSeedFromBins(allNoiseObs, 8)
	if len(candNS) == 0 {
		t.Fatalf("corpus=%s: failed to solve noiseSeed from %d crib observations", corpus, len(allNoiseObs))
	}

	var truncD [3]*Seed128
	for r := 0; r < 3; r++ {
		truncD[r] = tcMakeEquivSeed(2+r, pinnedDS[r], [4]byte{})
	}

	var truncNS *Seed128
	var nsLo, nsHi [4]byte
	var truncLS *Seed128
	var truncS [3]*Seed128
	msg0 := sess.messages[0]
	crib0 := msg0.plaintext[:cribLen]
	msg1 := sess.messages[1]
	crib1 := msg1.plaintext[:cribLen]
	for _, npair := range candNS {
		candSeedNS := tcMakeEquivSeed(0, npair.lo, npair.hi)
		for _, ss0 := range candSS[0] {
			s0 := tcMakeEquivSeed(5, ss0, [4]byte{})
			for _, ss1 := range candSS[1] {
				s1 := tcMakeEquivSeed(6, ss1, [4]byte{})
				for _, ss2 := range candSS[2] {
					s2 := tcMakeEquivSeed(7, ss2, [4]byte{})
					for _, sLo := range candSufLo {
						for _, flipLo := range [2]byte{0, 0x80} {
							for _, sHi := range candSufHi {
								for _, flipHi := range [2]byte{0, 0x80} {
									candLS := tcMakeEquivSeed(1,
										[4]byte{sLo[0] ^ flipLo, sLo[1], sLo[2], sLo[3]},
										[4]byte{sHi[0] ^ flipHi, sHi[1], sHi[2], sHi[3]})
									ptTry0, err0 := Decrypt3x128Cfg(sess.cfg, candSeedNS, candLS, truncD[0], truncD[1], truncD[2], s0, s1, s2, msg0.wire)
									if err0 != nil || len(ptTry0) < cribLen || !bytes.Equal(ptTry0[:cribLen], crib0) {
										continue
									}
									ptTry1, err1 := Decrypt3x128Cfg(sess.cfg, candSeedNS, candLS, truncD[0], truncD[1], truncD[2], s0, s1, s2, msg1.wire)
									if err1 == nil && len(ptTry1) >= cribLen && bytes.Equal(ptTry1[:cribLen], crib1) {
										truncNS = candSeedNS
										nsLo, nsHi = npair.lo, npair.hi
										truncLS = candLS
										truncS = [3]*Seed128{s0, s1, s2}
										break
									}
								}
								if truncLS != nil {
									break
								}
							}
							if truncLS != nil {
								break
							}
						}
						if truncLS != nil {
							break
						}
					}
					if truncLS != nil {
						break
					}
				}
				if truncLS != nil {
					break
				}
			}
			if truncLS != nil {
				break
			}
		}
		if truncLS != nil {
			break
		}
	}

	if truncLS == nil {
		t.Fatalf("corpus=%s: failed to select gauge-consistent lockSeed/startSeeds on messages 0..1", corpus)
	}

	msgsDecrypted := 0
	msgsSHA256Match := 0
	unkTotal, unkExact := 0, 0
	for _, vm := range sess.messages {
		ptDec, err := Decrypt3x128Cfg(sess.cfg, truncNS, truncLS, truncD[0], truncD[1], truncD[2], truncS[0], truncS[1], truncS[2], vm.wire)
		unkTotal += 512 - cribLen
		if err == nil && len(ptDec) == 512 {
			msgsDecrypted++
			if sha256.Sum256(ptDec) == sha256.Sum256(vm.plaintext) {
				msgsSHA256Match++
			}
			for i := cribLen; i < 512; i++ {
				if ptDec[i] == vm.plaintext[i] {
					unkExact++
				}
			}
		}
	}

	var rawNSLo, rawNSHi [4]byte
	for j := 0; j < 4; j++ {
		rawNSLo[j] = byte(sess.ns.Components[2*j] & 0xFF)
		rawNSHi[j] = byte(sess.ns.Components[2*j+1] & 0xFF)
	}
	nsLoMatch := tcCanonicalFunc4(nsLo, aPixelLo) == tcCanonicalFunc4(rawNSLo, aPixelLo)
	nsHiMatch := tcCanonicalFunc4(nsHi, aPixelHi) == tcCanonicalFunc4(rawNSHi, aPixelHi)

	t.Logf("corpus=%-6s | msgs=%d | crib=%dB (25%%) | noiseSeed (loMatch=%v, hiMatch=%v) | Decrypt3x128Cfg SHA-256=%d/%d (%.2f%%) | unknown 75%% exact=%d/%d (%.2f%%) | wall=%v",
		corpus, numMsgs, cribLen, nsLoMatch, nsHiMatch,
		msgsSHA256Match, numMsgs, 100*float64(msgsSHA256Match)/float64(numMsgs),
		unkExact, unkTotal, 100*float64(unkExact)/float64(unkTotal),
		time.Since(t0))

	if msgsDecrypted != numMsgs || msgsSHA256Match != numMsgs || unkExact != unkTotal {
		t.Fatalf("corpus=%s: expected 100%% recovery across %d messages, got decrypted=%d sha256=%d/%d unknown=%d/%d",
			corpus, numMsgs, msgsDecrypted, msgsSHA256Match, numMsgs, unkExact, unkTotal)
	}
}

func TestRedTeamTrainHashMultiMessage(t *testing.T) {
	const (
		cribLen = 128
		numMsgs = 50
	)
	for _, corpus := range []string{"ascii", "json", "binary"} {
		corpus := corpus
		t.Run(corpus, func(t *testing.T) {
			runTrainHashMultiMsgSession(t, corpus, cribLen, numMsgs)
		})
	}
}
