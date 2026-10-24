package chacha20ctr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime/debug"
	"testing"
	"unsafe"

	"golang.org/x/crypto/chacha20"
)

// TestChaCha20RFC8439Vector verifies XORKeyStreamBlocks and Cipher against the
// RFC 8439 § 2.4.2 test vector.
func TestChaCha20RFC8439Vector(t *testing.T) {
	keyBytes, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes, err := hex.DecodeString("000000000000004a00000000")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	wantHex := "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}

	var c Cipher
	if err := c.InitWithCounter(keyBytes, nonceBytes, 1); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	c.XORKeyStream(got, plaintext)
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 8439 § 2.4.2 mismatch:\ngot  %x\nwant %x", got, want)
	}
	c.Wipe()
}

// TestXChaCha20Parity verifies 24-byte XChaCha20 nonces against
// golang.org/x/crypto/chacha20.NewUnauthenticatedCipher.
func TestXChaCha20Parity(t *testing.T) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSizeX)
	for i := range key {
		key[i] = byte(0x31 + i*7)
	}
	for i := range nonce {
		nonce[i] = byte(0x95 + i*11)
	}
	src := make([]byte, 1000)
	for i := range src {
		src[i] = byte(i*19 + 3)
	}

	ref, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, len(src))
	ref.XORKeyStream(want, src)

	var c Cipher
	if err := c.Init(key, nonce); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(src))
	c.XORKeyStream(got, src)
	if !bytes.Equal(got, want) {
		t.Fatalf("XChaCha20 mismatch against x/crypto/chacha20")
	}
	c.Wipe()
}

// TestChaCha20XORKeyStreamBlocksParity verifies XORKeyStreamBlocks and
// scalarXORKeyStreamBlocks against golang.org/x/crypto/chacha20 across block
// counts 1..35 (exercising 8-block, 4-block, and 1-block tails) and high
// counter values near 2^32.
func TestChaCha20XORKeyStreamBlocksParity(t *testing.T) {
	var keyBytes [32]byte
	var nonceBytes [12]byte
	for i := range keyBytes {
		keyBytes[i] = byte(0x11 + i*7)
	}
	for i := range nonceBytes {
		nonceBytes[i] = byte(0xa3 + i*13)
	}
	var keyWords [8]uint32
	for i := 0; i < 8; i++ {
		keyWords[i] = binary.LittleEndian.Uint32(keyBytes[i*4:])
	}
	nonceWords := [3]uint32{
		binary.LittleEndian.Uint32(nonceBytes[0:4]),
		binary.LittleEndian.Uint32(nonceBytes[4:8]),
		binary.LittleEndian.Uint32(nonceBytes[8:12]),
	}

	counters := []uint32{0, 1, 7, 42, 0xfffffff0 - 40}
	for _, ctr := range counters {
		for nBlocks := 1; nBlocks <= 35; nBlocks++ {
			n := nBlocks * 64
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i*29 + 5)
			}
			want := make([]byte, n)
			ref, err := chacha20.NewUnauthenticatedCipher(keyBytes[:], nonceBytes[:])
			if err != nil {
				t.Fatal(err)
			}
			ref.SetCounter(ctr)
			ref.XORKeyStream(want, src)

			gotDispatch := make([]byte, n)
			XORKeyStreamBlocks(gotDispatch, src, &keyWords, &nonceWords, ctr)
			if !bytes.Equal(gotDispatch, want) {
				t.Fatalf("dispatch mismatch at ctr=%d nBlocks=%d", ctr, nBlocks)
			}

			gotScalar := make([]byte, n)
			scalarXORKeyStreamBlocks(gotScalar, src, &keyWords, &nonceWords, ctr)
			if !bytes.Equal(gotScalar, want) {
				t.Fatalf("scalar mismatch at ctr=%d nBlocks=%d", ctr, nBlocks)
			}
		}
	}
}

// TestChaCha20CounterBoundaryAndOverflow tests counters 0xfffffffe and
// 0xffffffff against golang.org/x/crypto/chacha20 and verifies that
// attempting to generate past block 0xffffffff panics with counter overflow.
func TestChaCha20CounterBoundaryAndOverflow(t *testing.T) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	for i := range key {
		key[i] = byte(0x41 + i*3)
	}
	for i := range nonce {
		nonce[i] = byte(0x17 + i*5)
	}
	src := make([]byte, 128)
	for i := range src {
		src[i] = byte(i + 1)
	}

	// 2 blocks starting at 0xfffffffe (blocks 0xfffffffe and 0xffffffff).
	ref, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	ref.SetCounter(0xfffffffe)
	want := make([]byte, 128)
	ref.XORKeyStream(want, src)

	var c Cipher
	if err := c.InitWithCounter(key, nonce, 0xfffffffe); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 128)
	c.XORKeyStream(got, src)
	if !bytes.Equal(got, want) {
		t.Fatal("mismatch at counter 0xfffffffe..0xffffffff")
	}

	// Any subsequent XORKeyStream call must panic with counter overflow.
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		var extra [1]byte
		c.XORKeyStream(extra[:], extra[:])
	}()
	if !panicked {
		t.Fatal("expected panic on XORKeyStream past block 0xffffffff")
	}

	// Direct 1-block call at 0xffffffff via ResetCounter.
	if err := c.ResetCounter(int(uint64(0xffffffff) * BlockSize)); err != nil {
		t.Fatal(err)
	}
	gotLast := make([]byte, 64)
	c.XORKeyStream(gotLast, src[64:128])
	if !bytes.Equal(gotLast, want[64:128]) {
		t.Fatal("mismatch at block 0xffffffff after ResetCounter")
	}
	c.Wipe()
}

// TestCipherWipe verifies that Wipe zeroes all key material, nonces,
// counters, and buffered keystream bytes in Cipher.
func TestCipherWipe(t *testing.T) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	for i := range key {
		key[i] = byte(0x55 + i)
	}
	for i := range nonce {
		nonce[i] = byte(0xaa + i)
	}
	var c Cipher
	if err := c.InitWithCounter(key, nonce, 7); err != nil {
		t.Fatal(err)
	}
	var dst, src [5]byte
	c.XORKeyStream(dst[:], src[:])
	// Consumed prefix [0:5] must already be zeroed.
	for i := 0; i < 5; i++ {
		if c.buf[i] != 0 {
			t.Fatalf("consumed keystream byte %d not zeroed: %#x", i, c.buf[i])
		}
	}
	c.Wipe()
	for i, w := range c.key {
		if w != 0 {
			t.Fatalf("key[%d] not zeroed on Wipe: %#x", i, w)
		}
	}
	for i, w := range c.nonce {
		if w != 0 {
			t.Fatalf("nonce[%d] not zeroed on Wipe: %#x", i, w)
		}
	}
	for i, b := range c.buf {
		if b != 0 {
			t.Fatalf("buf[%d] not zeroed on Wipe: %#x", i, b)
		}
	}
	if c.counter != 0 || c.bufOff != BlockSize || c.overflow {
		t.Fatalf("unexpected post-Wipe state: counter=%d bufOff=%d overflow=%v", c.counter, c.bufOff, c.overflow)
	}
}

// TestChaCha20XORKeyStreamBlocksBitSensitivity verifies that flipping any bit
// in key, nonce, counter, or plaintext changes the output of
// XORKeyStreamBlocks across all lane positions (15 blocks = 8 + 4 + 3).
func TestChaCha20XORKeyStreamBlocksBitSensitivity(t *testing.T) {
	const nBlocks = 15
	const nBytes = nBlocks * 64
	key := [8]uint32{
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
	}
	nonce := [3]uint32{0x09000000, 0x4a000000, 0x00000000}
	counter := uint32(5)
	src := make([]byte, nBytes)
	for i := range src {
		src[i] = byte(i*17 + 3)
	}
	base := make([]byte, nBytes)
	XORKeyStreamBlocks(base, src, &key, &nonce, counter)

	out := make([]byte, nBytes)
	for w := 0; w < 8; w++ {
		for b := 0; b < 32; b++ {
			k2 := key
			k2[w] ^= 1 << b
			XORKeyStreamBlocks(out, src, &k2, &nonce, counter)
			for blk := 0; blk < nBlocks; blk++ {
				if bytes.Equal(out[blk*64:(blk+1)*64], base[blk*64:(blk+1)*64]) {
					t.Fatalf("key word %d bit %d did not change block %d", w, b, blk)
				}
			}
		}
	}
	for w := 0; w < 3; w++ {
		for b := 0; b < 32; b++ {
			n2 := nonce
			n2[w] ^= 1 << b
			XORKeyStreamBlocks(out, src, &key, &n2, counter)
			for blk := 0; blk < nBlocks; blk++ {
				if bytes.Equal(out[blk*64:(blk+1)*64], base[blk*64:(blk+1)*64]) {
					t.Fatalf("nonce word %d bit %d did not change block %d", w, b, blk)
				}
			}
		}
	}
	for b := 0; b < 32; b++ {
		c2 := counter ^ (1 << b)
		XORKeyStreamBlocks(out, src, &key, &nonce, c2)
		if bytes.Equal(out, base) {
			t.Fatalf("counter bit %d did not change output", b)
		}
	}
}

const (
	residueGap      = 1 << 10
	residuePad      = 2 << 10
	residueWindow   = 16 << 10
	residueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
)

var dumpSIMDRegsHook func(dst *[88]uint64)
var dirtySIMDRegHook func(masked uint64)
var genericResidueSink uint64

//go:noinline
func leakyFrameForTest(secret uint64, i int) {
	var frame [8]uint64
	for j := range frame {
		frame[j] = secret
	}
	genericResidueSink = frame[(i+1)%len(frame)]
}

func checkResidueNegativeControls(t *testing.T) {
	t.Helper()
	secret := uint64(0xA5C35A3CF00DCAFE)
	resStack := stackResidue(func() { leakyFrameForTest(secret, 0) })
	stackHits := 0
	for _, w := range resStack[:residueWindow/8] {
		if w == secret {
			stackHits++
		}
	}
	if stackHits == 0 {
		t.Fatal("negative control: stack-residue probe did not see secret stored by leakyFrameForTest")
	}
	if dirtySIMDRegHook != nil {
		resReg := stackResidue(func() { dirtySIMDRegHook(secret ^ 0x5555555555555555) })
		regHits := 0
		for _, w := range resReg[residueWindow/8:] {
			if w == secret {
				regHits++
			}
		}
		if regHits == 0 {
			t.Fatal("negative control: register snapshot did not see leaked register word")
		}
	}
}

func stackResidue(fn func()) []uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, residueWindow/8+88)
	done := make(chan struct{})
	go func() {
		defer close(done)
		residueGrow(0)
		var regs [88]uint64
		residueProbe(fn, res[:residueWindow/8], &regs)
		copy(res[residueWindow/8:], regs[:])
	}()
	<-done
	return res
}

//go:noinline
func residueGrow(i int) byte {
	var pad [4 * residueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func residueProbe(fn func(), res []uint64, regs *[88]uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -residueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = residueSentinel
	}
	residueDeep(fn, 0, regs)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func residueDeep(fn func(), i int, regs *[88]uint64) byte {
	var pad [residuePad]byte
	pad[i] = 1
	fn()
	if dumpSIMDRegsHook != nil {
		dumpSIMDRegsHook(regs)
	}
	return pad[(i+7)%len(pad)]
}

func assertNoSecretResidue(t *testing.T, name string, res []uint64, secrets32 map[uint32]string) {
	t.Helper()
	written := 0
	stackWords := residueWindow / 8
	for i, w := range res {
		if i < stackWords && w != residueSentinel {
			written++
		}
		if i >= stackWords && w == 0 {
			continue
		}
		for h, d := range [2]uint32{uint32(w), uint32(w >> 32)} {
			if i >= stackWords && d == 0 {
				continue
			}
			if what, ok := secrets32[d]; ok {
				if i < stackWords {
					t.Errorf("%s: %s (%#x) left in the stack %d bytes below the window top", name, what, d, 8*(i+1)-4*h)
				} else {
					t.Errorf("%s: %s (%#x) left in post-RET register snapshot (word %d half %d)", name, what, d, i-stackWords, h)
				}
			}
		}
	}
	if written == 0 {
		t.Fatalf("%s: no word of the window was written; the probe missed the kernel frame", name)
	}
}

func makeTestSecrets(key *[8]uint32, nonce *[3]uint32) map[uint32]string {
	m := make(map[uint32]string, 11)
	for i, w := range key {
		m[w] = fmt.Sprintf("key[%d]", i)
	}
	for i, w := range nonce {
		m[w] = fmt.Sprintf("nonce[%d]", i)
	}
	return m
}

func TestScalarAndHChaCha20StackZeroization(t *testing.T) {
	checkResidueNegativeControls(t)
	key := [8]uint32{
		0xdeadbeef, 0xcafebabe, 0x01234567, 0x89abcdef,
		0xfedcba98, 0x76543210, 0x4b5a6978, 0x0f1e2d3c,
	}
	nonce := [3]uint32{0x11223344, 0x55667788, 0x99aabbcc}
	secrets := makeTestSecrets(&key, &nonce)

	src := make([]byte, 4*64)
	dst := make([]byte, 4*64)
	resScalar := stackResidue(func() {
		scalarXORKeyStreamBlocks(dst, src, &key, &nonce, 1)
	})
	assertNoSecretResidue(t, "scalarXORKeyStreamBlocks", resScalar, secrets)

	var keyBytes [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(keyBytes[i*4:], key[i])
	}
	var nonceX [24]byte
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint32(nonceX[i*4:], nonce[i])
		binary.LittleEndian.PutUint32(nonceX[12+i*4:], nonce[i]^0x13579bdf)
	}
	var c Cipher
	resInitX := stackResidue(func() {
		_ = c.InitWithCounter(keyBytes[:], nonceX[:], 0)
		c.Wipe()
	})
	assertNoSecretResidue(t, "InitWithCounter(XChaCha20)", resInitX, secrets)
}
