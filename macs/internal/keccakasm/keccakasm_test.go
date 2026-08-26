package keccakasm

import (
	"bytes"
	"math/rand"
	"testing"

	"golang.org/x/crypto/sha3"
	xcpu "golang.org/x/sys/cpu"
)

// ─── test-local NIST SP 800-185 framing helpers ────────────────────
//
// Deliberate test-side duplicates of the parent macs/ package's
// left_encode / encode_string / bytepad (Algorithms 3–5) so the
// sponge is validated against x/crypto through an independently
// written framing path.

func tLeftEncode(x uint64) []byte {
	var buf [9]byte
	n := 8
	for n > 1 && (x>>(uint(n-1)*8))&0xFF == 0 {
		n--
	}
	buf[0] = byte(n)
	for i := 0; i < n; i++ {
		buf[1+i] = byte(x >> (uint(n-1-i) * 8))
	}
	return buf[:1+n]
}

func tEncodeString(s []byte) []byte {
	return append(tLeftEncode(uint64(len(s))*8), s...)
}

func tBytepad(z []byte, w int) []byte {
	out := append(tLeftEncode(uint64(w)), z...)
	for len(out)%w != 0 {
		out = append(out, 0)
	}
	return out
}

// cshakePrefix returns bytepad(encode_string(N) || encode_string(S), Rate)
// — the block cSHAKE256 absorbs before the message.
func cshakePrefix(n, s []byte) []byte {
	return tBytepad(append(tEncodeString(n), tEncodeString(s)...), Rate)
}

// vendoredCShake256 computes cSHAKE256(X, 256, N, S) via the vendored
// sponge (dispatching per the build/CPU tier).
func vendoredCShake256(n, s, x []byte) [32]byte {
	h := NewCShake256()
	h.Write(cshakePrefix(n, s))
	h.Write(x)
	return h.Sum256()
}

// ─── dispatcher guard ──────────────────────────────────────────────

// TestDispatcherGuard asserts that on a host whose CPUID carries the
// full AVX-512 F/BW/VL/DQ baseline the kernel gate is actually open —
// a silent fall-through to the scalar arm on capable hosts would
// invalidate every parity result below.
func TestDispatcherGuard(t *testing.T) {
	cpuHas := xcpu.X86.HasAVX512F && xcpu.X86.HasAVX512BW &&
		xcpu.X86.HasAVX512VL && xcpu.X86.HasAVX512DQ
	if asmCompiled && cpuHas && !HasAVX512Fused {
		t.Fatal("AVX-512 F/BW/VL/DQ present but HasAVX512Fused is false: silent scalar fallback")
	}
	if !asmCompiled && HasAVX512Fused {
		t.Fatal("HasAVX512Fused true on a build without the asm kernel")
	}
	t.Logf("asmCompiled=%v cpuHas=%v HasAVX512Fused=%v", asmCompiled, cpuHas, HasAVX512Fused)
}

// ─── permutation parity ────────────────────────────────────────────

// TestKeccakF1600DispatchParity cross-checks the dispatched
// permutation (AVX-512 kernel where the gate is open) against the
// portable scalar arm on 1000 random states.
func TestKeccakF1600DispatchParity(t *testing.T) {
	if !HasAVX512Fused {
		t.Skip("dispatched arm is the generic arm on this build/host; nothing to compare")
	}
	rng := rand.New(rand.NewSource(0x5EED))
	for i := 0; i < 1000; i++ {
		var a, b [25]uint64
		for j := range a {
			a[j] = rng.Uint64()
			b[j] = a[j]
		}
		keccakF1600(&a)
		keccakF1600Generic(&b)
		if a != b {
			t.Fatalf("fixture %d: dispatched vs generic mismatch\nasm %x\ngen %x", i, a, b)
		}
	}
}

// ─── sponge parity vs x/crypto ─────────────────────────────────────

// TestCShake256VsXCrypto validates the vendored sponge (framing
// included) byte-for-byte against golang.org/x/crypto/sha3's
// cSHAKE256 across 200 random (N, S, message) fixtures spanning
// empty inputs, sub-rate, rate-boundary, and multi-block messages.
func TestCShake256VsXCrypto(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))
	lengths := []int{0, 1, 8, 135, 136, 137, 271, 272, 273, 1000, 4096}
	for i := 0; i < 200; i++ {
		n := make([]byte, 1+rng.Intn(16)) // x/crypto requires N or S non-empty
		s := make([]byte, rng.Intn(32))
		msg := make([]byte, lengths[i%len(lengths)]+rng.Intn(64))
		rng.Read(n)
		rng.Read(s)
		rng.Read(msg)

		got := vendoredCShake256(n, s, msg)

		ref := sha3.NewCShake256(n, s)
		ref.Write(msg)
		want := make([]byte, 32)
		ref.Read(want)

		if !bytes.Equal(got[:], want) {
			t.Fatalf("fixture %d (|N|=%d |S|=%d |X|=%d):\ngot  %x\nwant %x",
				i, len(n), len(s), len(msg), got, want)
		}
	}
}

// TestCShake256WriteSplitInvariance checks that arbitrary Write
// chunking yields the same digest as a single Write — the property
// the KMAC template/clone flow and the incremental MAC path rely on.
func TestCShake256WriteSplitInvariance(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	msg := make([]byte, 3000)
	rng.Read(msg)
	n := []byte("KMAC")
	s := []byte("split")

	want := vendoredCShake256(n, s, msg)
	for trial := 0; trial < 50; trial++ {
		h := NewCShake256()
		h.Write(cshakePrefix(n, s))
		rest := msg
		for len(rest) > 0 {
			k := 1 + rng.Intn(len(rest))
			h.Write(rest[:k])
			rest = rest[k:]
		}
		got := h.Sum256()
		if got != want {
			t.Fatalf("trial %d: split-write digest differs", trial)
		}
	}
}

// TestCShake256Clone checks that Clone yields an independent state:
// squeezing a clone leaves the template reusable.
func TestCShake256Clone(t *testing.T) {
	tmpl := NewCShake256()
	tmpl.Write(cshakePrefix([]byte("KMAC"), nil))
	tmpl.Write([]byte("prefix-key-block"))

	c1 := tmpl.Clone()
	c1.Write([]byte("message-A"))
	t1 := c1.Sum256()

	c2 := tmpl.Clone()
	c2.Write([]byte("message-A"))
	t2 := c2.Sum256()

	if t1 != t2 {
		t.Fatal("clone of same template over same message differs")
	}

	c3 := tmpl.Clone()
	c3.Write([]byte("message-B"))
	if t3 := c3.Sum256(); t3 == t1 {
		t.Fatal("different messages produced identical digests")
	}
}

// TestKeccakF1600BitSensitivity flips every one of the 1600 state
// bits and checks the permutation output changes — a structural
// sanity net over both arms.
func TestKeccakF1600BitSensitivity(t *testing.T) {
	var base [25]uint64
	for i := range base {
		base[i] = 0xA5A5A5A5A5A5A5A5 ^ uint64(i)*0x0123456789ABCDEF
	}
	ref := base
	keccakF1600(&ref)
	for lane := 0; lane < 25; lane++ {
		for bit := 0; bit < 64; bit++ {
			a := base
			a[lane] ^= 1 << uint(bit)
			keccakF1600(&a)
			if a == ref {
				t.Fatalf("flipping lane %d bit %d left permutation output unchanged", lane, bit)
			}
		}
	}
}

func BenchmarkKeccakF1600AVX512(b *testing.B) {
	if !HasAVX512Fused {
		b.Skip("no AVX-512 kernel on this build/host")
	}
	var a [25]uint64
	b.SetBytes(Rate)
	for i := 0; i < b.N; i++ {
		keccakF1600(&a)
	}
}

func BenchmarkKeccakF1600Generic(b *testing.B) {
	var a [25]uint64
	b.SetBytes(Rate)
	for i := 0; i < b.N; i++ {
		keccakF1600Generic(&a)
	}
}
