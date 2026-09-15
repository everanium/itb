package triple

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb"
)

// cascade_fill_test.go — the Interlocked Barrier cascade fill is the
// wire of every Pipeline regardless of the fast-path hooks its seeds
// carry. For every shipped profile, a Pipeline built by Init and a
// Pipeline rebuilt from its blob by Load with every hook stripped from
// every seed must decrypt each other's wire, on the message or the
// streaming surface the profile exposes; after Rekey the freshly
// loaded, hook-stripped receiver must decrypt the rekeyed sender's
// wire. A hook that changed the wire, or a constructor path that left
// the cascade behind, would break the cross-decrypt.

// stripHooks removes every fast-path hook from the eight seeds so the
// Pipeline runs the sequential cascade arms only.
func stripHooks(t *testing.T, seeds [8]any) {
	t.Helper()
	for i, s := range seeds {
		switch seed := s.(type) {
		case *itb.Seed128:
			seed.FusedChain, seed.BatchFusedChain = nil, nil
			seed.SetBatchFusedChain8(nil)
			seed.SetInterlockBatch16(nil)
		case *itb.Seed256:
			seed.FusedChain, seed.BatchFusedChain = nil, nil
			seed.SetInterlockBatch16(nil)
		case *itb.Seed512:
			seed.FusedChain, seed.BatchFusedChain = nil, nil
			seed.SetInterlockBatch16(nil)
		default:
			t.Fatalf("seed %d is %T", i, s)
		}
	}
}

// cipher runs the profile's cipher surface: the streaming byte API on
// streaming profiles, the message API otherwise.
func cipherEncrypt(t *testing.T, p *Pipeline, plain []byte) []byte {
	t.Helper()
	var wire []byte
	var err error
	if isStreamingMode(p.resolved.Mode) {
		wire, err = p.EncryptStreamBytes(plain)
	} else {
		wire, err = p.EncryptMessage(plain)
	}
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return wire
}

func cipherDecrypt(t *testing.T, p *Pipeline, wire []byte) []byte {
	t.Helper()
	var plain []byte
	var err error
	if isStreamingMode(p.resolved.Mode) {
		plain, err = p.DecryptStreamBytes(wire)
	} else {
		plain, err = p.DecryptMessage(wire)
	}
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return plain
}

// TestShippedProfilesCascadeFillHookIndependent runs the cross-decrypt
// on every shipped profile at its default shape.
func TestShippedProfilesCascadeFillHookIndependent(t *testing.T) {
	plain := make([]byte, 40_000)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	widths := map[int]int{}
	for _, name := range Profiles() {
		name := name
		t.Run(name, func(t *testing.T) {
			p, blob, err := Init(name, Opts{})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if hasNoCipherSurface(p.resolved.Mode) {
				t.Skip("blob-only profile")
			}
			widths[p.width]++
			q, err := Load(blob)
			if err != nil {
				t.Fatal(err)
			}
			defer q.Close()
			stripHooks(t, q.seeds)

			wire := cipherEncrypt(t, p, plain)
			if got := cipherDecrypt(t, q, wire); !bytes.Equal(got, plain) {
				t.Fatal("hook-stripped Load Pipeline does not decrypt the Init Pipeline's wire")
			}
			wire = cipherEncrypt(t, q, plain)
			if got := cipherDecrypt(t, p, wire); !bytes.Equal(got, plain) {
				t.Fatal("Init Pipeline does not decrypt the hook-stripped Load Pipeline's wire")
			}

			perm, wrap := make([]byte, 32), make([]byte, 32)
			rand.Read(perm)
			rand.Read(wrap)
			rekeyed, err := p.Rekey(perm, wrap)
			if err != nil {
				t.Fatalf("Rekey: %v", err)
			}
			r, err := Load(rekeyed)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			stripHooks(t, r.seeds)
			wire = cipherEncrypt(t, p, plain)
			if got := cipherDecrypt(t, r, wire); !bytes.Equal(got, plain) {
				t.Fatal("hook-stripped Pipeline loaded from the rekeyed blob does not decrypt the rekeyed sender's wire")
			}
		})
	}
	for _, w := range []int{128, 256, 512} {
		if widths[w] == 0 {
			t.Errorf("no shipped profile exercised width %d", w)
		}
	}
}
