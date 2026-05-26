package easy_test

import (
	"bytes"
	"testing"

	"github.com/everanium/itb/easy"
)

// TestEasyLockBatchRoundTrip verifies a SetLockSoup(1) + SetLockBatch(1)
// encryptor round-trips plaintext across Single and Triple modes for several
// sizes spanning sub-chunk, single-group, and tail-group cases.
func TestEasyLockBatchRoundTrip(t *testing.T) {
	sizes := []int{1, 8, 24, 25, 100, 1024, 4097}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			for _, n := range sizes {
				enc := newEncryptorFor("areion512", 1024, m.mode)
				enc.SetLockSoup(1)
				enc.SetLockBatch(1)
				plaintext := generateDataEasy(n)
				ct, err := enc.Encrypt(plaintext)
				if err != nil {
					enc.Close()
					t.Fatalf("size=%d: Encrypt: %v", n, err)
				}
				pt, err := enc.Decrypt(ct)
				enc.Close()
				if err != nil {
					t.Fatalf("size=%d: Decrypt: %v", n, err)
				}
				if !bytes.Equal(pt, plaintext) {
					t.Fatalf("size=%d: round-trip mismatch under SetLockBatch(1)", n)
				}
			}
		})
	}
}

// TestEasyLockBatchExportImport confirms the lock_batch flag survives an
// Export / Import round-trip: a sender with SetLockSoup(1) + SetLockBatch(1)
// produces ciphertext a receiver can decrypt only after importing the blob
// (which carries the batch mode).
func TestEasyLockBatchExportImport(t *testing.T) {
	plaintext := []byte("LockBatch export/import round-trip payload, multiple chunks long")
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			sender := newEncryptorFor("areion512", 1024, m.mode)
			defer sender.Close()
			sender.SetLockSoup(1)
			sender.SetLockBatch(1)

			ct, err := sender.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("sender Encrypt: %v", err)
			}
			blob := sender.Export()

			receiver := newEncryptorFor("areion512", 1024, m.mode)
			defer receiver.Close()
			receiver.SetLockSoup(1) // deployment config — must match sender
			if err := receiver.Import(blob); err != nil {
				t.Fatalf("receiver Import: %v", err)
			}

			pt, err := receiver.Decrypt(ct)
			if err != nil {
				t.Fatalf("receiver Decrypt: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatal("receiver round-trip differs after Import (lock_batch not carried)")
			}
		})
	}
}

// TestEasyLockBatchInert verifies SetLockBatch(1) is inert when Lock Soup is
// off: an encryptor with batch on but no Lock Soup produces the same
// plaintext on round-trip as the default (no overlay) encryptor, and the flag
// does not engage any overlay on its own.
func TestEasyLockBatchInert(t *testing.T) {
	plaintext := []byte("inertness payload spanning several 24-bit chunks for coverage")
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			enc := newEncryptorFor("areion512", 1024, m.mode)
			defer enc.Close()
			enc.SetLockBatch(1) // no SetLockSoup — must stay inert

			ct, err := enc.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			pt, err := enc.Decrypt(ct)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatal("round-trip mismatch with LockBatch on, Lock Soup off")
			}
		})
	}
}

// TestEasyLockBatchClosedPanics confirms SetLockBatch panics with ErrClosed
// after Close, matching the other setters.
func TestEasyLockBatchClosedPanics(t *testing.T) {
	enc := newEncryptorFor("areion512", 1024, 1)
	enc.Close()
	defer func() {
		if r := recover(); r != easy.ErrClosed {
			t.Fatalf("expected ErrClosed, got %v", r)
		}
	}()
	enc.SetLockBatch(1)
}
