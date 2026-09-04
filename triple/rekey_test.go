package triple

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// TestPipelineRekeyRoundTrip verifies that after Rekey, the fresh
// blob's masters differ from the pre-Rekey blob's, that Open with
// the fresh masters succeeds and reconstructs a Pipeline whose
// wrapper key matches the post-Rekey sender.
func TestPipelineRekeyRoundTrip(t *testing.T) {
	sender, oldBlob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	newPerm := freshBytes(t, 32)
	newWrap := freshBytes(t, 32)

	newBlob, err := sender.Rekey(newPerm, newWrap)
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	// Fresh blob must carry the new masters.
	var wnew blobWrapV2
	if err := json.Unmarshal(newBlob, &wnew); err != nil {
		t.Fatalf("Unmarshal(newBlob): %v", err)
	}
	if !bytes.Equal(wnew.PermMaster, newPerm) {
		t.Fatalf("new blob PermMaster: got %x, want %x", wnew.PermMaster, newPerm)
	}
	if !bytes.Equal(wnew.WrapMaster, newWrap) {
		t.Fatalf("new blob WrapMaster: got %x, want %x", wnew.WrapMaster, newWrap)
	}

	// Old blob must carry different bytes to be a meaningful test.
	var wold blobWrapV2
	if err := json.Unmarshal(oldBlob, &wold); err != nil {
		t.Fatalf("Unmarshal(oldBlob): %v", err)
	}
	if bytes.Equal(wold.PermMaster, wnew.PermMaster) {
		t.Fatalf("Rekey did not change PermMaster")
	}
	if bytes.Equal(wold.WrapMaster, wnew.WrapMaster) {
		t.Fatalf("Rekey did not change WrapMaster")
	}

	// Receiver opens the fresh blob successfully.
	receiver, err := Load(newBlob)
	if err != nil {
		t.Fatalf("Open(newBlob): %v", err)
	}
	defer receiver.Close()

	// Receiver's wrapper key must match the sender's post-Rekey key
	// (both are wrapper.DeriveKey applied to newWrap under the same
	// cipher).
	if !bytes.Equal(receiver.wrapperKey, sender.wrapperKey) {
		t.Fatalf("receiver wrapperKey %x != sender wrapperKey %x",
			receiver.wrapperKey, sender.wrapperKey)
	}
}

// TestPipelineRekeyErrIdenticalMasters verifies the sanity check
// rejects Rekey when the two supplied masters compare equal.
func TestPipelineRekeyErrIdenticalMasters(t *testing.T) {
	sender, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	shared := freshBytes(t, 32)
	_, err = sender.Rekey(shared, shared)
	if !errors.Is(err, ErrIdenticalMasters) {
		t.Fatalf("Rekey identical: got err=%v, want %v",
			err, ErrIdenticalMasters)
	}
}
