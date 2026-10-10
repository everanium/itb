package itb

// Regression coverage for the streaming encoders' one-write-per-record
// invariant.
//
// The Triple Ouroboros streaming encoders (EncryptStream3xCfg,
// EncryptStreamAuth3xCfg) emit every chunk behind its own 32-byte
// prefix. If a prefix and its chunk body land on the destination
// io.Writer as two separate dst.Write calls, a concurrent reader that
// drains the destination between the two calls can consume (and, in a
// drain-and-discard caller pattern, drop) the prefix independently.
// The receiving side then sees a wire missing 32 bytes and cannot
// parse the next header.
//
// The tests below pin the invariant "every chunk record — prefix and
// chunk body — is emitted as ONE atomic dst.Write call" via a
// recording io.Writer that captures every Write invocation's length:
// the captured lengths must be exactly the record lengths walked off
// the emitted wire, one call per record.

import (
	"bytes"
	"io"
	"sync"
	"testing"
)

// recordingWriter is an io.Writer that appends every Write call's bytes
// to an internal buffer and records the length of each individual
// invocation. Lets a test assert per-Write batching invariants.
type recordingWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	calls []int
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, len(p))
	return w.buf.Write(p)
}

func (w *recordingWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Bytes()
}

func (w *recordingWriter) Calls() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]int, len(w.calls))
	copy(out, w.calls)
	return out
}

// recordLengths walks a stream wire record by record and returns the
// length of each record: the 32-byte prefix plus the chunk its header
// announces.
func recordLengths(t *testing.T, wire []byte) []int {
	t.Helper()
	var lens []int
	for off := 0; off < len(wire); {
		if len(wire)-off <= streamIDPrefixLen {
			t.Fatalf("record at %d: %d bytes left, no room for a chunk behind the prefix", off, len(wire)-off)
		}
		clen, err := ParseChunkLenCfg(nil, wire[off+streamIDPrefixLen:])
		if err != nil {
			t.Fatalf("record at %d: %v", off, err)
		}
		lens = append(lens, streamIDPrefixLen+clen)
		off += streamIDPrefixLen + clen
	}
	return lens
}

// assertOneWritePerRecord fails unless the recorded dst.Write lengths
// are exactly the record lengths of the emitted wire, one call per
// record, across a multi-chunk stream.
func assertOneWritePerRecord(t *testing.T, w *recordingWriter) {
	t.Helper()
	calls := w.Calls()
	lens := recordLengths(t, w.Bytes())
	if len(lens) < 2 {
		t.Fatalf("setup: %d records emitted, want a multi-chunk stream", len(lens))
	}
	if len(calls) != len(lens) {
		t.Fatalf("%d dst.Write calls for %d records, want one call per record; per-Write breakdown: %v, records: %v",
			len(calls), len(lens), calls, lens)
	}
	for i := range calls {
		if calls[i] != lens[i] {
			t.Fatalf("dst.Write %d = %d bytes, want the whole %d-byte record (prefix batched with chunk body); "+
				"per-Write breakdown: %v, records: %v", i, calls[i], lens[i], calls, lens)
		}
	}
}

// TestStreamPrefixBodyBatchingNonAuth pins the Non-AEAD stream encoder's
// one-write-per-record invariant: EncryptStream3xCfg must emit every
// 32-byte dummy prefix and the chunk body behind it in a single atomic
// dst.Write call. A drain race between two separate writes could
// otherwise let a concurrent reader consume-and-discard a prefix,
// leaving the receiving side's wire 32 bytes short.
func TestStreamPrefixBodyBatchingNonAuth(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	pt := genTestPlaintext(t, 3*4096+13)
	var w recordingWriter
	if err := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &w, 4096); err != nil {
		t.Fatalf("EncryptStream3xCfg: %v", err)
	}
	assertOneWritePerRecord(t, &w)
	// Round-trip: the emitted wire must decode back to the original plaintext.
	var ptBuf bytes.Buffer
	if err := DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(w.Bytes()), &ptBuf); err != nil {
		t.Fatalf("DecryptStream3xCfg: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatal("Non-AEAD Triple stream round-trip mismatch after prefix-batched writes")
	}
}

// TestStreamPrefixBodyBatchingAuth is the Streaming AEAD counterpart of
// TestStreamPrefixBodyBatchingNonAuth: EncryptStreamAuth3xCfg must
// batch every 32-byte prefix — the streamID ahead of chunk 0, a chunk
// prefix ahead of every later chunk — with the chunk body behind it
// into one atomic dst.Write call.
func TestStreamPrefixBodyBatchingAuth(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	pt := genTestPlaintext(t, 3*4096+13)
	var key [32]byte
	for i := range key {
		key[i] = byte(i) * 17
	}
	mac := macFuncForTest(key)
	var w recordingWriter
	if err := EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &w, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth3xCfg: %v", err)
	}
	assertOneWritePerRecord(t, &w)
	// Round-trip through the AEAD decoder.
	var ptBuf bytes.Buffer
	if err := DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(w.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth3xCfg: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatal("Streaming AEAD Triple stream round-trip mismatch after prefix-batched writes")
	}
}

// TestStreamConcurrentDrain16MiB is the permanent regression gate for
// the one-write-per-record invariant under a realistic concurrent-drain
// caller pattern. A goroutine drives the streaming encoder against an
// io.PipeWriter while a second goroutine drains the io.PipeReader into
// a wire buffer. After the encoder finishes, the accumulated wire is
// decoded and compared against the original plaintext.
//
// The 16 MiB size lands at the DefaultChunkSize boundary — the exact
// case documented by the BEAM bench workaround where a concurrent
// stream_read between a prefix write and its chunk body write can
// strand the prefix on the wire independently.
func TestStreamConcurrentDrain16MiB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 16 MiB concurrent-drain regression under -short")
	}
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	// 16 MiB + slack hits the DefaultChunkSize boundary with a small
	// trailing chunk, exercising two batched record writes.
	pt := genTestPlaintext(t, 16<<20+12345)

	pr, pw := io.Pipe()
	var wire bytes.Buffer
	var wg sync.WaitGroup
	var drainErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		// io.Copy drains the pipe reader continuously as bytes arrive
		// — models a caller that reads whenever the spool has data
		// available, without waiting for stream_end.
		_, drainErr = io.Copy(&wire, pr)
	}()

	encErr := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), pw, 0)
	_ = pw.Close()
	wg.Wait()

	if encErr != nil {
		t.Fatalf("EncryptStream3xCfg: %v", encErr)
	}
	if drainErr != nil {
		t.Fatalf("io.Copy drain: %v", drainErr)
	}

	var ptBuf bytes.Buffer
	if err := DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(wire.Bytes()), &ptBuf); err != nil {
		t.Fatalf("DecryptStream3xCfg on concurrent-drain wire: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("plaintext mismatch: encoded %d B, decoded %d B", len(pt), ptBuf.Len())
	}
}

// BenchmarkStreamEncrypt3xBatched measures per-call throughput of the
// Non-AEAD IO-Driven encoder path, which writes every chunk record —
// prefix and chunk body, built in one buffer — in one dst.Write.
func BenchmarkStreamEncrypt3xBatched(b *testing.B) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTripleForBench(b)
	pt := make([]byte, 1<<20)
	for i := range pt {
		pt[i] = byte(i)
	}
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var w discardWriter
		if err := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &w, 0); err != nil {
			b.Fatalf("EncryptStream3xCfg: %v", err)
		}
	}
}

// BenchmarkStreamEncryptAuth3xBatched is the AEAD counterpart of
// BenchmarkStreamEncrypt3xBatched.
func BenchmarkStreamEncryptAuth3xBatched(b *testing.B) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTripleForBench(b)
	var key [32]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	mac := macFuncForTest(key)
	pt := make([]byte, 1<<20)
	for i := range pt {
		pt[i] = byte(i)
	}
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var w discardWriter
		if err := EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &w, mac, 0); err != nil {
			b.Fatalf("EncryptStreamAuth3xCfg: %v", err)
		}
	}
}

// mkTripleForBench mirrors mkTriple128 for a benchmark (which takes
// *testing.B, not *testing.T).
func mkTripleForBench(b *testing.B) (n, l, d1, d2, d3, s1, s2, s3 *Seed128) {
	b.Helper()
	mk := func() *Seed128 {
		s, err := NewSeed128(512, sipHash128)
		if err != nil {
			b.Fatalf("NewSeed128: %v", err)
		}
		return s
	}
	return mk(), mk(), mk(), mk(), mk(), mk(), mk(), mk()
}

// discardWriter is a zero-alloc io.Writer that drops every byte. Used
// by the throughput benchmarks so the timed loop measures the encoder
// path rather than allocation-heavy buffer growth on the sink.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
