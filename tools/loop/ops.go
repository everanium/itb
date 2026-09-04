package main

import (
	"crypto/rand"
	"fmt"

	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/triple"
)

// rekeyWrapMasterSize is the byte length of the fresh wrapper-side
// master drawn for every --rekey-every rotation. Matches the size
// [triple.Init] auto-generates when no override is supplied.
const rekeyWrapMasterSize = 32

// maintenance runs the periodic pipeline-mutating operations after a
// completed iteration: master rotation (--rekey-every) and blob
// export/reopen cycling (--blob-cycle-every). Both intervals count
// per-worker iterations; the warmup iteration (iter 0) never triggers
// because runLoop calls this for iter >= 1 only. Each operation takes
// the runState write lock, so in-flight cipher calls on other workers
// drain before any pipeline state mutates — the serialisation the
// [triple.Pipeline.Rekey] thread-safety contract requires.
func (w *worker) maintenance(r *runState, iter int64) error {
	if r.cfg.rekeyEvery > 0 && iter%r.cfg.rekeyEvery == 0 {
		if err := r.rekeyPipes(w.id, iter); err != nil {
			return err
		}
	}
	if r.cfg.blobCycleEvery > 0 && iter%r.cfg.blobCycleEvery == 0 {
		if err := r.blobCyclePipes(w.id, iter); err != nil {
			return err
		}
	}
	return nil
}

// rekeyPipes rotates the parallax + wrapper masters on every active
// pipeline via [triple.Pipeline.Rekey] under the write lock, and
// stores the refreshed session blobs for subsequent blob cycles.
// Masters are drawn fresh from CSPRNG on every rotation regardless of
// --seed (master rotation is pipeline keying, not plaintext content);
// a disabled layer receives nil, which Rekey ignores. The eight inner
// seeds and the MAC key are untouched by design — Rekey targets only
// the two outer-layer master secrets.
func (r *runState) rekeyPipes(workerID int, iter int64) error {
	var (
		permMaster []byte
		wrapMaster []byte
		err        error
	)
	if r.cfg.parallax {
		permMaster, err = parallax.GenerateMasterKey()
		if err != nil {
			return fmt.Errorf("g%d iter %d: parallax.GenerateMasterKey: %w", workerID, iter, err)
		}
	}
	if r.cfg.wrapper {
		wrapMaster = make([]byte, rekeyWrapMasterSize)
		if _, err = rand.Read(wrapMaster); err != nil {
			return fmt.Errorf("g%d iter %d: crypto/rand: %w", workerID, iter, err)
		}
	}

	r.pipeMu.Lock()
	defer r.pipeMu.Unlock()
	if r.streamPipe != nil {
		blob, rerr := r.streamPipe.Rekey(permMaster, wrapMaster)
		if rerr != nil {
			return fmt.Errorf("g%d iter %d: Rekey(%s): %w", workerID, iter, r.streamProfile, rerr)
		}
		r.streamBlob = blob
	}
	if r.msgPipe != nil {
		blob, rerr := r.msgPipe.Rekey(permMaster, wrapMaster)
		if rerr != nil {
			return fmt.Errorf("g%d iter %d: Rekey(%s): %w", workerID, iter, r.msgProfile, rerr)
		}
		r.msgBlob = blob
	}
	n := r.rekeys.Add(1)
	logf("rekey: g%d iter %d rotated parallax + wrapper masters (rekey #%d)", workerID, iter, n)
	return nil
}

// blobCyclePipes reopens every active pipeline from its current
// session blob under the write lock: a fresh Pipeline is built via
// [triple.Load], the running instance is closed, and the fresh one is
// swapped in. This exercises the blob export/import path's fidelity —
// every subsequent iteration round-trips through seeds and masters
// that survived a blob crossing. The blob carries the pipeline's full
// shape (the resolved profile record plus the inner Config snapshot),
// so no override reaches the reopen. On a Load failure the running
// pipeline is left in place and the error aborts the run.
func (r *runState) blobCyclePipes(workerID int, iter int64) error {
	r.pipeMu.Lock()
	defer r.pipeMu.Unlock()
	if r.streamPipe != nil {
		fresh, err := triple.Load(r.streamBlob)
		if err != nil {
			return fmt.Errorf("g%d iter %d: Load(%s): %w", workerID, iter, r.streamProfile, err)
		}
		_ = r.streamPipe.Close()
		r.streamPipe = fresh
	}
	if r.msgPipe != nil {
		fresh, err := triple.Load(r.msgBlob)
		if err != nil {
			return fmt.Errorf("g%d iter %d: Load(%s): %w", workerID, iter, r.msgProfile, err)
		}
		_ = r.msgPipe.Close()
		r.msgPipe = fresh
	}
	n := r.blobCycles.Add(1)
	logf("blob-cycle: g%d iter %d reopened from session blob (cycle #%d)", workerID, iter, n)
	return nil
}
