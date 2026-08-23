package triple

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/wrapper"
)

// Rekey swaps this Pipeline's parallax and wrapper masters. The eight
// ITB seeds and the MAC key are NOT rotated — Rekey targets only the
// two outer-layer master secrets.
//
// The returned blob carries the new masters + the unchanged inner
// [itb.Blob{N}] session state, exactly the shape [Init] returned but
// with the wrap-layer pm / wm fields refreshed. Distribute the new
// blob to the receiver so its Pipeline stays in sync (the receiver
// calls [Open] with the fresh blob or [Pipeline.Rekey] on its
// existing Pipeline with the same masters).
//
// THREAD-SAFETY. Rekey mutates Pipeline state. The caller is
// responsible for serialising this call against every concurrent
// [Pipeline.EncryptStream] / [Pipeline.DecryptStream] /
// [Pipeline.EncryptMessage] / [Pipeline.DecryptMessage] on the same
// Pipeline. Recommended pattern is a sync.RWMutex: acquire the read
// lock for cipher-path calls, the write lock for Rekey.
//
// Sanity checks: [ErrClosed] if the Pipeline has been closed;
// [ErrIdenticalMasters] if the two supplied masters compare
// bytewise-equal. When a layer is disabled for this Pipeline the
// corresponding master argument is ignored (may be nil); Rekey
// against a Pipeline with both layers off is a no-op that still
// produces a fresh blob (identical to the pre-Rekey blob).
func (p *Pipeline) Rekey(permMaster, wrapMaster []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if p.resolved.parallaxOn && len(permMaster) == 0 {
		return nil, ErrMissingMasters
	}
	if p.resolved.wrapperOn && len(wrapMaster) == 0 {
		return nil, ErrMissingMasters
	}
	if p.resolved.parallaxOn && p.resolved.wrapperOn && bytes.Equal(permMaster, wrapMaster) {
		return nil, ErrIdenticalMasters
	}

	freshPerm := append([]byte(nil), permMaster...)
	freshWrap := append([]byte(nil), wrapMaster...)

	if p.resolved.parallaxOn {
		// Rebuild Schedule + Cipherset from the fresh perm master.
		// Reuse the profile-resolved palette + segment size + chunk
		// size so the receiver's replay observes the same per-stream
		// shape.
		sched, err := parallax.NewSchedule(p.resolved.parallaxPalette, p.resolved.parallaxSegmentSize)
		if err != nil {
			return nil, fmt.Errorf("triple: Rekey parallax.NewSchedule: %w", err)
		}
		if p.resolved.chunkSize > 0 {
			if serr := sched.SetChunkSize(p.resolved.chunkSize); serr != nil {
				return nil, fmt.Errorf("triple: Rekey parallax.SetChunkSize: %w", serr)
			}
		}
		cs, err := parallax.NewCipherset(freshPerm, sched)
		if err != nil {
			return nil, fmt.Errorf("triple: Rekey parallax.NewCipherset: %w", err)
		}
		p.parallaxSched = sched
		p.parallaxCS = cs
	}

	if p.resolved.wrapperOn {
		derived, err := wrapper.DeriveKey(p.wrapperCipher, freshWrap)
		if err != nil {
			return nil, fmt.Errorf("triple: Rekey wrapper.DeriveKey: %w", err)
		}
		// Zero the previous wrapper key before dropping the
		// reference — it is a per-master derived secret and must
		// not remain in memory past the rotation.
		if p.wrapperKey != nil {
			clear(p.wrapperKey)
		}
		p.wrapperKey = derived
	}

	// Re-export the wrap-layer with the fresh masters. The inner
	// blob bytes carry the unchanged cfg + seeds + MAC material,
	// exactly as they were at [Init] time.
	innerBlob, err := exportInnerBlob(p.width, p.cfg, p.seeds, p.prfKeys, p.macKey, p.macName)
	if err != nil {
		return nil, err
	}

	wrap := blobWrapV1{
		Profile:  p.profileName,
		Version:  blobWrapVersionV1,
		Inner:    innerBlob,
		Parallax: p.resolved.parallaxOn,
		Wrapper:  p.resolved.wrapperOn,
	}
	if p.resolved.parallaxOn {
		wrap.PermMaster = freshPerm
	}
	if p.resolved.wrapperOn {
		wrap.WrapMaster = freshWrap
	}
	wrapBytes, err := json.Marshal(wrap)
	if err != nil {
		return nil, fmt.Errorf("triple: Rekey wrap-layer marshal: %w", err)
	}
	return wrapBytes, nil
}
