package triple

import "github.com/everanium/itb/internal/wipe"

// Close wipes every piece of secret material this [Pipeline] owns and
// marks the Pipeline closed. Subsequent [Pipeline.EncryptStream] /
// [Pipeline.DecryptStream] / [Pipeline.EncryptStreamBytes] /
// [Pipeline.DecryptStreamBytes] / [Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage] / [Pipeline.Rekey] / [Pipeline.SaveF]
// calls return [ErrClosed]; [Pipeline.Save] returns nil.
//
// Close is idempotent: a second call is a no-op returning nil. Close
// does NOT interrupt in-flight cipher calls; the caller is
// responsible for draining every concurrent operation on this
// Pipeline before invoking Close, otherwise those operations may
// observe zeroed key material and surface arbitrary errors.
//
// The two masters are retained inside the wrap-layer blob kept for
// [Pipeline.Save]; Close zeroes that blob (including permMaster and
// wrapMaster), the eight ITB seeds' Components, the per-slot PRF
// fixed keys, the wrapper per-Pipeline key, the MAC key, and the
// parallax cipherset subkeys (via [parallax.Cipherset.Close]),
// replaces the seed hash and MAC closures so closure-captured key
// schedules are released, and releases the parallax schedule and
// cipherset references. The [Pipeline.Rekey] caller supplies fresh
// masters directly; nothing stored on the Pipeline reveals the
// masters after Close.
func (p *Pipeline) Close() error {
	// Serialise a racing second Close body against the first. The
	// atomic flag below is the check-then-act guard that keeps the
	// cipher-path methods lock-free; the mutex here just makes the
	// wipe itself run once.
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed.Load() {
		return nil
	}
	// Publish the close via atomic-store first so cipher-path methods
	// consulting isClosed observe the transition before key material
	// is wiped.
	p.closed.Store(true)

	// Zero the 8 seed Components in place and release closure-captured
	// PRF key schedules.
	for _, s := range p.seeds {
		zeroSeedComponents(s, p.width)
	}

	// Zero the per-slot PRF fixed keys.
	for i, k := range p.prfKeys {
		wipe.Bytes(k)
		p.prfKeys[i] = nil
	}

	// Zero the wrapper key.
	if p.wrapperKey != nil {
		wipe.Bytes(p.wrapperKey)
		p.wrapperKey = nil
	}

	// Zero the MAC key and replace MAC closures with stateless stubs
	// so closure-captured MAC key schedules are released without
	// inducing a nil-func or MAC-to-No-MAC race on unsynchronised
	// in-flight calls.
	if p.macKey != nil {
		wipe.Bytes(p.macKey)
		p.macKey = nil
	}
	if p.macFunc != nil {
		p.macFunc = func([]byte) []byte { return make([]byte, 32) }
	}
	if p.cfg != nil && p.cfg.MACIncremental != nil {
		p.cfg.MACIncremental = func(...[]byte) []byte { return make([]byte, 32) }
	}

	// Zero the retained wrap-layer blob — it carries both masters and
	// the inner seed / PRF-key / MAC-key material.
	wipe.Bytes(p.blob)
	p.blob = nil

	// Zero parallax subkeys in place and drop parallax handles so the
	// GC reclaims the cipherset and schedule.
	_ = p.parallaxCS.Close()
	p.parallaxSched = nil
	p.parallaxCS = nil

	wipe.CallStack2K([9][8]uint64{})
	return nil
}
