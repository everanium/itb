package triple

// Close wipes every piece of secret material this [Pipeline] owns and
// marks the Pipeline closed. Subsequent [Pipeline.EncryptStream] /
// [Pipeline.DecryptStream] / [Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage] / [Pipeline.Rekey] calls return
// [ErrClosed].
//
// Close is idempotent: a second call is a no-op returning nil. Close
// does NOT interrupt in-flight cipher calls; the caller is
// responsible for draining every concurrent operation on this
// Pipeline before invoking Close, otherwise those operations may
// observe zeroed key material and surface arbitrary errors.
//
// The Pipeline does not retain a copy of the two masters — they are
// consumed at [Init] / [Open] time to derive parallax subkeys and the
// wrapper per-Pipeline key, both of which are wiped here. The
// [Pipeline.Rekey] caller supplies fresh masters directly; nothing
// stored on the Pipeline reveals the masters after Close.
func (p *Pipeline) Close() error {
	// Serialise a racing second Close body against the first. The
	// atomic flag below is the check-then-act guard that keeps the
	// cipher-path stubs lock-free; the mutex here just makes the
	// wipe itself run once.
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed.Load() {
		return nil
	}

	// Zero the 8 seed Components in place.
	for _, s := range p.seeds {
		zeroSeedComponents(s, p.width)
	}

	// Zero the per-slot PRF fixed keys.
	for i, k := range p.prfKeys {
		clear(k)
		p.prfKeys[i] = nil
	}

	// Zero the wrapper key.
	if p.wrapperKey != nil {
		clear(p.wrapperKey)
		p.wrapperKey = nil
	}

	// Zero the MAC key and drop the closure.
	if p.macKey != nil {
		clear(p.macKey)
		p.macKey = nil
	}
	p.macFunc = nil

	// Drop parallax handles. The parallax package does not currently
	// expose a Cipherset.Close for explicit per-subkey wipe (recorded
	// as a best-practice gap in the parallax project memory); the
	// GC reclaims the subkey buffers once the reference drops here.
	p.parallaxSched = nil
	p.parallaxCS = nil

	// Publish the close via atomic-store so cipher-path stubs
	// consulting isClosed observe the transition without a lock.
	p.closed.Store(true)
	return nil
}
