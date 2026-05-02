package easy

// Close zeroes the encryptor's PRF keys, MAC key, and seed
// components, drops the bound MAC closure and any dedicated
// LockSeedHandle, and marks the encryptor as closed. Subsequent
// method calls on this instance panic with [ErrClosed].
//
// Idempotent — multiple Close calls return nil without panic.
//
// Returns error to compose with `defer enc.Close()` and
// errors.Join; current implementation never returns a non-nil error
// (the close path has no I/O and no failure modes), but the
// signature reserves the slot for future extensions.
func (e *Encryptor) Close() error {
	if e.closed {
		return nil
	}

	for _, k := range e.prfKeys {
		clear(k)
	}
	e.prfKeys = nil

	clear(e.macKey)
	e.macKey = nil

	for _, s := range e.seeds {
		zeroSeedComponents(s, e.width)
	}
	e.seeds = nil

	e.macFunc = nil

	if e.cfg != nil {
		e.cfg.LockSeedHandle = nil
	}

	e.closed = true
	return nil
}
