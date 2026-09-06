package hashes

// Names returns a fresh slice of every shipped Registry primitive name in
// canonical order. User-registered primitives are excluded: the outer-
// cipher consumers (ctr, kdf, wrapper, parallax) construct keystreams for
// shipped names only.
//
// Names includes inner-PRF-only entries (Class = ClassNone) — the return
// value is the full FFI-iteration surface. Consumers that want the outer-
// cipher-eligible subset should call [KeystreamNames] instead.
func Names() []string {
	out := make([]string, len(Registry))
	for i := range Registry {
		out[i] = Registry[i].Name
	}
	return out
}

// KeystreamNames returns a fresh slice of every shipped Registry primitive
// name eligible for use as an outer cipher keystream (ClassNativeStream or
// ClassPRFCounter), in canonical order. Inner-PRF-only entries (ClassNone)
// are excluded — those primitives are safe only under ITB's compound inner-
// PRF defence stack and MUST NOT surface as user-selectable outer ciphers
// or parallax palette entries. Consumed by [wrapper.CipherNames] and the
// ctr / kdf drift tests.
func KeystreamNames() []string {
	out := make([]string, 0, len(Registry))
	for i := range Registry {
		if Registry[i].Class == ClassNone {
			continue
		}
		out = append(out, Registry[i].Name)
	}
	return out
}

// ClassOf returns the dispatch Class of a shipped Registry primitive, or
// ClassNone when name is not a shipped primitive.
func ClassOf(name string) Class {
	for i := range Registry {
		if Registry[i].Name == name {
			return Registry[i].Class
		}
	}
	return ClassNone
}

// Info is the plain-data view of one shipped Registry primitive — the
// fields of Spec that are comparable and printable, without the factory
// hooks.
type Info struct {
	Name  string
	Width Width
	Class Class
}

// FullView returns a fresh slice of Info for every shipped Registry
// primitive in canonical order.
func FullView() []Info {
	out := make([]Info, len(Registry))
	for i := range Registry {
		out[i] = Info{Name: Registry[i].Name, Width: Registry[i].Width, Class: Registry[i].Class}
	}
	return out
}
