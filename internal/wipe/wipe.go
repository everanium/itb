// Package wipe provides compiler-barrier-guarded zeroization helpers for
// heap allocations, interface-wrapped state structs, and callee stack frames.
package wipe

import (
	"reflect"
	"runtime"
	"unsafe"
)

// Bytes zeroes b and keeps its backing array live past the clear so the
// compiler cannot dead-store-eliminate the zeroing writes.
func Bytes(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}

// Uint64s zeroes s and keeps its backing array live past the clear.
func Uint64s(s []uint64) {
	if len(s) == 0 {
		return
	}
	clear(s)
	runtime.KeepAlive(s)
}

// StructPtr zeroes the concrete struct value pointed to by a non-nil pointer
// stored inside an interface value (such as cipher.Block, cipher.Stream, or
// hash.Hash) in place on the heap, as well as any heap-allocated struct
// pointers held inside a value-struct wrapper (such as stdlib's
// cipher.aesCtrWrapper{c: *aes.CTR}), and keeps v live so the compiler cannot
// elide the zeroing stores.
func StructPtr(v any) {
	if v == nil {
		return
	}
	wipeReflectValue(reflect.ValueOf(v), 0)
	runtime.KeepAlive(v)
}

func wipeSliceField(f reflect.Value) {
	if f.Cap() <= 0 {
		return
	}
	ptr := f.UnsafePointer()
	if ptr == nil {
		return
	}
	elemSize := int(f.Type().Elem().Size())
	if elemSize <= 0 {
		return
	}
	b := unsafe.Slice((*byte)(ptr), f.Cap()*elemSize)
	clear(b)
	runtime.KeepAlive(b)
}

func wipeReflectValue(rv reflect.Value, depth int) {
	if !rv.IsValid() || depth > 4 {
		return
	}
	switch rv.Kind() {
	case reflect.Interface:
		if !rv.IsNil() {
			wipeReflectValue(rv.Elem(), depth+1)
		}
	case reflect.Pointer:
		if rv.IsNil() {
			return
		}
		elem := rv.Elem()
		if elem.Kind() == reflect.Struct {
			for i := 0; i < elem.NumField(); i++ {
				f := elem.Field(i)
				switch f.Kind() {
				case reflect.Pointer, reflect.Struct:
					wipeReflectValue(f, depth+1)
				case reflect.Interface:
					// Skip shared cipher.Block interfaces inside stream structs
					// (e.g. generic cipher.ctr.b) so ResetCounter on a stream
					// does not zero a cached cipher.Block still in use; callers
					// that own a cipher.Block wipe it explicitly via StructPtr.
					if f.Type().Name() != "Block" {
						wipeReflectValue(f, depth+1)
					}
				case reflect.Slice:
					wipeSliceField(f)
				}
			}
			if elem.CanSet() {
				elem.SetZero()
			} else if sz := elem.Type().Size(); sz > 0 {
				b := unsafe.Slice((*byte)(rv.UnsafePointer()), sz)
				clear(b)
				runtime.KeepAlive(b)
			}
		}
	case reflect.Struct:
		for i := 0; i < rv.NumField(); i++ {
			f := rv.Field(i)
			switch f.Kind() {
			case reflect.Pointer, reflect.Interface, reflect.Struct:
				wipeReflectValue(f, depth+1)
			case reflect.Slice:
				wipeSliceField(f)
			}
		}
	}
}

//go:noinline
func clobberIntArgRegs(r0, r1, r2, r3, r4, r5, r6, r7, r8 uint64) uint64 {
	return r0 | r1 | r2 | r3 | r4 | r5 | r6 | r7 | r8
}

// CallStack512B scrubs 1280 B of callee stack space below the caller's frame
// and zeroes all caller-saved GPR and XMM/NEON registers without copying a
// 576-byte argument array or exceeding the 2 KiB initial goroutine stack.
//
//go:noinline
func CallStack512B() {
	var pad [160]uint64
	clear(pad[:])
	ClobberRegs()
	runtime.KeepAlive(&pad)
}

// CallStack2K scrubs 576 B of caller outgoing ABI stack slots (0(SP)..576(SP)),
// caller-saved GPR/SIMD registers, and 2 KiB of callee stack space below the
// caller's frame so intermediate compression state, block buffers, or subkey
// temporaries left by earlier sibling calls do not persist on the goroutine
// stack.
//
//go:noinline
func CallStack2K(argPad [9][8]uint64) {
	var pad [256]uint64
	clear(pad[:])
	clear(argPad[:])
	ClobberRegs()
	runtime.KeepAlive(&pad)
	runtime.KeepAlive(&argPad)
}

// CallStack4K scrubs 576 B of caller outgoing ABI stack slots, caller-saved
// GPR/SIMD registers, and 4 KiB of callee stack space below the caller's
// frame.
//
//go:noinline
func CallStack4K(argPad [9][8]uint64) {
	var pad [512]uint64
	clear(pad[:])
	clear(argPad[:])
	ClobberRegs()
	runtime.KeepAlive(&pad)
	runtime.KeepAlive(&argPad)
}

// CallStack8K pre-grows the goroutine stack past the 8 KiB runtime.morestack
// threshold when called before secret-bearing work and scrubs the 8 KiB
// callee frame, caller-saved GPR/SIMD registers, and 576 B of ABI stack
// argument slots when called on exit.
//
//go:noinline
func CallStack8K(argPad [9][8]uint64) {
	var framePad [1024]uint64
	clear(framePad[:])
	clear(argPad[:])
	ClobberRegs()
	runtime.KeepAlive(&framePad)
	runtime.KeepAlive(&argPad)
}

// CallStack12K pre-grows and scrubs 12 KiB of callee stack space along with
// caller-saved GPR/SIMD registers and 576 B of ABI stack argument slots (used
// around multi-chunk unkeyed BLAKE3 Sum256 frames).
//
//go:noinline
func CallStack12K(argPad [9][8]uint64) {
	var framePad [1536]uint64
	clear(framePad[:])
	clear(argPad[:])
	ClobberRegs()
	runtime.KeepAlive(&framePad)
	runtime.KeepAlive(&argPad)
}

// Internal cross-package hooks populated at init time by the root itb
// and hashes packages so closure-bound fixed keys share a single isolated
// backing array that Pipeline.Close can zero in place.
var (
	MakeAESITB128FromKeyPtr func(fixedKey *[16]byte) (
		func([]byte, uint64, uint64) (uint64, uint64),
		func(*[4][]byte, [4][2]uint64) [4][2]uint64,
	)
	MakeAreion256FromKeyPtr func(fixedKey *[32]byte) (
		func([]byte, [4]uint64) [4]uint64,
		func(*[4][]byte, [4][4]uint64) [4][4]uint64,
	)
	MakeAreion512FromKeyPtr func(fixedKey *[64]byte) (
		func([]byte, [8]uint64) [8]uint64,
		func(*[4][]byte, [4][8]uint64) [4][8]uint64,
	)
	SeedFromComponents128WithKey func(name string, key []byte, components ...uint64) (any, []byte, error)
	SeedFromComponents256WithKey func(name string, key []byte, components ...uint64) (any, []byte, error)
	SeedFromComponents512WithKey func(name string, key []byte, components ...uint64) (any, []byte, error)
)
