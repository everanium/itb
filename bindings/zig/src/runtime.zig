//! Profile registration, Go runtime knobs, and registry diagnostics.

const std = @import("std");
const ffi = @import("ffi.zig").c;
const err = @import("error.zig");
const Opts = @import("opts.zig").Opts;

/// Registers a user-defined Triple profile under `name`; the opts
/// follow the register-profile grammar validated by Go. A duplicate
/// name fails with `error.ProfileExists`.
pub fn registerProfile(name: [:0]const u8, opts: ?Opts) err.Error!void {
    const oh: ?*const ffi.itb_opts = if (opts) |o| o.handle else null;
    try err.check(ffi.itb_register_profile(name.ptr, oh));
}

/// The libitb library version string ("" if libitb misbehaves).
/// Thread-local C-side buffer — copy before the next call if kept.
pub fn version() [:0]const u8 {
    const v = ffi.itb_version();
    return if (v != null) std.mem.span(v) else "";
}

/// Sets the Go runtime's soft heap limit in bytes; returns the
/// previous limit. A negative value queries without changing.
pub fn setMemoryLimit(bytes: i64) i64 {
    return ffi.itb_set_memory_limit(bytes);
}

/// Sets the Go GC trigger percentage; returns the previous value. A
/// negative value queries without changing.
pub fn setGcPercent(pct: i32) i32 {
    return ffi.itb_set_gc_percent(pct);
}

/// Number of shipped hash primitives (diagnostic registry iteration
/// for CLI tooling — the binding performs no primitive-name
/// validation or enumeration of its own).
pub fn hashCount() usize {
    return ffi.itb_hash_count();
}

/// Canonical name of the index-th shipped hash primitive, or `null`
/// when `index` is out of range. Thread-local C-side buffer — valid
/// until the next `hashName` call on the same thread.
pub fn hashName(index: usize) ?[:0]const u8 {
    const name = ffi.itb_hash_name(index);
    return if (name != null) std.mem.span(name) else null;
}

/// Native state width in bits of the index-th shipped hash
/// primitive; 0 when `index` is out of range.
pub fn hashWidth(index: usize) i32 {
    return ffi.itb_hash_width(index);
}
