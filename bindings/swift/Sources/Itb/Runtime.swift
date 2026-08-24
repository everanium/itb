/*
 * Runtime.swift — profile registration, Go runtime knobs, and the
 * diagnostic registry surface.
 */

import CItb

/// Binding version. Tracks the Swift wrapper; `ItbRuntime.version`
/// reports the underlying libitb library version.
public let itbSwiftVersion = "0.3.0"

/// Registers a user-defined Triple profile; the opts follow the
/// register-profile grammar validated by Go. A duplicate name fails
/// with `.profileExists`.
public func registerProfile(name: String, opts: Opts) throws {
    try check(itb_register_profile(name, opts.raw))
}

public enum ItbRuntime {
    /// The libitb library version string (e.g. "0.3.0").
    public static var version: String {
        guard let v = itb_version() else {
            return ""
        }
        return String(cString: v)
    }

    /// The Go-side diagnostic recorded by the most recent failing
    /// libitb call (process-global last-write-wins; empty when none).
    public static var lastError: String {
        String(cString: itb_last_error())
    }

    /// Sets the Go runtime's soft heap limit in bytes; returns the
    /// previous limit. A negative value queries without changing.
    @discardableResult
    public static func setMemoryLimit(_ bytes: Int64) -> Int64 {
        itb_set_memory_limit(bytes)
    }

    /// Sets the Go GC trigger percentage; returns the previous value.
    /// A negative value queries without changing.
    @discardableResult
    public static func setGCPercent(_ percent: Int32) -> Int32 {
        itb_set_gc_percent(percent)
    }

    /// Number of shipped hash primitives (diagnostic registry
    /// iteration for CLI tooling — the binding itself performs no
    /// primitive-name validation or enumeration).
    public static var hashCount: Int {
        itb_hash_count()
    }

    /// Canonical name of the index-th shipped hash primitive; nil
    /// when the index is out of range.
    public static func hashName(_ index: Int) -> String? {
        guard index >= 0, let name = itb_hash_name(index) else {
            return nil
        }
        return String(cString: name)
    }

    /// Native state width in bits of the index-th shipped hash
    /// primitive; 0 when the index is out of range.
    public static func hashWidth(_ index: Int) -> Int {
        index >= 0 ? Int(itb_hash_width(index)) : 0
    }
}
