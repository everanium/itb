// Process-wide Go runtime knobs plus the library version string.

namespace EveraniumItb.FSharp

/// Accessors for the libitb process-wide Go runtime knobs and the
/// library version. The knobs are readable at libitb load time via
/// env vars (<c>ITB_GOMEMLIMIT</c>, <c>ITB_GOGC</c>) and adjustable
/// at any time programmatically; a setter wins over the env var.
[<RequireQualifiedAccess>]
module Runtime =

    /// The F# binding's own version.
    [<Literal>]
    let BindingVersion = "0.4.1"

    /// Sets the Go runtime's soft heap limit in bytes and returns
    /// the previous limit. A negative value queries without
    /// changing.
    let setMemoryLimit (bytes: int64) : int64 = Itb.Runtime.SetMemoryLimit bytes

    /// Sets the Go GC trigger percentage and returns the previous
    /// value. A negative value queries without changing.
    let setGCPercent (pct: int) : int = Itb.Runtime.SetGCPercent pct

    /// Returns the libitb library version string.
    let version () : string = Itb.Runtime.Version()
