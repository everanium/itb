// Process-wide Go runtime knobs plus the library version string.

namespace Everanium.Itb3.FSharp

/// Accessors for the libitb3 process-wide Go runtime knobs and the
/// library version. The knobs are readable at libitb3 load time via
/// env vars (<c>ITB_GOMEMLIMIT</c>, <c>ITB_GOGC</c>) and adjustable
/// at any time programmatically; a setter wins over the env var.
[<RequireQualifiedAccess>]
module Runtime =

    /// The F# binding's own version.
    [<Literal>]
    let BindingVersion = "0.5.1"

    /// Sets the Go runtime's soft heap limit in bytes and returns
    /// the previous limit. A negative value queries without
    /// changing.
    let setMemoryLimit (bytes: int64) : int64 = Everanium.Itb3.Runtime.SetMemoryLimit bytes

    /// Sets the Go GC trigger percentage and returns the previous
    /// value. A negative value queries without changing.
    let setGCPercent (pct: int) : int = Everanium.Itb3.Runtime.SetGCPercent pct

    /// Sets the Go runtime's GOMAXPROCS and returns the previous
    /// value. Zero or a negative value queries without changing.
    let setGOMAXPROCS (n: int) : int = Everanium.Itb3.Runtime.SetGOMAXPROCS n

    /// Writes the Go runtime's heap profile (pprof format) to
    /// <c>path</c> after one forced garbage collection. An empty path
    /// falls back to the <c>ITB_MEMPROFILE</c> environment variable
    /// inside libitb3; a path that is still empty, or a file-system
    /// failure, yields <c>ItbStatus.BadInput</c>.
    let writeHeapProfile (path: string) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> Everanium.Itb3.Runtime.WriteHeapProfile path)

    /// The number of slots <c>poolStats</c> returns.
    let poolStatsLen () : int = Everanium.Itb3.Runtime.PoolStatsLen()

    /// One snapshot of the library's pool hit / miss counters. Every
    /// counter is a monotonically increasing total since library load,
    /// so a per-window figure is the difference of two snapshots.
    ///
    /// Slot layout, with <c>T</c> the tier count in slot 0: hash-array
    /// tier <c>i</c> holds starter width, checkouts, constructor
    /// misses, regrow replacements and bytes allocated at slots
    /// <c>1 + 5*i .. 1 + 5*i + 4</c>; the scratch byte pool's get /
    /// new / regrow / regrow-bytes follow at <c>1 + 5*T</c>, and the
    /// parallax chunk pool's at <c>1 + 5*T + 4</c>. The vector is
    /// sized from the library's own length query, never from a
    /// constant.
    let poolStats () : Result<int64[], ItbError> =
        ItbError.attempt (fun () -> Everanium.Itb3.Runtime.PoolStats())

    /// Returns the libitb3 library version string.
    let version () : string = Everanium.Itb3.Runtime.Version()
