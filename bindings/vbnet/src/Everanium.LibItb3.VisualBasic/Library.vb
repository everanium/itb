' Process-wide Go runtime knobs, runtime diagnostics, and the library
' / binding versions.

''' <summary>Accessors for the libitb3 process-wide Go runtime knobs,
''' its runtime diagnostics, and the library version, relayed through
''' the C# layer.</summary>
Public Module Library

    ''' <summary>The binding's own version.</summary>
    Public Const BindingVersion As String = "0.5.1"

    ''' <summary>Sets the Go runtime's soft heap limit in bytes and
    ''' returns the previous limit. A negative value queries without
    ''' changing.</summary>
    Public Function SetMemoryLimit(bytes As Long) As Long
        Return Global.Everanium.Itb3.Runtime.SetMemoryLimit(bytes)
    End Function

    ''' <summary>Sets the Go GC trigger percentage and returns the
    ''' previous value. A negative value queries without
    ''' changing.</summary>
    Public Function SetGCPercent(pct As Integer) As Integer
        Return Global.Everanium.Itb3.Runtime.SetGCPercent(pct)
    End Function

    ''' <summary>Sets the Go runtime's GOMAXPROCS and returns the
    ''' previous value. Zero or a negative value queries without
    ''' changing.</summary>
    Public Function SetGOMAXPROCS(n As Integer) As Integer
        Return Global.Everanium.Itb3.Runtime.SetGOMAXPROCS(n)
    End Function

    ''' <summary>Writes the Go runtime's heap profile (pprof format) to
    ''' <paramref name="path"/> after one forced garbage collection. An
    ''' empty path falls back to the <c>ITB_MEMPROFILE</c> environment
    ''' variable inside libitb3; a path that is still empty, or a
    ''' file-system failure, throws with
    ''' <see cref="Status.BadInput"/>.</summary>
    Public Sub WriteHeapProfile(path As String)
        Guarded(Sub() Global.Everanium.Itb3.Runtime.WriteHeapProfile(path))
    End Sub

    ''' <summary>The number of slots <see cref="PoolStats"/>
    ''' fills.</summary>
    Public Function PoolStatsLen() As Integer
        Return Global.Everanium.Itb3.Runtime.PoolStatsLen()
    End Function

    ''' <summary>
    ''' One snapshot of the library's pool hit / miss counters. Every
    ''' counter is a monotonically increasing total since library load,
    ''' so a per-window figure is the difference of two snapshots.
    '''
    ''' Slot layout, with <c>T</c> the tier count in slot 0: hash-array
    ''' tier <c>i</c> holds starter width, checkouts, constructor
    ''' misses, regrow replacements and bytes allocated at slots
    ''' <c>1 + 5*i .. 1 + 5*i + 4</c>; the scratch byte pool's get /
    ''' new / regrow / regrow-bytes follow at <c>1 + 5*T</c>, and the
    ''' parallax chunk pool's at <c>1 + 5*T + 4</c>. The vector is
    ''' sized from the library's own length query, never from a
    ''' constant.
    ''' </summary>
    Public Function PoolStats() As Long()
        Return Guarded(Function() Global.Everanium.Itb3.Runtime.PoolStats())
    End Function

    ''' <summary>Returns the libitb3 library version string.</summary>
    Public Function Version() As String
        Return Guarded(Function() Global.Everanium.Itb3.Runtime.Version())
    End Function
End Module
