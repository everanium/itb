' Process-wide Go runtime knobs plus the library / binding versions.

''' <summary>Accessors for the libitb process-wide Go runtime knobs
''' and the library version, relayed through the C# layer.</summary>
Public Module Library

    ''' <summary>The binding's own version.</summary>
    Public Const BindingVersion As String = "0.3.3"

    ''' <summary>Sets the Go runtime's soft heap limit in bytes and
    ''' returns the previous limit. A negative value queries without
    ''' changing.</summary>
    Public Function SetMemoryLimit(bytes As Long) As Long
        Return Global.Itb.Runtime.SetMemoryLimit(bytes)
    End Function

    ''' <summary>Sets the Go GC trigger percentage and returns the
    ''' previous value. A negative value queries without
    ''' changing.</summary>
    Public Function SetGCPercent(pct As Integer) As Integer
        Return Global.Itb.Runtime.SetGCPercent(pct)
    End Function

    ''' <summary>Returns the libitb library version string.</summary>
    Public Function Version() As String
        Return Guarded(Function() Global.Itb.Runtime.Version())
    End Function
End Module
