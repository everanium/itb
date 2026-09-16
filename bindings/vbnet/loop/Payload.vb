' Plaintext content: the payload modes, the seeded per-worker
' generator, and the buffer fill from the operating-system CSPRNG.

Imports System.Runtime.InteropServices

''' <summary>
''' Payload mode selector values for the --payload-mode flag.
'''
'''   - Fixed: one CSPRNG-generated buffer per worker, held unchanged
'''     for the whole run (the default).
'''   - Rotating: the buffer is regenerated before every iteration, so
'''     no two encrypt calls see the same plaintext.
'''   - PatternZero / PatternFf: degenerate constant fills (all 0x00 /
'''     all 0xFF) probing minimum-entropy plaintext handling.
'''   - PatternAscii: a repeating 'A'..'Z' ramp probing low-entropy
'''     structured text.
''' </summary>
Friend Enum PayloadMode
    Fixed
    Rotating
    PatternZero
    PatternFf
    PatternAscii
End Enum

Friend Module Payload

    Private ReadOnly ModeNames As (Name As String, Mode As PayloadMode)() = {
        ("fixed", PayloadMode.Fixed),
        ("rotating", PayloadMode.Rotating),
        ("pattern-zero", PayloadMode.PatternZero),
        ("pattern-ff", PayloadMode.PatternFf),
        ("pattern-ascii", PayloadMode.PatternAscii)}

    Friend Function PayloadModeName(mode As PayloadMode) As String
        For Each entry In ModeNames
            If entry.Mode = mode Then Return entry.Name
        Next
        Return "fixed"
    End Function

    Friend Function ParsePayloadMode(s As String) As PayloadMode?
        For Each entry In ModeNames
            If entry.Name = s Then Return entry.Mode
        Next
        Return Nothing
    End Function

    ''' <summary>
    ''' Seeded plaintext. The seed makes plaintext content reproducible
    ''' so a failing iteration can be replayed with the same bytes; it
    ''' governs nothing else — pipeline keys, nonces and masters stay
    ''' CSPRNG-drawn, so a seeded run is a reproduction aid and never a
    ''' security test. Each worker's stream is domain-separated by its
    ''' id so seeded workers still hold pairwise-distinct buffers under
    ''' the fixed and rotating modes. The generator is splitmix64: a few
    ''' lines in any language, which is why it is the one every binding
    ''' uses.
    '''
    ''' VB-specific. splitmix64 depends on the add and the two
    ''' multiplies wrapping at 64 bits, which this language checks for
    ''' overflow by default and would raise on; the project turns the
    ''' integer overflow checks off so the generator produces the values
    ''' its definition calls for.
    ''' </summary>
    Friend Function SeedWorker(seed As ULong, workerId As Integer) As ULong
        Return seed + CULng(workerId) + 1UL
    End Function

    Private Function Splitmix64(ByRef state As ULong) As ULong
        state = state + &H9E3779B97F4A7C15UL
        Dim z As ULong = state
        z = (z Xor (z >> 30)) * &HBF58476D1CE4E5B9UL
        z = (z Xor (z >> 27)) * &H94D049BB133111EBUL
        Return z Xor (z >> 31)
    End Function

    <DllImport("libc", EntryPoint:="getrandom", SetLastError:=True)>
    Private Function GetRandomNative(buf As IntPtr, buflen As UIntPtr, flags As UInteger) As IntPtr
    End Function

    ''' <summary>
    ''' Fills buf from the operating-system CSPRNG.
    '''
    ''' .NET-specific. The glibc entry is called directly rather than
    ''' through RandomNumberGenerator: the .NET native layer reaches the
    ''' kernel through arc4random_buf, a userspace generator that
    ''' reseeds on its own schedule, so the number of kernel draws no
    ''' longer tracks the number of fills and the plaintext-content
    ''' flags become unobservable from outside the process. Going
    ''' straight to the libc entry keeps one draw per fill, which is
    ''' what makes --payload-mode and --seed checkable against a run
    ''' that never touches them. The entry returns short on a signal and
    ''' caps a single draw, so the fill loops until every byte is in
    ''' place. False on failure.
    ''' </summary>
    Friend Function FillRandom(buf As Byte()) As Boolean
        Dim handle As GCHandle = GCHandle.Alloc(buf, GCHandleType.Pinned)
        Try
            Dim basePtr As IntPtr = handle.AddrOfPinnedObject()
            Dim off As Integer = 0
            Do While off < buf.Length
                Dim r As IntPtr
                Try
                    r = GetRandomNative(basePtr + off, New UIntPtr(CUInt(buf.Length - off)), 0UI)
                Catch ex As EntryPointNotFoundException
                    ' .NET-specific fallback for a platform without the
                    ' glibc entry; the managed generator is correct, only
                    ' unobservable from a syscall trace.
                    Dim tail(buf.Length - off - 1) As Byte
                    Security.Cryptography.RandomNumberGenerator.Fill(tail)
                    Array.Copy(tail, 0, buf, off, tail.Length)
                    Return True
                Catch ex As DllNotFoundException
                    Dim tail(buf.Length - off - 1) As Byte
                    Security.Cryptography.RandomNumberGenerator.Fill(tail)
                    Array.Copy(tail, 0, buf, off, tail.Length)
                    Return True
                End Try
                If CLng(r) <= 0 Then Return False
                off += CInt(r)
            Loop
            Return True
        Finally
            handle.Free()
        End Try
    End Function

    ''' <summary>
    ''' Writes one plaintext buffer according to the payload mode. The
    ''' fixed and rotating modes draw from the seeded generator when the
    ''' run is seeded and from the OS CSPRNG otherwise; the pattern
    ''' modes are deterministic regardless of the seed. False when the
    ''' CSPRNG fails.
    ''' </summary>
    Friend Function FillPayload(
            mode As PayloadMode, seeded As Boolean, ByRef rng As ULong, buf As Byte()) As Boolean
        Select Case mode
            Case PayloadMode.Fixed, PayloadMode.Rotating
                If Not seeded Then Return FillRandom(buf)
                Dim i As Integer = 0
                Do While i < buf.Length
                    Dim v As ULong = Splitmix64(rng)
                    Dim n As Integer = Math.Min(8, buf.Length - i)
                    For k As Integer = 0 To n - 1
                        buf(i + k) = CByte((v >> (8 * k)) And &HFFUL)
                    Next
                    i += 8
                Loop
                Return True
            Case PayloadMode.PatternZero
                Array.Clear(buf)
                Return True
            Case PayloadMode.PatternFf
                Array.Fill(buf, CByte(&HFF))
                Return True
            Case Else
                For i As Integer = 0 To buf.Length - 1
                    buf(i) = CByte(Asc("A"c) + (i Mod 26))
                Next
                Return True
        End Select
    End Function
End Module
