' Long-run stress harness. The loop utility holds one Pipeline handle
' per exercised cipher surface for minutes, hammers it with concurrent
' encrypt → decrypt → compare round-trips from N worker threads, rotates
' the outer masters and reopens the handle from its session blob on a
' schedule, and reports whether the process survived with every byte
' intact. It is the VB.NET binding's counterpart of the Go harness under
' tools/loop: the same flags, the same round structure, the same summary
' in both renderings.
'
' The default shape is full production: the Streaming AEAD profile with
' parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
' 1024-bit keys, and the compile-in 512-bit nonce width, driven through a
' stream session by three workers for five minutes on 16 MiB plaintexts.
' Every worker owns a distinct CSPRNG-generated plaintext held for the
' whole run, so any cross-call state leakage inside the Pipeline surfaces
' as a data mismatch between workers rather than cancelling out.
'
' A failure is one of two things. A cipher, rekey or load call that
' returns a non-OK status is a worker error: the run stops, the summary
' lists it, the verdict is FAIL and the exit code 1. A round-trip that
' returns without error but with different bytes is a data mismatch: the
' process terminates on the spot with exit code 3, printing the worker,
' the iteration and the first differing offset, and no summary — the
' state that produced the wrong bytes is the evidence. A crash inside the
' shared library or the host runtime has no exit code of its own here;
' surfacing it is what the utility is for. This binding runs a Go
' c-shared runtime and CoreCLR in one process, two runtimes that each
' drive threads through signals, which is the interaction the long run is
' meant to expose.
'
' Usage:
'
'   ./bin/Release/net10.0/Everanium.LibItb3.VisualBasic.Loop --duration 5m \
'          --goroutines 3 --shape stream --hash areion512 \
'          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
'          --parallax on --wrapper on
'
' Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
' then the partial summary prints.

Imports System.Diagnostics
Imports System.Globalization
Imports System.Runtime.InteropServices
Imports System.Threading
Imports Everanium.Itb3.VisualBasic

''' <summary>The resolved command line.</summary>
Friend Class Config
    Friend DurationNs As Long
    Friend Iterations As Long
    Friend WorkersRequested As Integer
    Friend Workers As Integer
    Friend Shape As Shape
    Friend Hash As String = ""
    Friend Mac As String = ""
    Friend PayloadBytes As Long
    Friend Memlimit As Long
    Friend MemlimitAuto As Boolean
    Friend Gogc As Integer
    Friend Parallax As Boolean
    Friend Wrapper As Boolean
    Friend ProfileName As String = ""
    Friend KeyBits As Long
    Friend NonceBits As Long
    Friend ChunkSize As Long
    Friend BarrierFill As Long
    Friend Gomaxprocs As Integer
    Friend RekeyEvery As Long
    Friend BlobCycleEvery As Long
    Friend Mode As PayloadMode
    Friend Seed As ULong
    Friend JsonOutput As Boolean
    Friend Memprofile As String = ""
End Class

''' <summary>The Pipeline handles and their retained blobs, behind the
''' lock that keeps iterations clear of handle mutation.</summary>
Friend Class Pipes
    Friend StreamPipe As Pipeline
    Friend MsgPipe As Pipeline
    ''' <summary>The blob Init handed out, replaced by every rekey; the
    ''' input of the next blob reopen.</summary>
    Friend StreamBlob As Byte() = Array.Empty(Of Byte)()
    Friend MsgBlob As Byte() = Array.Empty(Of Byte)()
End Class

''' <summary>One worker's counters, read by the summary after every
''' worker has returned, and the error it stopped on.</summary>
Friend Class Counters
    Friend Iters As Long
    Friend BytesEnc As Long
    Friend BytesDec As Long
    Friend NanosEnc As Long
    Friend NanosDec As Long
    Friend ReadOnly ErrorLock As New Object()
    Friend ErrorText As String
End Class

''' <summary>One worker's private state, owned by its thread: its
''' plaintext, its reusable pump accumulators, its generator.</summary>
Friend Class WorkerState
    Friend Id As Integer
    Friend Plaintext As Byte() = Array.Empty(Of Byte)()
    Friend Mode As PayloadMode
    Friend Seeded As Boolean
    Friend Rng As ULong
    Friend ReadOnly Wire As New IO.MemoryStream()
    Friend ReadOnly Plain As New IO.MemoryStream()
    Friend Scratch As Byte() = Array.Empty(Of Byte)()
End Class

''' <summary>The state every worker shares.</summary>
Friend Class RunState
    Friend Cfg As Config
    Friend StreamProfile As String = ""
    Friend MsgProfile As String = ""
    ''' <summary>Handle mutation. Iterations hold the read side for
    ''' their whole encrypt → decrypt → compare; rekey and blob reopen
    ''' take the write side, so no cipher call is in flight while a
    ''' handle's keying changes or the handle itself is swapped, and no
    ''' encrypt is separated from its decrypt by either.</summary>
    Friend ReadOnly PipesLock As New ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion)
    Friend Pipes As Pipes
    Friend Rekeys As Long
    Friend BlobCycles As Long
    Friend Workers As Counters() = Array.Empty(Of Counters)()
    ''' <summary>Warmup barrier: workers arrive at WarmupDone after
    ''' iteration 0 and at Release once main has taken the
    ''' baselines.</summary>
    Friend WarmupDone As Barrier
    Friend ReleaseGate As Barrier
    ''' <summary>Set by the duration timer, by a signal, or by a failing
    ''' worker; checked by every worker before it starts an
    ''' iteration.</summary>
    Private _stop As Integer

    Friend Property StopRequested As Boolean
        Get
            Return Volatile.Read(_stop) <> 0
        End Get
        Set(value As Boolean)
            Volatile.Write(_stop, If(value, 1, 0))
        End Set
    End Property

    Friend ReadOnly DoneLock As New Object()
    ''' <summary>Guards the two aggregate maintenance counters.</summary>
    Friend ReadOnly CounterLock As New Object()
    Friend Active As Integer
    Friend FinishTimestamp As Long
    Friend RssWarmup As Long
    Friend RssPeak As Long
    Friend RssFinal As Long
    Friend PoolWarmup As Long() = Array.Empty(Of Long)()
    Friend PoolSteady As Long() = Array.Empty(Of Long)()
End Class

Friend Module Program

    ''' <summary>--goroutines ceiling; the harness targets modest hosts
    ''' and each worker pins payload-sized buffers for the whole
    ''' run.</summary>
    Friend Const MaxWorkers As Integer = 10

    ''' <summary>The concurrency mode this binding implements, as the
    ''' summary reports it (shared-handle / independent-handles /
    ''' single).</summary>
    Friend Const Concurrency As String = "shared-handle"

    ''' <summary>Largest slice fed to a stream session per write; the
    ''' drain after every write uses the same bound.</summary>
    Friend Const PumpSlice As Integer = 1 << 20

    ''' <summary>Profiles the shape-based pair is built against when
    ''' --profile is empty.</summary>
    Private Const DefaultStreamProfile As String = "streaming-aead-triple-mac-v1"
    Private Const DefaultMessageProfile As String = "singlemsg-triple-mac-v1"

    ''' <summary>The keystream-capable primitive supplied for a layer a
    ''' profile leaves unnamed: PRF-grade, so sound outside the barrier,
    ''' and the closest relative of the AES-based inner primitive whose
    ''' profiles need the fill.</summary>
    Private Const KeystreamFillCipher As String = "aescmac"

    ''' <summary>The parallax segment size a filled palette runs with —
    ''' the library's own default; a schedule rejects zero.</summary>
    Private Const KeystreamFillSegment As Long = 4093

    Private ReadOnly NsPerTick As Double = 1000000000.0 / CDbl(Stopwatch.Frequency)

    ''' <summary>Nanoseconds elapsed since a Stopwatch.GetTimestamp
    ''' reading.</summary>
    Friend Function ElapsedNs(since As Long) As Long
        Return CLng(CDbl(Stopwatch.GetTimestamp() - since) * NsPerTick)
    End Function

    Friend Function TicksToNs(ticks As Long) As Long
        Return CLng(CDbl(ticks) * NsPerTick)
    End Function

    ''' <summary>Prints one prefixed status line to stdout.</summary>
    Friend Sub LogLine(line As String)
        Console.Out.WriteLine("[loop] " & line)
    End Sub

    Friend Function OnOff(b As Boolean) As String
        Return If(b, "on", "off")
    End Function

    ''' <summary>Renders an encoder policy env value for the summary:
    ''' the raw string when set, "default" when the shipped ladder
    ''' applies.</summary>
    Friend Function PolicyLabel(name As String) As String
        Dim v As String = Environment.GetEnvironmentVariable(name)
        If String.IsNullOrWhiteSpace(v) Then Return "default"
        Return v.TrimStart()
    End Function

    ' ----------------------------------------------------------------
    ' Flags
    ' ----------------------------------------------------------------

    ''' <summary>The raw flag values before validation.</summary>
    Friend Class RawFlags
        Friend BarrierFill As Long = 0
        Friend BlobCycleEvery As Long = 0
        Friend ChunkSize As String = "0"
        Friend Duration As String = "5m"
        Friend Gogc As Long = 0
        Friend Gomaxprocs As Long = 0
        Friend Goroutines As Long = 3
        Friend Hash As String = "areion512"
        Friend Iterations As Long = 0
        Friend JsonOutput As Boolean = False
        Friend KeyBits As Long = 0
        Friend Mac As String = "hmac-blake3"
        Friend Memlimit As String = "auto"
        Friend Memprofile As String = ""
        Friend NonceBits As Long = 0
        Friend Parallax As String = "on"
        Friend PayloadModeName As String = "fixed"
        Friend PayloadSize As String = "16MB"
        Friend ProfileName As String = ""
        Friend RekeyEvery As Long = 0
        Friend Seed As ULong = 0
        Friend Shape As String = "stream"
        Friend Wrapper As String = "on"
    End Class

    ''' <summary>One command-line flag: its name, the type label the
    ''' usage prints, its help text, whether it takes a value, the
    ''' default-value suffix the usage appends, and the store that
    ''' parses a value into the raw flags. Values are validated after
    ''' the whole line is parsed. The table is in alphabetical order —
    ''' the order the usage prints.</summary>
    Friend Class Flag
        Friend ReadOnly Name As String
        Friend ReadOnly TypeLabel As String
        Friend ReadOnly Help As String
        Friend ReadOnly IsBool As Boolean
        Friend ReadOnly DefaultSuffix As String
        Friend ReadOnly Store As Func(Of RawFlags, String, Boolean)

        Friend Sub New(name As String, typeLabel As String, help As String, isBool As Boolean,
                       defaultSuffix As String, store As Func(Of RawFlags, String, Boolean))
            Me.Name = name
            Me.TypeLabel = typeLabel
            Me.Help = help
            Me.IsBool = isBool
            Me.DefaultSuffix = defaultSuffix
            Me.Store = store
        End Sub
    End Class

    Private Function DefaultOf(v As Long) As String
        Return If(v <> 0, " (default " & Dx(v) & ")", "")
    End Function

    Private Function DefaultOf(v As String) As String
        Return If(v.Length > 0, " (default """ & v & """)", "")
    End Function

    Private Function TryLong(s As String, ByRef v As Long) As Boolean
        Return Long.TryParse(s, NumberStyles.AllowLeadingSign, Inv, v)
    End Function

    Private ReadOnly Flags As Flag() = BuildFlags()

    Private Function BuildFlags() As Flag()
        Dim d As New RawFlags()
        Return {
            New Flag("barrier-fill", "int",
                "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)",
                False, DefaultOf(d.BarrierFill),
                Function(f, s) TryLong(s, f.BarrierFill)),
            New Flag("blob-cycle-every", "int",
                "reopen each pipeline from its session blob every N iterations per worker; 0 = never",
                False, "",
                Function(f, s) TryLong(s, f.BlobCycleEvery)),
            New Flag("chunk-size", "string",
                "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape",
                False, DefaultOf(d.ChunkSize),
                Function(f, s)
                    f.ChunkSize = s
                    Return True
                End Function),
            New Flag("duration", "duration",
                "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0",
                False, DefaultOf(d.Duration),
                Function(f, s)
                    f.Duration = s
                    Return True
                End Function),
            New Flag("gogc", "int",
                "GC trigger percentage; 0 = leave the runtime default",
                False, DefaultOf(d.Gogc),
                Function(f, s) TryLong(s, f.Gogc)),
            New Flag("gomaxprocs", "int",
                "Go runtime GOMAXPROCS override; 0 = inherit from the environment",
                False, DefaultOf(d.Gomaxprocs),
                Function(f, s) TryLong(s, f.Gomaxprocs)),
            New Flag("goroutines", "int",
                "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1",
                False, DefaultOf(d.Goroutines),
                Function(f, s) TryLong(s, f.Goroutines)),
            New Flag("hash", "string",
                "inner ITB hash primitive name",
                False, DefaultOf(d.Hash),
                Function(f, s)
                    f.Hash = s
                    Return True
                End Function),
            New Flag("iterations", "int",
                "fixed per-worker iteration count; 0 = duration-based",
                False, "",
                Function(f, s) TryLong(s, f.Iterations)),
            New Flag("json-output", "",
                "print the final summary as one compact JSON object instead of log lines",
                True, "",
                Function(f, s)
                    If s = "true" Then
                        f.JsonOutput = True
                        Return True
                    ElseIf s = "false" Then
                        f.JsonOutput = False
                        Return True
                    End If
                    Return False
                End Function),
            New Flag("key-bits", "int",
                "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)",
                False, DefaultOf(d.KeyBits),
                Function(f, s) TryLong(s, f.KeyBits)),
            New Flag("mac", "string",
                "MAC primitive name",
                False, DefaultOf(d.Mac),
                Function(f, s)
                    f.Mac = s
                    Return True
                End Function),
            New Flag("memlimit", "string",
                "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)",
                False, DefaultOf(d.Memlimit),
                Function(f, s)
                    f.Memlimit = s
                    Return True
                End Function),
            New Flag("memprofile", "string",
                "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none",
                False, DefaultOf(d.Memprofile),
                Function(f, s)
                    f.Memprofile = s
                    Return True
                End Function),
            New Flag("nonce-bits", "int",
                "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)",
                False, DefaultOf(d.NonceBits),
                Function(f, s) TryLong(s, f.NonceBits)),
            New Flag("parallax", "string",
                "parallax layer: on | off",
                False, DefaultOf(d.Parallax),
                Function(f, s)
                    f.Parallax = s
                    Return True
                End Function),
            New Flag("payload-mode", "string",
                "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii",
                False, DefaultOf(d.PayloadModeName),
                Function(f, s)
                    f.PayloadModeName = s
                    Return True
                End Function),
            New Flag("payload-size", "string",
                "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)",
                False, DefaultOf(d.PayloadSize),
                Function(f, s)
                    f.PayloadSize = s
                    Return True
                End Function),
            New Flag("profile", "string",
                "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair",
                False, DefaultOf(d.ProfileName),
                Function(f, s)
                    f.ProfileName = s
                    Return True
                End Function),
            New Flag("rekey-every", "int",
                "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never",
                False, "",
                Function(f, s) TryLong(s, f.RekeyEvery)),
            New Flag("seed", "uint",
                "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts",
                False, "",
                Function(f, s) ULong.TryParse(s, NumberStyles.None, Inv, f.Seed)),
            New Flag("shape", "string",
                "cipher surface to exercise: stream | message | stream_one_shot | both",
                False, DefaultOf(d.Shape),
                Function(f, s)
                    f.Shape = s
                    Return True
                End Function),
            New Flag("wrapper", "string",
                "wrapper (Outer cipher) layer: on | off",
                False, DefaultOf(d.Wrapper),
                Function(f, s)
                    f.Wrapper = s
                    Return True
                End Function)}
    End Function

    Private Sub Usage()
        Console.Error.WriteLine("Usage of loop:")
        For Each fl In Flags
            Console.Error.WriteLine(
                If(fl.TypeLabel.Length = 0, "  -" & fl.Name, "  -" & fl.Name & " " & fl.TypeLabel))
            Console.Error.WriteLine("    " & vbTab & fl.Help & fl.DefaultSuffix)
        Next
    End Sub

    ''' <summary>Parses argv into the raw flag values. Accepts -name
    ''' value, --name value, -name=value and --name=value; a boolean
    ''' flag takes no value unless given as -name=true / -name=false.
    ''' True for -h / --help (usage printed); Nothing after printing the
    ''' error.</summary>
    Private Function ParseArgv(args As String(), f As RawFlags) As Boolean?
        Dim i As Integer = 0
        Do While i < args.Length
            Dim arg As String = args(i)
            If arg.Length <= 1 OrElse arg(0) <> "-"c Then
                Console.Error.WriteLine("loop: unexpected positional arguments: [" & arg & "]")
                Return Nothing
            End If

            Dim raw As String = If(arg.StartsWith("--", StringComparison.Ordinal),
                                   arg.Substring(2), arg.Substring(1))
            If raw = "h" OrElse raw = "help" Then
                Usage()
                Return True
            End If

            Dim inlineValue As String = Nothing
            Dim name As String = raw
            Dim eq As Integer = raw.IndexOf("="c)
            If eq >= 0 Then
                inlineValue = raw.Substring(eq + 1)
                name = raw.Substring(0, eq)
            End If

            Dim fl As Flag = Nothing
            For Each candidate In Flags
                If candidate.Name = name Then
                    fl = candidate
                    Exit For
                End If
            Next
            If fl Is Nothing Then
                Console.Error.WriteLine("loop: flag provided but not defined: -" & name)
                Usage()
                Return Nothing
            End If

            Dim value As String
            If inlineValue IsNot Nothing Then
                value = inlineValue
            ElseIf fl.IsBool Then
                value = "true"
            Else
                i += 1
                If i >= args.Length Then
                    Console.Error.WriteLine("loop: flag needs an argument: -" & fl.Name)
                    Return Nothing
                End If
                value = args(i)
            End If

            If Not fl.Store(f, value) Then
                Console.Error.WriteLine("loop: invalid value """ & value & """ for flag -" & fl.Name)
                Return Nothing
            End If
            i += 1
        Loop
        Return False
    End Function

    ''' <summary>Whether name is in the shipped hash registry the
    ''' binding returns.</summary>
    Private Function HashRegistered(name As String) As Boolean
        Try
            Return Array.IndexOf(Pipeline.HashNames(), name) >= 0
        Catch ex As Exception
            Return False
        End Try
    End Function

    ''' <summary>Resolves a registered profile to the shape family its
    ''' record's mode exposes by reading the record through the
    ''' binding's lookup: a mode beginning with "streaming" exposes the
    ''' stream surfaces, one beginning with "singlemsg" the message
    ''' surface, "blob-only" none. Prints the validation message and
    ''' returns Nothing on rejection.</summary>
    Private Function ProfileSurface(name As String) As Shape?
        Dim p As Global.Everanium.Itb3.Profile
        Try
            p = Pipeline.Lookup(name)
        Catch ex As Exception
            Console.Error.WriteLine(
                "loop: --profile """ & name & """ is not a registered triple profile")
            Return Nothing
        End Try
        If p.Mode.StartsWith("streaming", StringComparison.Ordinal) Then Return Shape.StreamShape
        If p.Mode.StartsWith("singlemsg", StringComparison.Ordinal) Then Return Shape.MessageShape
        Console.Error.WriteLine(
            "loop: --profile """ & name & """ carries no cipher surface (blob-only mode)")
        Return Nothing
    End Function

    ''' <summary>Applies a --profile's surface to the requested shape: a
    ''' message-surface profile forces message; a stream-surface profile
    ''' keeps stream or stream_one_shot as requested and turns message
    ''' or both into stream.</summary>
    Private Function NarrowShape(requested As Shape, surface As Shape) As Shape
        If surface = Shape.MessageShape Then Return Shape.MessageShape
        Return If(requested = Shape.StreamOneShotShape, Shape.StreamOneShotShape, Shape.StreamShape)
    End Function

    Private Function Reject(message As String) As Integer
        Console.Error.WriteLine("loop: " & message)
        Return 2
    End Function

    ''' <summary>Builds the resolved config from argv. The returned code
    ''' is 0 with a config, 0 with Nothing for help, or 2 with Nothing
    ''' after printing "loop: &lt;message&gt;" for the first failing
    ''' rule.</summary>
    Private Function ParseFlags(args As String(), ByRef cfg As Config) As Integer
        Dim f As New RawFlags()
        Dim help As Boolean? = ParseArgv(args, f)
        If Not help.HasValue Then Return 2
        If help.Value Then Return 0

        Dim durationNs As Long? = ParseDuration(f.Duration)
        If Not durationNs.HasValue OrElse durationNs.Value <= 0 Then
            Return Reject("--duration must be positive, got " & f.Duration)
        End If
        If f.Iterations < 0 Then
            Return Reject("--iterations must be >= 0, got " & Dx(f.Iterations))
        End If
        If f.Goroutines < 1 OrElse f.Goroutines > MaxWorkers Then
            Return Reject("--goroutines must be in 1.." & MaxWorkers.ToString(Inv) &
                          ", got " & Dx(f.Goroutines))
        End If

        ' Concurrency mode. This binding runs shared-handle: CLR threads
        ' call into one Pipeline handle concurrently. The handle under
        ' this binding's Pipeline type is the C# layer's SafeHandle over
        ' an opaque Go-side registry key, every entry it is passed to is
        ' re-entrant after construction, and nothing in either layer is
        ' thread-affine, so --goroutines is the thread count verbatim,
        ' never clamped.
        Dim workers As Integer = CInt(f.Goroutines)

        Dim shape As Shape? = ParseShape(f.Shape)
        If Not shape.HasValue Then
            Return Reject("--shape must be stream | message | stream_one_shot | both, got """ &
                          f.Shape & """")
        End If
        If Not HashRegistered(f.Hash) Then
            Return Reject("--hash """ & f.Hash & """ is not a registered hash primitive")
        End If

        ' --mac is validated by Init: the C ABI enumerates no MAC names.
        Dim payload As Long? = ParseSize(f.PayloadSize)
        If Not payload.HasValue Then
            Return Reject("--payload-size: invalid size """ & f.PayloadSize & """")
        End If
        If payload.Value < 1 Then
            Return Reject("--payload-size must be at least 1 byte")
        End If

        Dim memlimitAuto As Boolean = f.Memlimit = "auto"
        Dim memlimit As Long
        If memlimitAuto Then
            memlimit = If(workers <= 3, 1L << 30, 256L << 20)
        Else
            Dim parsed As Long? = ParseSize(f.Memlimit)
            If Not parsed.HasValue Then
                Return Reject("--memlimit: invalid size """ & f.Memlimit & """")
            End If
            memlimit = parsed.Value
        End If

        If f.Gogc < 0 Then Return Reject("--gogc must be >= 0, got " & Dx(f.Gogc))
        If f.Parallax <> "on" AndAlso f.Parallax <> "off" Then
            Return Reject("--parallax must be on | off, got """ & f.Parallax & """")
        End If
        If f.Wrapper <> "on" AndAlso f.Wrapper <> "off" Then
            Return Reject("--wrapper must be on | off, got """ & f.Wrapper & """")
        End If

        Dim effectiveShape As Shape = shape.Value
        If f.ProfileName.Length > 0 Then
            Dim surface As Shape? = ProfileSurface(f.ProfileName)
            If Not surface.HasValue Then Return 2
            effectiveShape = NarrowShape(effectiveShape, surface.Value)
        End If

        If f.KeyBits <> 0 AndAlso f.KeyBits <> 512 AndAlso f.KeyBits <> 1024 AndAlso f.KeyBits <> 2048 Then
            Return Reject("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got " &
                          Dx(f.KeyBits))
        End If
        If f.NonceBits <> 0 AndAlso f.NonceBits <> 128 AndAlso f.NonceBits <> 256 AndAlso f.NonceBits <> 512 Then
            Return Reject("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got " &
                          Dx(f.NonceBits))
        End If
        If Array.IndexOf({0L, 1L, 2L, 4L, 8L, 16L, 32L}, f.BarrierFill) < 0 Then
            Return Reject("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got " &
                          Dx(f.BarrierFill))
        End If

        Dim chunkSize As Long? = ParseSize(f.ChunkSize)
        If Not chunkSize.HasValue Then
            Return Reject("--chunk-size: invalid size """ & f.ChunkSize & """")
        End If
        If f.Gomaxprocs < 0 Then
            Return Reject("--gomaxprocs must be > 0 when specified, got " & Dx(f.Gomaxprocs))
        End If
        If f.RekeyEvery < 0 Then
            Return Reject("--rekey-every must be >= 0, got " & Dx(f.RekeyEvery))
        End If
        If f.BlobCycleEvery < 0 Then
            Return Reject("--blob-cycle-every must be >= 0, got " & Dx(f.BlobCycleEvery))
        End If

        Dim mode As PayloadMode? = ParsePayloadMode(f.PayloadModeName)
        If Not mode.HasValue Then
            Return Reject("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | " &
                          "pattern-ascii, got """ & f.PayloadModeName & """")
        End If

        cfg = New Config With {
            .DurationNs = durationNs.Value,
            .Iterations = f.Iterations,
            .WorkersRequested = workers,
            .Workers = workers,
            .Shape = effectiveShape,
            .Hash = f.Hash,
            .Mac = f.Mac,
            .PayloadBytes = payload.Value,
            .Memlimit = memlimit,
            .MemlimitAuto = memlimitAuto,
            .Gogc = CInt(f.Gogc),
            .Parallax = f.Parallax = "on",
            .Wrapper = f.Wrapper = "on",
            .ProfileName = f.ProfileName,
            .KeyBits = f.KeyBits,
            .NonceBits = f.NonceBits,
            .ChunkSize = chunkSize.Value,
            .BarrierFill = f.BarrierFill,
            .Gomaxprocs = CInt(f.Gomaxprocs),
            .RekeyEvery = f.RekeyEvery,
            .BlobCycleEvery = f.BlobCycleEvery,
            .Mode = mode.Value,
            .Seed = f.Seed,
            .JsonOutput = f.JsonOutput,
            .Memprofile = f.Memprofile}
        Return 0
    End Function

    ' ----------------------------------------------------------------
    ' Signals
    ' ----------------------------------------------------------------

    Private SignalSeen As Integer = 0
    Private ReadOnly SignalRegistrations As New List(Of PosixSignalRegistration)()

    ''' <summary>
    ''' Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
    ''' while it waits for the workers; it turns the flag into the stop
    ''' request every worker checks before starting an iteration, so a
    ''' signal interrupts nothing mid-call — the in-flight encrypt /
    ''' decrypt / compare completes, the worker returns, and the partial
    ''' summary prints with the verdict the completed iterations earned.
    ''' .NET-specific: the registration cancels the runtime's own default
    ''' termination for both signals, and the registration objects are
    ''' held for the life of the process because disposing one restores
    ''' that default.
    ''' </summary>
    Private Sub InstallSignals()
        For Each sig In {PosixSignal.SIGINT, PosixSignal.SIGTERM}
            SignalRegistrations.Add(PosixSignalRegistration.Create(
                sig,
                Sub(ctx)
                    ctx.Cancel = True
                    Volatile.Write(SignalSeen, 1)
                End Sub))
        Next
    End Sub

    ' ----------------------------------------------------------------
    ' Pipelines
    ' ----------------------------------------------------------------

    ''' <summary>
    ''' Supplies the keystream-capable primitive for every layer the
    ''' profile record leaves unnamed and the run engages: a missing
    ''' parallax palette becomes three copies of the fill cipher (with
    ''' the library's default segment size when the record carries
    ''' none), a missing outer cipher becomes the fill cipher. These are
    ''' opts overrides that fold into the resolved record the blob
    ''' carries — a derived profile is never registered, so no name the
    ''' receiver did not agree to reaches the wire. False on a lookup
    ''' failure, after printing the validation message.
    ''' </summary>
    Private Function FillKeystreamLayers(name As String, ByRef opts As Opts,
                                         wantParallax As Boolean, wantWrapper As Boolean,
                                         ByRef filled As Boolean) As Boolean
        Dim p As Global.Everanium.Itb3.Profile
        Try
            p = Pipeline.Lookup(name)
        Catch ex As Exception
            Console.Error.WriteLine(
                "loop: --profile """ & name & """ is not a registered triple profile")
            Return False
        End Try

        filled = False
        If wantParallax AndAlso p.Palette.Length = 0 Then
            opts = opts.WithParallaxPalette(
                KeystreamFillCipher, KeystreamFillCipher, KeystreamFillCipher)
            If p.Segment = 0 Then
                ' A recipe that never carried a palette never carried a
                ' segment size either, and the schedule rejects zero.
                opts = opts.WithParallaxSegmentSize(KeystreamFillSegment)
            End If
            filled = True
        End If
        If wantWrapper AndAlso p.Outer.Length = 0 Then
            opts = opts.WithOuterCipher(KeystreamFillCipher)
            filled = True
        End If
        Return True
    End Function

    ''' <summary>Prints the construction line with the recipe read back
    ''' from the blob the Pipeline handed out, not echoed from the
    ''' flags: every construction override is proven to have reached the
    ''' library by the value the receiver would see. Record values that
    ''' are empty (a No MAC profile's MAC, a mixed profile's single
    ''' hash) print as "-".</summary>
    Private Sub LogPipelineInitialised(profile As String, blob As Byte())
        Dim rec As Global.Everanium.Itb3.Profile
        Try
            rec = Pipeline.Inspect(blob)
        Catch ex As Exception
            LogLine("pipeline initialised: profile=" & profile & " blob=" &
                    blob.Length.ToString(Inv) & " bytes (inspect: " & Detail(ex) & ")")
            Return
        End Try

        LogLine("pipeline initialised: profile=" & profile & " blob=" &
                blob.Length.ToString(Inv) & " bytes hash=" & Dash(rec.Hash) &
                " key-bits=" & rec.KeyBits.ToString(Inv) &
                " nonce-bits=" & If(rec.NonceBits.HasValue, rec.NonceBits.Value, 0).ToString(Inv) &
                " barrier-fill=" & If(rec.BarrierFill.HasValue, rec.BarrierFill.Value, 0).ToString(Inv) &
                " chunk-size=" & rec.Chunk.ToString(Inv) & " mac=" & Dash(rec.Mac) &
                " parallax=" & OnOff(rec.Parallax) & " wrapper=" & OnOff(rec.Wrapper))
    End Sub

    Private Function Dash(s As String) As String
        Return If(String.IsNullOrEmpty(s), "-", s)
    End Function

    ''' <summary>Constructs one Pipeline against profile with every
    ''' flag-carried override in the opts string (zero values included —
    ''' the shared library treats zero as "profile default"), then
    ''' obtains the Init blob once through Save: the binding's init entry
    ''' does not hand the blob back, and the bytes are the ones Init
    ''' produced. Later blob reopens use the retained blob; Save is never
    ''' called again.</summary>
    Private Function BuildPipeline(cfg As Config, profile As String,
                                   ByRef pipe As Pipeline, ByRef blob As Byte()) As Boolean
        Dim opts As Opts = New Opts().
            WithInnerHash(cfg.Hash).
            WithMacName(cfg.Mac).
            WithParallax(cfg.Parallax).
            WithWrapper(cfg.Wrapper).
            WithKeyBits(cfg.KeyBits).
            WithNonceBits(cfg.NonceBits).
            WithBarrierFill(cfg.BarrierFill).
            WithChunkSize(cfg.ChunkSize)

        If cfg.ProfileName.Length > 0 Then
            Dim filled As Boolean = False
            If Not FillKeystreamLayers(cfg.ProfileName, opts, cfg.Parallax, cfg.Wrapper, filled) Then
                Return False
            End If
            If filled Then
                Console.Error.WriteLine("loop: " & cfg.ProfileName &
                    " leaves the requested keystream layers unnamed; " &
                    KeystreamFillCipher & " supplied for them")
            End If
        End If

        Try
            pipe = Pipeline.Init(profile, opts)
        Catch ex As Exception
            Console.Error.WriteLine("loop: Init(" & profile & "): " & Detail(ex))
            Return False
        End Try

        Try
            blob = pipe.Save()
        Catch ex As Exception
            Console.Error.WriteLine("loop: Save(" & profile & "): " & Detail(ex))
            pipe.Dispose()
            Return False
        End Try

        LogPipelineInitialised(profile, blob)
        Return True
    End Function

    ' ----------------------------------------------------------------
    ' Run
    ' ----------------------------------------------------------------

    Private Function Run(args As String()) As Integer
        Dim cfg As Config = Nothing
        Dim code As Integer = ParseFlags(args, cfg)
        If cfg Is Nothing Then Return code

        ' Runtime shaping. A long run under allocation churn grows the Go
        ' heap inside the shared library without bound unless a soft
        ' limit paces the collector, so a limit is always in force: an
        ' explicit --memlimit is set as given, and auto caps the heap only
        ' when the runtime reports no limit at all (a limit already
        ' installed from the environment is left standing). The GC
        ' percentage and GOMAXPROCS are set only when their flag is
        ' non-zero — a zero flag skips the setter rather than calling it
        ' with zero, because zero is a real value to the GC-percent
        ' setter, and a call would clobber whatever the environment
        ' installed. All of it lands before any Pipeline exists so the
        ' baselines are taken under the shaped runtime.
        If cfg.MemlimitAuto Then
            If Library.SetMemoryLimit(-1) = Long.MaxValue Then
                Library.SetMemoryLimit(cfg.Memlimit)
            End If
        Else
            Library.SetMemoryLimit(cfg.Memlimit)
        End If
        cfg.Memlimit = Library.SetMemoryLimit(-1)
        If cfg.Gogc > 0 Then Library.SetGCPercent(cfg.Gogc)
        If cfg.Gomaxprocs > 0 Then Library.SetGOMAXPROCS(cfg.Gomaxprocs)

        LogLine("start: duration=" & HumanDuration(cfg.DurationNs) &
                " iterations=" & Dx(cfg.Iterations) &
                " goroutines=" & cfg.WorkersRequested.ToString(Inv) &
                " workers=" & cfg.Workers.ToString(Inv) &
                " concurrency=" & Concurrency & " shape=" & ShapeName(cfg.Shape) &
                " hash=" & cfg.Hash & " mac=" & cfg.Mac &
                " payload=" & HumanBytes(cfg.PayloadBytes) &
                " memlimit=" & HumanBytes(cfg.Memlimit) &
                " parallax=" & OnOff(cfg.Parallax) & " wrapper=" & OnOff(cfg.Wrapper))
        LogLine("overrides: profile=""" & cfg.ProfileName & """ key-bits=" & Dx(cfg.KeyBits) &
                " nonce-bits=" & Dx(cfg.NonceBits) &
                " chunk-size=" & HumanBytes(cfg.ChunkSize) &
                " barrier-fill=" & Dx(cfg.BarrierFill) &
                " gomaxprocs=" & cfg.Gomaxprocs.ToString(Inv) &
                " rekey-every=" & Dx(cfg.RekeyEvery) &
                " blob-cycle-every=" & Dx(cfg.BlobCycleEvery) &
                " payload-mode=" & PayloadModeName(cfg.Mode) &
                " seed=" & cfg.Seed.ToString(Inv) &
                " json-output=" & If(cfg.JsonOutput, "true", "false"))
        LogLine("policy: microbatch-tiers=" & PolicyLabel("ITB_MICROBATCH_TIERS") &
                " hashpool-starters=" & PolicyLabel("ITB_HASHPOOL_STARTERS"))

        ' Pipeline construction — one shared handle per exercised shape.
        ' stream and stream_one_shot share the streaming handle.
        Dim streamProfile As String = If(cfg.ProfileName.Length = 0, DefaultStreamProfile, cfg.ProfileName)
        Dim msgProfile As String = If(cfg.ProfileName.Length = 0, DefaultMessageProfile, cfg.ProfileName)
        Dim pipes As New Pipes()

        If cfg.Shape = Shape.StreamShape OrElse cfg.Shape = Shape.StreamOneShotShape OrElse
           cfg.Shape = Shape.BothShape Then
            Dim p As Pipeline = Nothing
            Dim b As Byte() = Nothing
            If Not BuildPipeline(cfg, streamProfile, p, b) Then Return 1
            pipes.StreamPipe = p
            pipes.StreamBlob = b
        End If
        If cfg.Shape = Shape.MessageShape OrElse cfg.Shape = Shape.BothShape Then
            Dim p As Pipeline = Nothing
            Dim b As Byte() = Nothing
            If Not BuildPipeline(cfg, msgProfile, p, b) Then Return 1
            pipes.MsgPipe = p
            pipes.MsgBlob = b
        End If

        ' Allocation posture. Per-worker plaintexts are allocated once
        ' and held for the whole run (rotating mode refills them in place
        ' per iteration); the pump accumulators and the drain scratch
        ' live inside each worker and are reused across iterations — the
        ' session's offset / count write overload keeps the feed side
        ' allocation-free as well; the message and one-shot outputs are
        ' allocated by the binding per call and reclaimed per iteration.
        ' Under the default fixed CSPRNG mode every worker's buffer is
        ' distinct, so cross-worker data crossover is detectable; pattern
        ' modes trade that property for content edge-case coverage.
        Dim states As New List(Of WorkerState)(cfg.Workers)
        For id As Integer = 0 To cfg.Workers - 1
            Dim w As New WorkerState With {
                .Id = id,
                .Plaintext = New Byte(CInt(cfg.PayloadBytes) - 1) {},
                .Mode = cfg.Mode,
                .Seeded = cfg.Seed <> 0,
                .Rng = SeedWorker(cfg.Seed, id),
                .Scratch = New Byte(PumpSlice - 1) {}}
            If Not FillPayload(cfg.Mode, w.Seeded, w.Rng, w.Plaintext) Then
                Console.Error.WriteLine("loop: payload fill: csprng")
                Return 1
            End If
            states.Add(w)
        Next

        InstallSignals()
        Dim r As New RunState With {
            .Cfg = cfg,
            .StreamProfile = streamProfile,
            .MsgProfile = msgProfile,
            .Pipes = pipes,
            .WarmupDone = New Barrier(cfg.Workers + 1),
            .ReleaseGate = New Barrier(cfg.Workers + 1),
            .Active = cfg.Workers}
        Dim counters(cfg.Workers - 1) As Counters
        For i As Integer = 0 To cfg.Workers - 1
            counters(i) = New Counters()
        Next
        r.Workers = counters

        ' Warmup barrier. Every worker runs one iteration and waits; the
        ' clock starts only once all of them have paid their first-call
        ' costs (pool warm-up, lazy kernel dispatch, page faults on the
        ' payload buffers, and on this runtime the tiered JIT's first
        ' pass over the iteration body), and the RSS and pool baselines
        ' taken here describe a process that has already run the whole
        ' cipher path once per worker.
        Dim warmupStart As Long = Stopwatch.GetTimestamp()
        Dim threads As New List(Of Thread)(cfg.Workers)
        For Each w In states
            Dim captured As WorkerState = w
            Dim t As New Thread(Sub() RunWorker(r, captured)) With {
                .IsBackground = False,
                .Name = "loop-worker-" & captured.Id.ToString(Inv)}
            threads.Add(t)
            t.Start()
        Next

        r.WarmupDone.SignalAndWait()
        Dim rssWarmup As Long = 0, rssPeakIgnored As Long = 0
        ReadRss(rssWarmup, rssPeakIgnored)
        Dim poolWarmup As Long() = PoolSnapshot()
        LogLine("warmup: " & cfg.Workers.ToString(Inv) & " workers x 1 iter completed in " &
                HumanDuration(RoundTo(ElapsedNs(warmupStart), 100000000L)) &
                " (baseline rss=" & HumanBytes(rssWarmup) & ")")

        ' Open the gate; the duration is a deadline the waiter below
        ' enforces in duration mode.
        Dim startTicks As Long = Stopwatch.GetTimestamp()
        r.ReleaseGate.SignalAndWait()

        ' Wait for every worker, polling every 100 ms so the deadline and
        ' a signal are both noticed promptly.
        Dim finishTicks As Long = startTicks
        SyncLock r.DoneLock
            Do While r.Active > 0
                If Volatile.Read(SignalSeen) <> 0 OrElse
                   (cfg.Iterations = 0 AndAlso ElapsedNs(startTicks) >= cfg.DurationNs) Then
                    r.StopRequested = True
                End If
                Monitor.Wait(r.DoneLock, 100)
            Loop
            If r.FinishTimestamp <> 0 Then finishTicks = r.FinishTimestamp
        End SyncLock

        Dim elapsedNanos As Long = TicksToNs(finishTicks - startTicks)
        Dim rssFinal As Long = 0, rssPeak As Long = 0
        ReadRss(rssFinal, rssPeak)
        Dim poolSteady As Long() = PoolSnapshot()
        For Each t In threads
            t.Join()
        Next

        r.RssWarmup = rssWarmup
        r.RssPeak = rssPeak
        r.RssFinal = rssFinal
        r.PoolWarmup = poolWarmup
        r.PoolSteady = poolSteady

        If cfg.Memprofile.Length > 0 Then
            Try
                Library.WriteHeapProfile(cfg.Memprofile)
                LogLine("memprofile: heap profile written to " & cfg.Memprofile)
            Catch ex As Exception
                Console.Error.WriteLine("loop: memprofile: " & Detail(ex))
            End Try
        End If

        Dim exitCode As Integer = FinalSummary(r, elapsedNanos)
        If r.Pipes.StreamPipe IsNot Nothing Then r.Pipes.StreamPipe.Dispose()
        If r.Pipes.MsgPipe IsNot Nothing Then r.Pipes.MsgPipe.Dispose()
        Return exitCode
    End Function

    <DllImport("libc", EntryPoint:="signal")>
    Private Function SysSignal(sig As Integer, handler As IntPtr) As IntPtr
    End Function

    Private Const Sigpipe As Integer = 13

    Friend Function Main(args As String()) As Integer
        ' .NET-specific. The runtime ignores SIGPIPE and the console
        ' stream drops a write to a closed pipe without a word, so a
        ' consumer that stops reading leaves the process printing into
        ' nothing and exiting 0 with its verdict undelivered. With the
        ' default disposition back the first such write ends the process,
        ' which is what every other implementation does and what a fleet
        ' driver expects.
        SysSignal(Sigpipe, IntPtr.Zero)

        ' .NET-specific. Number rendering is part of the output contract,
        ' so the process runs under the invariant culture rather than the
        ' operator's locale; every formatter names the culture as well,
        ' and this pin is the second line of defence.
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture
        CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.InvariantCulture
        Return Run(args)
    End Function
End Module
