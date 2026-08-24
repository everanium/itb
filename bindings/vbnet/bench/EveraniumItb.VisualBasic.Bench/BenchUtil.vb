' Shared timing + reporting helpers for the VB.NET binding
' micro-benchmarks. Wall-clock via Stopwatch; output is a
' fixed-width table:
'
'   bench             size     mb_per_sec
'   message           1 MiB    <n>
'   ...
'
' Bench configuration is driven by environment variables so a
' side-by-side comparison with the root Go bench harness is
' straightforward:
'
'   ITB_NONCE_BITS     nonce width (default 512)
'   ITB_KEY_BITS       key bits (default 1024)
'   ITB_WITH_PARALLAX  parallax layer on/off (default false)
'   ITB_WITH_WRAPPER   wrapper layer on/off (default false)
'   ITB_INNER_HASH     opaque hash name (default: profile's)
'   ITB_PROFILE        profile name override
'   ITB_BENCH_MIN_SEC  per-case wall-clock budget (default 5.0)

Imports System.Diagnostics
Imports System.Globalization
Imports Everanium.Itb.VisualBasic

Friend Module BenchUtil

    ''' <summary>Iteration floor per case.</summary>
    Private Const MinIters As Integer = 3

    ''' <summary>Payload sizes exercised by both shapes.</summary>
    Friend ReadOnly Sizes As Integer() = {1 << 20, 16 << 20, 64 << 20}

    Friend Function MinSeconds() As Double
        Dim raw As String = Environment.GetEnvironmentVariable("ITB_BENCH_MIN_SEC")
        Dim v As Double
        If Not String.IsNullOrEmpty(raw) AndAlso
                Double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, v) AndAlso
                v > 0.0 Then
            Return v
        End If
        Return 5.0
    End Function

    ''' <summary>Reads the bench-shape env vars and builds an
    ''' <see cref="Opts"/>. Defaults match root Go BENCH3.md so
    ''' numbers are directly comparable.</summary>
    Friend Function BuildOpts() As Opts
        Dim opts As Opts = New Opts().
            WithNonceBits(EnvLong("ITB_NONCE_BITS", 512)).
            WithKeyBits(EnvLong("ITB_KEY_BITS", 1024)).
            WithParallax(EnvBool("ITB_WITH_PARALLAX")).
            WithWrapper(EnvBool("ITB_WITH_WRAPPER"))
        Dim innerHash As String = Environment.GetEnvironmentVariable("ITB_INNER_HASH")
        If Not String.IsNullOrEmpty(innerHash) Then
            opts = opts.WithInnerHash(innerHash)
        End If
        Return opts
    End Function

    Friend Function ProfileName(fallback As String) As String
        Dim env As String = Environment.GetEnvironmentVariable("ITB_PROFILE")
        Return If(String.IsNullOrEmpty(env), fallback, env)
    End Function

    Friend Sub Header()
        Console.WriteLine(String.Format(
            CultureInfo.InvariantCulture, "{0,-17} {1,-8} {2}", "bench", "size", "mb_per_sec"))
    End Sub

    Private Function SizeLabel(size As Integer) As String
        Return If(size >= (1 << 20), $"{size >> 20} MiB", $"{size >> 10} KiB")
    End Function

    ''' <summary>Runs <paramref name="run"/> until the wall-clock
    ''' budget is spent (with an iteration floor + one untimed
    ''' warm-up), then prints one table row.</summary>
    Friend Sub [Case](name As String, size As Integer, run As Action)
        run() ' warm-up
        Dim budget As Double = MinSeconds()
        Dim clock As Stopwatch = Stopwatch.StartNew()
        Dim iters As Long = 0
        While clock.Elapsed.TotalSeconds < budget OrElse iters < MinIters
            run()
            iters += 1
        End While
        Dim elapsed As Double = clock.Elapsed.TotalSeconds
        Dim mb As Double = CDbl(size) * iters / (1024.0 * 1024.0)
        Console.WriteLine(String.Format(
            CultureInfo.InvariantCulture, "{0,-17} {1,-8} {2:F1}",
            name, SizeLabel(size), mb / elapsed))
    End Sub

    Private Function EnvLong(name As String, fallback As Long) As Long
        Dim raw As String = Environment.GetEnvironmentVariable(name)
        Dim v As Long
        Return If(Not String.IsNullOrEmpty(raw) AndAlso Long.TryParse(raw, v), v, fallback)
    End Function

    Private Function EnvBool(name As String) As Boolean
        Dim raw As String = Environment.GetEnvironmentVariable(name)
        Return raw = "true" OrElse raw = "1"
    End Function
End Module
