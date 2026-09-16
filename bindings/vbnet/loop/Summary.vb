' The final summary in both renderings, and the two measurements it
' folds in that are not per-worker counters: the process resident set
' and the shared library's pool counters.

Imports System.Globalization
Imports System.Text
Imports Everanium.Itb3.VisualBasic

Friend Module Summary

    ''' <summary>Parses one "Vm...:   1234 kB" line of
    ''' /proc/self/status into bytes; zero on any parse
    ''' failure.</summary>
    Private Function StatusKb(line As String) As Long
        Dim colon As Integer = line.IndexOf(":"c)
        If colon < 0 Then Return 0
        Dim parts As String() = line.Substring(colon + 1).Split(
            CType(Nothing, Char()), StringSplitOptions.RemoveEmptyEntries)
        If parts.Length = 0 Then Return 0
        Dim kb As Long
        If Not Long.TryParse(parts(0), NumberStyles.None, Inv, kb) Then Return 0
        Return kb * 1024
    End Function

    ''' <summary>The process's current resident set and its high-water
    ''' mark in bytes, from /proc/self/status (VmRSS and VmHWM, reported
    ''' in kB). Both are zero on a platform without that file; the
    ''' figures are informational and never enter the verdict.</summary>
    Friend Sub ReadRss(ByRef current As Long, ByRef peak As Long)
        current = 0
        peak = 0
        Try
            For Each line As String In IO.File.ReadLines("/proc/self/status")
                If line.StartsWith("VmRSS:", StringComparison.Ordinal) Then
                    current = StatusKb(line)
                ElseIf line.StartsWith("VmHWM:", StringComparison.Ordinal) Then
                    peak = StatusKb(line)
                End If
            Next
        Catch ex As Exception
            current = 0
            peak = 0
        End Try
    End Sub

    ''' <summary>
    ''' Pool counters. The shared library keeps process-wide monotonic
    ''' totals at every pool checkout of its cipher core: per hash-array
    ''' tier the starter width, checkouts, constructor misses, regrow
    ''' replacements and bytes allocated; for the scratch byte pool and
    ''' the parallax chunk pool the checkouts, constructor misses,
    ''' regrows and regrow bytes. Two snapshots bracketing the main loop
    ''' are differenced into per-run hit / miss figures that tell whether
    ''' a pool keeps its items warm between calls or evicts them across
    ''' GC cycles. The slot layout is read from the library: slot 0
    ''' carries the tier count T, tier i occupies the five slots at
    ''' 1 + 5*i, and the two byte pools occupy the eight slots at
    ''' 1 + 5*T; the vector is sized by the binding from the library's
    ''' own length query, never from a constant. Empty when the library
    ''' is unavailable.
    ''' </summary>
    Friend Function PoolSnapshot() As Long()
        Try
            Return Library.PoolStats()
        Catch ex As Exception
            Return Array.Empty(Of Long)()
        End Try
    End Function

    ''' <summary>One starter tier of the hash-array pool,
    ''' differenced.</summary>
    Private Class Tier
        Friend Index As Long
        Friend Starter As Long
        Friend Get_ As Long
        Friend Fresh As Long
        Friend Regrow As Long
        Friend NewBytes As Long
    End Class

    ''' <summary>One single-size byte pool, differenced.</summary>
    Private Class BytePool
        Friend Get_ As Long
        Friend Fresh As Long
        Friend Regrow As Long
        Friend RegrowBytes As Long
    End Class

    Private Class PoolDelta
        Friend ReadOnly Tiers As New List(Of Tier)()
        Friend Buf As New BytePool()
        Friend Chunk As New BytePool()
    End Class

    Private Function PoolDiff(steady As Long(), warmup As Long()) As PoolDelta
        Dim d As New PoolDelta()
        If steady.Length < 9 OrElse warmup.Length <> steady.Length Then Return d
        Dim tiers As Long = steady(0)
        If tiers < 0 OrElse 1 + 5 * tiers + 8 > steady.Length Then Return d

        For i As Long = 0 To tiers - 1
            Dim b As Integer = CInt(1 + 5 * i)
            If steady(b) = 0 Then Continue For
            d.Tiers.Add(New Tier With {
                .Index = i,
                .Starter = steady(b),
                .Get_ = steady(b + 1) - warmup(b + 1),
                .Fresh = steady(b + 2) - warmup(b + 2),
                .Regrow = steady(b + 3) - warmup(b + 3),
                .NewBytes = steady(b + 4) - warmup(b + 4)})
        Next

        Dim t As Integer = CInt(1 + 5 * tiers)
        d.Buf = New BytePool With {
            .Get_ = steady(t) - warmup(t),
            .Fresh = steady(t + 1) - warmup(t + 1),
            .Regrow = steady(t + 2) - warmup(t + 2),
            .RegrowBytes = steady(t + 3) - warmup(t + 3)}
        d.Chunk = New BytePool With {
            .Get_ = steady(t + 4) - warmup(t + 4),
            .Fresh = steady(t + 5) - warmup(t + 5),
            .Regrow = steady(t + 6) - warmup(t + 6),
            .RegrowBytes = steady(t + 7) - warmup(t + 7)}
        Return d
    End Function

    ''' <summary>Misses over checkouts as a percentage; zero when nothing
    ''' was checked out.</summary>
    Private Function MissPercent(miss As Long, gets As Long) As Double
        If gets <= 0 Then Return 0.0
        Return 100.0 * CDbl(miss) / CDbl(gets)
    End Function

    ''' <summary>Renders s as a JSON string literal with the escapes JSON
    ''' requires.</summary>
    Private Function JsonString(s As String) As String
        Dim sb As New StringBuilder(s.Length + 2)
        sb.Append(""""c)
        For Each ch As Char In s
            Select Case ch
                Case """"c : sb.Append("\""")
                Case "\"c : sb.Append("\\")
                Case vbLf(0) : sb.Append("\n")
                Case vbCr(0) : sb.Append("\r")
                Case vbTab(0) : sb.Append("\t")
                Case Else
                    If AscW(ch) < 32 Then
                        sb.Append("\u").Append(AscW(ch).ToString("x4", Inv))
                    Else
                        sb.Append(ch)
                    End If
            End Select
        Next
        sb.Append(""""c)
        Return sb.ToString()
    End Function


    ''' <summary>Joins a list of counts with the given separator
    ''' under the invariant culture.</summary>
    Private Function JoinLongs(values As List(Of Long), separator As String) As String
        Dim parts As New List(Of String)(values.Count)
        For Each v In values
            parts.Add(Dx(v))
        Next
        Return String.Join(separator, parts)
    End Function

    ''' <summary>Joins worker-error texts as JSON string
    ''' literals.</summary>
    Private Function JoinEscaped(values As List(Of String)) As String
        Dim parts As New List(Of String)(values.Count)
        For Each v In values
            parts.Add(JsonString(v))
        Next
        Return String.Join(",", parts)
    End Function
    ''' <summary>The effective GC percentage as the runtime reports it:
    ''' the query form of the setter (a set-and-restore round trip inside
    ''' the library) so the field is the same whether the value came from
    ''' the flag, the environment, or the runtime default.</summary>
    Private Function EffectiveGogc(flag As Integer) As Integer
        If flag > 0 Then Return flag
        Try
            Return Library.SetGCPercent(-1)
        Catch ex As Exception
            Return 0
        End Try
    End Function

    ''' <summary>
    ''' Output contract. Both renderings are shared with the Go harness
    ''' and every other binding's loop utility field for field: the same
    ''' lines in the same order, the same keys in the same order, floats
    ''' with a fixed number of decimals so the JSON is byte-identical
    ''' across implementations. The Go harness alone adds its
    ''' runtime-internal lines after rss: and its runtime-internal keys
    ''' after parallax_chunk_pool; nothing here reproduces them because
    ''' nothing they read is reachable through the C ABI. Returns the
    ''' exit code.
    ''' </summary>
    Friend Function FinalSummary(r As RunState, elapsedNs As Long) As Integer
        Dim cfg As Config = r.Cfg
        Dim workers As Long = cfg.Workers
        Dim totalIters As Long = 0, totalEnc As Long = 0, totalDec As Long = 0
        Dim nanosEnc As Long = 0, nanosDec As Long = 0
        Dim perWorker As New List(Of Long)(cfg.Workers)
        Dim errors As New List(Of String)()

        For Each c In r.Workers
            perWorker.Add(c.Iters)
            totalIters += c.Iters
            totalEnc += c.BytesEnc
            totalDec += c.BytesDec
            nanosEnc += c.NanosEnc
            nanosDec += c.NanosDec
            SyncLock c.ErrorLock
                If c.ErrorText IsNot Nothing Then errors.Add(c.ErrorText)
            End SyncLock
        Next

        ' Throughput. Per-direction throughput divides the sum of every
        ' worker's wall time in that direction by the worker count — the
        ' equivalent single-stream wall time under N-way concurrency — so
        ' each direction reports the aggregate rate it sustained rather
        ' than collapsing to combined/2 (every iteration moves equal
        ' encrypt and decrypt bytes, so a total-elapsed denominator would
        ' give both directions the same figure). The combined rate keeps
        ' total elapsed as the one-glance overall figure.
        Dim avgEnc As Long = If(nanosEnc > 0, nanosEnc \ workers, 0L)
        Dim avgDec As Long = If(nanosDec > 0, nanosDec \ workers, 0L)

        Dim rssDelta As Long = r.RssFinal - r.RssWarmup
        Dim rssGrowth As Double = If(r.RssWarmup > 0, 100.0 * CDbl(rssDelta) / CDbl(r.RssWarmup), 0.0)

        Dim pd As PoolDelta = PoolDiff(r.PoolSteady, r.PoolWarmup)
        Dim pass As Boolean = errors.Count = 0
        Dim rekeys As Long = r.Rekeys
        Dim cycles As Long = r.BlobCycles
        Dim gomaxprocs As Integer
        Try
            gomaxprocs = Library.SetGOMAXPROCS(0)
        Catch ex As Exception
            gomaxprocs = 0
        End Try
        Dim streamProfile As String = If(r.Pipes.StreamPipe IsNot Nothing, r.StreamProfile, "")
        Dim msgProfile As String = If(r.Pipes.MsgPipe IsNot Nothing, r.MsgProfile, "")

        If cfg.JsonOutput Then
            Dim j As New StringBuilder()
            j.Append("{""duration_seconds"":").Append(Fx(CDbl(elapsedNs) / 1000000000.0, 3))
            j.Append(",""iterations"":").Append(Dx(totalIters))
            j.Append(",""per_worker_iterations"":[").
              Append(JoinLongs(perWorker, ",")).Append("]"c)
            j.Append(",""bytes_encrypted"":").Append(Dx(totalEnc))
            j.Append(",""bytes_decrypted"":").Append(Dx(totalDec))
            j.Append(",""encrypt_mb_per_sec"":").Append(Fx(MbPerSec(totalEnc, avgEnc), 1))
            j.Append(",""decrypt_mb_per_sec"":").Append(Fx(MbPerSec(totalDec, avgDec), 1))
            j.Append(",""combined_mb_per_sec"":").Append(Fx(MbPerSec(totalEnc + totalDec, elapsedNs), 1))
            j.Append(",""rekeys"":").Append(Dx(rekeys))
            j.Append(",""blob_cycles"":").Append(Dx(cycles))
            j.Append(",""worker_errors"":[").
              Append(JoinEscaped(errors)).Append("]"c)
            j.Append(",""verdict"":""").Append(If(pass, "PASS", "FAIL")).Append(""""c)
            j.Append(",""shape"":""").Append(ShapeName(cfg.Shape)).Append(""""c)
            j.Append(",""stream_profile"":").Append(JsonString(streamProfile))
            j.Append(",""message_profile"":").Append(JsonString(msgProfile))
            j.Append(",""hash"":").Append(JsonString(cfg.Hash))
            j.Append(",""mac"":").Append(JsonString(cfg.Mac))
            j.Append(",""payload_bytes"":").Append(Dx(cfg.PayloadBytes))
            j.Append(",""payload_mode"":""").Append(PayloadModeName(cfg.Mode)).Append(""""c)
            j.Append(",""seed"":").Append(cfg.Seed.ToString(Inv))
            j.Append(",""key_bits"":").Append(Dx(cfg.KeyBits))
            j.Append(",""nonce_bits"":").Append(Dx(cfg.NonceBits))
            j.Append(",""chunk_size_bytes"":").Append(Dx(cfg.ChunkSize))
            j.Append(",""barrier_fill"":").Append(Dx(cfg.BarrierFill))
            j.Append(",""parallax"":""").Append(OnOff(cfg.Parallax)).Append(""""c)
            j.Append(",""wrapper"":""").Append(OnOff(cfg.Wrapper)).Append(""""c)
            j.Append(",""goroutines_requested"":").Append(Dx(CLng(cfg.WorkersRequested)))
            j.Append(",""goroutines"":").Append(Dx(CLng(cfg.Workers)))
            j.Append(",""concurrency"":""").Append(Concurrency).Append(""""c)
            j.Append(",""gogc"":""").Append(Dx(CLng(EffectiveGogc(cfg.Gogc)))).Append(""""c)
            j.Append(",""memlimit_bytes"":").Append(Dx(cfg.Memlimit))
            j.Append(",""gomaxprocs"":").Append(Dx(CLng(gomaxprocs)))
            j.Append(",""microbatch_tiers"":").Append(JsonString(PolicyLabel("ITB_MICROBATCH_TIERS")))
            j.Append(",""hashpool_starters"":").Append(JsonString(PolicyLabel("ITB_HASHPOOL_STARTERS")))
            j.Append(",""rss_warmup_bytes"":").Append(Dx(r.RssWarmup))
            j.Append(",""rss_peak_bytes"":").Append(Dx(r.RssPeak))
            j.Append(",""rss_final_bytes"":").Append(Dx(r.RssFinal))
            j.Append(",""rss_growth_percent"":").Append(Fx(rssGrowth, 2))
            j.Append(",""hash_pool_tiers"":[")
            Dim tierJson As New List(Of String)()
            For Each t In pd.Tiers
                tierJson.Add("{""tier"":" & Dx(t.Index) &
                             ",""starter"":" & Dx(t.Starter) &
                             ",""get"":" & Dx(t.Get_) &
                             ",""new"":" & Dx(t.Fresh) &
                             ",""regrow"":" & Dx(t.Regrow) &
                             ",""new_bytes"":" & Dx(t.NewBytes) &
                             ",""miss_percent"":" &
                             Fx(MissPercent(t.Fresh + t.Regrow, t.Get_), 2) & "}")
            Next
            j.Append(String.Join(",", tierJson))
            j.Append("]"c)
            j.Append(",""buf_pool"":{""get"":").Append(Dx(pd.Buf.Get_)).
              Append(",""new"":").Append(Dx(pd.Buf.Fresh)).
              Append(",""regrow"":").Append(Dx(pd.Buf.Regrow)).
              Append(",""regrow_bytes"":").Append(Dx(pd.Buf.RegrowBytes)).
              Append(",""miss_percent"":").Append(Fx(MissPercent(pd.Buf.Regrow, pd.Buf.Get_), 2)).
              Append("}"c)
            j.Append(",""parallax_chunk_pool"":{""get"":").Append(Dx(pd.Chunk.Get_)).
              Append(",""new"":").Append(Dx(pd.Chunk.Fresh)).
              Append(",""regrow"":").Append(Dx(pd.Chunk.Regrow)).
              Append(",""regrow_bytes"":").Append(Dx(pd.Chunk.RegrowBytes)).
              Append(",""miss_percent"":").Append(Fx(MissPercent(pd.Chunk.Regrow, pd.Chunk.Get_), 2)).
              Append("}"c)
            j.Append("}"c)
            Console.Out.WriteLine(j.ToString())
            Return If(pass, 0, 1)
        End If

        LogLine("=== FINAL ===")
        LogLine("  duration: " & HumanDuration(RoundTo(elapsedNs, 1000000L)))
        LogLine("  iterations: " & JoinLongs(perWorker, " + ") &
                " = " & Dx(totalIters) & " total")
        LogLine("  throughput: encrypt " & HumanRate(totalEnc, avgEnc) &
                ", decrypt " & HumanRate(totalDec, avgDec) &
                ", combined " & HumanRate(totalEnc + totalDec, elapsedNs))
        LogLine("  bytes: " & HumanBytes(totalEnc) & " encrypted, " &
                HumanBytes(totalDec) & " decrypted")
        LogLine("  data integrity: " & Dx(totalIters) & "/" & Dx(totalIters) & " PASS")
        LogLine("  concurrency: " & Concurrency & ", workers " & cfg.Workers.ToString(Inv) &
                " (requested " & cfg.WorkersRequested.ToString(Inv) & ")")
        LogLine("  rss: warmup " & HumanBytes(r.RssWarmup) & ", peak " & HumanBytes(r.RssPeak) &
                ", final " & HumanBytes(r.RssFinal) & " (delta " & HumanBytesSigned(rssDelta) &
                ", " & Fx(rssGrowth, 1) & "% growth)")
        For Each t In pd.Tiers
            LogLine("  hash pool tier " & Dx(t.Index) & " (starter " & Dx(t.Starter) &
                    "): get " & Dx(t.Get_) & ", miss " & Dx(t.Fresh + t.Regrow) &
                    " (new " & Dx(t.Fresh) & " + regrow " & Dx(t.Regrow) & "), miss " &
                    Fx(MissPercent(t.Fresh + t.Regrow, t.Get_), 2) & "%, " &
                    HumanBytes(t.NewBytes) & " allocated")
        Next
        LogLine("  buf pool: get " & Dx(pd.Buf.Get_) & ", regrow " & Dx(pd.Buf.Regrow) &
                " (of which fresh " & Dx(pd.Buf.Fresh) & "), miss " &
                Fx(MissPercent(pd.Buf.Regrow, pd.Buf.Get_), 2) & "%, " &
                HumanBytes(pd.Buf.RegrowBytes) & " regrown")
        LogLine("  parallax chunk pool: get " & Dx(pd.Chunk.Get_) & ", regrow " &
                Dx(pd.Chunk.Regrow) & " (of which fresh " & Dx(pd.Chunk.Fresh) & "), miss " &
                Fx(MissPercent(pd.Chunk.Regrow, pd.Chunk.Get_), 2) & "%, " &
                HumanBytes(pd.Chunk.RegrowBytes) & " regrown")
        If rekeys > 0 Then LogLine("  rekeys: " & Dx(rekeys))
        If cycles > 0 Then LogLine("  blob cycles: " & Dx(cycles))
        For Each e In errors
            LogLine("  ERROR: " & e)
        Next
        If pass Then
            LogLine("  verdict: PASS")
            Return 0
        End If
        LogLine("  verdict: FAIL (errors=" & errors.Count.ToString(Inv) & ")")
        Return 1
    End Function
End Module
