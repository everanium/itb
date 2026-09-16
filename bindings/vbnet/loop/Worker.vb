' The worker: its thread body (one warmup iteration, the warmup
' barrier, the main loop), one iteration, the session pump loop the
' stream shape drives, and the round-trip comparison that decides
' between a worker error and a data mismatch.

Imports System.Diagnostics
Imports System.Threading
Imports Everanium.Itb3.VisualBasic

''' <summary>Cipher surfaces the --shape flag selects. The member names
''' carry a Shape suffix because two of the bare words are reserved in
''' this language.</summary>
Friend Enum Shape
    ''' <summary>Session pump: begin / write / read / end.</summary>
    StreamShape
    ''' <summary>Single Message: one whole-buffer call.</summary>
    MessageShape
    ''' <summary>Stream surface, one whole-buffer call.</summary>
    StreamOneShotShape
    ''' <summary>All three, rotating by iteration number.</summary>
    BothShape
End Enum

Friend Module Worker

    Private ReadOnly ShapeNames As (Name As String, Value As Shape)() = {
        ("stream", Shape.StreamShape),
        ("message", Shape.MessageShape),
        ("stream_one_shot", Shape.StreamOneShotShape),
        ("both", Shape.BothShape)}

    Friend Function ShapeName(shape As Shape) As String
        For Each entry In ShapeNames
            If entry.Value = shape Then Return entry.Name
        Next
        Return "stream"
    End Function

    Friend Function ParseShape(s As String) As Shape?
        For Each entry In ShapeNames
            If entry.Name = s Then Return entry.Value
        Next
        Return Nothing
    End Function

    ''' <summary>Renders a binding error the way every implementation
    ''' reports a failed library call: <c>status &lt;code&gt;: &lt;last
    ''' error&gt;</c>; any other failure carries its own text. The
    ''' library assembles the whole sentence — the class of failure
    ''' and the case that raised it — so this reports what arrived
    ''' and composes nothing.</summary>
    Friend Function Detail(ex As Exception) As String
        Dim ie As ItbException = TryCast(ex, ItbException)
        If ie Is Nothing Then Return ex.Message

        Dim code As Integer = CInt(ie.Status)
        ' The C# layer under this binding folds the diagnostic into the
        ' exception message behind a fixed prefix; strip that prefix to
        ' recover the library's own text.
        Dim message As String = ie.Message
        If message.StartsWith("itb: status=", StringComparison.Ordinal) Then
            Dim i As Integer = message.IndexOf("): ", StringComparison.Ordinal)
            If i >= 0 Then message = message.Substring(i + 3)
        End If
        Return "status " & code.ToString(Inv) & ": " & message
    End Function

    ''' <summary>Records the worker's error text (first error wins) and
    ''' requests a stop of the whole run.</summary>
    Friend Sub FailWorker(r As RunState, id As Integer, text As String)
        Dim c As Counters = r.Workers(id)
        SyncLock c.ErrorLock
            If c.ErrorText Is Nothing Then c.ErrorText = text
        End SyncLock
        r.StopRequested = True
    End Sub

    ''' <summary>
    ''' Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
    ''' and ITB drives the chunk loop internally; the C ABI has no reader
    ''' / writer entry, so the caller drives it: open a session, feed
    ''' slices of at most 1 MiB, drain whatever the session has produced
    ''' after every write (a read before end never blocks), end, then
    ''' drain until the session reports finished (after end, a read on an
    ''' empty spool blocks until the terminal bytes arrive). The whole
    ''' produced output lands in the worker's reusable accumulator. The
    ''' loop is written here rather than delegated to the binding's pump
    ''' convenience so it stands in the utility, at the same place, in
    ''' every language. On failure the result names the failing call in
    ''' failedCall and carries its error; Nothing on success.
    ''' </summary>
    Private Function Pump(pipe As Pipeline, encrypt As Boolean, src As Byte(), srcLen As Integer,
                          acc As IO.MemoryStream, scratch As Byte(),
                          ByRef failedCall As String) As Exception
        acc.SetLength(0)
        failedCall = Nothing

        Dim enc As EncryptStream = Nothing
        Dim dec As DecryptStream = Nothing
        Try
            Try
                If encrypt Then
                    enc = pipe.BeginEncryptStream()
                Else
                    dec = pipe.BeginDecryptStream()
                End If
            Catch ex As Exception
                failedCall = "StreamBegin"
                Return ex
            End Try

            ' VB-specific. The two session directions are distinct sealed
            ' types with identical members, so the loop body reaches them
            ' through a pair of local delegates rather than one handle
            ' variable.
            Dim writeSlice As Action(Of Byte(), Integer, Integer)
            Dim endSession As Action
            If encrypt Then
                writeSlice = Sub(b As Byte(), o As Integer, n As Integer) enc.Write(b, o, n)
                endSession = Sub() enc.End()
            Else
                writeSlice = Sub(b As Byte(), o As Integer, n As Integer) dec.Write(b, o, n)
                endSession = Sub() dec.End()
            End If

            Dim off As Integer = 0
            Do While off < srcLen
                Dim n As Integer = Math.Min(PumpSlice, srcLen - off)
                Try
                    writeSlice(src, off, n)
                Catch ex As Exception
                    failedCall = "StreamWrite"
                    Return ex
                End Try

                Do
                    Dim finished As Boolean = False
                    Dim m As Integer
                    Try
                        m = If(encrypt, enc.Read(scratch, finished), dec.Read(scratch, finished))
                    Catch ex As Exception
                        failedCall = "StreamRead"
                        Return ex
                    End Try
                    If m = 0 Then Exit Do
                    acc.Write(scratch, 0, m)
                Loop

                off += n
            Loop

            Try
                endSession()
            Catch ex As Exception
                failedCall = "StreamEnd"
                Return ex
            End Try

            Do
                Dim finished As Boolean = False
                Dim m As Integer
                Try
                    m = If(encrypt, enc.Read(scratch, finished), dec.Read(scratch, finished))
                Catch ex As Exception
                    failedCall = "StreamRead"
                    Return ex
                End Try
                acc.Write(scratch, 0, m)
                If finished Then Exit Do
            Loop

            Return Nothing
        Finally
            If enc IsNot Nothing Then enc.Dispose()
            If dec IsNot Nothing Then dec.Dispose()
        End Try
    End Function

    ''' <summary>First offset at which a and b differ; the shorter length
    ''' when one is a prefix of the other.</summary>
    Private Function FirstDifference(a As Byte(), aLen As Integer, b As Byte(), bLen As Integer) As Integer
        Dim n As Integer = Math.Min(aLen, bLen)
        Dim i As Integer = 0
        Do While i < n AndAlso a(i) = b(i)
            i += 1
        Loop
        Return i
    End Function

    ''' <summary>Up to 16 bytes of buf from off as lowercase hex, or "-"
    ''' when buf has no bytes there.</summary>
    Private Function HexWindow(buf As Byte(), len As Integer, off As Integer) As String
        If off >= len Then Return "-"
        Return Convert.ToHexStringLower(buf, off, Math.Min(16, len - off))
    End Function

    ''' <summary>Records a worker error for a failed cipher call.</summary>
    Private Sub CipherFail(r As RunState, id As Integer, iter As Long, shape As Shape,
                           direction As String, what As String, ex As Exception)
        Dim head As String = "g" & id.ToString(Inv) & " iter " & Dx(iter) &
                             " shape=" & ShapeName(shape) & ": " & direction
        If what Is Nothing Then
            FailWorker(r, id, head & ": " & Detail(ex))
        Else
            FailWorker(r, id, head & ": " & what & ": " & Detail(ex))
        End If
    End Sub

    ''' <summary>The body of one iteration that runs under the read lock:
    ''' pick the surface, encrypt, decrypt, compare, bump the
    ''' counters.</summary>
    Private Function IterateLocked(r As RunState, w As WorkerState, iter As Long) As Boolean
        Dim c As Counters = r.Workers(w.Id)
        r.PipesLock.EnterReadLock()
        Try
            ' Shape dispatch. message is one whole-buffer call on the
            ' Single Message Pipeline; stream_one_shot is one whole-buffer
            ' call on the streaming Pipeline (the C ABI's
            ' ITB_Triple_EncryptStream, which routes to the same
            ' whole-buffer stream entry the Go harness calls by name);
            ' stream opens a session on the same streaming Pipeline and
            ' drives the chunk loop from here. Under both the three rotate
            ' by iteration number so the session path and the whole-buffer
            ' path alternate on one handle inside every worker — the
            ' cross-path state-reuse hazard this harness exists to catch.
            Dim shape As Shape = r.Cfg.Shape
            If shape = Shape.BothShape Then
                Select Case iter Mod 3
                    Case 0 : shape = Shape.StreamShape
                    Case 1 : shape = Shape.MessageShape
                    Case Else : shape = Shape.StreamOneShotShape
                End Select
            End If

            ' .NET-specific. The message and one-shot entries return a
            ' fresh array per call that the collector reclaims at the end
            ' of the iteration; the pump accumulators are the worker's own
            ' and are reused. got / gotLen hold the round-trip output for
            ' either posture, so one comparison below serves both.
            Dim got As Byte()
            Dim gotLen As Integer
            Dim t0 As Long

            If shape = Shape.StreamShape Then
                Dim pipe As Pipeline = r.Pipes.StreamPipe
                Dim failedCall As String = Nothing
                t0 = Stopwatch.GetTimestamp()
                Dim ex As Exception = Pump(pipe, True, w.Plaintext, w.Plaintext.Length,
                                           w.Wire, w.Scratch, failedCall)
                If ex IsNot Nothing Then
                    CipherFail(r, w.Id, iter, shape, "encrypt", failedCall, ex)
                    Return False
                End If
                Interlocked.Add(c.NanosEnc, ElapsedNs(t0))

                t0 = Stopwatch.GetTimestamp()
                ex = Pump(pipe, False, w.Wire.GetBuffer(), CInt(w.Wire.Length),
                          w.Plain, w.Scratch, failedCall)
                If ex IsNot Nothing Then
                    CipherFail(r, w.Id, iter, shape, "decrypt", failedCall, ex)
                    Return False
                End If
                Interlocked.Add(c.NanosDec, ElapsedNs(t0))
                got = w.Plain.GetBuffer()
                gotLen = CInt(w.Plain.Length)
            Else
                Dim pipe As Pipeline = If(shape = Shape.MessageShape, r.Pipes.MsgPipe, r.Pipes.StreamPipe)
                Dim wire As Byte()
                t0 = Stopwatch.GetTimestamp()
                Try
                    wire = If(shape = Shape.MessageShape,
                              pipe.EncryptMessage(w.Plaintext),
                              pipe.EncryptStreamOneShot(w.Plaintext))
                Catch ex As Exception
                    CipherFail(r, w.Id, iter, shape, "encrypt", Nothing, ex)
                    Return False
                End Try
                Interlocked.Add(c.NanosEnc, ElapsedNs(t0))

                t0 = Stopwatch.GetTimestamp()
                Try
                    got = If(shape = Shape.MessageShape,
                             pipe.DecryptMessage(wire),
                             pipe.DecryptStreamOneShot(wire))
                Catch ex As Exception
                    CipherFail(r, w.Id, iter, shape, "decrypt", Nothing, ex)
                    Return False
                End Try
                Interlocked.Add(c.NanosDec, ElapsedNs(t0))
                gotLen = got.Length
            End If

            ' Failure model. A cipher call that returns a non-OK status is
            ' a worker error: it is recorded, the run is asked to stop,
            ' the other workers finish their in-flight iteration, and the
            ' error is listed in the summary with the FAIL verdict. A
            ' round-trip that returns OK with different bytes is a data
            ' mismatch: the process terminates here, without summary or
            ' cleanup, because the Pipeline state that produced the wrong
            ' bytes is the evidence and nothing that runs afterwards may
            ' touch it. .NET-specific: Environment.Exit is the exit that
            ' leaves handle finalizers unrun, which is the point — a
            ' finalizer-driven free would release the very state the
            ' operator is meant to inspect.
            ' VB-specific. The language has no span type, so the
            ' comparison is the same single scan the mismatch report
            ' needs: equal lengths plus a first difference at the end.
            Dim want As Byte() = w.Plaintext
            Dim off As Integer = FirstDifference(want, want.Length, got, gotLen)
            If gotLen <> want.Length OrElse off <> want.Length Then
                Console.Error.WriteLine(
                    "loop: DATA MISMATCH g" & w.Id.ToString(Inv) & " iter " & Dx(iter) &
                    " shape=" & ShapeName(shape) & ": want " & want.Length.ToString(Inv) &
                    " bytes, got " & gotLen.ToString(Inv) &
                    " bytes, first difference at offset " & off.ToString(Inv) &
                    ": want " & HexWindow(want, want.Length, off) &
                    " got " & HexWindow(got, gotLen, off))
                Console.Error.Flush()
                Console.Out.Flush()
                Environment.Exit(3)
            End If

            Interlocked.Increment(c.Iters)
            Interlocked.Add(c.BytesEnc, CLng(want.Length))
            Interlocked.Add(c.BytesDec, CLng(gotLen))
            Return True
        Finally
            r.PipesLock.ExitReadLock()
        End Try
    End Function

    ''' <summary>One iteration. In order: refill the plaintext under
    ''' rotating mode; take the read lock; pick the surface; encrypt
    ''' (timed); decrypt (timed); compare the round-trip with the
    ''' plaintext; bump the counters; release the lock. The whole
    ''' round-trip runs under the read lock so handle-mutating
    ''' maintenance (rekey, blob reopen) never lands between an encrypt
    ''' and its matching decrypt — maintenance runs after this returns,
    ''' from the worker loop. False after recording a worker
    ''' error.</summary>
    Private Function Iterate(r As RunState, w As WorkerState, iter As Long) As Boolean
        If w.Mode = PayloadMode.Rotating AndAlso
           Not FillPayload(PayloadMode.Rotating, w.Seeded, w.Rng, w.Plaintext) Then
            FailWorker(r, w.Id, "g" & w.Id.ToString(Inv) & " iter " & Dx(iter) &
                                ": payload refill: csprng")
            Return False
        End If
        Return IterateLocked(r, w, iter)
    End Function

    ''' <summary>Marks this worker returned; the last one to return
    ''' stamps the finish instant and wakes main.</summary>
    Private Sub MarkDone(r As RunState)
        SyncLock r.DoneLock
            r.Active -= 1
            If r.Active = 0 Then
                r.FinishTimestamp = Stopwatch.GetTimestamp()
                Monitor.Pulse(r.DoneLock)
            End If
        End SyncLock
    End Sub

    ''' <summary>The worker thread body: one warmup iteration, the warmup
    ''' barrier, then the main loop until a stop is requested or the
    ''' fixed per-worker iteration budget (warmup included) is spent. A
    ''' failing warmup still passes both barriers so the launcher never
    ''' waits on a worker that has already given up.</summary>
    Friend Sub RunWorker(r As RunState, w As WorkerState)
        ' Warmup iteration — counted in the totals; its completion feeds
        ' the post-warmup baselines.
        Dim ok As Boolean = Iterate(r, w, 0)
        r.WarmupDone.SignalAndWait()
        r.ReleaseGate.SignalAndWait()
        If Not ok Then
            MarkDone(r)
            Return
        End If

        Dim iter As Long = 1
        Do
            If r.Cfg.Iterations > 0 AndAlso iter >= r.Cfg.Iterations Then Exit Do
            If r.StopRequested Then Exit Do
            If Not Iterate(r, w, iter) Then Exit Do
            If Not Maintenance(r, w.Id, iter) Then Exit Do
            iter += 1
        Loop
        MarkDone(r)
    End Sub
End Module
