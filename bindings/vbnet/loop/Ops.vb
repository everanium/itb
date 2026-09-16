' The maintenance operations that mutate a live Pipeline handle between
' iterations: master rotation (--rekey-every) and blob reopen
' (--blob-cycle-every).

Imports Everanium.Itb3.VisualBasic

Friend Module Ops

    ''' <summary>Byte length of each fresh master drawn for a rotation.
    ''' Matches the size Init auto-generates for both the parallax and
    ''' the wrapper master.</summary>
    Private Const RekeyMasterSize As Integer = 32

    ''' <summary>
    ''' Master rotation. Rotates the parallax + wrapper masters on every
    ''' active Pipeline under the write lock and retains the refreshed
    ''' blob for subsequent blob reopens. Masters are drawn fresh from
    ''' the OS CSPRNG on every rotation regardless of --seed (master
    ''' rotation is pipeline keying, not plaintext content); a disabled
    ''' layer passes no bytes, which Rekey ignores. The eight inner seeds
    ''' and the MAC key are untouched by design — Rekey targets only the
    ''' two outer-layer master secrets.
    ''' </summary>
    Private Function RekeyPipes(r As RunState, id As Integer, iter As Long) As Boolean
        Dim perm As Byte() = Array.Empty(Of Byte)()
        Dim wrap As Byte() = Array.Empty(Of Byte)()

        If r.Cfg.Parallax Then
            perm = New Byte(RekeyMasterSize - 1) {}
            If Not FillRandom(perm) Then
                FailWorker(r, id, "g" & id.ToString(Inv) & " iter " & Dx(iter) &
                                  ": csprng: parallax master")
                Return False
            End If
        End If
        If r.Cfg.Wrapper Then
            wrap = New Byte(RekeyMasterSize - 1) {}
            If Not FillRandom(wrap) Then
                FailWorker(r, id, "g" & id.ToString(Inv) & " iter " & Dx(iter) &
                                  ": csprng: wrapper master")
                Return False
            End If
        End If

        Dim failure As String = Nothing
        r.PipesLock.EnterWriteLock()
        Try
            If r.Pipes.StreamPipe IsNot Nothing Then
                Try
                    r.Pipes.StreamBlob = r.Pipes.StreamPipe.Rekey(perm, wrap)
                Catch ex As Exception
                    failure = "g" & id.ToString(Inv) & " iter " & Dx(iter) &
                              ": Rekey(" & r.StreamProfile & "): " & Detail(ex)
                End Try
            End If
            If failure Is Nothing AndAlso r.Pipes.MsgPipe IsNot Nothing Then
                Try
                    r.Pipes.MsgBlob = r.Pipes.MsgPipe.Rekey(perm, wrap)
                Catch ex As Exception
                    failure = "g" & id.ToString(Inv) & " iter " & Dx(iter) &
                              ": Rekey(" & r.MsgProfile & "): " & Detail(ex)
                End Try
            End If
        Finally
            r.PipesLock.ExitWriteLock()
        End Try

        If failure IsNot Nothing Then
            FailWorker(r, id, failure)
            Return False
        End If

        Dim n As Long
        SyncLock r.CounterLock
            r.Rekeys += 1
            n = r.Rekeys
        End SyncLock
        LogLine("rekey: g" & id.ToString(Inv) & " iter " & Dx(iter) &
                " rotated parallax + wrapper masters (rekey #" & Dx(n) & ")")
        Return True
    End Function

    ''' <summary>
    ''' Blob reopen. Reopens every active Pipeline from its retained blob
    ''' under the write lock: a fresh handle is loaded from the blob, the
    ''' running handle is freed, and the fresh one is swapped in, so
    ''' every later iteration round-trips through seeds and masters that
    ''' survived a blob crossing. The input is the blob Init or the
    ''' latest Rekey handed out, not a fresh Save: that is what a
    ''' receiver holds, and reopening from it proves the handed-out bytes
    ''' rather than the live state. The blob carries the Pipeline's full
    ''' shape, so no override reaches the reopen. On a Load failure the
    ''' running handle stays and the failure aborts the run.
    ''' </summary>
    Private Function BlobCyclePipes(r As RunState, id As Integer, iter As Long) As Boolean
        Dim failure As String = Nothing
        r.PipesLock.EnterWriteLock()
        Try
            If r.Pipes.StreamPipe IsNot Nothing Then
                Try
                    Dim fresh As Pipeline = Pipeline.Load(r.Pipes.StreamBlob)
                    r.Pipes.StreamPipe.Dispose()
                    r.Pipes.StreamPipe = fresh
                Catch ex As Exception
                    failure = "g" & id.ToString(Inv) & " iter " & Dx(iter) &
                              ": Load(" & r.StreamProfile & "): " & Detail(ex)
                End Try
            End If
            If failure Is Nothing AndAlso r.Pipes.MsgPipe IsNot Nothing Then
                Try
                    Dim fresh As Pipeline = Pipeline.Load(r.Pipes.MsgBlob)
                    r.Pipes.MsgPipe.Dispose()
                    r.Pipes.MsgPipe = fresh
                Catch ex As Exception
                    failure = "g" & id.ToString(Inv) & " iter " & Dx(iter) &
                              ": Load(" & r.MsgProfile & "): " & Detail(ex)
                End Try
            End If
        Finally
            r.PipesLock.ExitWriteLock()
        End Try

        If failure IsNot Nothing Then
            FailWorker(r, id, failure)
            Return False
        End If

        Dim n As Long
        SyncLock r.CounterLock
            r.BlobCycles += 1
            n = r.BlobCycles
        End SyncLock
        LogLine("blob-cycle: g" & id.ToString(Inv) & " iter " & Dx(iter) &
                " reopened from session blob (cycle #" & Dx(n) & ")")
        Return True
    End Function

    ''' <summary>
    ''' Handle mutation. Runs the periodic Pipeline-mutating operations
    ''' after a completed iteration: master rotation (--rekey-every) and
    ''' blob reopen (--blob-cycle-every). Both intervals count per-worker
    ''' iterations; the warmup iteration (iter 0) never triggers because
    ''' the worker loop calls this for iter >= 1 only. Rekey rewrites the
    ''' outer-layer keying of a live handle and a blob reopen replaces
    ''' the handle outright; each takes the write lock, so in-flight
    ''' cipher calls on other workers drain before anything changes and
    ''' no encrypt is separated from its decrypt by either. False after
    ''' recording the worker error.
    ''' </summary>
    Friend Function Maintenance(r As RunState, id As Integer, iter As Long) As Boolean
        Dim cfg As Config = r.Cfg
        If cfg.RekeyEvery > 0 AndAlso iter Mod cfg.RekeyEvery = 0 Then
            If Not RekeyPipes(r, id, iter) Then Return False
        End If
        If cfg.BlobCycleEvery > 0 AndAlso iter Mod cfg.BlobCycleEvery = 0 Then
            If Not BlobCyclePipes(r, id, iter) Then Return False
        End If
        Return True
    End Function
End Module
