' Delegating lifetime wrapper around the C# layer's Pipeline.
'
' Every member forwards to the sibling C# binding (bindings/csharp)
' through plain CLR bytecode interop — no FFI layer of its own. The
' C# side carries the P/Invoke surface, the handle lifetime
' (SafeHandle finalizer backstop), the buffer pre-allocation with
' the BufferTooSmall retry-once, and the libitb lookup order; this
' layer re-shapes that surface into idiomatic VB.NET (Using blocks,
' Try ... Catch ex As ItbException, Byte() signatures).

''' <summary>
''' A Triple Pipeline session plus its exported blob bytes.
'''
''' The blob carries the session bundle the receiver feeds to
''' <see cref="Open"/>; <see cref="Rekey"/> refreshes it. Disposing
''' the Pipeline frees the handle (libitb zeroes key material
''' internally); an undisposed Pipeline is reclaimed by the C#
''' layer's SafeHandle finalizer.
'''
''' Streaming-decrypt caveat: chunked Streaming AEAD verifies per
''' chunk, so plaintext of verified chunks is released before a later
''' chunk can fail authentication.
''' </summary>
Public NotInheritable Class Pipeline
    Implements IDisposable

    Private ReadOnly _inner As Global.Itb.Pipeline

    Private Sub New(inner As Global.Itb.Pipeline)
        _inner = inner
    End Sub

    ''' <summary>The wrapped C# Pipeline the stream sessions run
    ''' against.</summary>
    Friend ReadOnly Property Inner As Global.Itb.Pipeline
        Get
            Return _inner
        End Get
    End Property

    ''' <summary>The exported session bundle bytes for the receiver
    ''' side. Each access returns a fresh copy.</summary>
    Public ReadOnly Property Blob As Byte()
        Get
            Return _inner.Blob.ToArray()
        End Get
    End Property

    ''' <summary>Constructs a fresh Pipeline against the named
    ''' profile.</summary>
    Public Shared Function Init(profile As String, Optional opts As Opts = Nothing) As Pipeline
        Return Guarded(Function() New Pipeline(Global.Itb.Pipeline.Init(profile, InnerOpts(opts))))
    End Function

    ''' <summary>
    ''' Reconstructs a Pipeline from a blob produced by
    ''' <see cref="Init"/> or <see cref="Rekey"/>. Omitting
    ''' <paramref name="permMaster"/> / <paramref name="wrapMaster"/>
    ''' uses the blob-embedded masters; supplying both (non-empty)
    ''' overrides them. Supplying only one raises
    ''' <see cref="ArgumentException"/>.
    ''' </summary>
    Public Shared Function Open(
            profile As String, blob As Byte(), Optional opts As Opts = Nothing,
            Optional permMaster As Byte() = Nothing,
            Optional wrapMaster As Byte() = Nothing) As Pipeline
        Return Guarded(Function() New Pipeline(Global.Itb.Pipeline.Open(
            profile, blob, InnerOpts(opts), permMaster, wrapMaster)))
    End Function

    ''' <summary>
    ''' Registers a user-defined Triple profile under
    ''' <paramref name="name"/> so subsequent <see cref="Init"/> /
    ''' <see cref="Open"/> calls resolve it. The opts follow the
    ''' register-profile grammar validated by Go — build them with
    ''' <see cref="Opts.WithRaw"/> plus the typed setters where key
    ''' names coincide. A duplicate name fails with
    ''' <see cref="Status.ProfileExists"/>.
    ''' </summary>
    Public Shared Sub RegisterProfile(name As String, opts As Opts)
        Guarded(Sub() Global.Itb.Pipeline.RegisterProfile(name, opts.Inner))
    End Sub

    ''' <summary>
    ''' Rotates the parallax + wrapper masters and refreshes
    ''' <see cref="Blob"/>. Must not run concurrently with cipher
    ''' calls or open stream sessions on the same Pipeline.
    ''' </summary>
    Public Sub Rekey(permMaster As Byte(), wrapMaster As Byte())
        Guarded(Sub() _inner.Rekey(permMaster, wrapMaster))
    End Sub

    ''' <summary>
    ''' Zeroes the Pipeline's key material and marks it closed.
    ''' Idempotent; subsequent cipher calls fail with
    ''' <see cref="Status.TripleClosed"/>. The handle itself is
    ''' released by <see cref="Dispose"/>.
    ''' </summary>
    Public Sub Close()
        Guarded(Sub() _inner.Close())
    End Sub

    ''' <summary>Single Message encrypt: one call, one self-contained
    ''' wire.</summary>
    Public Function EncryptMessage(plaintext As Byte()) As Byte()
        Return Guarded(Function() _inner.EncryptMessage(plaintext))
    End Function

    ''' <summary>Receive-side counterpart of
    ''' <see cref="EncryptMessage"/>.</summary>
    Public Function DecryptMessage(wire As Byte()) As Byte()
        Return Guarded(Function() _inner.DecryptMessage(wire))
    End Function

    ''' <summary>
    ''' One-shot stream encrypt for callers holding the whole
    ''' plaintext in memory. For bounded-memory streaming use
    ''' <see cref="BeginEncryptStream"/> /
    ''' <see cref="EncryptStreamPump"/>.
    ''' </summary>
    Public Function EncryptStreamOneShot(plaintext As Byte()) As Byte()
        Return Guarded(Function() _inner.EncryptStreamOneShot(plaintext))
    End Function

    ''' <summary>Receive-side counterpart of
    ''' <see cref="EncryptStreamOneShot"/>.</summary>
    Public Function DecryptStreamOneShot(wire As Byte()) As Byte()
        Return Guarded(Function() _inner.DecryptStreamOneShot(wire))
    End Function

    ''' <summary>Opens an incremental encrypt session (plaintext in,
    ''' wire out).</summary>
    Public Function BeginEncryptStream() As EncryptStream
        Return New EncryptStream(Me, Guarded(Function() _inner.BeginEncryptStream()))
    End Function

    ''' <summary>Opens an incremental decrypt session (wire in,
    ''' plaintext out).</summary>
    Public Function BeginDecryptStream() As DecryptStream
        Return New DecryptStream(Me, Guarded(Function() _inner.BeginDecryptStream()))
    End Function

    ''' <summary>
    ''' Pumps <paramref name="source"/> through an encrypt session
    ''' into <paramref name="destination"/> with bounded memory: feed
    ''' a block, drain available wire, repeat; end + final drain on
    ''' source EOF. The session is freed on return.
    ''' </summary>
    Public Sub EncryptStreamPump(source As IO.Stream, destination As IO.Stream)
        Guarded(Sub() _inner.EncryptStreamPump(source, destination))
    End Sub

    ''' <summary>Receive-side counterpart of
    ''' <see cref="EncryptStreamPump"/>.</summary>
    Public Sub DecryptStreamPump(source As IO.Stream, destination As IO.Stream)
        Guarded(Sub() _inner.DecryptStreamPump(source, destination))
    End Sub

    Public Sub Dispose() Implements IDisposable.Dispose
        _inner.Dispose()
    End Sub

    Private Shared Function InnerOpts(opts As Opts) As Global.Itb.Opts
        Return If(opts Is Nothing, Nothing, opts.Inner)
    End Function
End Class
