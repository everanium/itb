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
''' A Triple Pipeline session.
'''
''' <see cref="Save"/> exports the self-describing session blob the
''' receiver feeds to <see cref="Load"/> / <see cref="LoadF"/>;
''' <see cref="Rekey"/> refreshes it. Disposing the Pipeline frees
''' the handle (libitb zeroes key material internally); an
''' undisposed Pipeline is reclaimed by the C# layer's SafeHandle
''' finalizer. Profile records (<see cref="Inspect"/> /
''' <see cref="Lookup"/> results, <see cref="Register"/> input) are
''' the C# layer's <see cref="Global.Itb.Profile"/> type.
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

    ''' <summary>Constructs a fresh Pipeline against the named
    ''' profile. The session blob is available through
    ''' <see cref="Save"/>.</summary>
    Public Shared Function Init(profile As String, Optional opts As Opts = Nothing) As Pipeline
        Return Guarded(Function() New Pipeline(Global.Itb.Pipeline.Init(profile, InnerOpts(opts))))
    End Function

    ''' <summary>
    ''' Reconstructs a Pipeline from a blob produced by
    ''' <see cref="Save"/> or <see cref="Rekey"/>. The blob's embedded
    ''' profile record is the sole structural source. Omitting
    ''' <paramref name="permMaster"/> / <paramref name="wrapMaster"/>
    ''' uses the blob-embedded masters; supplying both (non-empty)
    ''' overrides them. Supplying only one raises
    ''' <see cref="ArgumentException"/>.
    ''' </summary>
    Public Shared Function Load(
            blob As Byte(),
            Optional permMaster As Byte() = Nothing,
            Optional wrapMaster As Byte() = Nothing) As Pipeline
        Return Guarded(Function() New Pipeline(Global.Itb.Pipeline.Load(
            blob, permMaster, wrapMaster)))
    End Function

    ''' <summary><see cref="Load"/> for a blob stored in a file; the
    ''' file is read inside the library. Same masters
    ''' semantics.</summary>
    Public Shared Function LoadF(
            path As String,
            Optional permMaster As Byte() = Nothing,
            Optional wrapMaster As Byte() = Nothing) As Pipeline
        Return Guarded(Function() New Pipeline(Global.Itb.Pipeline.LoadF(
            path, permMaster, wrapMaster)))
    End Function

    ''' <summary>Decodes the blob's embedded profile record without
    ''' opening a Pipeline. No registry read, no primitive
    ''' probe.</summary>
    Public Shared Function Inspect(blob As Byte()) As Global.Itb.Profile
        Return Guarded(Function() Global.Itb.Pipeline.Inspect(blob))
    End Function

    ''' <summary>
    ''' Registers <paramref name="profile"/> under
    ''' <paramref name="name"/> so subsequent <see cref="Init"/> /
    ''' <see cref="Lookup"/> calls resolve it. Every field rule is
    ''' validated by Go; a duplicate name fails with
    ''' <see cref="Status.ProfileExists"/>.
    ''' </summary>
    Public Shared Sub Register(name As String, profile As Global.Itb.Profile)
        Guarded(Sub() Global.Itb.Pipeline.Register(name, profile))
    End Sub

    ''' <summary>Looks up a registered profile (shipped or
    ''' <see cref="Register"/>ed) by name; an unknown name fails with
    ''' <see cref="Status.UnknownProfile"/>.</summary>
    Public Shared Function Lookup(name As String) As Global.Itb.Profile
        Return Guarded(Function() Global.Itb.Pipeline.Lookup(name))
    End Function

    ''' <summary>The sorted names of every registered
    ''' profile.</summary>
    Public Shared Function Profiles() As String()
        Return Guarded(Function() Global.Itb.Pipeline.Profiles())
    End Function

    ''' <summary>The current self-describing session blob: the bytes
    ''' <see cref="Init"/> produced, the bytes <see cref="Load"/>
    ''' re-marshalled, or the bytes of the latest
    ''' <see cref="Rekey"/>.</summary>
    Public Function Save() As Byte()
        Return Guarded(Function() _inner.Save())
    End Function

    ''' <summary>Writes <see cref="Save"/> to <paramref name="path"/>
    ''' inside the library with mode 0600; the containing directory
    ''' must exist.</summary>
    Public Sub SaveF(path As String)
        Guarded(Sub() _inner.SaveF(path))
    End Sub

    ''' <summary>Sets the worker cap for every subsequent cipher call.
    ''' <paramref name="n"/> is clamped, never rejected: n &lt;= 0
    ''' selects auto (CPU count), n &gt; 256 is treated as 256. Only
    ''' the handle statuses raise.</summary>
    Public Sub MaxWorkers(n As Integer)
        Guarded(Sub() _inner.MaxWorkers(n))
    End Sub

    ''' <summary>
    ''' Rotates the parallax + wrapper masters and returns the fresh
    ''' session blob (also available through <see cref="Save"/>).
    ''' Must not run concurrently with cipher calls or open stream
    ''' sessions on the same Pipeline.
    ''' </summary>
    Public Function Rekey(permMaster As Byte(), wrapMaster As Byte()) As Byte()
        Return Guarded(Function() _inner.Rekey(permMaster, wrapMaster))
    End Function

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
