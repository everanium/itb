' Incremental stream sessions over an open Pipeline.
'
' A session is a dumb byte pump: EncryptStream takes plaintext in
' through Write and yields wire through Read / CopyTo; DecryptStream
' is the mirror (wire in, plaintext out). All chunking, MAC,
' envelope, and wire-format decisions stay inside libitb. Disposing
' a session cancels it and frees the Go-side state; the session
' keeps a reference to the parent Pipeline (both the VB wrapper and,
' inside the C# layer, the wrapped C# Pipeline), so the pipeline
' stays reachable while a session on it is live.

''' <summary>
''' Incremental encrypt session: plaintext in through
''' <see cref="Write"/>, wire out through <see cref="Read"/> /
''' <see cref="CopyTo"/>. Disposing cancels the session and frees
''' the Go-side state.
''' </summary>
Public NotInheritable Class EncryptStream
    Implements IDisposable

    ' Keeps the parent Pipeline reachable while the session is live.
    Private ReadOnly _parent As Pipeline
    Private ReadOnly _inner As Global.Itb.EncryptStream

    Friend Sub New(parent As Pipeline, inner As Global.Itb.EncryptStream)
        _parent = parent
        _inner = inner
    End Sub

    ''' <summary>The parent Pipeline this session runs against.</summary>
    Public ReadOnly Property Parent As Pipeline
        Get
            Return _parent
        End Get
    End Property

    ''' <summary>Feeds bytes into the session. Blocks until the cipher
    ''' chain accepts them; errors are sticky.</summary>
    Public Sub Write(src As Byte())
        Guarded(Sub() _inner.Write(src))
    End Sub

    ''' <summary>Feeds <paramref name="count"/> bytes starting at
    ''' <paramref name="offset"/> into the session.</summary>
    Public Sub Write(src As Byte(), offset As Integer, count As Integer)
        Guarded(Sub() _inner.Write(src.AsSpan(offset, count)))
    End Sub

    ''' <summary>Signals end-of-input. Idempotent; <see cref="Write"/>
    ''' after End fails with <see cref="Status.BadInput"/>.</summary>
    Public Sub [End]()
        Guarded(Sub() _inner.End())
    End Sub

    ''' <summary>
    ''' Drains up to <paramref name="dst"/>.Length produced bytes;
    ''' returns the count read and sets <paramref name="finished"/>
    ''' when the session output is complete. Partial drains are
    ''' normal. After End, an empty-spool read blocks until the
    ''' terminal bytes arrive or the session errors.
    ''' </summary>
    Public Function Read(dst As Byte(), ByRef finished As Boolean) As Integer
        Try
            Return _inner.Read(dst, finished)
        Catch ex As Global.Itb.ItbException
            Throw Translate(ex)
        End Try
    End Function

    ''' <summary>Calls <see cref="[End]"/> (if not yet called) and
    ''' writes every remaining output byte to
    ''' <paramref name="destination"/>.</summary>
    Public Sub CopyTo(destination As IO.Stream)
        Guarded(Sub() _inner.CopyTo(destination))
    End Sub

    Public Sub Dispose() Implements IDisposable.Dispose
        _inner.Dispose()
    End Sub
End Class

''' <summary>
''' Incremental decrypt session: wire in through <see cref="Write"/>,
''' plaintext out through <see cref="Read"/> / <see cref="CopyTo"/>.
''' Disposing cancels the session and frees the Go-side state.
''' </summary>
Public NotInheritable Class DecryptStream
    Implements IDisposable

    ' Keeps the parent Pipeline reachable while the session is live.
    Private ReadOnly _parent As Pipeline
    Private ReadOnly _inner As Global.Itb.DecryptStream

    Friend Sub New(parent As Pipeline, inner As Global.Itb.DecryptStream)
        _parent = parent
        _inner = inner
    End Sub

    ''' <summary>The parent Pipeline this session runs against.</summary>
    Public ReadOnly Property Parent As Pipeline
        Get
            Return _parent
        End Get
    End Property

    ''' <summary>Feeds bytes into the session. Blocks until the cipher
    ''' chain accepts them; errors are sticky.</summary>
    Public Sub Write(src As Byte())
        Guarded(Sub() _inner.Write(src))
    End Sub

    ''' <summary>Feeds <paramref name="count"/> bytes starting at
    ''' <paramref name="offset"/> into the session.</summary>
    Public Sub Write(src As Byte(), offset As Integer, count As Integer)
        Guarded(Sub() _inner.Write(src.AsSpan(offset, count)))
    End Sub

    ''' <summary>Signals end-of-input. Idempotent; <see cref="Write"/>
    ''' after End fails with <see cref="Status.BadInput"/>.</summary>
    Public Sub [End]()
        Guarded(Sub() _inner.End())
    End Sub

    ''' <summary>
    ''' Drains up to <paramref name="dst"/>.Length produced bytes;
    ''' returns the count read and sets <paramref name="finished"/>
    ''' when the session output is complete. Partial drains are
    ''' normal. After End, an empty-spool read blocks until the
    ''' terminal bytes arrive or the session errors.
    ''' </summary>
    Public Function Read(dst As Byte(), ByRef finished As Boolean) As Integer
        Try
            Return _inner.Read(dst, finished)
        Catch ex As Global.Itb.ItbException
            Throw Translate(ex)
        End Try
    End Function

    ''' <summary>Calls <see cref="[End]"/> (if not yet called) and
    ''' writes every remaining output byte to
    ''' <paramref name="destination"/>.</summary>
    Public Sub CopyTo(destination As IO.Stream)
        Guarded(Sub() _inner.CopyTo(destination))
    End Sub

    Public Sub Dispose() Implements IDisposable.Dispose
        _inner.Dispose()
    End Sub
End Class
