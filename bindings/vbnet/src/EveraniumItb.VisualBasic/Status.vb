' Status codes mirrored from the libitb C ABI
' (cmd/cshared/internal/capi/errors.go; numeric values are stable
' across releases), the exception surface for structured
' Try ... Catch handling, and the internal relay translating the C#
' layer's exception into this binding's own type.

''' <summary>Integer status code carried by every
''' <see cref="ItbException"/>.</summary>
Public Enum Status
    Ok = 0
    BadHash = 1
    BadKeyBits = 2
    BadHandle = 3
    BadInput = 4
    BufferTooSmall = 5
    EncryptFailed = 6
    DecryptFailed = 7
    SeedWidthMix = 8
    BadMac = 9
    MacFailure = 10
    BlobMalformedRecipe = 11
    RecipePrimitiveUnknown = 12
    UnknownProfile = 13
    Reserved14 = 14
    Reserved15 = 15
    Reserved16 = 16
    Reserved17 = 17
    BlobModeMismatch = 19
    BlobMalformed = 20
    BlobVersionTooNew = 21
    BlobTooManyOpts = 22
    StreamTruncated = 23
    StreamAfterFinal = 24
    TripleClosed = 25
    ProfileExists = 26
    Internal = 99
End Enum

''' <summary>
''' Raised when libitb reports a non-OK status. <see cref="Status"/>
''' carries the structural code; <see cref="Exception.Message"/>
''' relays the C# layer's formatted diagnostic (which appends the
''' <c>ITB_LastError</c> text captured immediately after the failing
''' call — process-global last-write-wins, so under concurrent use
''' the message may belong to a different call; the status code is
''' always attributable). The originating C# exception rides on
''' <see cref="Exception.InnerException"/>.
''' </summary>
Public NotInheritable Class ItbException
    Inherits Exception

    Private ReadOnly _status As Status

    ''' <summary>The libitb status code for the failing call.</summary>
    Public ReadOnly Property Status As Status
        Get
            Return _status
        End Get
    End Property

    Friend Sub New(status As Status, inner As Global.Itb.ItbException)
        MyBase.New(inner.Message, inner)
        _status = status
    End Sub
End Class

''' <summary>Translation + guard helpers shared by every delegating
''' member of the binding: a C# <c>Itb.ItbException</c> escaping the
''' inner layer is re-raised as this binding's
''' <see cref="ItbException"/> with the numeric status preserved.
''' </summary>
Friend Module ErrorRelay

    Friend Function Translate(ex As Global.Itb.ItbException) As ItbException
        ' The numeric values are identical on both sides (both mirror
        ' the C ABI); an unlisted code passes through as its raw value.
        Return New ItbException(CType(CInt(ex.Status), Status), ex)
    End Function

    Friend Function Guarded(Of T)(fn As Func(Of T)) As T
        Try
            Return fn()
        Catch ex As Global.Itb.ItbException
            Throw Translate(ex)
        End Try
    End Function

    Friend Sub Guarded(fn As Action)
        Try
            fn()
        Catch ex As Global.Itb.ItbException
            Throw Translate(ex)
        End Try
    End Sub
End Module
