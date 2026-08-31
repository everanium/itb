' Chaining wrapper over the C# layer's URL-query opts builder.
'
' The builder performs no validation — every key and value is
' rendered into a percent-encoded query string and passed through to
' Go verbatim; libitb rejects unknown keys or bad values with a
' diagnostic surfaced via ItbException. Primitive / MAC / cipher /
' palette names are opaque strings.

''' <summary>
''' Builder producing the opts string consumed by
''' <see cref="Pipeline.Init"/>, <see cref="Pipeline.Open"/>, and
''' <see cref="Pipeline.RegisterProfile"/>. Setters chain; an empty
''' builder renders the empty query (pure profile defaults).
''' </summary>
Public NotInheritable Class Opts

    Private ReadOnly _inner As New Global.Itb.Opts()

    ''' <summary>The wrapped C# builder handed to the inner layer's
    ''' entry points.</summary>
    Friend ReadOnly Property Inner As Global.Itb.Opts
        Get
            Return _inner
        End Get
    End Property

    ''' <summary>Hex-encodes the parallax master override
    ''' (<c>pm</c>).</summary>
    Public Function WithPermMaster(master As Byte()) As Opts
        _inner.WithPermMaster(master)
        Return Me
    End Function

    ''' <summary>Hex-encodes the wrapper master override
    ''' (<c>wm</c>).</summary>
    Public Function WithWrapMaster(master As Byte()) As Opts
        _inner.WithWrapMaster(master)
        Return Me
    End Function

    Public Function WithParallax([on] As Boolean) As Opts
        _inner.WithParallax([on])
        Return Me
    End Function

    Public Function WithWrapper([on] As Boolean) As Opts
        _inner.WithWrapper([on])
        Return Me
    End Function

    Public Function WithMaxWorkers(n As Long) As Opts
        _inner.WithMaxWorkers(n)
        Return Me
    End Function

    Public Function WithNonceBits(n As Long) As Opts
        _inner.WithNonceBits(n)
        Return Me
    End Function

    Public Function WithBarrierFill(n As Long) As Opts
        _inner.WithBarrierFill(n)
        Return Me
    End Function

    Public Function WithChunkSize(n As Long) As Opts
        _inner.WithChunkSize(n)
        Return Me
    End Function

    Public Function WithKeyBits(n As Long) As Opts
        _inner.WithKeyBits(n)
        Return Me
    End Function

    Public Function WithParallaxSegmentSize(n As Long) As Opts
        _inner.WithParallaxSegmentSize(n)
        Return Me
    End Function

    Public Function WithMacName(name As String) As Opts
        _inner.WithMacName(name)
        Return Me
    End Function

    Public Function WithInnerHash(name As String) As Opts
        _inner.WithInnerHash(name)
        Return Me
    End Function

    ''' <summary>Comma-joins an 8-slot per-call inner-hash
    ''' constellation into the <c>innerHashes</c> opts key. Parallel
    ''' to the Go-side <c>Opts.MixedHashes [8]string</c> per-call
    ''' override; slot ordering is
    ''' <c>[noise, lock, data1, data2, data3, start1, start2, start3]</c>.
    ''' Fail-fast validation surfaces at Init on the Go side; a
    ''' typo'd slot or width mismatch surfaces with an error naming
    ''' the offending slot. When both this and
    ''' <see cref="WithInnerHash"/> are set, the mixed override wins
    ''' on the Go side.</summary>
    Public Function WithInnerHashes(ParamArray names As String()) As Opts
        _inner.WithInnerHashes(names)
        Return Me
    End Function

    Public Function WithOuterCipher(name As String) As Opts
        _inner.WithOuterCipher(name)
        Return Me
    End Function

    ''' <summary>Comma-joins the palette names
    ''' (<c>parallaxPalette</c>).</summary>
    Public Function WithParallaxPalette(ParamArray names As String()) As Opts
        _inner.WithParallaxPalette(names)
        Return Me
    End Function

    ''' <summary>Escape hatch appending a raw <c>key=value</c> pair.
    ''' Covers every key the Go side accepts, including the
    ''' register-profile grammar (<c>mode</c>, <c>width</c>,
    ''' <c>innerHashes</c>, <c>parallaxOn</c>, <c>wrapperOn</c>, …).
    ''' </summary>
    Public Function WithRaw(key As String, value As String) As Opts
        _inner.WithRaw(key, value)
        Return Me
    End Function
End Class
