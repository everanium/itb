' Query-string rendering of the Opts builder (no FFI involved). The
' rendering itself lives in the C# layer; the internal relay
' Itb.VisualBasicInterop.RenderOpts exposes it here so the wrapped
' builder's pass-through is verified end to end.

Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class OptsTests

    Private Shared Function Render(opts As Opts) As String
        Return Global.Itb.VisualBasicInterop.RenderOpts(opts.Inner)
    End Function

    <Fact>
    Public Sub TypedSettersRenderExpectedKeys()
        Dim opts As Opts = New Opts().
            WithPermMaster(New Byte() {&HAB, &H1}).
            WithWrapMaster(New Byte() {&HCD, &HEF}).
            WithParallax(True).
            WithWrapper(False).
            WithMaxWorkers(4).
            WithNonceBits(512).
            WithBarrierFill(4).
            WithChunkSize(4096).
            WithKeyBits(1024).
            WithParallaxSegmentSize(65536).
            WithMacName("hmac-blake3").
            WithInnerHash("areion512").
            WithOuterCipher("chacha20").
            WithParallaxPalette("aescmac", "chacha20", "blake3")
        Assert.Equal(
            "pm=ab01&wm=cdef&withParallax=true&withWrapper=false&" &
            "maxWorkers=4&nonceBits=512&barrierFill=4&chunkSize=4096&" &
            "keyBits=1024&parallaxSegmentSize=65536&macName=hmac-blake3&" &
            "innerHash=areion512&outerCipher=chacha20&" &
            "parallaxPalette=aescmac,chacha20,blake3",
            Render(opts))
    End Sub

    <Fact>
    Public Sub RawEscapeHatchAndEncoding()
        Assert.Equal("mode=a%20b%26c%3Dd%25", Render(New Opts().WithRaw("mode", "a b&c=d%")))
    End Sub

    <Fact>
    Public Sub EmptyBuilderRendersEmptyQuery()
        Assert.Equal(String.Empty, Render(New Opts()))
    End Sub
End Class
