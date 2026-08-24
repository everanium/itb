' Error-mapping surface: opaque-string relay, closed Pipeline,
' duplicate profile registration (with an 8-entry innerHashes
' constellation). Every failure surfaces as this binding's own
' ItbException with the numeric status preserved.

Imports System.Text
Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class ErrorTests

    <Fact>
    Public Sub UnknownProfileIsBadInputWithDiagnostic()
        Dim ex As ItbException =
            Assert.Throws(Of ItbException)(Sub() Pipeline.Init("no-such-profile"))
        Assert.Equal(Status.BadInput, ex.Status)
        Assert.False(String.IsNullOrEmpty(ex.Message))
    End Sub

    <Fact>
    Public Sub UnknownOptsKeyIsBadInput()
        ' Typoed key (lowercase s) — Go rejects unknown keys.
        Dim opts As Opts = New Opts().WithRaw("chunksize", "4096")
        Dim ex As ItbException = Assert.Throws(Of ItbException)(
            Sub() Pipeline.Init("singlemsg-triple-mac-v1", opts))
        Assert.Equal(Status.BadInput, ex.Status)
    End Sub

    <Fact>
    Public Sub ClosedPipelineReportsTripleClosed()
        Using pipe As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1")
            pipe.Close()
            pipe.Close() ' idempotent
            Dim ex As ItbException = Assert.Throws(Of ItbException)(
                Sub() pipe.EncryptMessage(Encoding.UTF8.GetBytes("payload")))
            Assert.Equal(Status.TripleClosed, ex.Status)
        End Using
    End Sub

    <Fact>
    Public Sub RegisterProfileMixedThenDuplicate()
        ' 8-entry width-256 innerHashes constellation, layers off.
        Dim opts As Opts = New Opts().
            WithRaw("mode", "singlemsg-nomac").
            WithRaw("width", "256").
            WithRaw(
                "innerHashes",
                "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256").
            WithRaw("keyBits", "1024").
            WithRaw("parallaxOn", "false").
            WithRaw("wrapperOn", "false")
        Pipeline.RegisterProfile("vbnet-binding-test-mixed", opts)

        ' The registered profile round-trips.
        Using sender As Pipeline = Pipeline.Init("vbnet-binding-test-mixed")
            Using receiver As Pipeline = Pipeline.Open("vbnet-binding-test-mixed", sender.Blob)
                Dim plain As Byte() = Encoding.UTF8.GetBytes("custom profile")
                Dim wire As Byte() = sender.EncryptMessage(plain)
                Assert.Equal(Of Byte)(plain, receiver.DecryptMessage(wire))
            End Using
        End Using

        ' Duplicate name is a distinct status.
        Dim ex As ItbException = Assert.Throws(Of ItbException)(
            Sub() Pipeline.RegisterProfile("vbnet-binding-test-mixed", opts))
        Assert.Equal(Status.ProfileExists, ex.Status)
    End Sub

    <Fact>
    Public Sub OpaquePrimitiveNameRelay()
        ' An unknown inner-hash name is relayed to Go and rejected
        ' there — the binding performs no name validation of its own.
        Dim opts As Opts = New Opts().WithInnerHash("no-such-hash")
        Dim ex As ItbException = Assert.Throws(Of ItbException)(
            Sub() Pipeline.Init("singlemsg-triple-mac-v1", opts))
        Assert.NotEqual(Status.Ok, ex.Status)
    End Sub
End Class
