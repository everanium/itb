' Error-mapping surface: opaque-string relay, closed Pipeline,
' duplicate profile registration (with an 8-entry mixed
' constellation), unknown lookup, MaxWorkers on a closed handle.
' Every failure surfaces as this binding's own
' ItbException with the numeric status preserved.

Imports System.Text
Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class ErrorTests

    <Fact>
    Public Sub UnknownProfileIsUnknownProfileWithDiagnostic()
        Dim ex As ItbException =
            Assert.Throws(Of ItbException)(Sub() Pipeline.Init("no-such-profile"))
        Assert.Equal(Status.UnknownProfile, ex.Status)
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
    Public Sub RegisterMixedThenDuplicate()
        ' 8-entry width-256 mixed constellation, layers off.
        Dim profile As New Global.Itb.Profile With {
            .Mode = "singlemsg-nomac",
            .Width = 256,
            .Hashes = {"blake3", "blake2s", "areion256", "blake2b256",
                       "chacha20", "blake3", "blake2s", "areion256"},
            .KeyBits = 1024,
            .Parallax = False,
            .Wrapper = False}
        Pipeline.Register("vbnet-binding-test-mixed", profile)

        ' The registered profile round-trips.
        Using sender As Pipeline = Pipeline.Init("vbnet-binding-test-mixed")
            Using receiver As Pipeline = Pipeline.Load(sender.Save())
                Dim plain As Byte() = Encoding.UTF8.GetBytes("custom profile")
                Dim wire As Byte() = sender.EncryptMessage(plain)
                Assert.Equal(Of Byte)(plain, receiver.DecryptMessage(wire))
            End Using
        End Using

        ' Duplicate name is a distinct status.
        Dim ex As ItbException = Assert.Throws(Of ItbException)(
            Sub() Pipeline.Register("vbnet-binding-test-mixed", profile))
        Assert.Equal(Status.ProfileExists, ex.Status)
    End Sub

    <Fact>
    Public Sub LookupUnknownNameIsUnknownProfile()
        Dim ex As ItbException =
            Assert.Throws(Of ItbException)(Sub() Pipeline.Lookup("no-such-profile"))
        Assert.Equal(Status.UnknownProfile, ex.Status)
    End Sub

    <Fact>
    Public Sub MaxWorkersOnClosedPipelineIsTripleClosed()
        Using pipe As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1")
            pipe.Close()
            Dim ex As ItbException =
                Assert.Throws(Of ItbException)(Sub() pipe.MaxWorkers(2))
            Assert.Equal(Status.TripleClosed, ex.Status)
        End Using
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

    <Fact>
    Public Sub PerCallInnerHashesOverrideRoundTrips()
        ' The single-primitive width-512 base profile takes an 8-slot
        ' per-call MixedHashes override (Go-side Opts.MixedHashes,
        ' wired through the innerHashes= opts key). Round-trip proves
        ' the typed helper's comma-join lands in the Go parser
        ' correctly.
        Dim senderOpts As Opts = New Opts().WithInnerHashes(
            "areion512", "blake2b512", "areion512", "blake2b512",
            "areion512", "blake2b512", "areion512", "blake2b512")
        Dim receiverOpts As Opts = New Opts().WithInnerHashes(
            "areion512", "blake2b512", "areion512", "blake2b512",
            "areion512", "blake2b512", "areion512", "blake2b512")
        Using sender As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1", senderOpts)
            Using receiver As Pipeline = Pipeline.Load(sender.Save())
                Dim plain As Byte() = Encoding.UTF8.GetBytes(
                    "per-call inner-hashes override round-trip payload")
                Dim wire As Byte() = sender.EncryptMessage(plain)
                Assert.Equal(Of Byte)(plain, receiver.DecryptMessage(wire))
            End Using
        End Using
    End Sub
End Class
