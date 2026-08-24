' Single Message round trip across every shipped cipher profile at
' small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
' has no cipher surface and is exercised in ErrorTests instead.

Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class MessageTests

    ''' <summary>Deterministic non-trivial payload (xorshift
    ''' fill).</summary>
    Friend Shared Function Payload(n As Integer, seed As ULong) As Byte()
        Dim buf(n - 1) As Byte
        Dim x As ULong = seed Or 1UL
        For i As Integer = 0 To n - 1
            x = x Xor (x << 13)
            x = x Xor (x >> 7)
            x = x Xor (x << 17)
            buf(i) = CByte(x And &HFFUL)
        Next
        Return buf
    End Function

    <Fact>
    Public Sub MessageRoundTripEveryProfile()
        Dim profiles As String() = {
            "streaming-aead-triple-mac-v1",
            "streaming-noaead-triple-v1",
            "singlemsg-triple-mac-v1",
            "singlemsg-triple-nomac-v1",
            "streaming-aead-triple-mac-mixed-v1",
            "streaming-noaead-triple-mixed-v1",
            "singlemsg-triple-mac-mixed-v1",
            "singlemsg-triple-nomac-mixed-v1"
        }
        For Each profile As String In profiles
            Using sender As Pipeline = Pipeline.Init(profile)
                Using receiver As Pipeline = Pipeline.Open(profile, sender.Blob)
                    For Each size As Integer In {4 * 1024, 256 * 1024}
                        Dim plain As Byte() = Payload(size, CULng(size))
                        Dim wire As Byte() = sender.EncryptMessage(plain)
                        Dim back As Byte() = receiver.DecryptMessage(wire)
                        Assert.Equal(Of Byte)(plain, back)
                    Next
                End Using
            End Using
        Next
    End Sub
End Class
