' Init -> Rekey -> Open receiver with the rotated blob -> round trip.

Imports System.Text
Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class RekeyTests

    <Fact>
    Public Sub RekeyRoundTrip()
        Using sender As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1")
            Dim blobBefore As Byte() = sender.Blob

            Dim perm(31) As Byte
            Array.Fill(perm, CByte(&H11))
            Dim wrap(31) As Byte
            Array.Fill(wrap, CByte(&H22))
            sender.Rekey(perm, wrap)
            Assert.False(sender.Blob.SequenceEqual(blobBefore))

            Using receiver As Pipeline = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob)
                Dim plain As Byte() = Encoding.UTF8.GetBytes("post-rekey payload")
                Dim wire As Byte() = sender.EncryptMessage(plain)
                Assert.Equal(Of Byte)(plain, receiver.DecryptMessage(wire))
            End Using
        End Using
    End Sub
End Class
