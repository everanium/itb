' Init -> blob -> Open -> EncryptMessage -> DecryptMessage round trip.

Imports System.Text
Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class SmokeTests

    <Fact>
    Public Sub SmokeRoundTrip()
        Using sender As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1")
            Assert.NotEmpty(sender.Blob)

            Using receiver As Pipeline = Pipeline.Open("singlemsg-triple-mac-v1", sender.Blob)
                Dim plain As Byte() = Encoding.UTF8.GetBytes("smoke round-trip payload")
                Dim wire As Byte() = sender.EncryptMessage(plain)
                Assert.NotEqual(Of Byte)(plain, wire)

                Dim back As Byte() = receiver.DecryptMessage(wire)
                Assert.Equal(Of Byte)(plain, back)
            End Using
        End Using
    End Sub
End Class
