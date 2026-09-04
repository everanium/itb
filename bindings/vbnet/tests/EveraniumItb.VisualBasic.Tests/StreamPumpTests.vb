' Round trip through the stream pumps on a Streaming AEAD profile,
' plus session-lifecycle hygiene: disposing an encrypt session
' mid-flight cleans up and leaves the Pipeline usable.

Imports System.IO
Imports System.Text
Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class StreamPumpTests

    <Fact>
    Public Sub PumpRoundTrip1MiB()
        Using sender As Pipeline = Pipeline.Init("streaming-aead-triple-mac-v1")
            Using receiver As Pipeline = Pipeline.Load(sender.Save())
                Dim plain((1 << 20) - 1) As Byte
                For i As Integer = 0 To plain.Length - 1
                    plain(i) = CByte(i Mod 251)
                Next

                Using wire As New MemoryStream()
                    sender.EncryptStreamPump(New MemoryStream(plain, writable:=False), wire)
                    Assert.True(wire.Length > 0)

                    Using back As New MemoryStream()
                        receiver.DecryptStreamPump(
                            New MemoryStream(wire.ToArray(), writable:=False), back)
                        Assert.Equal(Of Byte)(plain, back.ToArray())
                    End Using
                End Using
            End Using
        End Using
    End Sub

    <Fact>
    Public Sub PumpMatchesOneShot()
        Using sender As Pipeline = Pipeline.Init("streaming-aead-triple-mac-v1")
            Using receiver As Pipeline = Pipeline.Load(sender.Save())
                Dim plain(65535) As Byte
                For i As Integer = 0 To plain.Length - 1
                    plain(i) = CByte(i Mod 199)
                Next
                Dim wire As Byte() = sender.EncryptStreamOneShot(plain)

                Using back As New MemoryStream()
                    receiver.DecryptStreamPump(New MemoryStream(wire, writable:=False), back)
                    Assert.Equal(Of Byte)(plain, back.ToArray())
                End Using

                Dim back2 As Byte() = receiver.DecryptStreamOneShot(wire)
                Assert.Equal(Of Byte)(plain, back2)
            End Using
        End Using
    End Sub

    <Fact>
    Public Sub DisposeMidFlightThenReusePipeline()
        Using sender As Pipeline = Pipeline.Init("streaming-aead-triple-mac-v1")
            Using session As EncryptStream = sender.BeginEncryptStream()
                Dim block(99999) As Byte
                Array.Fill(block, CByte(&HA5))
                session.Write(block)
                ' Disposed here without End() — Dispose cancels and
                ' frees the session; the test passing (process not
                ' hanging) is the assertion.
            End Using

            ' The Pipeline stays usable after the cancelled session.
            Using receiver As Pipeline = Pipeline.Load(sender.Save())
                Dim plain As Byte() = Encoding.UTF8.GetBytes("after cancel")
                Dim wire As Byte() = sender.EncryptMessage(plain)
                Assert.Equal(Of Byte)(plain, receiver.DecryptMessage(wire))
            End Using
        End Using
    End Sub
End Class
