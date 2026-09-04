' Explicit Write / End / Read round trip with pathological batch
' sizes (17-byte feed, 23-byte drain) across multiple chunks.

Imports System.IO
Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class StreamIncrementalTests

    <Fact>
    Public Sub IncrementalTinyBatches()
        ' Small chunk size so the 64 KiB payload spans many chunks.
        Dim opts As Opts = New Opts().WithChunkSize(4096)
        Using sender As Pipeline = Pipeline.Init("streaming-aead-triple-mac-v1", opts)
            Using receiver As Pipeline = Pipeline.Load(sender.Save())
                Dim plain(65535) As Byte
                For i As Integer = 0 To plain.Length - 1
                    plain(i) = CByte(i Mod 241)
                Next

                ' Encrypt: 17-byte writes, then End + 23-byte drains.
                Dim wire As Byte()
                Using session As EncryptStream = sender.BeginEncryptStream()
                    Dim off As Integer = 0
                    While off < plain.Length
                        Dim n As Integer = Math.Min(17, plain.Length - off)
                        session.Write(plain, off, n)
                        off += n
                    End While
                    session.End()
                    Using spool As New MemoryStream()
                        Dim buf(22) As Byte
                        Dim finished As Boolean = False
                        While Not finished
                            Dim m As Integer = session.Read(buf, finished)
                            spool.Write(buf, 0, m)
                        End While
                        wire = spool.ToArray()
                    End Using
                End Using
                Assert.True(wire.Length > 0)

                ' Decrypt with the same pathological batch sizes.
                Dim back As Byte()
                Using session As DecryptStream = receiver.BeginDecryptStream()
                    Dim off As Integer = 0
                    While off < wire.Length
                        Dim n As Integer = Math.Min(17, wire.Length - off)
                        session.Write(wire, off, n)
                        off += n
                    End While
                    session.End()
                    Using spool As New MemoryStream()
                        Dim buf(22) As Byte
                        Dim finished As Boolean = False
                        While Not finished
                            Dim m As Integer = session.Read(buf, finished)
                            spool.Write(buf, 0, m)
                        End While
                        back = spool.ToArray()
                    End Using
                End Using
                Assert.Equal(Of Byte)(plain, back)
            End Using
        End Using
    End Sub
End Class
