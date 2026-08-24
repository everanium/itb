' Stream-pump throughput vs plaintext size (Streaming Non-AEAD
' profile) at 1 MiB / 16 MiB / 64 MiB.

Imports System.IO
Imports System.Security.Cryptography
Imports Everanium.Itb.VisualBasic

Friend Module BenchStream

    Friend Sub Run()
        Using pipe As Pipeline = Pipeline.Init(
                ProfileName("streaming-noaead-triple-v1"), BuildOpts())
            Header()
            For Each size As Integer In Sizes
                Dim plain(size - 1) As Byte
                ' CSPRNG-fill so plaintext content matches the root Go
                ' bench (crypto/rand). Not in the timing loop.
                RandomNumberGenerator.Fill(plain)
                [Case]("stream_pump", size,
                    Sub()
                        Dim wire As New MemoryStream(size + size \ 4 + 131072)
                        pipe.EncryptStreamPump(New MemoryStream(plain, writable:=False), wire)
                    End Sub)
                ' Pre-encrypt one wire outside the decrypt timing loop.
                Dim setupWire As New MemoryStream(size + size \ 4 + 131072)
                pipe.EncryptStreamPump(New MemoryStream(plain, writable:=False), setupWire)
                Dim decWire As Byte() = setupWire.ToArray()
                [Case]("stream_pump-dec", size,
                    Sub()
                        Dim out As New MemoryStream(size + 131072)
                        pipe.DecryptStreamPump(New MemoryStream(decWire, writable:=False), out)
                    End Sub)
            Next
        End Using
    End Sub
End Module
