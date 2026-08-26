' Whole-buffer Stream throughput vs plaintext size (Streaming
' Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
' EncryptStreamOneShot / DecryptStreamOneShot, the single FFI
' round-trip surface for callers holding the whole payload in
' memory.

Imports System.Security.Cryptography
Imports Everanium.Itb.VisualBasic

Friend Module BenchStreamOneShot

    Friend Sub Run()
        Using pipe As Pipeline = Pipeline.Init(
                ProfileName("streaming-noaead-triple-v1"), BuildOpts())
            Header()
            For Each size As Integer In Sizes
                Dim plain(size - 1) As Byte
                ' CSPRNG-fill so plaintext content matches the root Go
                ' bench (crypto/rand). Not in the timing loop.
                RandomNumberGenerator.Fill(plain)
                [Case]("stream_one_shot", size,
                    Sub()
                        pipe.EncryptStreamOneShot(plain)
                    End Sub)
                ' Pre-encrypt one wire outside the decrypt timing loop.
                Dim decWire As Byte() = pipe.EncryptStreamOneShot(plain)
                [Case]("stream_one_shot-dec", size,
                    Sub()
                        pipe.DecryptStreamOneShot(decWire)
                    End Sub)
            Next
        End Using
    End Sub
End Module
