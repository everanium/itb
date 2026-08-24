' EncryptMessage throughput vs plaintext size (Single Message
' profile) at 1 MiB / 16 MiB / 64 MiB.

Imports System.Security.Cryptography
Imports Everanium.Itb.VisualBasic

Friend Module BenchMessage

    Friend Sub Run()
        Using pipe As Pipeline = Pipeline.Init(
                ProfileName("singlemsg-triple-nomac-v1"), BuildOpts())
            Header()
            For Each size As Integer In Sizes
                Dim plain(size - 1) As Byte
                ' CSPRNG-fill so plaintext content matches the root Go
                ' bench (crypto/rand). Not in the timing loop.
                RandomNumberGenerator.Fill(plain)
                [Case]("message", size, Sub() pipe.EncryptMessage(plain))
            Next
        End Using
    End Sub
End Module
