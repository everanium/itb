' eitb — command-line demonstrator for the ITB VB.NET binding.
'
' Subcommands:
'
'   eitb version                                   library + binding versions
'   eitb hashes                                    shipped hash primitive roster
'   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
'   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
'
' `encrypt` prints the session blob to stderr as hex; feed that hex
' back to `decrypt` on the receiving side.
'
' The `hashes` diagnostic iterates the registry through the C#
' layer's internal relay (InternalsVisibleTo) — the binding library
' itself deliberately exposes no primitive enumeration.

Imports System.IO
Imports Everanium.Itb.VisualBasic

Friend Module Program

    Friend Function Main(args As String()) As Integer
        Library.SetMemoryLimit(512L * 1024 * 1024)
        Library.SetGCPercent(20)
        Try
            Select Case If(args.Length > 0, args(0), Nothing)
                Case "version"
                    Return CmdVersion()
                Case "hashes"
                    Return CmdHashes()
                Case "encrypt"
                    If args.Length = 4 Then
                        Return CmdEncrypt(args(1), args(2), args(3))
                    End If
                Case "decrypt"
                    If args.Length = 5 Then
                        Return CmdDecrypt(args(1), args(2), args(3), args(4))
                    End If
            End Select
            Console.Error.WriteLine(
                "usage: eitb version" & Environment.NewLine &
                "       eitb hashes" & Environment.NewLine &
                "       eitb encrypt <profile> <in-file> <out-file>" & Environment.NewLine &
                "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>")
            Return 2
        Catch e As Exception
            Console.Error.WriteLine($"eitb: {e.Message}")
            Return 1
        End Try
    End Function

    Private Function CmdVersion() As Integer
        Console.WriteLine($"libitb {Library.Version()}")
        Console.WriteLine($"itb-vbnet {Library.BindingVersion}")
        Return 0
    End Function

    Private Function CmdHashes() As Integer
        Dim count As Integer = Global.Itb.VisualBasicInterop.HashCount()
        For i As Integer = 0 To count - 1
            Dim name As String = Global.Itb.VisualBasicInterop.HashName(i)
            Dim width As Integer = Global.Itb.VisualBasicInterop.HashWidth(i)
            Console.WriteLine($"{i,2}  {name,-12} {width} bits")
        Next
        Return 0
    End Function

    ' Profiles whose canonical name begins with "streaming-" route
    ' through the one-shot streaming buffered pair instead of the
    ' Single Message pair.
    Private Function IsStreamingProfile(profile As String) As Boolean
        Return profile.StartsWith("streaming-", StringComparison.Ordinal)
    End Function

    ' Recursively create the parent directory of `filePath` (mkdir -p).
    ' The parameter is named `filePath`, not `path`: VB.NET identifier
    ' lookup is case-insensitive, so a parameter named `path` shadows
    ' the imported `System.IO.Path` class and turns `Path.GetDirectoryName`
    ' into a bogus String method call.
    Private Sub EnsureParentDir(filePath As String)
        Dim parent As String = Path.GetDirectoryName(filePath)
        If Not String.IsNullOrEmpty(parent) Then
            Directory.CreateDirectory(parent)
        End If
    End Sub

    Private Function CmdEncrypt(profile As String, inFile As String, outFile As String) As Integer
        Dim plain As Byte() = File.ReadAllBytes(inFile)
        Using pipe As Pipeline = Pipeline.Init(profile)
            Dim wire As Byte() = If(IsStreamingProfile(profile),
                                    pipe.EncryptStreamOneShot(plain),
                                    pipe.EncryptMessage(plain))
            EnsureParentDir(outFile)
            File.WriteAllBytes(outFile, wire)
            Console.Error.WriteLine(Convert.ToHexStringLower(pipe.Blob))
            Console.WriteLine(
                $"encrypted {inFile} -> {outFile} ({plain.Length} -> {wire.Length} bytes)")
        End Using
        Return 0
    End Function

    Private Function CmdDecrypt(
            profile As String, blobHex As String, inFile As String, outFile As String) As Integer
        Dim blob As Byte() = Convert.FromHexString(blobHex)
        Dim wire As Byte() = File.ReadAllBytes(inFile)
        Using pipe As Pipeline = Pipeline.Open(profile, blob)
            Dim plain As Byte() = If(IsStreamingProfile(profile),
                                     pipe.DecryptStreamOneShot(wire),
                                     pipe.DecryptMessage(wire))
            EnsureParentDir(outFile)
            File.WriteAllBytes(outFile, plain)
            Console.WriteLine(
                $"decrypted {inFile} -> {outFile} ({wire.Length} -> {plain.Length} bytes)")
        End Using
        Return 0
    End Function
End Module
