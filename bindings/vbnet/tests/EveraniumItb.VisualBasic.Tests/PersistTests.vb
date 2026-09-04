' Session persistence surface: Save / Load, SaveF / LoadF, Inspect,
' Lookup / Profiles / Register round trip, MaxWorkers clamping.

Imports System.IO
Imports System.Text
Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class PersistTests

    Private Shared ReadOnly Plain As Byte() = Encoding.UTF8.GetBytes("persisted session payload")

    <Fact>
    Public Sub SaveThenLoadRoundTrip()
        Using sender As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1")
            Dim blob As Byte() = sender.Save()
            Assert.NotEmpty(blob)
            Assert.Equal(Of Byte)(blob, sender.Save())
            Using receiver As Pipeline = Pipeline.Load(blob)
                Assert.Equal(Of Byte)(blob, receiver.Save())
                Assert.Equal(Of Byte)(Plain, receiver.DecryptMessage(sender.EncryptMessage(Plain)))
            End Using
        End Using
    End Sub

    <Fact>
    Public Sub SaveFThenLoadFRoundTrip()
        Dim dir As DirectoryInfo = Directory.CreateTempSubdirectory("itb-vbnet-")
        Try
            Dim file As String = Path.Combine(dir.FullName, "session.blob")
            Using sender As Pipeline = Pipeline.Init("streaming-aead-triple-mac-v1")
                sender.SaveF(file)
                Assert.Equal(Of Byte)(sender.Save(), IO.File.ReadAllBytes(file))
                Using receiver As Pipeline = Pipeline.LoadF(file)
                    Assert.Equal(Of Byte)(Plain,
                        receiver.DecryptStreamOneShot(sender.EncryptStreamOneShot(Plain)))
                End Using
            End Using
        Finally
            dir.Delete(True)
        End Try
    End Sub

    <Fact>
    Public Sub LoadWithMasterOverride()
        Dim perm(31) As Byte
        Dim wrap(31) As Byte
        Array.Fill(perm, CByte(&H33))
        Array.Fill(wrap, CByte(&H44))
        Using sender As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1")
            Dim blob As Byte() = sender.Save()
            Dim rotated As Byte() = sender.Rekey(perm, wrap)
            Assert.False(blob.SequenceEqual(rotated))
            Assert.Equal(Of Byte)(rotated, sender.Save())
            Using receiver As Pipeline = Pipeline.Load(blob, perm, wrap)
                Assert.Equal(Of Byte)(Plain, receiver.DecryptMessage(sender.EncryptMessage(Plain)))
            End Using
        End Using
    End Sub

    <Fact>
    Public Sub InspectReadsTheEmbeddedRecord()
        Using pipe As Pipeline = Pipeline.Init("streaming-aead-triple-mac-v1")
            Dim prof As Global.Itb.Profile = Pipeline.Inspect(pipe.Save())
            Assert.Equal("streaming-aead-triple-mac-v1", prof.Name)
            Assert.Equal("streaming-aead", prof.Mode)
            Assert.Equal(512, prof.Width)
            Assert.Equal(Pipeline.Lookup("streaming-aead-triple-mac-v1"), prof)
        End Using
    End Sub

    <Fact>
    Public Sub ProfilesListsTheCatalogue()
        Dim names As String() = Pipeline.Profiles()
        Assert.Contains("singlemsg-triple-mac-v1", names)
        Assert.Contains("streaming-aead-triple-mac-v1", names)
    End Sub

    <Fact>
    Public Sub RegisterCopyOfShippedProfile()
        Dim copy As Global.Itb.Profile = Pipeline.Lookup("singlemsg-triple-nomac-v1")
        copy.Name = ""
        Pipeline.Register("vbnet-binding-test-copy", copy)
        Dim back As Global.Itb.Profile = Pipeline.Lookup("vbnet-binding-test-copy")
        Assert.Equal("vbnet-binding-test-copy", back.Name)
        Assert.Equal(copy.Mode, back.Mode)
        Assert.Contains("vbnet-binding-test-copy", Pipeline.Profiles())
        Using sender As Pipeline = Pipeline.Init("vbnet-binding-test-copy")
            Using receiver As Pipeline = Pipeline.Load(sender.Save())
                Assert.Equal(Of Byte)(Plain, receiver.DecryptMessage(sender.EncryptMessage(Plain)))
            End Using
        End Using
    End Sub

    <Fact>
    Public Sub MaxWorkersClamps()
        Using pipe As Pipeline = Pipeline.Init("singlemsg-triple-mac-v1", New Opts().WithMaxWorkers(-1))
            pipe.MaxWorkers(2)
            pipe.MaxWorkers(-1)
            pipe.MaxWorkers(1000)
            Assert.Equal(Of Byte)(Plain, pipe.DecryptMessage(pipe.EncryptMessage(Plain)))
        End Using
    End Sub
End Class
