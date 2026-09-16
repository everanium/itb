' Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
' heap-profile writer, the pool-counter snapshot and its slot layout,
' and the hash-registry enumeration.

Imports System.IO
Imports Everanium.Itb3.VisualBasic
Imports Xunit

Public Class RuntimeTests

    <Fact>
    Public Sub GomaxprocsQuerySetRestore()
        Dim orig As Integer = Library.SetGOMAXPROCS(0)
        Assert.True(orig > 0)
        Assert.Equal(orig, Library.SetGOMAXPROCS(-3))
        Assert.Equal(orig, Library.SetGOMAXPROCS(orig + 1))
        Assert.Equal(orig + 1, Library.SetGOMAXPROCS(0))
        Assert.Equal(orig + 1, Library.SetGOMAXPROCS(orig))
    End Sub

    <Fact>
    Public Sub HeapProfileWrittenAndEmptyPathRejected()
        Dim dir As String = Path.Combine(
            Path.GetTempPath(), $"itb-loop-test-heap-vbnet-{Environment.ProcessId}")
        Directory.CreateDirectory(dir)
        Dim profilePath As String = Path.Combine(dir, "heap.prof")
        Library.WriteHeapProfile(profilePath)
        Assert.True(New FileInfo(profilePath).Length > 0)
        Directory.Delete(dir, True)

        ' The empty path falls back to ITB_MEMPROFILE inside libitb3;
        ' with the variable clear there is nothing to fall back to.
        Environment.SetEnvironmentVariable("ITB_MEMPROFILE", Nothing)
        Dim ex As ItbException = Assert.Throws(Of ItbException)(
            Sub() Library.WriteHeapProfile(""))
        Assert.Equal(Status.BadInput, ex.Status)
    End Sub

    <Fact>
    Public Sub PoolStatsLayout()
        Dim len As Integer = Library.PoolStatsLen()
        Assert.True(len >= 9)
        Dim v As Long() = Library.PoolStats()
        Assert.Equal(len, v.Length)
        Dim tiers As Long = v(0)
        Assert.True(tiers > 0)
        Assert.Equal(CLng(len), 1L + 5L * tiers + 8L)
    End Sub

    <Fact>
    Public Sub HashNamesCanonical()
        Dim names As String() = Pipeline.HashNames()
        Assert.Equal("aesitb128", names(0))
        Assert.Contains("areion512", names)
    End Sub
End Class
