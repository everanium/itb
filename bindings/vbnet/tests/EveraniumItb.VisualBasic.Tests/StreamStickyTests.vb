' A decrypt session fed a tampered wire fails with a sticky MAC
' failure. Uses a position probe rather than a single bit flip
' because the over-sized container carries CSPRNG residue in the
' non-payload area — a flip that lands inside the residue is
' architecturally inert (residue is not payload) and the session
' finishes clean. Probing 32 evenly-spaced positions makes the
' all-residue probability negligible; the first position that
' surfaces an error must give Status.MacFailure and remain sticky on
' subsequent reads.

Imports Everanium.Itb.VisualBasic
Imports Xunit

Public Class StreamStickyTests

    <Fact>
    Public Sub TamperedWireStickyFailure()
        Using sender As Pipeline = Pipeline.Init("streaming-aead-triple-mac-v1")
            Using receiver As Pipeline = Pipeline.Load(sender.Save())
                Dim plain(65535) As Byte
                For i As Integer = 0 To plain.Length - 1
                    plain(i) = CByte(i Mod 227)
                Next
                Dim baseWire As Byte() = sender.EncryptStreamOneShot(plain)
                Assert.True(baseWire.Length > 128,
                    $"wire too short to place a distributed probe: {baseWire.Length} bytes")

                Const Probes As Integer = 32
                ' Evenly spread through the wire body; skip the first /
                ' last 16 bytes so a hit against the outer envelope
                ' framing does not muddy the observation.
                Dim bodyStart As Integer = 16
                Dim bodyEnd As Integer = baseWire.Length - 16
                Dim stride As Integer = (bodyEnd - bodyStart) \ Probes

                For probe As Integer = 0 To Probes - 1
                    Dim idx As Integer = bodyStart + probe * stride

                    Dim wire As Byte() = CType(baseWire.Clone(), Byte())
                    wire(idx) = wire(idx) Xor CByte(1)

                    Using session As DecryptStream = receiver.BeginDecryptStream()
                        ' Ignore Write / End status — the failure may
                        ' surface on either side or only on the drain
                        ' that follows.
                        Try
                            session.Write(wire)
                            session.End()
                        Catch ex As ItbException
                        End Try

                        Dim buf(4095) As Byte
                        Dim firstErr As ItbException = Nothing
                        Dim finishedClean As Boolean = False
                        While True
                            Try
                                Dim finished As Boolean = False
                                session.Read(buf, finished)
                                If finished Then
                                    finishedClean = True
                                    Exit While
                                End If
                            Catch ex As ItbException
                                firstErr = ex
                                Exit While
                            End Try
                        End While
                        If finishedClean Then
                            ' Residue hit at this offset — try the next
                            ' probe.
                            Continue For
                        End If
                        Assert.NotNull(firstErr)
                        Assert.True(Status.MacFailure = firstErr.Status,
                            $"expected MAC failure on tampered wire at probe {probe} " &
                            $"(byte {idx}), got {firstErr.Status}")

                        ' Sticky: a subsequent read reports the same
                        ' status.
                        Dim again As ItbException = Assert.Throws(Of ItbException)(
                            Sub()
                                Dim fin As Boolean = False
                                session.Read(buf, fin)
                            End Sub)
                        Assert.Equal(firstErr.Status, again.Status)
                        Return
                    End Using
                Next
                Assert.Fail(
                    $"no probe among {Probes} evenly-spaced positions surfaced a MAC " &
                    "failure — either the probe pattern is degenerate or " &
                    "authentication is not covering the wire body it should")
            End Using
        End Using
    End Sub
End Class
