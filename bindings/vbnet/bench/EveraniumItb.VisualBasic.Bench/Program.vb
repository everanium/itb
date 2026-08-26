' Bench entry point: `message` runs the Single Message shape,
' `stream` the stream-pump shape, `all` (default) both.

Imports Everanium.Itb.VisualBasic

Friend Module Program

    Friend Function Main(args As String()) As Integer
        ' Bench-scale allocation churn leaks Go scratch heap
        ' unboundedly without a soft memory cap + aggressive GC; the
        ' return values report the previous settings, not an error.
        Library.SetMemoryLimit(512L * 1024 * 1024)
        Library.SetGCPercent(20)

        Select Case If(args.Length > 0, args(0), "all")
            Case "message"
                BenchMessage.Run()
                Return 0
            Case "stream"
                BenchStream.Run()
                Return 0
            Case "stream_one_shot"
                BenchStreamOneShot.Run()
                Return 0
            Case "all"
                BenchMessage.Run()
                BenchStream.Run()
                BenchStreamOneShot.Run()
                Return 0
            Case Else
                Console.Error.WriteLine(
                    "usage: EveraniumItb.VisualBasic.Bench [message|stream|stream_one_shot|all]")
                Return 2
        End Select
    End Function
End Module
