// Bench entry point: `message` runs the Single Message shape,
// `stream` the stream-pump shape, `all` (default) both.

module EveraniumItb.FSharp.Bench.Program

open EveraniumItb.FSharp

[<EntryPoint>]
let main args =
    // Bench-scale allocation churn leaks Go scratch heap unboundedly
    // without a soft memory cap + aggressive GC; the return values
    // report the previous settings, not an error.
    Runtime.setMemoryLimit (512L * 1024L * 1024L) |> ignore
    Runtime.setGCPercent 20 |> ignore

    match (if args.Length > 0 then args[0] else "all") with
    | "message" ->
        BenchMessage.run ()
        0
    | "stream" ->
        BenchStream.run ()
        0
    | "all" ->
        BenchMessage.run ()
        BenchStream.run ()
        0
    | _ ->
        eprintfn "usage: EveraniumItb.FSharp.Bench [message|stream|all]"
        2
