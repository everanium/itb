// encryptMessage throughput vs plaintext size (Single Message
// profile) at 1 MiB / 16 MiB / 64 MiB.

module EveraniumItb.FSharp.Bench.BenchMessage

open EveraniumItb.FSharp

let run () : unit =
    use pipe =
        ItbError.get (Pipeline.init (BenchUtil.profileName "singlemsg-triple-nomac-v1") (BenchUtil.buildOpts ()))

    BenchUtil.header ()

    for size in BenchUtil.sizes do
        let plain = BenchUtil.payload size

        BenchUtil.benchCase "message" size (fun () ->
            ItbError.get (Pipeline.encryptMessage pipe plain) |> ignore)
