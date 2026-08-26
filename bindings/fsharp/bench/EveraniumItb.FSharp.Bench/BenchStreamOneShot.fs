// Whole-buffer Stream throughput vs plaintext size (Streaming
// Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
// encryptStreamOneShot / decryptStreamOneShot, the single FFI
// round-trip surface for callers holding the whole payload in
// memory.

module EveraniumItb.FSharp.Bench.BenchStreamOneShot

open EveraniumItb.FSharp

let run () : unit =
    use pipe =
        ItbError.get (Pipeline.init (BenchUtil.profileName "streaming-noaead-triple-v1") (BenchUtil.buildOpts ()))

    BenchUtil.header ()

    for size in BenchUtil.sizes do
        let plain = BenchUtil.payload size

        BenchUtil.benchCase "stream_one_shot" size (fun () ->
            ItbError.get (Pipeline.encryptStreamOneShot pipe plain) |> ignore)
        // Pre-encrypt one wire outside the decrypt timing loop.
        let decWire = ItbError.get (Pipeline.encryptStreamOneShot pipe plain)
        BenchUtil.benchCase "stream_one_shot-dec" size (fun () ->
            ItbError.get (Pipeline.decryptStreamOneShot pipe decWire) |> ignore)
