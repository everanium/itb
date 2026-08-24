// Stream-pump throughput vs plaintext size (Streaming Non-AEAD
// profile) at 1 MiB / 16 MiB / 64 MiB.

module EveraniumItb.FSharp.Bench.BenchStream

open System.IO
open EveraniumItb.FSharp

let run () : unit =
    use pipe =
        ItbError.get (Pipeline.init (BenchUtil.profileName "streaming-noaead-triple-v1") (BenchUtil.buildOpts ()))

    BenchUtil.header ()

    for size in BenchUtil.sizes do
        let plain = BenchUtil.payload size

        BenchUtil.benchCase "stream_pump" size (fun () ->
            use wire = new MemoryStream(size + size / 4 + 131_072)
            ItbError.get (Stream.pumpEncrypt pipe (new MemoryStream(plain, false)) wire))
        // Pre-encrypt one wire outside the decrypt timing loop.
        use setupWire = new MemoryStream(size + size / 4 + 131_072)
        ItbError.get (Stream.pumpEncrypt pipe (new MemoryStream(plain, false)) setupWire)
        let decWire = setupWire.ToArray()
        BenchUtil.benchCase "stream_pump-dec" size (fun () ->
            use out = new MemoryStream(size + 131_072)
            ItbError.get (Stream.pumpDecrypt pipe (new MemoryStream(decWire, false)) out))
