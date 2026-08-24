// Explicit write / finish / read round trip with pathological batch
// sizes (17-byte feed, 23-byte drain) across multiple chunks, plus
// mid-flight session disposal leaving the Pipeline usable.

module EveraniumItb.FSharp.Tests.StreamIncrementalTests

open System.IO
open System.Text
open Xunit
open EveraniumItb.FSharp
open EveraniumItb.FSharp.Tests.TestSupport

/// Feeds `src` in 17-byte writes, finishes, then drains in 23-byte
/// reads.
let private pumpTiny (session: Session) (src: byte[]) : byte[] =
    for off in 0..17 .. src.Length - 1 do
        let len = min 17 (src.Length - off)
        unwrap (Stream.write session src[off .. off + len - 1])

    unwrap (Stream.finish session)

    use spool = new MemoryStream()
    let buf = Array.zeroCreate 23
    let mutable finished = false

    while not finished do
        let r = unwrap (Stream.read session buf)
        spool.Write(buf, 0, r.Count)
        finished <- r.Finished

    spool.ToArray()

[<Fact>]
let ``incremental tiny batches`` () =
    // Small chunk size so the 64 KiB payload spans many chunks.
    let opts = Opts.empty |> Opts.withChunkSize 4096L
    use sender = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" opts)
    use receiver = unwrap (Pipeline.openBlob "streaming-aead-triple-mac-v1" (Pipeline.blob sender) opts)

    let plain = Array.init 65536 (fun i -> byte (i % 241))

    let wire =
        (fun () ->
            use session = unwrap (Stream.beginEncrypt sender)
            pumpTiny session plain) ()

    Assert.True(wire.Length > 0)

    let back =
        (fun () ->
            use session = unwrap (Stream.beginDecrypt receiver)
            pumpTiny session wire) ()

    Assert.Equal<byte[]>(plain, back)

[<Fact>]
let ``dispose mid-flight then reuse pipeline`` () =
    use sender = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" Opts.empty)

    (fun () ->
        use session = unwrap (Stream.beginEncrypt sender)
        unwrap (Stream.write session (Array.create 100_000 0xA5uy))
        // Disposed here without finish — Dispose cancels and frees
        // the session; the test passing (process not hanging) is the
        // assertion.
        ignore session.Parent) ()

    // The Pipeline stays usable after the cancelled session.
    use receiver =
        unwrap (Pipeline.openBlob "streaming-aead-triple-mac-v1" (Pipeline.blob sender) Opts.empty)

    let plain = Encoding.UTF8.GetBytes "after cancel"
    let wire = unwrap (Pipeline.encryptMessage sender plain)
    Assert.Equal<byte[]>(plain, unwrap (Pipeline.decryptMessage receiver wire))
