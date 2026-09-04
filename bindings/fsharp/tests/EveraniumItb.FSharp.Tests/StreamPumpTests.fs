// Round trip through the stream pumps and the lazy transform
// adapter on a Streaming AEAD profile.

module EveraniumItb.FSharp.Tests.StreamPumpTests

open System.IO
open Xunit
open EveraniumItb.FSharp
open EveraniumItb.FSharp.Tests.TestSupport

[<Fact>]
let ``pump round trip 1 MiB`` () =
    use sender = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" Opts.empty)
    use receiver =
        unwrap (Pipeline.load (unwrap (Pipeline.save sender)))

    let plain = Array.init (1 <<< 20) (fun i -> byte (i % 251))

    use wire = new MemoryStream()
    unwrap (Stream.pumpEncrypt sender (new MemoryStream(plain, false)) wire)
    Assert.True(wire.Length > 0L)

    use back = new MemoryStream()
    unwrap (Stream.pumpDecrypt receiver (new MemoryStream(wire.ToArray(), false)) back)
    Assert.Equal<byte[]>(plain, back.ToArray())

[<Fact>]
let ``pump matches one-shot`` () =
    use sender = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" Opts.empty)
    use receiver =
        unwrap (Pipeline.load (unwrap (Pipeline.save sender)))

    let plain = Array.init 65536 (fun i -> byte (i % 199))
    let wire = unwrap (Pipeline.encryptStreamOneShot sender plain)

    use back = new MemoryStream()
    unwrap (Stream.pumpDecrypt receiver (new MemoryStream(wire, false)) back)
    Assert.Equal<byte[]>(plain, back.ToArray())

    let back2 = unwrap (Pipeline.decryptStreamOneShot receiver wire)
    Assert.Equal<byte[]>(plain, back2)

[<Fact>]
let ``transform adapter round trip`` () =
    use sender = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" Opts.empty)
    use receiver =
        unwrap (Pipeline.load (unwrap (Pipeline.save sender)))

    let plain = payload 65536 0xF5AA55AAUL
    let plainChunks = plain |> Array.chunkBySize 4099 |> Seq.ofArray

    let wire =
        (fun () ->
            use session = unwrap (Stream.beginEncrypt sender)
            Assert.Equal(Direction.Encrypt, session.Direction)
            Stream.transform session plainChunks |> Array.concat) ()

    Assert.True(wire.Length > 0)

    let back =
        (fun () ->
            use session = unwrap (Stream.beginDecrypt receiver)
            Assert.Equal(Direction.Decrypt, session.Direction)
            Stream.transform session (wire |> Array.chunkBySize 7013) |> Array.concat) ()

    Assert.Equal<byte[]>(plain, back)
