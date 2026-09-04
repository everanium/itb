// Session persistence surface: save / load, saveF / loadF, inspect,
// lookup / profiles / register round trip, maxWorkers clamping.

module EveraniumItb.FSharp.Tests.PersistTests

open System.IO
open System.Text
open Xunit
open EveraniumItb.FSharp
open EveraniumItb.FSharp.Tests.TestSupport

let private plain = Encoding.UTF8.GetBytes "persisted session payload"

[<Fact>]
let ``save then load round trip`` () =
    use sender = unwrap (Pipeline.init "singlemsg-triple-mac-v1" Opts.empty)
    let blob = unwrap (Pipeline.save sender)
    Assert.NotEmpty blob
    Assert.Equal<byte[]>(blob, unwrap (Pipeline.save sender))
    use receiver = unwrap (Pipeline.load blob)
    Assert.Equal<byte[]>(blob, unwrap (Pipeline.save receiver))
    let wire = unwrap (Pipeline.encryptMessage sender plain)
    Assert.Equal<byte[]>(plain, unwrap (Pipeline.decryptMessage receiver wire))

[<Fact>]
let ``saveF then loadF round trip`` () =
    let dir = Directory.CreateTempSubdirectory "itb-fsharp-"

    try
        let file = Path.Combine(dir.FullName, "session.blob")
        use sender = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" Opts.empty)
        unwrap (Pipeline.saveF sender file)
        Assert.Equal<byte[]>(unwrap (Pipeline.save sender), File.ReadAllBytes file)
        use receiver = unwrap (Pipeline.loadF file)
        let wire = unwrap (Pipeline.encryptStreamOneShot sender plain)
        Assert.Equal<byte[]>(plain, unwrap (Pipeline.decryptStreamOneShot receiver wire))
    finally
        dir.Delete true

[<Fact>]
let ``load with master override`` () =
    let perm = Array.create 32 0x33uy
    let wrap = Array.create 32 0x44uy
    use sender = unwrap (Pipeline.init "singlemsg-triple-mac-v1" Opts.empty)
    let blob = unwrap (Pipeline.save sender)
    let rotated = unwrap (Pipeline.rekey sender perm wrap)
    Assert.NotEqual<byte[]>(blob, rotated)
    Assert.Equal<byte[]>(rotated, unwrap (Pipeline.save sender))
    use receiver = unwrap (Pipeline.loadWithMasters blob perm wrap)
    let wire = unwrap (Pipeline.encryptMessage sender plain)
    Assert.Equal<byte[]>(plain, unwrap (Pipeline.decryptMessage receiver wire))

[<Fact>]
let ``inspect reads the embedded record`` () =
    use pipe = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" Opts.empty)
    let prof = unwrap (Pipeline.inspect (unwrap (Pipeline.save pipe)))
    Assert.Equal("streaming-aead-triple-mac-v1", prof.Name)
    Assert.Equal("streaming-aead", prof.Mode)
    Assert.Equal(512, prof.Width)
    Assert.Equal(unwrap (Pipeline.lookup "streaming-aead-triple-mac-v1"), prof)

[<Fact>]
let ``profiles lists the catalogue`` () =
    let names = unwrap (Pipeline.profiles ())
    Assert.Contains("singlemsg-triple-mac-v1", names)
    Assert.Contains("streaming-aead-triple-mac-v1", names)

[<Fact>]
let ``register copy of shipped profile`` () =
    let copy = unwrap (Pipeline.lookup "singlemsg-triple-nomac-v1")
    copy.Name <- ""
    unwrap (Pipeline.register "fsharp-binding-test-copy" copy)
    let back = unwrap (Pipeline.lookup "fsharp-binding-test-copy")
    Assert.Equal("fsharp-binding-test-copy", back.Name)
    Assert.Equal(copy.Mode, back.Mode)
    Assert.Contains("fsharp-binding-test-copy", unwrap (Pipeline.profiles ()))
    use sender = unwrap (Pipeline.init "fsharp-binding-test-copy" Opts.empty)
    use receiver = unwrap (Pipeline.load (unwrap (Pipeline.save sender)))
    let wire = unwrap (Pipeline.encryptMessage sender plain)
    Assert.Equal<byte[]>(plain, unwrap (Pipeline.decryptMessage receiver wire))

[<Fact>]
let ``maxWorkers clamps`` () =
    let opts = Opts.empty |> Opts.withMaxWorkers -1L
    use pipe = unwrap (Pipeline.init "singlemsg-triple-mac-v1" opts)
    unwrap (Pipeline.maxWorkers pipe 2)
    unwrap (Pipeline.maxWorkers pipe -1)
    unwrap (Pipeline.maxWorkers pipe 1000)
    let wire = unwrap (Pipeline.encryptMessage pipe plain)
    Assert.Equal<byte[]>(plain, unwrap (Pipeline.decryptMessage pipe wire))
