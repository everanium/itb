// Session persistence surface: save / load, saveF / loadF, inspect,
// lookup / profiles / register round trip, maxWorkers clamping.

module Everanium.Itb3.FSharp.Tests.PersistTests

open System.IO
open System.Text
open Xunit
open Everanium.Itb3.FSharp
open Everanium.Itb3.FSharp.Tests.TestSupport

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
    // The recipe fields match the registry entry; the two
    // inspection-only fields separate the two records.
    let recipe = prof.Clone()
    recipe.NonceBits <- System.Nullable()
    recipe.BarrierFill <- System.Nullable()
    Assert.Equal(unwrap (Pipeline.lookup "streaming-aead-triple-mac-v1"), recipe)

[<Fact>]
let ``inspect carries the runtime globals, lookup does not`` () =
    // Defaults: the blob records the compile-in nonce width and
    // barrier fill margin, and inspect surfaces both.
    (use pipe = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" Opts.empty)
     let prof = unwrap (Pipeline.inspect (unwrap (Pipeline.save pipe)))
     Assert.Equal(System.Nullable 512, prof.NonceBits)
     Assert.Equal(System.Nullable 1, prof.BarrierFill))

    // Per-Pipeline overrides travel through the blob into inspect.
    let opts = Opts.empty |> Opts.withNonceBits 256L |> Opts.withBarrierFill 4L
    (use pipe = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" opts)
     let prof = unwrap (Pipeline.inspect (unwrap (Pipeline.save pipe)))
     Assert.Equal(System.Nullable 256, prof.NonceBits)
     Assert.Equal(System.Nullable 4, prof.BarrierFill)
     Assert.Contains("\"nonce_bits\":256", prof.ToJson())
     Assert.Contains("\"barrier_fill\":4", prof.ToJson()))

    // The registry entry is the recipe alone — neither field is part
    // of it, so both read as absent rather than as zero.
    let registry = unwrap (Pipeline.lookup "streaming-aead-triple-mac-v1")
    Assert.False registry.NonceBits.HasValue
    Assert.False registry.BarrierFill.HasValue
    Assert.DoesNotContain("nonce_bits", registry.ToJson())
    Assert.DoesNotContain("barrier_fill", registry.ToJson())

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
