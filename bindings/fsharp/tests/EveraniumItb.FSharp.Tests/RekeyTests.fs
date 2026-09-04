// init -> rekey -> load receiver from the rotated blob -> round
// trip.

module EveraniumItb.FSharp.Tests.RekeyTests

open System.Text
open Xunit
open EveraniumItb.FSharp
open EveraniumItb.FSharp.Tests.TestSupport

[<Fact>]
let ``rekey round trip`` () =
    use sender = unwrap (Pipeline.init "singlemsg-triple-mac-v1" Opts.empty)
    let blobBefore = unwrap (Pipeline.save sender)

    let perm = Array.create 32 0x11uy
    let wrap = Array.create 32 0x22uy
    unwrap (Pipeline.rekey sender perm wrap) |> ignore
    Assert.NotEqual<byte[]>(blobBefore, unwrap (Pipeline.save sender))

    use receiver = unwrap (Pipeline.load (unwrap (Pipeline.save sender)))
    let plain = Encoding.UTF8.GetBytes "post-rekey payload"
    let wire = unwrap (Pipeline.encryptMessage sender plain)
    Assert.Equal<byte[]>(plain, unwrap (Pipeline.decryptMessage receiver wire))
