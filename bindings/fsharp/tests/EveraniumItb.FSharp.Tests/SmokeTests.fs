// Init -> blob -> openBlob -> encryptMessage -> decryptMessage round
// trip, composed through the itb computation expression.

module EveraniumItb.FSharp.Tests.SmokeTests

open System.Text
open Xunit
open EveraniumItb.FSharp
open EveraniumItb.FSharp.Tests.TestSupport

[<Fact>]
let ``smoke round trip through the itb computation expression`` () =
    let plain = Encoding.UTF8.GetBytes "smoke round-trip payload"

    let result =
        itb {
            use! sender = Pipeline.init "singlemsg-triple-mac-v1" Opts.empty
            let blob = Pipeline.blob sender
            use! receiver = Pipeline.openBlob "singlemsg-triple-mac-v1" blob Opts.empty
            let! wire = Pipeline.encryptMessage sender plain
            let! back = Pipeline.decryptMessage receiver wire
            return blob, wire, back
        }

    let blob, wire, back = unwrap result
    Assert.NotEmpty blob
    Assert.NotEqual<byte[]>(plain, wire)
    Assert.Equal<byte[]>(plain, back)

[<Fact>]
let ``library version string is non-empty`` () =
    Assert.False(System.String.IsNullOrEmpty(Runtime.version ()))
    Assert.Equal("0.3.4", Runtime.BindingVersion)
