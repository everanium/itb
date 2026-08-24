// Single Message round trip across every shipped cipher profile at
// small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
// has no cipher surface and is exercised in ErrorTests instead.

module EveraniumItb.FSharp.Tests.MessageTests

open Xunit
open EveraniumItb.FSharp
open EveraniumItb.FSharp.Tests.TestSupport

let private profiles =
    [ "streaming-aead-triple-mac-v1"
      "streaming-noaead-triple-v1"
      "singlemsg-triple-mac-v1"
      "singlemsg-triple-nomac-v1"
      "streaming-aead-triple-mac-mixed-v1"
      "streaming-noaead-triple-mixed-v1"
      "singlemsg-triple-mac-mixed-v1"
      "singlemsg-triple-nomac-mixed-v1" ]

[<Fact>]
let ``message round trip every profile`` () =
    for profile in profiles do
        use sender = unwrap (Pipeline.init profile Opts.empty)
        use receiver = unwrap (Pipeline.openBlob profile (Pipeline.blob sender) Opts.empty)

        for size in [ 4 * 1024; 256 * 1024 ] do
            let plain = payload size (uint64 size)
            let wire = unwrap (Pipeline.encryptMessage sender plain)
            let back = unwrap (Pipeline.decryptMessage receiver wire)
            Assert.Equal<byte[]>(plain, back)
