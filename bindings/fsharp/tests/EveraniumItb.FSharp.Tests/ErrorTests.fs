// Error-mapping surface: opaque-string relay, closed Pipeline,
// duplicate profile registration (with an 8-entry innerHashes
// constellation), Status code mapping, and ItbFailure interop.

module EveraniumItb.FSharp.Tests.ErrorTests

open System.Text
open Xunit
open EveraniumItb.FSharp
open EveraniumItb.FSharp.Tests.TestSupport

[<Fact>]
let ``unknown profile is BadInput with diagnostic`` () =
    let err = unwrapError (Pipeline.init "no-such-profile" Opts.empty)
    Assert.Equal(Status.BadInput, err.Status)
    Assert.Equal(4, err.Code)
    Assert.False(System.String.IsNullOrEmpty err.Detail)

[<Fact>]
let ``unknown opts key is BadInput`` () =
    // Typoed key (lowercase s) — Go rejects unknown keys.
    let opts = Opts.empty |> Opts.withRaw "chunksize" "4096"
    let err = unwrapError (Pipeline.init "singlemsg-triple-mac-v1" opts)
    Assert.Equal(Status.BadInput, err.Status)

[<Fact>]
let ``closed pipeline reports TripleClosed`` () =
    use pipe = unwrap (Pipeline.init "singlemsg-triple-mac-v1" Opts.empty)
    unwrap (Pipeline.closeSession pipe)
    unwrap (Pipeline.closeSession pipe) // idempotent
    let err = unwrapError (Pipeline.encryptMessage pipe (Encoding.UTF8.GetBytes "payload"))
    Assert.Equal(Status.TripleClosed, err.Status)

[<Fact>]
let ``register profile mixed then duplicate`` () =
    // 8-entry width-256 innerHashes constellation, layers off.
    let opts =
        Opts.empty
        |> Opts.withRaw "mode" "singlemsg-nomac"
        |> Opts.withRaw "width" "256"
        |> Opts.withRaw "innerHashes" "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256"
        |> Opts.withRaw "keyBits" "1024"
        |> Opts.withRaw "parallaxOn" "false"
        |> Opts.withRaw "wrapperOn" "false"

    unwrap (Pipeline.registerProfile "fsharp-binding-test-mixed" opts)

    // The registered profile round-trips.
    use sender = unwrap (Pipeline.init "fsharp-binding-test-mixed" Opts.empty)
    use receiver = unwrap (Pipeline.openBlob "fsharp-binding-test-mixed" (Pipeline.blob sender) Opts.empty)
    let plain = Encoding.UTF8.GetBytes "custom profile"
    let wire = unwrap (Pipeline.encryptMessage sender plain)
    Assert.Equal<byte[]>(plain, unwrap (Pipeline.decryptMessage receiver wire))

    // Duplicate name is a distinct status.
    let err = unwrapError (Pipeline.registerProfile "fsharp-binding-test-mixed" opts)
    Assert.Equal(Status.ProfileExists, err.Status)

[<Fact>]
let ``opaque primitive name relay`` () =
    // An unknown inner-hash name is relayed to Go and rejected there
    // — the binding performs no name validation of its own.
    let opts = Opts.empty |> Opts.withInnerHash "no-such-hash"
    let err = unwrapError (Pipeline.init "singlemsg-triple-mac-v1" opts)
    Assert.NotEqual(Status.Ok, err.Status)

[<Fact>]
let ``status mapping preserves unnamed codes`` () =
    Assert.Equal(Status.Unknown 12, Status.ofCode 12)
    Assert.Equal(12, Status.toCode (Status.Unknown 12))
    Assert.Equal(Status.MacFailure, Status.ofCode 10)

    for code in [ 0; 1; 4; 5; 10; 19; 25; 26; 99 ] do
        Assert.Equal(code, Status.toCode (Status.ofCode code))

[<Fact>]
let ``ItbError get raises ItbFailure carrying the error`` () =
    let err = unwrapError (Pipeline.init "no-such-profile" Opts.empty)

    let raised =
        Assert.Throws<ItbFailure>(fun () -> ItbError.get (Error err: Result<unit, ItbError>) |> ignore)

    match raised :> exn with
    | ItbFailure carried -> Assert.Equal(err, carried)
    | _ -> failwith "unreachable"

[<Fact>]
let ``failed itb computation expression short-circuits`` () =
    let mutable reached = false

    let result =
        itb {
            use! pipe = Pipeline.init "no-such-profile" Opts.empty
            reached <- true
            let! wire = Pipeline.encryptMessage pipe [| 1uy |]
            return wire
        }

    Assert.False reached
    Assert.Equal(Status.BadInput, (unwrapError result).Status)
