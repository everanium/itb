// Pair accumulation of the immutable Opts value (no FFI involved).
// Query rendering and percent-encoding are owned — and tested — by
// the C# layer; these tests pin the F# layer's key names, value
// formatting, ordering, and immutability.

module EveraniumItb.FSharp.Tests.OptsTests

open Xunit
open EveraniumItb.FSharp

[<Fact>]
let ``typed setters accumulate expected pairs in order`` () =
    let opts =
        Opts.empty
        |> Opts.withPermMaster [| 0xabuy; 0x01uy |]
        |> Opts.withWrapMaster [| 0xcduy; 0xefuy |]
        |> Opts.withParallax true
        |> Opts.withWrapper false
        |> Opts.withMaxWorkers 4L
        |> Opts.withNonceBits 512L
        |> Opts.withBarrierFill 4L
        |> Opts.withChunkSize 4096L
        |> Opts.withKeyBits 1024L
        |> Opts.withParallaxSegmentSize 65536L
        |> Opts.withMacName "hmac-blake3"
        |> Opts.withInnerHash "areion512"
        |> Opts.withOuterCipher "chacha20"
        |> Opts.withParallaxPalette [ "aescmac"; "chacha20"; "blake3" ]

    let expected =
        [ "pm", "ab01"
          "wm", "cdef"
          "withParallax", "true"
          "withWrapper", "false"
          "maxWorkers", "4"
          "nonceBits", "512"
          "barrierFill", "4"
          "chunkSize", "4096"
          "keyBits", "1024"
          "parallaxSegmentSize", "65536"
          "macName", "hmac-blake3"
          "innerHash", "areion512"
          "outerCipher", "chacha20"
          "parallaxPalette", "aescmac,chacha20,blake3" ]

    Assert.Equal<(string * string) list>(expected, opts.Pairs)

[<Fact>]
let ``withRaw appends and values are immutable`` () =
    let base' = Opts.empty |> Opts.withRaw "mode" "singlemsg-nomac"
    let extended = base' |> Opts.withRaw "width" "256"

    Assert.Equal<(string * string) list>([ "mode", "singlemsg-nomac" ], base'.Pairs)

    Assert.Equal<(string * string) list>(
        [ "mode", "singlemsg-nomac"; "width", "256" ],
        extended.Pairs
    )

[<Fact>]
let ``empty opts carries no pairs`` () = Assert.Empty Opts.empty.Pairs
