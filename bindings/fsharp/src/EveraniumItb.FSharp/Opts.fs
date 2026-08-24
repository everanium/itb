// Immutable options value mirroring the C# binding's Opts builder.
//
// No validation happens here — every key and value is passed through
// to Go verbatim; libitb rejects unknown keys or bad values with a
// diagnostic surfaced via ItbError. Primitive / MAC / cipher /
// palette names are opaque strings.

namespace EveraniumItb.FSharp

/// Immutable, pipeable options for <c>Pipeline.init</c>,
/// <c>Pipeline.openBlob</c>, and <c>Pipeline.registerProfile</c>. An
/// empty value renders the empty query (pure profile defaults). Each
/// setter returns a new value; sharing a prefix between two
/// configurations is safe:
///
/// <code>
/// Opts.empty |> Opts.withNonceBits 512L |> Opts.withKeyBits 1024L
/// </code>
type Opts =
    { Pairs: (string * string) list }

[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Opts =

    /// The empty options value (pure profile defaults).
    let empty: Opts = { Pairs = [] }

    /// Escape hatch appending a raw <c>key=value</c> pair. Covers
    /// every key the Go side accepts, including the register-profile
    /// grammar (<c>mode</c>, <c>width</c>, <c>innerHashes</c>,
    /// <c>parallaxOn</c>, <c>wrapperOn</c>, …).
    let withRaw (key: string) (value: string) (opts: Opts) : Opts =
        { opts with Pairs = opts.Pairs @ [ key, value ] }

    let private hex (bytes: byte[]) : string =
        System.Convert.ToHexStringLower bytes

    let private boolStr (on: bool) : string = if on then "true" else "false"

    /// Hex-encodes the parallax master override (<c>pm</c>).
    let withPermMaster (master: byte[]) (opts: Opts) : Opts = withRaw "pm" (hex master) opts

    /// Hex-encodes the wrapper master override (<c>wm</c>).
    let withWrapMaster (master: byte[]) (opts: Opts) : Opts = withRaw "wm" (hex master) opts

    let withParallax (on: bool) (opts: Opts) : Opts = withRaw "withParallax" (boolStr on) opts

    let withWrapper (on: bool) (opts: Opts) : Opts = withRaw "withWrapper" (boolStr on) opts

    let withMaxWorkers (n: int64) (opts: Opts) : Opts = withRaw "maxWorkers" (string n) opts

    let withNonceBits (n: int64) (opts: Opts) : Opts = withRaw "nonceBits" (string n) opts

    let withBarrierFill (n: int64) (opts: Opts) : Opts = withRaw "barrierFill" (string n) opts

    let withChunkSize (n: int64) (opts: Opts) : Opts = withRaw "chunkSize" (string n) opts

    let withKeyBits (n: int64) (opts: Opts) : Opts = withRaw "keyBits" (string n) opts

    let withParallaxSegmentSize (n: int64) (opts: Opts) : Opts =
        withRaw "parallaxSegmentSize" (string n) opts

    let withMacName (name: string) (opts: Opts) : Opts = withRaw "macName" name opts

    let withInnerHash (name: string) (opts: Opts) : Opts = withRaw "innerHash" name opts

    let withOuterCipher (name: string) (opts: Opts) : Opts = withRaw "outerCipher" name opts

    /// Comma-joins the palette names (<c>parallaxPalette</c>).
    let withParallaxPalette (names: string list) (opts: Opts) : Opts =
        withRaw "parallaxPalette" (String.concat "," names) opts

    /// Replays the accumulated pairs into a fresh C# builder; the C#
    /// side owns query rendering and percent-encoding.
    let internal toNative (opts: Opts) : Itb.Opts =
        let native = Itb.Opts()
        for key, value in opts.Pairs do
            native.WithRaw(key, value) |> ignore
        native
