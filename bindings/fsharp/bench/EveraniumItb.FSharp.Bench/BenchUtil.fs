// Shared timing + reporting helpers for the F# binding
// micro-benchmarks. Wall-clock via Stopwatch; output is a
// fixed-width table:
//
//   bench             size     mb_per_sec
//   message           1 MiB    <n>
//   ...
//
// Bench configuration is driven by environment variables so a
// side-by-side comparison with the root Go bench harness is
// straightforward:
//
//   ITB_NONCE_BITS     nonce width (default 512)
//   ITB_KEY_BITS       key bits (default 1024)
//   ITB_WITH_PARALLAX  parallax layer on/off (default false)
//   ITB_WITH_WRAPPER   wrapper layer on/off (default false)
//   ITB_INNER_HASH     opaque hash name (default: profile's)
//   ITB_PROFILE        profile name override
//   ITB_BENCH_MIN_SEC  per-case wall-clock budget (default 5.0)

module EveraniumItb.FSharp.Bench.BenchUtil

open System
open System.Diagnostics
open System.Globalization
open EveraniumItb.FSharp

/// Iteration floor per case.
let private minIters = 3L

/// Payload sizes exercised by both shapes.
let sizes = [ 1 <<< 20; 16 <<< 20; 64 <<< 20 ]

let private env (name: string) : string option =
    match Environment.GetEnvironmentVariable name with
    | null
    | "" -> None
    | value -> Some value

let minSeconds () : float =
    env "ITB_BENCH_MIN_SEC"
    |> Option.bind (fun raw ->
        match Double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture) with
        | true, v when v > 0.0 -> Some v
        | _ -> None)
    |> Option.defaultValue 5.0

let private envLong (name: string) (fallback: int64) : int64 =
    env name
    |> Option.bind (fun raw ->
        match Int64.TryParse raw with
        | true, v -> Some v
        | _ -> None)
    |> Option.defaultValue fallback

let private envBool (name: string) : bool =
    match env name with
    | Some "true"
    | Some "1" -> true
    | _ -> false

/// Reads the bench-shape env vars and builds an Opts. Defaults match
/// root Go BENCH3.md so numbers are directly comparable.
let buildOpts () : Opts =
    let baseOpts =
        Opts.empty
        |> Opts.withNonceBits (envLong "ITB_NONCE_BITS" 512L)
        |> Opts.withKeyBits (envLong "ITB_KEY_BITS" 1024L)
        |> Opts.withParallax (envBool "ITB_WITH_PARALLAX")
        |> Opts.withWrapper (envBool "ITB_WITH_WRAPPER")

    match env "ITB_INNER_HASH" with
    | Some name -> baseOpts |> Opts.withInnerHash name
    | None -> baseOpts

let profileName (fallback: string) : string =
    env "ITB_PROFILE" |> Option.defaultValue fallback

let header () : unit =
    printfn "%-17s %-8s mb_per_sec" "bench" "size"

let private sizeLabel (size: int) : string =
    if size >= (1 <<< 20) then $"{size >>> 20} MiB" else $"{size >>> 10} KiB"

/// Runs `run` until the wall-clock budget is spent (with an
/// iteration floor + one untimed warm-up), then prints one table
/// row.
let benchCase (name: string) (size: int) (run: unit -> unit) : unit =
    run () // warm-up
    let budget = minSeconds ()
    let clock = Stopwatch.StartNew()
    let mutable iters = 0L

    while clock.Elapsed.TotalSeconds < budget || iters < minIters do
        run ()
        iters <- iters + 1L

    let elapsed = clock.Elapsed.TotalSeconds
    let mb = float size * float iters / (1024.0 * 1024.0)
    printfn "%-17s %-8s %s" name (sizeLabel size) ((mb / elapsed).ToString("F1", CultureInfo.InvariantCulture))

/// CSPRNG-filled payload so plaintext content matches the root Go
/// bench (crypto/rand). Never inside the timing loop.
let payload (n: int) : byte[] =
    let buf = Array.zeroCreate n
    Security.Cryptography.RandomNumberGenerator.Fill(Span buf)
    buf
