// Long-run stress harness. The loop utility holds one Pipeline handle
// per exercised cipher surface for minutes, hammers it with concurrent
// encrypt → decrypt → compare round-trips from N worker threads,
// rotates the outer masters and reopens the handle from its session
// blob on a schedule, and reports whether the process survived with
// every byte intact. It is the F# binding's counterpart of the Go
// harness under tools/loop: the same flags, the same round structure,
// the same summary in both renderings.
//
// The default shape is full production: the Streaming AEAD profile with
// parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
// 1024-bit keys, and the compile-in 512-bit nonce width, driven through
// a stream session by three workers for five minutes on 16 MiB
// plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
// held for the whole run, so any cross-call state leakage inside the
// Pipeline surfaces as a data mismatch between workers rather than
// cancelling out.
//
// A failure is one of two things. A cipher, rekey or load call that
// returns a non-OK status is a worker error: the run stops, the summary
// lists it, the verdict is FAIL and the exit code 1. A round-trip that
// returns without error but with different bytes is a data mismatch:
// the process terminates on the spot with exit code 3, printing the
// worker, the iteration and the first differing offset, and no summary
// — the state that produced the wrong bytes is the evidence. A crash
// inside the shared library or the host runtime has no exit code of its
// own here; surfacing it is what the utility is for. This binding runs
// a Go c-shared runtime and CoreCLR in one process, two runtimes that
// each drive threads through signals, which is the interaction the long
// run is meant to expose.
//
// Usage:
//
//   ./bin/Release/net10.0/Everanium.LibItb3.FSharp.Loop --duration 5m \
//          --goroutines 3 --shape stream --hash areion512 \
//          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
//          --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.

module Everanium.Itb3.FSharp.Loop.Main

open System
open System.Diagnostics
open System.Globalization
open System.Runtime.InteropServices
open System.Threading
open Everanium.Itb3.FSharp
open Everanium.Itb3.FSharp.Loop
open Everanium.Itb3.FSharp.Loop.Size

/// Profiles the shape-based pair is built against when --profile is
/// empty.
let private defaultStreamProfile = "streaming-aead-triple-mac-v1"
let private defaultMessageProfile = "singlemsg-triple-mac-v1"

/// The keystream-capable primitive supplied for a layer a profile leaves
/// unnamed: PRF-grade, so sound outside the barrier, and the closest
/// relative of the AES-based inner primitive whose profiles need the
/// fill.
let private keystreamFillCipher = "aescmac"

/// The parallax segment size a filled palette runs with — the library's
/// own default; a schedule rejects zero.
let private keystreamFillSegment = 4093L

// ------------------------------------------------------------------
// Flags
// ------------------------------------------------------------------

/// The raw flag values before validation.
type private RawFlags() =
    member val BarrierFill = 0L with get, set
    member val BlobCycleEvery = 0L with get, set
    member val ChunkSize = "0" with get, set
    member val Duration = "5m" with get, set
    member val Gogc = 0L with get, set
    member val Gomaxprocs = 0L with get, set
    member val Goroutines = 3L with get, set
    member val Hash = "areion512" with get, set
    member val Iterations = 0L with get, set
    member val JsonOutput = false with get, set
    member val KeyBits = 0L with get, set
    member val Mac = "hmac-blake3" with get, set
    member val Memlimit = "auto" with get, set
    member val Memprofile = "" with get, set
    member val NonceBits = 0L with get, set
    member val Parallax = "on" with get, set
    member val PayloadMode = "fixed" with get, set
    member val PayloadSize = "16MB" with get, set
    member val Profile = "" with get, set
    member val RekeyEvery = 0L with get, set
    member val Seed = 0UL with get, set
    member val Shape = "stream" with get, set
    member val Wrapper = "on" with get, set

/// One command-line flag: its name, the type label the usage prints, its
/// help text, whether it takes a value, the default-value suffix the
/// usage appends, and the store that parses a value into the raw flags.
/// Values are validated after the whole line is parsed. The table is in
/// alphabetical order — the order the usage prints.
type private Flag =
    { Name: string
      TypeLabel: string
      Help: string
      IsBool: bool
      DefaultSuffix: string
      Store: RawFlags -> string -> bool }

let private defaultOfInt (v: int64) =
    if v <> 0L then " (default " + d v + ")" else ""

let private defaultOfStr (v: string) =
    if v.Length > 0 then " (default \"" + v + "\")" else ""

let private storeInt (set: RawFlags -> int64 -> unit) (fl: RawFlags) (s: string) =
    match Int64.TryParse(s, NumberStyles.AllowLeadingSign, inv) with
    | true, v ->
        set fl v
        true
    | _ -> false

let private storeStr (set: RawFlags -> string -> unit) (fl: RawFlags) (s: string) =
    set fl s
    true

let private flags: Flag list =
    let dflt = RawFlags()

    [ { Name = "barrier-fill"
        TypeLabel = "int"
        Help = "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"
        IsBool = false
        DefaultSuffix = defaultOfInt dflt.BarrierFill
        Store = storeInt (fun f v -> f.BarrierFill <- v) }
      { Name = "blob-cycle-every"
        TypeLabel = "int"
        Help = "reopen each pipeline from its session blob every N iterations per worker; 0 = never"
        IsBool = false
        DefaultSuffix = ""
        Store = storeInt (fun f v -> f.BlobCycleEvery <- v) }
      { Name = "chunk-size"
        TypeLabel = "string"
        Help =
          "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.ChunkSize
        Store = storeStr (fun f v -> f.ChunkSize <- v) }
      { Name = "duration"
        TypeLabel = "duration"
        Help = "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Duration
        Store = storeStr (fun f v -> f.Duration <- v) }
      { Name = "gogc"
        TypeLabel = "int"
        Help = "GC trigger percentage; 0 = leave the runtime default"
        IsBool = false
        DefaultSuffix = defaultOfInt dflt.Gogc
        Store = storeInt (fun f v -> f.Gogc <- v) }
      { Name = "gomaxprocs"
        TypeLabel = "int"
        Help = "Go runtime GOMAXPROCS override; 0 = inherit from the environment"
        IsBool = false
        DefaultSuffix = defaultOfInt dflt.Gomaxprocs
        Store = storeInt (fun f v -> f.Gomaxprocs <- v) }
      { Name = "goroutines"
        TypeLabel = "int"
        Help =
          "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1"
        IsBool = false
        DefaultSuffix = defaultOfInt dflt.Goroutines
        Store = storeInt (fun f v -> f.Goroutines <- v) }
      { Name = "hash"
        TypeLabel = "string"
        Help = "inner ITB hash primitive name"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Hash
        Store = storeStr (fun f v -> f.Hash <- v) }
      { Name = "iterations"
        TypeLabel = "int"
        Help = "fixed per-worker iteration count; 0 = duration-based"
        IsBool = false
        DefaultSuffix = ""
        Store = storeInt (fun f v -> f.Iterations <- v) }
      { Name = "json-output"
        TypeLabel = ""
        Help = "print the final summary as one compact JSON object instead of log lines"
        IsBool = true
        DefaultSuffix = ""
        Store =
          fun f s ->
              match s with
              | "true" ->
                  f.JsonOutput <- true
                  true
              | "false" ->
                  f.JsonOutput <- false
                  true
              | _ -> false }
      { Name = "key-bits"
        TypeLabel = "int"
        Help = "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"
        IsBool = false
        DefaultSuffix = defaultOfInt dflt.KeyBits
        Store = storeInt (fun f v -> f.KeyBits <- v) }
      { Name = "mac"
        TypeLabel = "string"
        Help = "MAC primitive name"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Mac
        Store = storeStr (fun f v -> f.Mac <- v) }
      { Name = "memlimit"
        TypeLabel = "string"
        Help =
          "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Memlimit
        Store = storeStr (fun f v -> f.Memlimit <- v) }
      { Name = "memprofile"
        TypeLabel = "string"
        Help = "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Memprofile
        Store = storeStr (fun f v -> f.Memprofile <- v) }
      { Name = "nonce-bits"
        TypeLabel = "int"
        Help = "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"
        IsBool = false
        DefaultSuffix = defaultOfInt dflt.NonceBits
        Store = storeInt (fun f v -> f.NonceBits <- v) }
      { Name = "parallax"
        TypeLabel = "string"
        Help = "parallax layer: on | off"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Parallax
        Store = storeStr (fun f v -> f.Parallax <- v) }
      { Name = "payload-mode"
        TypeLabel = "string"
        Help = "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.PayloadMode
        Store = storeStr (fun f v -> f.PayloadMode <- v) }
      { Name = "payload-size"
        TypeLabel = "string"
        Help = "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.PayloadSize
        Store = storeStr (fun f v -> f.PayloadSize <- v) }
      { Name = "profile"
        TypeLabel = "string"
        Help =
          "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Profile
        Store = storeStr (fun f v -> f.Profile <- v) }
      { Name = "rekey-every"
        TypeLabel = "int"
        Help = "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never"
        IsBool = false
        DefaultSuffix = ""
        Store = storeInt (fun f v -> f.RekeyEvery <- v) }
      { Name = "seed"
        TypeLabel = "uint"
        Help =
          "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts"
        IsBool = false
        DefaultSuffix = ""
        Store =
          fun f s ->
              match UInt64.TryParse(s, NumberStyles.None, inv) with
              | true, v ->
                  f.Seed <- v
                  true
              | _ -> false }
      { Name = "shape"
        TypeLabel = "string"
        Help = "cipher surface to exercise: stream | message | stream_one_shot | both"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Shape
        Store = storeStr (fun f v -> f.Shape <- v) }
      { Name = "wrapper"
        TypeLabel = "string"
        Help = "wrapper (Outer cipher) layer: on | off"
        IsBool = false
        DefaultSuffix = defaultOfStr dflt.Wrapper
        Store = storeStr (fun f v -> f.Wrapper <- v) } ]

let private usage () =
    Console.Error.WriteLine "Usage of loop:"

    for fl in flags do
        Console.Error.WriteLine(if fl.TypeLabel.Length = 0 then "  -" + fl.Name else "  -" + fl.Name + " " + fl.TypeLabel)
        Console.Error.WriteLine("    \t" + fl.Help + fl.DefaultSuffix)

/// Parses argv into the raw flag values. Accepts -name value, --name
/// value, -name=value and --name=value; a boolean flag takes no value
/// unless given as -name=true / -name=false. Some true for -h / --help
/// (usage printed); None after printing the error.
let private parseArgv (args: string[]) (f: RawFlags) : bool option =
    let mutable i = 0
    let mutable result = Some false
    let mutable running = true

    while running && i < args.Length do
        let arg = args[i]

        if arg.Length <= 1 || arg[0] <> '-' then
            Console.Error.WriteLine("loop: unexpected positional arguments: [" + arg + "]")
            result <- None
            running <- false
        else

        let raw = if arg.StartsWith("--", StringComparison.Ordinal) then arg.Substring 2 else arg.Substring 1

        if raw = "h" || raw = "help" then
            usage ()
            result <- Some true
            running <- false
        else

        let name, inline_ =
            match raw.IndexOf '=' with
            | -1 -> raw, None
            | eq -> raw.Substring(0, eq), Some(raw.Substring(eq + 1))

        match flags |> List.tryFind (fun fl -> fl.Name = name) with
        | None ->
            Console.Error.WriteLine("loop: flag provided but not defined: -" + name)
            usage ()
            result <- None
            running <- false
        | Some fl ->
            let value =
                match inline_ with
                | Some v -> Some v
                | None when fl.IsBool -> Some "true"
                | None ->
                    i <- i + 1

                    if i >= args.Length then
                        Console.Error.WriteLine("loop: flag needs an argument: -" + fl.Name)
                        None
                    else
                        Some args[i]

            match value with
            | None ->
                result <- None
                running <- false
            | Some v ->
                if not (fl.Store f v) then
                    Console.Error.WriteLine("loop: invalid value \"" + v + "\" for flag -" + fl.Name)
                    result <- None
                    running <- false
                else
                    i <- i + 1

    result

/// Whether name is in the shipped hash registry the binding returns.
let private hashRegistered (name: string) : bool =
    match Pipeline.hashNames () with
    | Ok names -> names |> List.contains name
    | Error _ -> false

/// Resolves a registered profile to the shape family its record's mode
/// exposes by reading the record through the binding's lookup: a mode
/// beginning with "streaming" exposes the stream surfaces, one beginning
/// with "singlemsg" the message surface, "blob-only" none. Prints the
/// validation message and returns None on rejection.
let private profileSurface (name: string) : Shape option =
    match Pipeline.lookup name with
    | Error _ ->
        Console.Error.WriteLine("loop: --profile \"" + name + "\" is not a registered triple profile")
        None
    | Ok p ->
        if p.Mode.StartsWith("streaming", StringComparison.Ordinal) then
            Some Stream
        elif p.Mode.StartsWith("singlemsg", StringComparison.Ordinal) then
            Some Message
        else
            Console.Error.WriteLine(
                "loop: --profile \"" + name + "\" carries no cipher surface (blob-only mode)"
            )

            None

/// Applies a --profile's surface to the requested shape: a
/// message-surface profile forces message; a stream-surface profile
/// keeps stream or stream_one_shot as requested and turns message or
/// both into stream.
let private narrowShape (requested: Shape) (surface: Shape) : Shape =
    if surface = Message then Message
    elif requested = StreamOneShot then StreamOneShot
    else Stream

/// Builds the resolved config from argv. (None, 0) for help; (None, 2)
/// after printing "loop: <message>" for the first failing rule.
let private parseFlags (args: string[]) : Config option * int =
    let f = RawFlags()

    match parseArgv args f with
    | None -> None, 2
    | Some true -> None, 0
    | Some false ->

    let reject (message: string) =
        Console.Error.WriteLine("loop: " + message)
        None, 2

    let parsedDuration = parseDuration f.Duration

    if parsedDuration.IsNone || parsedDuration.Value <= 0L then
        reject ("--duration must be positive, got " + f.Duration)
    else

    let durationNs = parsedDuration.Value

    if f.Iterations < 0L then
        reject ("--iterations must be >= 0, got " + d f.Iterations)
    elif f.Goroutines < 1L || f.Goroutines > int64 MaxWorkers then
        reject ("--goroutines must be in 1.." + string MaxWorkers + ", got " + d f.Goroutines)
    else

    // Concurrency mode. This binding runs shared-handle: CLR threads call
    // into one Pipeline handle concurrently. The handle under the F#
    // Pipeline type is the C# binding's SafeHandle over an opaque Go-side
    // registry key, every entry it is passed to is re-entrant after
    // construction, and nothing in either layer is thread-affine, so
    // --goroutines is the thread count verbatim, never clamped.
    let workers = int f.Goroutines

    match parseShape f.Shape with
    | None ->
        reject ("--shape must be stream | message | stream_one_shot | both, got \"" + f.Shape + "\"")
    | Some requestedShape ->

    if not (hashRegistered f.Hash) then
        reject ("--hash \"" + f.Hash + "\" is not a registered hash primitive")
    else

    // --mac is validated by Init: the C ABI enumerates no MAC names.
    match parseSize f.PayloadSize with
    | None -> reject ("--payload-size: invalid size \"" + f.PayloadSize + "\"")
    | Some payload when payload < 1L -> reject "--payload-size must be at least 1 byte"
    | Some payload ->

    let memlimitAuto = f.Memlimit = "auto"

    let memlimitParsed =
        if memlimitAuto then
            Some(if workers <= 3 then 1L <<< 30 else 256L <<< 20)
        else
            parseSize f.Memlimit

    match memlimitParsed with
    | None -> reject ("--memlimit: invalid size \"" + f.Memlimit + "\"")
    | Some memlimit ->

    if f.Gogc < 0L then
        reject ("--gogc must be >= 0, got " + d f.Gogc)
    elif f.Parallax <> "on" && f.Parallax <> "off" then
        reject ("--parallax must be on | off, got \"" + f.Parallax + "\"")
    elif f.Wrapper <> "on" && f.Wrapper <> "off" then
        reject ("--wrapper must be on | off, got \"" + f.Wrapper + "\"")
    else

    let narrowed =
        if f.Profile.Length = 0 then
            Some requestedShape
        else
            profileSurface f.Profile |> Option.map (narrowShape requestedShape)

    match narrowed with
    | None -> None, 2
    | Some shape ->

    if not (List.contains f.KeyBits [ 0L; 512L; 1024L; 2048L ]) then
        reject ("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got " + d f.KeyBits)
    elif not (List.contains f.NonceBits [ 0L; 128L; 256L; 512L ]) then
        reject ("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got " + d f.NonceBits)
    elif not (List.contains f.BarrierFill [ 0L; 1L; 2L; 4L; 8L; 16L; 32L ]) then
        reject (
            "--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got "
            + d f.BarrierFill
        )
    else

    match parseSize f.ChunkSize with
    | None -> reject ("--chunk-size: invalid size \"" + f.ChunkSize + "\"")
    | Some chunkSize ->

    if f.Gomaxprocs < 0L then
        reject ("--gomaxprocs must be > 0 when specified, got " + d f.Gomaxprocs)
    elif f.RekeyEvery < 0L then
        reject ("--rekey-every must be >= 0, got " + d f.RekeyEvery)
    elif f.BlobCycleEvery < 0L then
        reject ("--blob-cycle-every must be >= 0, got " + d f.BlobCycleEvery)
    else

    match Payload.parseMode f.PayloadMode with
    | None ->
        reject (
            "--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \""
            + f.PayloadMode + "\""
        )
    | Some payloadMode ->

    Some
        { DurationNs = durationNs
          Iterations = f.Iterations
          WorkersRequested = workers
          Workers = workers
          Shape = shape
          Hash = f.Hash
          Mac = f.Mac
          Payload = payload
          Memlimit = memlimit
          MemlimitAuto = memlimitAuto
          Gogc = int f.Gogc
          Parallax = f.Parallax = "on"
          Wrapper = f.Wrapper = "on"
          Profile = f.Profile
          KeyBits = f.KeyBits
          NonceBits = f.NonceBits
          ChunkSize = chunkSize
          BarrierFill = f.BarrierFill
          Gomaxprocs = int f.Gomaxprocs
          RekeyEvery = f.RekeyEvery
          BlobCycleEvery = f.BlobCycleEvery
          PayloadMode = payloadMode
          Seed = f.Seed
          JsonOutput = f.JsonOutput
          Memprofile = f.Memprofile },
    0

// ------------------------------------------------------------------
// Signals
// ------------------------------------------------------------------

let mutable private signalSeen = 0
let private signalRegistrations = ResizeArray<PosixSignalRegistration>()

/// Graceful stop. SIGINT / SIGTERM set a flag the main thread polls while
/// it waits for the workers; it turns the flag into the stop request
/// every worker checks before starting an iteration, so a signal
/// interrupts nothing mid-call — the in-flight encrypt / decrypt /
/// compare completes, the worker returns, and the partial summary prints
/// with the verdict the completed iterations earned. .NET-specific: the
/// registration cancels the runtime's own default termination for both
/// signals, and the registration objects are held for the life of the
/// process because disposing one restores that default.
let private installSignals () =
    for sig_ in [ PosixSignal.SIGINT; PosixSignal.SIGTERM ] do
        signalRegistrations.Add(
            PosixSignalRegistration.Create(
                sig_,
                fun ctx ->
                    ctx.Cancel <- true
                    Volatile.Write(&signalSeen, 1)
            )
        )

// ------------------------------------------------------------------
// Pipelines
// ------------------------------------------------------------------

/// Supplies the keystream-capable primitive for every layer the profile
/// record leaves unnamed and the run engages: a missing parallax palette
/// becomes three copies of the fill cipher (with the library's default
/// segment size when the record carries none), a missing outer cipher
/// becomes the fill cipher. These are opts overrides that fold into the
/// resolved record the blob carries — a derived profile is never
/// registered, so no name the receiver did not agree to reaches the
/// wire. The second element is true when anything was filled; None after
/// printing the validation message.
let private fillKeystreamLayers
    (name: string)
    (opts: Opts)
    (wantParallax: bool)
    (wantWrapper: bool)
    : (Opts * bool) option =
    match Pipeline.lookup name with
    | Error _ ->
        Console.Error.WriteLine("loop: --profile \"" + name + "\" is not a registered triple profile")
        None
    | Ok p ->
        let mutable o = opts
        let mutable filled = false

        if wantParallax && p.Palette.Length = 0 then
            o <-
                o
                |> Opts.withParallaxPalette [ keystreamFillCipher; keystreamFillCipher; keystreamFillCipher ]

            if p.Segment = 0 then
                // A recipe that never carried a palette never carried a
                // segment size either, and the schedule rejects zero.
                o <- o |> Opts.withParallaxSegmentSize keystreamFillSegment

            filled <- true

        if wantWrapper && p.Outer.Length = 0 then
            o <- o |> Opts.withOuterCipher keystreamFillCipher
            filled <- true

        Some(o, filled)

/// Prints the construction line with the recipe read back from the blob
/// the Pipeline handed out, not echoed from the flags: every
/// construction override is proven to have reached the library by the
/// value the receiver would see. Record values that are empty (a No MAC
/// profile's MAC, a mixed profile's single hash) print as "-".
let private logPipelineInitialised (profile: string) (blob: byte[]) =
    let dash (s: string) = if String.IsNullOrEmpty s then "-" else s

    match Pipeline.inspect blob with
    | Error e ->
        logLine (
            "pipeline initialised: profile=" + profile + " blob=" + string blob.Length + " bytes (inspect: "
            + detail e + ")"
        )
    | Ok rec_ ->
        let orZero (v: Nullable<int>) = if v.HasValue then v.Value else 0

        logLine (
            "pipeline initialised: profile=" + profile + " blob=" + string blob.Length + " bytes hash="
            + dash rec_.Hash + " key-bits=" + string rec_.KeyBits + " nonce-bits="
            + string (orZero rec_.NonceBits) + " barrier-fill=" + string (orZero rec_.BarrierFill)
            + " chunk-size=" + string rec_.Chunk + " mac=" + dash rec_.Mac + " parallax="
            + onOff rec_.Parallax + " wrapper=" + onOff rec_.Wrapper
        )

/// Constructs one Pipeline against profile with every flag-carried
/// override in the opts string (zero values included — the shared
/// library treats zero as "profile default"), then obtains the Init blob
/// once through save: the binding's init entry does not hand the blob
/// back, and the bytes are the ones Init produced. Later blob reopens use
/// the retained blob; save is never called again.
let private buildPipeline (cfg: Config) (profile: string) : (Pipeline * byte[]) option =
    let baseOpts =
        Opts.empty
        |> Opts.withInnerHash cfg.Hash
        |> Opts.withMacName cfg.Mac
        |> Opts.withParallax cfg.Parallax
        |> Opts.withWrapper cfg.Wrapper
        |> Opts.withKeyBits cfg.KeyBits
        |> Opts.withNonceBits cfg.NonceBits
        |> Opts.withBarrierFill cfg.BarrierFill
        |> Opts.withChunkSize cfg.ChunkSize

    let resolved =
        if cfg.Profile.Length = 0 then
            Some(baseOpts, false)
        else
            fillKeystreamLayers cfg.Profile baseOpts cfg.Parallax cfg.Wrapper

    match resolved with
    | None -> None
    | Some(opts, filled) ->
        if filled then
            Console.Error.WriteLine(
                "loop: " + cfg.Profile + " leaves the requested keystream layers unnamed; "
                + keystreamFillCipher + " supplied for them"
            )

        match Pipeline.init profile opts with
        | Error e ->
            Console.Error.WriteLine("loop: Init(" + profile + "): " + detail e)
            None
        | Ok pipe ->
            match Pipeline.save pipe with
            | Error e ->
                Console.Error.WriteLine("loop: Save(" + profile + "): " + detail e)
                pipe.Dispose()
                None
            | Ok blob ->
                logPipelineInitialised profile blob
                Some(pipe, blob)

// ------------------------------------------------------------------
// Run
// ------------------------------------------------------------------

let private run (args: string[]) : int =
    match parseFlags args with
    | None, code -> code
    | Some cfg, _ ->

    // Runtime shaping. A long run under allocation churn grows the Go
    // heap inside the shared library without bound unless a soft limit
    // paces the collector, so a limit is always in force: an explicit
    // --memlimit is set as given, and auto caps the heap only when the
    // runtime reports no limit at all (a limit already installed from the
    // environment is left standing). The GC percentage and GOMAXPROCS are
    // set only when their flag is non-zero — a zero flag skips the setter
    // rather than calling it with zero, because zero is a real value to
    // the GC-percent setter, and a call would clobber whatever the
    // environment installed. All of it lands before any Pipeline exists
    // so the baselines are taken under the shaped runtime.
    if cfg.MemlimitAuto then
        if Runtime.setMemoryLimit -1L = Int64.MaxValue then
            Runtime.setMemoryLimit cfg.Memlimit |> ignore
    else
        Runtime.setMemoryLimit cfg.Memlimit |> ignore

    cfg.Memlimit <- Runtime.setMemoryLimit -1L

    if cfg.Gogc > 0 then
        Runtime.setGCPercent cfg.Gogc |> ignore

    if cfg.Gomaxprocs > 0 then
        Runtime.setGOMAXPROCS cfg.Gomaxprocs |> ignore

    logLine (
        "start: duration=" + humanDuration cfg.DurationNs + " iterations=" + d cfg.Iterations
        + " goroutines=" + string cfg.WorkersRequested + " workers=" + string cfg.Workers
        + " concurrency=" + Concurrency + " shape=" + shapeName cfg.Shape + " hash=" + cfg.Hash
        + " mac=" + cfg.Mac + " payload=" + humanBytes cfg.Payload + " memlimit="
        + humanBytes cfg.Memlimit + " parallax=" + onOff cfg.Parallax + " wrapper=" + onOff cfg.Wrapper
    )

    logLine (
        "overrides: profile=\"" + cfg.Profile + "\" key-bits=" + d cfg.KeyBits + " nonce-bits="
        + d cfg.NonceBits + " chunk-size=" + humanBytes cfg.ChunkSize + " barrier-fill="
        + d cfg.BarrierFill + " gomaxprocs=" + string cfg.Gomaxprocs + " rekey-every="
        + d cfg.RekeyEvery + " blob-cycle-every=" + d cfg.BlobCycleEvery + " payload-mode="
        + Payload.modeName cfg.PayloadMode + " seed=" + cfg.Seed.ToString inv + " json-output="
        + (if cfg.JsonOutput then "true" else "false")
    )

    logLine (
        "policy: microbatch-tiers=" + policyLabel "ITB_MICROBATCH_TIERS" + " hashpool-starters="
        + policyLabel "ITB_HASHPOOL_STARTERS"
    )

    // Pipeline construction — one shared handle per exercised shape.
    // stream and stream_one_shot share the streaming handle.
    let streamProfile = if cfg.Profile.Length = 0 then defaultStreamProfile else cfg.Profile
    let msgProfile = if cfg.Profile.Length = 0 then defaultMessageProfile else cfg.Profile
    let pipes = Pipes()

    let wantStream =
        cfg.Shape = Stream || cfg.Shape = StreamOneShot || cfg.Shape = Both

    let wantMsg = cfg.Shape = Message || cfg.Shape = Both

    let built =
        (if wantStream then
             match buildPipeline cfg streamProfile with
             | None -> false
             | Some(p, b) ->
                 pipes.Stream <- Some p
                 pipes.StreamBlob <- b
                 true
         else
             true)
        && (if wantMsg then
                match buildPipeline cfg msgProfile with
                | None -> false
                | Some(p, b) ->
                    pipes.Msg <- Some p
                    pipes.MsgBlob <- b
                    true
            else
                true)

    if not built then
        1
    else

    // Allocation posture. Per-worker plaintexts are allocated once and
    // held for the whole run (rotating mode refills them in place per
    // iteration); the pump accumulators and the drain scratch live inside
    // each worker and are reused across iterations; the message and
    // one-shot outputs are allocated by the binding per call and
    // reclaimed per iteration, as is the slice the pump hands to the
    // session's array-typed write. Under the default fixed CSPRNG mode
    // every worker's buffer is distinct, so cross-worker data crossover
    // is detectable; pattern modes trade that property for content
    // edge-case coverage.
    let states =
        [ for id in 0 .. cfg.Workers - 1 do
              let w = WorkerState()
              w.Id <- id
              w.Plaintext <- Array.zeroCreate (int cfg.Payload)
              w.PayloadMode <- cfg.PayloadMode
              w.Seeded <- cfg.Seed <> 0UL
              w.Rng <- Payload.seedWorker cfg.Seed id
              w.Scratch <- Array.zeroCreate PumpSlice
              let mutable rng = w.Rng
              let ok = Payload.fill cfg.PayloadMode w.Seeded &rng w.Plaintext
              w.Rng <- rng

              if not ok then
                  Console.Error.WriteLine "loop: payload fill: csprng"
                  exit 1

              w ]

    installSignals ()
    let r = RunState()
    r.Cfg <- cfg
    r.StreamProfile <- streamProfile
    r.MsgProfile <- msgProfile
    r.Pipes <- pipes
    r.Workers <- Array.init cfg.Workers (fun _ -> Counters())
    r.WarmupDone <- new Barrier(cfg.Workers + 1)
    r.Release <- new Barrier(cfg.Workers + 1)
    r.Active <- cfg.Workers

    // Warmup barrier. Every worker runs one iteration and waits; the
    // clock starts only once all of them have paid their first-call costs
    // (pool warm-up, lazy kernel dispatch, page faults on the payload
    // buffers, and on this runtime the tiered JIT's first pass over the
    // iteration body), and the RSS and pool baselines taken here describe
    // a process that has already run the whole cipher path once per
    // worker.
    let warmupStart = Stopwatch.GetTimestamp()

    let threads =
        states
        |> List.map (fun w ->
            let t = Thread((fun () -> Worker.run r w), IsBackground = false, Name = "loop-worker-" + string w.Id)
            t.Start()
            t)

    r.WarmupDone.SignalAndWait()
    let rssWarmup, _ = Summary.readRss ()
    let poolWarmup = Summary.poolSnapshot ()

    logLine (
        "warmup: " + string cfg.Workers + " workers x 1 iter completed in "
        + humanDuration (roundTo (elapsedNs warmupStart) 100_000_000L) + " (baseline rss="
        + humanBytes rssWarmup + ")"
    )

    // Open the gate; the duration is a deadline the waiter below enforces
    // in duration mode.
    let start = Stopwatch.GetTimestamp()
    r.Release.SignalAndWait()

    // Wait for every worker, polling every 100 ms so the deadline and a
    // signal are both noticed promptly.
    let finish =
        lock r.DoneLock (fun () ->
            while r.Active > 0 do
                if Volatile.Read(&signalSeen) <> 0 || (cfg.Iterations = 0L && elapsedNs start >= cfg.DurationNs) then
                    r.Stop <- true

                Monitor.Wait(r.DoneLock, 100) |> ignore

            if r.FinishTimestamp <> 0L then r.FinishTimestamp else start)

    let elapsed = ticksToNs (finish - start)
    let rssFinal, rssPeak = Summary.readRss ()
    let poolSteady = Summary.poolSnapshot ()

    for t in threads do
        t.Join()

    r.RssWarmup <- rssWarmup
    r.RssPeak <- rssPeak
    r.RssFinal <- rssFinal
    r.PoolWarmup <- poolWarmup
    r.PoolSteady <- poolSteady

    if cfg.Memprofile.Length > 0 then
        match Runtime.writeHeapProfile cfg.Memprofile with
        | Ok() -> logLine ("memprofile: heap profile written to " + cfg.Memprofile)
        | Error e -> Console.Error.WriteLine("loop: memprofile: " + detail e)

    let code = Summary.final r elapsed
    r.Pipes.Stream |> Option.iter (fun p -> p.Dispose())
    r.Pipes.Msg |> Option.iter (fun p -> p.Dispose())
    code

[<EntryPoint>]
let main args =
    // .NET-specific. Number rendering is part of the output contract, so
    // the process runs under the invariant culture rather than the
    // operator's locale; every formatter names the culture as well, and
    // this pin is the second line of defence.
    CultureInfo.DefaultThreadCurrentCulture <- CultureInfo.InvariantCulture
    CultureInfo.DefaultThreadCurrentUICulture <- CultureInfo.InvariantCulture
    run args
