// Shared declarations of the utility: the cipher-surface selector, the
// resolved command line, the run-wide state every unit reaches, and the
// two helpers — the worker-error recorder and the library-error
// rendering — that both the worker and the maintenance unit call.
//
// F#-specific. A file may only reference files compiled before it, so
// the mutually-referencing pieces the other implementations keep inside
// their worker and main units live here, in the same role a C
// implementation's shared header plays: the declarations several units
// need, in one place, ahead of all of them.

namespace Everanium.Itb3.FSharp.Loop

open System
open System.Diagnostics
open System.Globalization
open System.Threading
open Everanium.Itb3.FSharp
open Everanium.Itb3.FSharp.Loop.Payload

/// Cipher surfaces the --shape flag selects.
type Shape =
    /// Session pump: begin / write / read / end.
    | Stream
    /// Single Message: one whole-buffer call.
    | Message
    /// Stream surface, one whole-buffer call.
    | StreamOneShot
    /// All three, rotating by iteration number.
    | Both

/// The resolved command line.
type Config =
    { mutable DurationNs: int64
      Iterations: int64
      WorkersRequested: int
      Workers: int
      Shape: Shape
      Hash: string
      Mac: string
      Payload: int64
      mutable Memlimit: int64
      MemlimitAuto: bool
      Gogc: int
      Parallax: bool
      Wrapper: bool
      Profile: string
      KeyBits: int64
      NonceBits: int64
      ChunkSize: int64
      BarrierFill: int64
      Gomaxprocs: int
      RekeyEvery: int64
      BlobCycleEvery: int64
      PayloadMode: PayloadMode
      Seed: uint64
      JsonOutput: bool
      Memprofile: string }

/// The Pipeline handles and their retained blobs, behind the lock that
/// keeps iterations clear of handle mutation.
type Pipes() =
    member val Stream: Pipeline option = None with get, set
    member val Msg: Pipeline option = None with get, set
    /// The blob Init handed out, replaced by every rekey; the input of
    /// the next blob reopen.
    member val StreamBlob: byte[] = Array.empty with get, set
    member val MsgBlob: byte[] = Array.empty with get, set

/// One worker's counters, read by the summary after every worker has
/// returned, and the error it stopped on.
type Counters() =
    // F#-specific. Interlocked takes its target by reference, which an
    // auto-property cannot supply, so the five counters are mutable
    // fields rather than properties.
    [<DefaultValue>]
    val mutable Iters: int64

    [<DefaultValue>]
    val mutable BytesEnc: int64

    [<DefaultValue>]
    val mutable BytesDec: int64

    [<DefaultValue>]
    val mutable NanosEnc: int64

    [<DefaultValue>]
    val mutable NanosDec: int64

    member val ErrorLock = obj ()
    member val Error: string option = None with get, set

/// One worker's private state, owned by its thread: its plaintext, its
/// reusable pump accumulators, its generator.
type WorkerState() =
    member val Id = 0 with get, set
    member val Plaintext: byte[] = Array.empty with get, set
    member val PayloadMode = Fixed with get, set
    member val Seeded = false with get, set
    member val Rng = 0UL with get, set
    member val Wire = new IO.MemoryStream()
    member val Plain = new IO.MemoryStream()
    member val Scratch: byte[] = Array.empty with get, set

/// The state every worker shares.
type RunState() =
    /// The stop request is read by every worker before every iteration
    /// and written by the deadline, a signal and a failing worker, so it
    /// is a volatile field rather than an auto-property.
    let mutable stop = 0

    member _.Stop
        with get () = Volatile.Read(&stop) <> 0
        and set (v: bool) = Volatile.Write(&stop, (if v then 1 else 0))

    member val Cfg: Config = Unchecked.defaultof<Config> with get, set
    member val StreamProfile = "" with get, set
    member val MsgProfile = "" with get, set
    /// Handle mutation. Iterations hold the read side for their whole
    /// encrypt → decrypt → compare; rekey and blob reopen take the
    /// write side, so no cipher call is in flight while a handle's
    /// keying changes or the handle itself is swapped, and no encrypt is
    /// separated from its decrypt by either.
    member val PipesLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion)
    member val Pipes = Pipes() with get, set
    member val Rekeys = 0L with get, set
    member val BlobCycles = 0L with get, set
    member val Workers: Counters[] = Array.empty with get, set
    /// Warmup barrier: workers arrive at WarmupDone after iteration 0
    /// and at Release once main has taken the baselines.
    member val WarmupDone = new Barrier(1) with get, set
    member val Release = new Barrier(1) with get, set
    member val DoneLock = obj ()
    /// Guards the two aggregate maintenance counters.
    member val CounterLock = obj ()
    member val Active = 0 with get, set
    member val FinishTimestamp = 0L with get, set
    member val RssWarmup = 0L with get, set
    member val RssPeak = 0L with get, set
    member val RssFinal = 0L with get, set
    member val PoolWarmup: int64[] = Array.empty with get, set
    member val PoolSteady: int64[] = Array.empty with get, set

[<AutoOpen>]
module Common =

    let inv = CultureInfo.InvariantCulture

    /// --goroutines ceiling; the harness targets modest hosts and each
    /// worker pins payload-sized buffers for the whole run.
    let MaxWorkers = 10

    /// The concurrency mode this binding implements, as the summary
    /// reports it (shared-handle / independent-handles / single).
    let Concurrency = "shared-handle"

    /// Largest slice fed to a stream session per write; the drain after
    /// every write uses the same bound.
    let PumpSlice = 1 <<< 20

    let private shapeNames =
        [ "stream", Stream; "message", Message; "stream_one_shot", StreamOneShot; "both", Both ]

    let shapeName (shape: Shape) : string =
        shapeNames
        |> List.tryPick (fun (n, s) -> if s = shape then Some n else None)
        |> Option.defaultValue "stream"

    let parseShape (s: string) : Shape option =
        shapeNames |> List.tryPick (fun (n, sh) -> if n = s then Some sh else None)

    /// Prints one prefixed status line to stdout.
    let logLine (line: string) = Console.Out.WriteLine("[loop] " + line)

    let onOff (b: bool) = if b then "on" else "off"

    /// Renders an encoder policy env value for the summary: the raw
    /// string when set, "default" when the shipped ladder applies.
    let policyLabel (name: string) : string =
        let v = Environment.GetEnvironmentVariable name

        if String.IsNullOrWhiteSpace v then "default" else v.TrimStart()

    let private nsPerTick = 1e9 / float Stopwatch.Frequency

    /// Nanoseconds elapsed since a Stopwatch.GetTimestamp reading.
    let elapsedNs (since: int64) : int64 =
        int64 (float (Stopwatch.GetTimestamp() - since) * nsPerTick)

    let ticksToNs (ticks: int64) : int64 = int64 (float ticks * nsPerTick)

    /// Renders a binding error the way every implementation reports a
    /// failed library call: `status <code>: <last error>`. The library
    /// assembles the whole sentence — the class of failure and the case
    /// that raised it — so this reports what arrived and composes
    /// nothing.
    let detail (e: ItbError) : string =
        // The C# layer under this binding folds the diagnostic into
        // the exception message behind a fixed prefix; strip that
        // prefix to recover the library's own text.
        let message =
            if e.Detail.StartsWith("itb: status=", StringComparison.Ordinal) then
                match e.Detail.IndexOf("): ", StringComparison.Ordinal) with
                | -1 -> e.Detail
                | i -> e.Detail.Substring(i + 3)
            else
                e.Detail

        "status " + e.Code.ToString inv + ": " + message

    /// Records the worker's error text (first error wins) and requests a
    /// stop of the whole run.
    let fail (r: RunState) (id: int) (text: string) =
        let c = r.Workers[id]

        lock c.ErrorLock (fun () ->
            if c.Error.IsNone then
                c.Error <- Some text)

        r.Stop <- true
