// The worker: its thread body (one warmup iteration, the warmup
// barrier, the main loop), one iteration, the session pump loop the
// stream shape drives, and the round-trip comparison that decides
// between a worker error and a data mismatch.

module Everanium.Itb3.FSharp.Loop.Worker

open System
open System.Diagnostics
open System.Threading
open Everanium.Itb3.FSharp
open Everanium.Itb3.FSharp.Loop
open Everanium.Itb3.FSharp.Loop.Size

/// Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
/// and ITB drives the chunk loop internally; the C ABI has no reader /
/// writer entry, so the caller drives it: open a session, feed slices of
/// at most 1 MiB, drain whatever the session has produced after every
/// write (a read before end never blocks), end, then drain until the
/// session reports finished (after end, a read on an empty spool blocks
/// until the terminal bytes arrive). The whole produced output lands in
/// the worker's reusable accumulator. The loop is written here rather
/// than delegated to the binding's pump convenience so it stands in the
/// utility, at the same place, in every language. On failure the result
/// names the failing call and carries its error.
let private pump
    (pipe: Pipeline)
    (encrypt: bool)
    (src: byte[])
    (srcLen: int)
    (acc: IO.MemoryStream)
    (scratch: byte[])
    : (string * ItbError) option =
    acc.SetLength 0L

    let opened =
        if encrypt then Stream.beginEncrypt pipe else Stream.beginDecrypt pipe

    match opened with
    | Error e -> Some("StreamBegin", e)
    | Ok session ->
        try
            let mutable failure = None
            let mutable off = 0

            while failure.IsNone && off < srcLen do
                let n = min PumpSlice (srcLen - off)
                let slice = Array.sub src off n

                match Stream.write session slice with
                | Error e -> failure <- Some("StreamWrite", e)
                | Ok() ->
                    let mutable draining = true

                    while failure.IsNone && draining do
                        match Stream.read session scratch with
                        | Error e -> failure <- Some("StreamRead", e)
                        | Ok res ->
                            if res.Count = 0 then
                                draining <- false
                            else
                                acc.Write(scratch, 0, res.Count)

                off <- off + n

            if failure.IsNone then
                match Stream.finish session with
                | Error e -> failure <- Some("StreamEnd", e)
                | Ok() ->
                    let mutable draining = true

                    while failure.IsNone && draining do
                        match Stream.read session scratch with
                        | Error e -> failure <- Some("StreamRead", e)
                        | Ok res ->
                            acc.Write(scratch, 0, res.Count)

                            if res.Finished then
                                draining <- false

            failure
        finally
            session.Dispose()

/// First offset at which a and b differ; the shorter length when one is
/// a prefix of the other.
let private firstDifference (a: byte[]) (aLen: int) (b: byte[]) (bLen: int) : int =
    let n = min aLen bLen
    let mutable i = 0

    while i < n && a[i] = b[i] do
        i <- i + 1

    i

/// Up to 16 bytes of buf from off as lowercase hex, or "-" when buf has
/// no bytes there.
let private hexWindow (buf: byte[]) (len: int) (off: int) : string =
    if off >= len then
        "-"
    else
        Convert.ToHexStringLower(ReadOnlySpan<byte>(buf, off, min 16 (len - off)))

/// Records a worker error for a failed cipher call.
let private cipherFail
    (r: RunState)
    (id: int)
    (iter: int64)
    (shape: Shape)
    (direction: string)
    (what: string option)
    (e: ItbError)
    =
    let head = "g" + string id + " iter " + d iter + " shape=" + shapeName shape + ": " + direction

    let text =
        match what with
        | Some w -> head + ": " + w + ": " + detail e
        | None -> head + ": " + detail e

    fail r id text

/// The body of one iteration that runs under the read lock:
/// pick the surface, encrypt, decrypt, compare, bump the counters.
let private iterateLocked (r: RunState) (w: WorkerState) (iter: int64) : bool =
    let c = r.Workers[w.Id]
    r.PipesLock.EnterReadLock()

    try
        // Shape dispatch. message is one whole-buffer call on the Single
        // Message Pipeline; stream_one_shot is one whole-buffer call on
        // the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
        // which routes to the same whole-buffer stream entry the Go
        // harness calls by name); stream opens a session on the same
        // streaming Pipeline and drives the chunk loop from here. Under
        // both the three rotate by iteration number so the session path
        // and the whole-buffer path alternate on one handle inside every
        // worker — the cross-path state-reuse hazard this harness exists
        // to catch.
        let shape =
            match r.Cfg.Shape with
            | Both ->
                match iter % 3L with
                | 0L -> Stream
                | 1L -> Message
                | _ -> StreamOneShot
            | s -> s

        // .NET-specific. The message and one-shot entries return a fresh
        // array per call that the collector reclaims at the end of the
        // iteration; the pump accumulators are the worker's own and are
        // reused. `got` / `gotLen` hold the round-trip output for either
        // posture, so one comparison below serves both.
        let outcome =
            match shape with
            | Stream ->
                let pipe = r.Pipes.Stream.Value
                let t0 = Stopwatch.GetTimestamp()

                match pump pipe true w.Plaintext w.Plaintext.Length w.Wire w.Scratch with
                | Some(what, e) ->
                    cipherFail r w.Id iter shape "encrypt" (Some what) e
                    None
                | None ->
                    Interlocked.Add(&c.NanosEnc, elapsedNs t0) |> ignore
                    let t1 = Stopwatch.GetTimestamp()

                    match pump pipe false (w.Wire.GetBuffer()) (int w.Wire.Length) w.Plain w.Scratch with
                    | Some(what, e) ->
                        cipherFail r w.Id iter shape "decrypt" (Some what) e
                        None
                    | None ->
                        Interlocked.Add(&c.NanosDec, elapsedNs t1) |> ignore
                        Some(w.Plain.GetBuffer(), int w.Plain.Length)
            | StreamOneShot
            | Message ->
                let pipe, encryptOne, decryptOne =
                    if shape = Message then
                        r.Pipes.Msg.Value, Pipeline.encryptMessage, Pipeline.decryptMessage
                    else
                        r.Pipes.Stream.Value, Pipeline.encryptStreamOneShot, Pipeline.decryptStreamOneShot

                let t0 = Stopwatch.GetTimestamp()

                match encryptOne pipe w.Plaintext with
                | Error e ->
                    cipherFail r w.Id iter shape "encrypt" None e
                    None
                | Ok wire ->
                    Interlocked.Add(&c.NanosEnc, elapsedNs t0) |> ignore
                    let t1 = Stopwatch.GetTimestamp()

                    match decryptOne pipe wire with
                    | Error e ->
                        cipherFail r w.Id iter shape "decrypt" None e
                        None
                    | Ok back ->
                        Interlocked.Add(&c.NanosDec, elapsedNs t1) |> ignore
                        Some(back, back.Length)
            | Both -> failwith "resolved above"

        // Failure model. A cipher call that returns a non-OK status is a
        // worker error: it is recorded, the run is asked to stop, the
        // other workers finish their in-flight iteration, and the error
        // is listed in the summary with the FAIL verdict. A round-trip
        // that returns OK with different bytes is a data mismatch: the
        // process terminates here, without summary or cleanup, because
        // the Pipeline state that produced the wrong bytes is the
        // evidence and nothing that runs afterwards may touch it.
        // .NET-specific: Environment.Exit is the exit that leaves handle
        // finalizers unrun, which is the point — a finalizer-driven free
        // would release the very state the operator is meant to inspect.
        match outcome with
        | None -> false
        | Some(got, gotLen) ->
            let want = w.Plaintext

            if
                gotLen <> want.Length
                || not (ReadOnlySpan<byte>(want).SequenceEqual(ReadOnlySpan<byte>(got, 0, gotLen)))
            then
                let off = firstDifference want want.Length got gotLen

                Console.Error.WriteLine(
                    "loop: DATA MISMATCH g" + string w.Id + " iter " + d iter + " shape=" + shapeName shape
                    + ": want " + string want.Length + " bytes, got " + string gotLen
                    + " bytes, first difference at offset " + string off + ": want "
                    + hexWindow want want.Length off + " got " + hexWindow got gotLen off
                )

                Console.Error.Flush()
                Console.Out.Flush()
                exit 3

            Interlocked.Increment(&c.Iters) |> ignore
            Interlocked.Add(&c.BytesEnc, int64 want.Length) |> ignore
            Interlocked.Add(&c.BytesDec, int64 gotLen) |> ignore
            true
    finally
        r.PipesLock.ExitReadLock()

/// One iteration. In order: refill the plaintext under rotating mode;
/// take the read lock; pick the surface; encrypt (timed); decrypt
/// (timed); compare the round-trip with the plaintext; bump the
/// counters; release the lock. The whole round-trip runs under the read
/// lock so handle-mutating maintenance (rekey, blob reopen) never lands
/// between an encrypt and its matching decrypt — maintenance runs after
/// this returns, from the worker loop. False after recording a worker
/// error.
let private iterate (r: RunState) (w: WorkerState) (iter: int64) : bool =
    let mutable rng = w.Rng
    let refilled =
        if w.PayloadMode <> Payload.Rotating then
            true
        else
            let ok = Payload.fill Payload.Rotating w.Seeded &rng w.Plaintext
            w.Rng <- rng
            ok

    if not refilled then
        fail r w.Id ("g" + string w.Id + " iter " + d iter + ": payload refill: csprng")
        false
    else
        iterateLocked r w iter


/// Marks this worker returned; the last one to return stamps the finish
/// instant and wakes main.
let private markDone (r: RunState) =
    lock r.DoneLock (fun () ->
        r.Active <- r.Active - 1

        if r.Active = 0 then
            r.FinishTimestamp <- Stopwatch.GetTimestamp()
            Monitor.Pulse r.DoneLock)

/// The worker thread body: one warmup iteration, the warmup barrier,
/// then the main loop until a stop is requested or the fixed per-worker
/// iteration budget (warmup included) is spent. A failing warmup still
/// passes both barriers so the launcher never waits on a worker that has
/// already given up.
let run (r: RunState) (w: WorkerState) =
    // Warmup iteration — counted in the totals; its completion feeds the
    // post-warmup baselines.
    let ok = iterate r w 0L
    r.WarmupDone.SignalAndWait()
    r.Release.SignalAndWait()

    if not ok then
        markDone r
    else
        let mutable iter = 1L
        let mutable running = true

        while running do
            if r.Cfg.Iterations > 0L && iter >= r.Cfg.Iterations then running <- false
            elif r.Stop then running <- false
            elif not (iterate r w iter) then running <- false
            elif not (Ops.maintenance r w.Id iter) then running <- false
            else iter <- iter + 1L

        markDone r
