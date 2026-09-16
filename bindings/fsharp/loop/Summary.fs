// The final summary in both renderings, and the two measurements it
// folds in that are not per-worker counters: the process resident set
// and the shared library's pool counters.

module Everanium.Itb3.FSharp.Loop.Summary

open System
open System.Globalization
open System.Text
open Everanium.Itb3.FSharp
open Everanium.Itb3.FSharp.Loop
open Everanium.Itb3.FSharp.Loop.Size

/// Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
/// zero on any parse failure.
let private statusKb (line: string) : int64 =
    match line.IndexOf ':' with
    | -1 -> 0L
    | colon ->
        let parts =
            line.Substring(colon + 1).Split((null: char[]), StringSplitOptions.RemoveEmptyEntries)

        if parts.Length = 0 then
            0L
        else
            match Int64.TryParse(parts[0], NumberStyles.None, inv) with
            | true, kb -> kb * 1024L
            | _ -> 0L

/// The process's current resident set and its high-water mark in bytes,
/// from /proc/self/status (VmRSS and VmHWM, reported in kB). Both are
/// zero on a platform without that file; the figures are informational
/// and never enter the verdict.
let readRss () : int64 * int64 =
    try
        let mutable current = 0L
        let mutable peak = 0L

        for line in IO.File.ReadLines "/proc/self/status" do
            if line.StartsWith("VmRSS:", StringComparison.Ordinal) then
                current <- statusKb line
            elif line.StartsWith("VmHWM:", StringComparison.Ordinal) then
                peak <- statusKb line

        current, peak
    with _ ->
        0L, 0L

/// Pool counters. The shared library keeps process-wide monotonic
/// totals at every pool checkout of its cipher core: per hash-array tier
/// the starter width, checkouts, constructor misses, regrow replacements
/// and bytes allocated; for the scratch byte pool and the parallax chunk
/// pool the checkouts, constructor misses, regrows and regrow bytes. Two
/// snapshots bracketing the main loop are differenced into per-run hit /
/// miss figures that tell whether a pool keeps its items warm between
/// calls or evicts them across GC cycles. The slot layout is read from
/// the library: slot 0 carries the tier count T, tier i occupies the
/// five slots at 1 + 5*i, and the two byte pools occupy the eight slots
/// at 1 + 5*T; the vector is sized by the binding from the library's own
/// length query, never from a constant. Empty when the library is
/// unavailable.
let poolSnapshot () : int64[] =
    match Runtime.poolStats () with
    | Ok v -> v
    | Error _ -> Array.empty

/// One starter tier of the hash-array pool, differenced.
type private Tier =
    { Index: int64
      Starter: int64
      Get: int64
      Fresh: int64
      Regrow: int64
      NewBytes: int64 }

/// One single-size byte pool, differenced.
type private BytePool =
    { Get: int64
      Fresh: int64
      Regrow: int64
      RegrowBytes: int64 }

let private emptyBytePool =
    { Get = 0L; Fresh = 0L; Regrow = 0L; RegrowBytes = 0L }

type private PoolDelta =
    { Tiers: Tier list
      Buf: BytePool
      Chunk: BytePool }

let private poolDiff (steady: int64[]) (warmup: int64[]) : PoolDelta =
    let empty =
        { Tiers = []; Buf = emptyBytePool; Chunk = emptyBytePool }

    if steady.Length < 9 || warmup.Length <> steady.Length then
        empty
    else
        let tiers = steady[0]

        if tiers < 0L || int (1L + 5L * tiers + 8L) > steady.Length then
            empty
        else
            let rows =
                [ for i in 0L .. tiers - 1L do
                      let b = int (1L + 5L * i)

                      if steady[b] <> 0L then
                          { Index = i
                            Starter = steady[b]
                            Get = steady[b + 1] - warmup[b + 1]
                            Fresh = steady[b + 2] - warmup[b + 2]
                            Regrow = steady[b + 3] - warmup[b + 3]
                            NewBytes = steady[b + 4] - warmup[b + 4] } ]

            let t = int (1L + 5L * tiers)

            { Tiers = rows
              Buf =
                { Get = steady[t] - warmup[t]
                  Fresh = steady[t + 1] - warmup[t + 1]
                  Regrow = steady[t + 2] - warmup[t + 2]
                  RegrowBytes = steady[t + 3] - warmup[t + 3] }
              Chunk =
                { Get = steady[t + 4] - warmup[t + 4]
                  Fresh = steady[t + 5] - warmup[t + 5]
                  Regrow = steady[t + 6] - warmup[t + 6]
                  RegrowBytes = steady[t + 7] - warmup[t + 7] } }

/// Misses over checkouts as a percentage; zero when nothing was checked
/// out.
let private missPercent (miss: int64) (get: int64) : float =
    if get <= 0L then 0.0 else 100.0 * float miss / float get

/// Renders s as a JSON string literal with the escapes JSON requires.
let private jsonString (s: string) : string =
    let sb = StringBuilder(s.Length + 2)
    sb.Append '"' |> ignore

    for ch in s do
        match ch with
        | '"' -> sb.Append "\\\"" |> ignore
        | '\\' -> sb.Append "\\\\" |> ignore
        | '\n' -> sb.Append "\\n" |> ignore
        | '\r' -> sb.Append "\\r" |> ignore
        | '\t' -> sb.Append "\\t" |> ignore
        | c when c < ' ' -> sb.Append("\\u").Append((int c).ToString("x4", inv)) |> ignore
        | c -> sb.Append c |> ignore

    sb.Append '"' |> ignore
    sb.ToString()

/// The effective GC percentage as the runtime reports it: the query form
/// of the setter (a set-and-restore round trip inside the library) so
/// the field is the same whether the value came from the flag, the
/// environment, or the runtime default.
let private effectiveGogc (flag: int) : int =
    if flag > 0 then flag else Runtime.setGCPercent -1

/// Output contract. Both renderings are shared with the Go harness and
/// every other binding's loop utility field for field: the same lines in
/// the same order, the same keys in the same order, floats with a fixed
/// number of decimals so the JSON is byte-identical across
/// implementations. The Go harness alone adds its runtime-internal lines
/// after rss: and its runtime-internal keys after parallax_chunk_pool;
/// nothing here reproduces them because nothing they read is reachable
/// through the C ABI. Returns the exit code.
let final (r: RunState) (elapsedNs: int64) : int =
    let cfg = r.Cfg
    let workers = int64 cfg.Workers
    let perWorker = r.Workers |> Array.map (fun c -> c.Iters) |> List.ofArray
    let totalIters = perWorker |> List.sum
    let totalEnc = r.Workers |> Array.sumBy (fun c -> c.BytesEnc)
    let totalDec = r.Workers |> Array.sumBy (fun c -> c.BytesDec)
    let nanosEnc = r.Workers |> Array.sumBy (fun c -> c.NanosEnc)
    let nanosDec = r.Workers |> Array.sumBy (fun c -> c.NanosDec)

    let errors =
        r.Workers
        |> Array.choose (fun c -> lock c.ErrorLock (fun () -> c.Error))
        |> List.ofArray

    // Throughput. Per-direction throughput divides the sum of every
    // worker's wall time in that direction by the worker count — the
    // equivalent single-stream wall time under N-way concurrency — so
    // each direction reports the aggregate rate it sustained rather than
    // collapsing to combined/2 (every iteration moves equal encrypt and
    // decrypt bytes, so a total-elapsed denominator would give both
    // directions the same figure). The combined rate keeps total elapsed
    // as the one-glance overall figure.
    let avgEnc = if nanosEnc > 0L then nanosEnc / workers else 0L
    let avgDec = if nanosDec > 0L then nanosDec / workers else 0L

    let rssDelta = r.RssFinal - r.RssWarmup

    let rssGrowth =
        if r.RssWarmup > 0L then
            100.0 * float rssDelta / float r.RssWarmup
        else
            0.0

    let pd = poolDiff r.PoolSteady r.PoolWarmup
    let pass = List.isEmpty errors
    let rekeys = r.Rekeys
    let cycles = r.BlobCycles
    let gomaxprocs = Runtime.setGOMAXPROCS 0
    let streamProfile = if r.Pipes.Stream.IsSome then r.StreamProfile else ""
    let msgProfile = if r.Pipes.Msg.IsSome then r.MsgProfile else ""

    if cfg.JsonOutput then
        let j = StringBuilder()
        let add (s: string) = j.Append s |> ignore
        add ("{\"duration_seconds\":" + f (float elapsedNs / 1e9) 3)
        add (",\"iterations\":" + d totalIters)
        add (",\"per_worker_iterations\":[" + String.Join(",", perWorker |> List.map d) + "]")
        add (",\"bytes_encrypted\":" + d totalEnc)
        add (",\"bytes_decrypted\":" + d totalDec)
        add (",\"encrypt_mb_per_sec\":" + f (mbPerSec totalEnc avgEnc) 1)
        add (",\"decrypt_mb_per_sec\":" + f (mbPerSec totalDec avgDec) 1)
        add (",\"combined_mb_per_sec\":" + f (mbPerSec (totalEnc + totalDec) elapsedNs) 1)
        add (",\"rekeys\":" + d rekeys)
        add (",\"blob_cycles\":" + d cycles)
        add (",\"worker_errors\":[" + String.Join(",", errors |> List.map jsonString) + "]")
        add (",\"verdict\":\"" + (if pass then "PASS" else "FAIL") + "\"")
        add (",\"shape\":\"" + shapeName cfg.Shape + "\"")
        add (",\"stream_profile\":" + jsonString streamProfile)
        add (",\"message_profile\":" + jsonString msgProfile)
        add (",\"hash\":" + jsonString cfg.Hash)
        add (",\"mac\":" + jsonString cfg.Mac)
        add (",\"payload_bytes\":" + d cfg.Payload)
        add (",\"payload_mode\":\"" + Payload.modeName cfg.PayloadMode + "\"")
        add (",\"seed\":" + cfg.Seed.ToString inv)
        add (",\"key_bits\":" + d cfg.KeyBits)
        add (",\"nonce_bits\":" + d cfg.NonceBits)
        add (",\"chunk_size_bytes\":" + d cfg.ChunkSize)
        add (",\"barrier_fill\":" + d cfg.BarrierFill)
        add (",\"parallax\":\"" + onOff cfg.Parallax + "\"")
        add (",\"wrapper\":\"" + onOff cfg.Wrapper + "\"")
        add (",\"goroutines_requested\":" + d (int64 cfg.WorkersRequested))
        add (",\"goroutines\":" + d (int64 cfg.Workers))
        add (",\"concurrency\":\"" + Concurrency + "\"")
        add (",\"gogc\":\"" + d (int64 (effectiveGogc cfg.Gogc)) + "\"")
        add (",\"memlimit_bytes\":" + d cfg.Memlimit)
        add (",\"gomaxprocs\":" + d (int64 gomaxprocs))
        add (",\"microbatch_tiers\":" + jsonString (policyLabel "ITB_MICROBATCH_TIERS"))
        add (",\"hashpool_starters\":" + jsonString (policyLabel "ITB_HASHPOOL_STARTERS"))
        add (",\"rss_warmup_bytes\":" + d r.RssWarmup)
        add (",\"rss_peak_bytes\":" + d r.RssPeak)
        add (",\"rss_final_bytes\":" + d r.RssFinal)
        add (",\"rss_growth_percent\":" + f rssGrowth 2)

        let tierJson =
            pd.Tiers
            |> List.map (fun t ->
                "{\"tier\":" + d t.Index + ",\"starter\":" + d t.Starter + ",\"get\":" + d t.Get
                + ",\"new\":" + d t.Fresh + ",\"regrow\":" + d t.Regrow + ",\"new_bytes\":" + d t.NewBytes
                + ",\"miss_percent\":" + f (missPercent (t.Fresh + t.Regrow) t.Get) 2 + "}")

        add (",\"hash_pool_tiers\":[" + String.Join(",", tierJson) + "]")

        let bytePoolJson (name: string) (p: BytePool) =
            ",\"" + name + "\":{\"get\":" + d p.Get + ",\"new\":" + d p.Fresh + ",\"regrow\":" + d p.Regrow
            + ",\"regrow_bytes\":" + d p.RegrowBytes + ",\"miss_percent\":"
            + f (missPercent p.Regrow p.Get) 2 + "}"

        add (bytePoolJson "buf_pool" pd.Buf)
        add (bytePoolJson "parallax_chunk_pool" pd.Chunk)
        add "}"
        Console.Out.WriteLine(j.ToString())
        if pass then 0 else 1
    else

        logLine "=== FINAL ==="
        logLine ("  duration: " + humanDuration (roundTo elapsedNs 1_000_000L))
        logLine ("  iterations: " + String.Join(" + ", perWorker |> List.map d) + " = " + d totalIters + " total")

        logLine (
            "  throughput: encrypt " + humanRate totalEnc avgEnc + ", decrypt " + humanRate totalDec avgDec
            + ", combined " + humanRate (totalEnc + totalDec) elapsedNs
        )

        logLine ("  bytes: " + humanBytes totalEnc + " encrypted, " + humanBytes totalDec + " decrypted")
        logLine ("  data integrity: " + d totalIters + "/" + d totalIters + " PASS")

        logLine (
            "  concurrency: " + Concurrency + ", workers " + string cfg.Workers + " (requested "
            + string cfg.WorkersRequested + ")"
        )

        logLine (
            "  rss: warmup " + humanBytes r.RssWarmup + ", peak " + humanBytes r.RssPeak + ", final "
            + humanBytes r.RssFinal + " (delta " + humanBytesSigned rssDelta + ", " + f rssGrowth 1 + "% growth)"
        )

        for t in pd.Tiers do
            logLine (
                "  hash pool tier " + d t.Index + " (starter " + d t.Starter + "): get " + d t.Get + ", miss "
                + d (t.Fresh + t.Regrow) + " (new " + d t.Fresh + " + regrow " + d t.Regrow + "), miss "
                + f (missPercent (t.Fresh + t.Regrow) t.Get) 2 + "%, " + humanBytes t.NewBytes + " allocated"
            )

        logLine (
            "  buf pool: get " + d pd.Buf.Get + ", regrow " + d pd.Buf.Regrow + " (of which fresh "
            + d pd.Buf.Fresh + "), miss " + f (missPercent pd.Buf.Regrow pd.Buf.Get) 2 + "%, "
            + humanBytes pd.Buf.RegrowBytes + " regrown"
        )

        logLine (
            "  parallax chunk pool: get " + d pd.Chunk.Get + ", regrow " + d pd.Chunk.Regrow
            + " (of which fresh " + d pd.Chunk.Fresh + "), miss "
            + f (missPercent pd.Chunk.Regrow pd.Chunk.Get) 2 + "%, " + humanBytes pd.Chunk.RegrowBytes
            + " regrown"
        )

        if rekeys > 0L then
            logLine ("  rekeys: " + d rekeys)

        if cycles > 0L then
            logLine ("  blob cycles: " + d cycles)

        for e in errors do
            logLine ("  ERROR: " + e)

        if pass then
            logLine "  verdict: PASS"
            0
        else
            logLine ("  verdict: FAIL (errors=" + string (List.length errors) + ")")
            1
