// The maintenance operations that mutate a live Pipeline handle
// between iterations: master rotation (--rekey-every) and blob reopen
// (--blob-cycle-every).

module Everanium.Itb3.FSharp.Loop.Ops

open Everanium.Itb3.FSharp
open Everanium.Itb3.FSharp.Loop
open Everanium.Itb3.FSharp.Loop.Size

/// Byte length of each fresh master drawn for a rotation. Matches the
/// size Init auto-generates for both the parallax and the wrapper
/// master.
let private rekeyMasterSize = 32

/// Master rotation. Rotates the parallax + wrapper masters on every
/// active Pipeline under the write lock and retains the refreshed blob
/// for subsequent blob reopens. Masters are drawn fresh from the OS
/// CSPRNG on every rotation regardless of --seed (master rotation is
/// pipeline keying, not plaintext content); a disabled layer passes no
/// bytes, which Rekey ignores. The eight inner seeds and the MAC key
/// are untouched by design — Rekey targets only the two outer-layer
/// master secrets.
let private rekeyPipes (r: RunState) (id: int) (iter: int64) : bool =
    let draw (want: bool) (what: string) =
        if not want then
            Some Array.empty
        else
            let buf = Array.zeroCreate<byte> rekeyMasterSize

            if Payload.fillRandom buf then
                Some buf
            else
                fail r id ("g" + string id + " iter " + d iter + ": csprng: " + what + " master")
                None

    match draw r.Cfg.Parallax "parallax", draw r.Cfg.Wrapper "wrapper" with
    | Some perm, Some wrap ->
        r.PipesLock.EnterWriteLock()

        let outcome =
            try
                let rotate (pipe: Pipeline option) (profile: string) (store: byte[] -> unit) =
                    match pipe with
                    | None -> Ok()
                    | Some p ->
                        match Pipeline.rekey p perm wrap with
                        | Ok blob ->
                            store blob
                            Ok()
                        | Error e ->
                            Error(
                                "g" + string id + " iter " + d iter + ": Rekey(" + profile + "): " + detail e
                            )

                match rotate r.Pipes.Stream r.StreamProfile (fun b -> r.Pipes.StreamBlob <- b) with
                | Error m -> Error m
                | Ok() -> rotate r.Pipes.Msg r.MsgProfile (fun b -> r.Pipes.MsgBlob <- b)
            finally
                r.PipesLock.ExitWriteLock()

        match outcome with
        | Error m ->
            fail r id m
            false
        | Ok() ->
            let n =
                lock r.CounterLock (fun () ->
                    r.Rekeys <- r.Rekeys + 1L
                    r.Rekeys)

            logLine (
                "rekey: g" + string id + " iter " + d iter
                + " rotated parallax + wrapper masters (rekey #" + d n + ")"
            )
            true
    | _ -> false

/// Blob reopen. Reopens every active Pipeline from its retained blob
/// under the write lock: a fresh handle is loaded from the blob, the
/// running handle is freed, and the fresh one is swapped in, so every
/// later iteration round-trips through seeds and masters that survived
/// a blob crossing. The input is the blob Init or the latest Rekey
/// handed out, not a fresh Save: that is what a receiver holds, and
/// reopening from it proves the handed-out bytes rather than the live
/// state. The blob carries the Pipeline's full shape, so no override
/// reaches the reopen. On a Load failure the running handle stays and
/// the failure aborts the run.
let private blobCyclePipes (r: RunState) (id: int) (iter: int64) : bool =
    r.PipesLock.EnterWriteLock()

    let outcome =
        try
            let reopen (pipe: Pipeline option) (blob: byte[]) (profile: string) (store: Pipeline -> unit) =
                match pipe with
                | None -> Ok()
                | Some running ->
                    match Pipeline.load blob with
                    | Ok fresh ->
                        running.Dispose()
                        store fresh
                        Ok()
                    | Error e ->
                        Error("g" + string id + " iter " + d iter + ": Load(" + profile + "): " + detail e)

            match reopen r.Pipes.Stream r.Pipes.StreamBlob r.StreamProfile (fun p -> r.Pipes.Stream <- Some p) with
            | Error m -> Error m
            | Ok() -> reopen r.Pipes.Msg r.Pipes.MsgBlob r.MsgProfile (fun p -> r.Pipes.Msg <- Some p)
        finally
            r.PipesLock.ExitWriteLock()

    match outcome with
    | Error m ->
        fail r id m
        false
    | Ok() ->
        let n =
            lock r.CounterLock (fun () ->
                r.BlobCycles <- r.BlobCycles + 1L
                r.BlobCycles)

        logLine (
            "blob-cycle: g" + string id + " iter " + d iter
            + " reopened from session blob (cycle #" + d n + ")"
        )
        true

/// Handle mutation. Runs the periodic Pipeline-mutating operations
/// after a completed iteration: master rotation (--rekey-every) and
/// blob reopen (--blob-cycle-every). Both intervals count per-worker
/// iterations; the warmup iteration (iter 0) never triggers because the
/// worker loop calls this for iter >= 1 only. Rekey rewrites the
/// outer-layer keying of a live handle and a blob reopen replaces the
/// handle outright; each takes the write lock, so in-flight cipher calls
/// on other workers drain before anything changes and no encrypt is
/// separated from its decrypt by either. False after recording the
/// worker error.
let maintenance (r: RunState) (id: int) (iter: int64) : bool =
    let cfg = r.Cfg

    if cfg.RekeyEvery > 0L && iter % cfg.RekeyEvery = 0L && not (rekeyPipes r id iter) then
        false
    elif cfg.BlobCycleEvery > 0L && iter % cfg.BlobCycleEvery = 0L && not (blobCyclePipes r id iter) then
        false
    else
        true
