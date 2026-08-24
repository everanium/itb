// Incremental stream sessions over an open Pipeline.
//
// A session is a dumb byte pump: an encrypt session takes plaintext
// in through write and yields wire through read / copyTo; a decrypt
// session is the mirror (wire in, plaintext out). All chunking, MAC,
// envelope, and wire-format decisions stay inside libitb. Both
// directions share one Session type (a Direction tag distinguishes
// them) so the pump / transform plumbing exists once; the underlying
// C# session pins the parent Pipeline while it is live.

namespace EveraniumItb.FSharp

open System

/// Result of one stream drain call: <c>Count</c> bytes were placed
/// into the destination buffer; <c>Finished</c> marks the session
/// output as complete.
[<Struct>]
type ReadResult = { Count: int; Finished: bool }

/// Direction of a stream session.
[<RequireQualifiedAccess>]
type Direction =
    | Encrypt
    | Decrypt

/// Incremental stream session over an open Pipeline. Constructed via
/// <c>Stream.beginEncrypt</c> / <c>Stream.beginDecrypt</c>; driven
/// through the functions in the <c>Stream</c> module. Disposing the
/// session cancels it and frees the Go-side state (idempotent); the
/// session keeps <c>Parent</c> reachable while it is live.
[<Sealed>]
type Session
    internal
    (
        parent: Pipeline,
        direction: Direction,
        inner: IDisposable,
        writeImpl: byte[] -> unit,
        finishImpl: unit -> unit,
        readImpl: byte[] -> ReadResult,
        copyToImpl: IO.Stream -> unit
    ) =

    /// The parent Pipeline this session runs against.
    member _.Parent = parent

    /// Whether this session encrypts or decrypts.
    member _.Direction = direction

    member internal _.WriteImpl = writeImpl
    member internal _.FinishImpl = finishImpl
    member internal _.ReadImpl = readImpl
    member internal _.CopyToImpl = copyToImpl

    /// Cancels the session and frees the Go-side state. Idempotent.
    member _.Dispose() = inner.Dispose()

    interface IDisposable with
        member this.Dispose() = this.Dispose()

[<RequireQualifiedAccess>]
module Stream =

    /// Feed / drain block size used by the transform adapter (1 MiB).
    [<Literal>]
    let DrainChunk = 1048576

    /// Opens an incremental encrypt session (plaintext in, wire out).
    let beginEncrypt (pipe: Pipeline) : Result<Session, ItbError> =
        ItbError.attempt (fun () ->
            let s = pipe.BeginEncryptStream()
            new Session(
                pipe,
                Direction.Encrypt,
                s,
                (fun chunk -> s.Write(ReadOnlySpan chunk)),
                (fun () -> s.End()),
                (fun dst ->
                    let count, finished = s.Read(Span dst)
                    { Count = count; Finished = finished }),
                (fun destination -> s.CopyTo destination)
            ))

    /// Opens an incremental decrypt session (wire in, plaintext out).
    let beginDecrypt (pipe: Pipeline) : Result<Session, ItbError> =
        ItbError.attempt (fun () ->
            let s = pipe.BeginDecryptStream()
            new Session(
                pipe,
                Direction.Decrypt,
                s,
                (fun chunk -> s.Write(ReadOnlySpan chunk)),
                (fun () -> s.End()),
                (fun dst ->
                    let count, finished = s.Read(Span dst)
                    { Count = count; Finished = finished }),
                (fun destination -> s.CopyTo destination)
            ))

    /// Feeds bytes into the session. Blocks until the cipher chain
    /// accepts them; errors are sticky.
    let write (session: Session) (chunk: byte[]) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> session.WriteImpl chunk)

    /// Signals end-of-input. Idempotent; <c>write</c> after finish
    /// fails with <c>Status.BadInput</c>.
    let finish (session: Session) : Result<unit, ItbError> =
        ItbError.attempt session.FinishImpl

    /// Drains up to <c>dst.Length</c> produced bytes. Partial drains
    /// are normal; before <c>finish</c> a drain on an empty spool
    /// returns a zero count without blocking, after <c>finish</c> it
    /// blocks until the terminal bytes arrive or the session errors.
    let read (session: Session) (dst: byte[]) : Result<ReadResult, ItbError> =
        ItbError.attempt (fun () -> session.ReadImpl dst)

    /// Calls <c>finish</c> (idempotent) and writes every remaining
    /// output byte to <c>destination</c>.
    let copyTo (session: Session) (destination: IO.Stream) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> session.CopyToImpl destination)

    /// Pumps <c>source</c> through an encrypt session into
    /// <c>destination</c> with bounded memory: feed a block, drain
    /// available wire, repeat; finish + final drain on source EOF.
    /// The session is freed on return.
    let pumpEncrypt (pipe: Pipeline) (source: IO.Stream) (destination: IO.Stream) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> pipe.EncryptStreamPump(source, destination))

    /// Receive-side counterpart of <c>pumpEncrypt</c>.
    let pumpDecrypt (pipe: Pipeline) (source: IO.Stream) (destination: IO.Stream) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> pipe.DecryptStreamPump(source, destination))

    /// Lazily maps input chunks to output chunks through the
    /// session: each pulled output chunk feeds and drains the session
    /// as needed, calling <c>finish</c> once the input is exhausted.
    /// Single pass — traverse the returned sequence at most once and
    /// do not mix it with direct <c>write</c> / <c>read</c> calls on
    /// the same session. A libitb failure surfaces as a raised
    /// <c>ItbFailure</c> carrying the <c>ItbError</c>.
    let transform (session: Session) (chunks: seq<byte[]>) : seq<byte[]> =
        seq {
            let buf = Array.zeroCreate DrainChunk
            use e = chunks.GetEnumerator()
            let mutable ended = false
            let mutable finished = false

            while not finished do
                let r = ItbError.get (read session buf)

                if r.Count > 0 then
                    yield buf[.. r.Count - 1]

                if r.Finished then
                    finished <- true
                elif r.Count = 0 && not ended then
                    if e.MoveNext() then
                        ItbError.get (write session e.Current)
                    else
                        ItbError.get (finish session)
                        ended <- true
        // After finish, an empty drain blocks inside libitb until
        // the terminal bytes arrive — the loop simply reads again.
        }
