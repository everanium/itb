// Result-based lifetime + cipher surface over the C# binding's
// Triple Pipeline (plain CLR interop — the C# binding carries the
// P/Invoke layer and the buffer-sizing retry; nothing is
// re-implemented here).

namespace EveraniumItb.FSharp

open System

/// A Triple Pipeline profile record — the C# binding's
/// <c>Itb.Profile</c>: a plain data holder plus a JSON codec over the
/// fourteen wire keys (name, mode, width, hash, hashes, keybits, mac,
/// tagstub, chunk, wrapper, outer, parallax, palette, segment). No
/// semantic validation happens on the .NET side — every field rule
/// is enforced by Go at <c>Pipeline.register</c> /
/// <c>Pipeline.load</c> time and surfaces as <c>ItbError</c>.
type Profile = Itb.Profile

/// A Triple Pipeline session.
///
/// The type is the C# binding's <c>Itb.Pipeline</c> — it implements
/// <c>IDisposable</c>, so <c>use</c> / <c>use!</c> bindings give the
/// deterministic release path (libitb zeroes key material
/// internally) and the C# SafeHandle finalizer reclaims an
/// undisposed Pipeline. <c>Pipeline.save</c> exports the
/// self-describing session blob the receiver feeds to
/// <c>Pipeline.load</c> / <c>Pipeline.loadF</c>. The functions in the
/// <c>Pipeline</c> module wrap every fallible operation as
/// <c>Result&lt;_, ItbError&gt;</c>; the <c>itb { }</c> computation
/// expression is the intended composition style.
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
type Pipeline = Itb.Pipeline

[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Pipeline =

    /// Constructs a fresh Pipeline against the named profile.
    let init (profile: string) (opts: Opts) : Result<Pipeline, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.Init(profile, Opts.toNative opts))

    /// Reconstructs a Pipeline from a blob produced by <c>save</c> or
    /// <c>rekey</c>, using the blob-embedded masters. The blob's
    /// embedded profile record is the sole structural source. See
    /// <c>loadWithMasters</c> to override the masters.
    let load (blob: byte[]) : Result<Pipeline, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.Load(ReadOnlySpan blob))

    /// <c>load</c> with explicit (non-empty) parallax + wrapper
    /// masters overriding the blob-embedded ones; both must be
    /// supplied.
    let loadWithMasters (blob: byte[]) (permMaster: byte[]) (wrapMaster: byte[]) : Result<Pipeline, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.Load(ReadOnlySpan blob, permMaster, wrapMaster))

    /// <c>load</c> for a blob stored in a file; the file is read
    /// inside the library.
    let loadF (path: string) : Result<Pipeline, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.LoadF path)

    /// <c>loadF</c> with explicit (non-empty) parallax + wrapper
    /// masters overriding the blob-embedded ones; both must be
    /// supplied.
    let loadFWithMasters (path: string) (permMaster: byte[]) (wrapMaster: byte[]) : Result<Pipeline, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.LoadF(path, permMaster, wrapMaster))

    /// Decodes the blob's embedded profile record without opening a
    /// Pipeline. No registry read, no primitive probe.
    let inspect (blob: byte[]) : Result<Profile, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.Inspect(ReadOnlySpan blob))

    /// Registers <c>profile</c> under <c>name</c> so subsequent
    /// <c>init</c> / <c>lookup</c> calls resolve it. Every field rule
    /// is validated by Go; a duplicate name fails with
    /// <c>Status.ProfileExists</c>.
    let register (name: string) (profile: Profile) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.Register(name, profile))

    /// Looks up a registered profile (shipped or <c>register</c>ed)
    /// by name; an unknown name fails with
    /// <c>Status.UnknownProfile</c>.
    let lookup (name: string) : Result<Profile, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.Lookup name)

    /// The sorted names of every registered profile.
    let profiles () : Result<string list, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.Profiles() |> List.ofArray)

    /// The current self-describing session blob: the bytes
    /// <c>init</c> produced, the bytes <c>load</c> re-marshalled, or
    /// the bytes of the latest <c>rekey</c>.
    let save (pipe: Pipeline) : Result<byte[], ItbError> =
        ItbError.attempt (fun () -> pipe.Save())

    /// Writes <c>save</c> to <c>path</c> inside the library with mode
    /// 0600; the containing directory must exist.
    let saveF (pipe: Pipeline) (path: string) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> pipe.SaveF path)

    /// Sets the worker cap for every subsequent cipher call. <c>n</c>
    /// is clamped, never rejected: <c>n &lt;= 0</c> selects auto (CPU
    /// count), <c>n &gt; 256</c> is treated as 256. Only the handle
    /// statuses fail.
    let maxWorkers (pipe: Pipeline) (n: int) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> pipe.MaxWorkers n)

    /// Rotates the parallax + wrapper masters and returns the fresh
    /// session blob (also available through <c>save</c>). Must not
    /// run concurrently with cipher calls or open stream sessions on
    /// the same Pipeline.
    let rekey (pipe: Pipeline) (permMaster: byte[]) (wrapMaster: byte[]) : Result<byte[], ItbError> =
        ItbError.attempt (fun () -> pipe.Rekey(ReadOnlySpan permMaster, ReadOnlySpan wrapMaster))

    /// Zeroes the Pipeline's key material and marks it closed.
    /// Idempotent; subsequent cipher calls fail with
    /// <c>Status.TripleClosed</c>. The native handle itself is
    /// released by <c>Dispose</c> (a <c>use</c> binding).
    let closeSession (pipe: Pipeline) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> pipe.Close())

    /// Single Message encrypt: one call, one self-contained wire.
    let encryptMessage (pipe: Pipeline) (plaintext: byte[]) : Result<byte[], ItbError> =
        ItbError.attempt (fun () -> pipe.EncryptMessage(ReadOnlySpan plaintext))

    /// Receive-side counterpart of <c>encryptMessage</c>.
    let decryptMessage (pipe: Pipeline) (wire: byte[]) : Result<byte[], ItbError> =
        ItbError.attempt (fun () -> pipe.DecryptMessage(ReadOnlySpan wire))

    /// One-shot stream encrypt for callers holding the whole
    /// plaintext in memory. For bounded-memory streaming use
    /// <c>Stream.beginEncrypt</c> / <c>Stream.pumpEncrypt</c>.
    let encryptStreamOneShot (pipe: Pipeline) (plaintext: byte[]) : Result<byte[], ItbError> =
        ItbError.attempt (fun () -> pipe.EncryptStreamOneShot(ReadOnlySpan plaintext))

    /// Receive-side counterpart of <c>encryptStreamOneShot</c>.
    let decryptStreamOneShot (pipe: Pipeline) (wire: byte[]) : Result<byte[], ItbError> =
        ItbError.attempt (fun () -> pipe.DecryptStreamOneShot(ReadOnlySpan wire))
