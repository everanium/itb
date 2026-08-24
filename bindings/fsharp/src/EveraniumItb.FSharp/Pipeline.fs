// Result-based lifetime + cipher surface over the C# binding's
// Triple Pipeline (plain CLR interop — the C# binding carries the
// P/Invoke layer and the buffer-sizing retry; nothing is
// re-implemented here).

namespace EveraniumItb.FSharp

open System

/// A Triple Pipeline session plus its exported blob bytes.
///
/// The type is the C# binding's <c>Itb.Pipeline</c> — it implements
/// <c>IDisposable</c>, so <c>use</c> / <c>use!</c> bindings give the
/// deterministic release path (libitb zeroes key material
/// internally) and the C# SafeHandle finalizer reclaims an
/// undisposed Pipeline. The functions in the <c>Pipeline</c> module
/// wrap every fallible operation as <c>Result&lt;_, ItbError&gt;</c>;
/// the <c>itb { }</c> computation expression is the intended
/// composition style.
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

    /// Reconstructs a Pipeline from a blob produced by <c>init</c> or
    /// <c>rekey</c>, using the blob-embedded masters. See
    /// <c>openWithMasters</c> to override them.
    let openBlob (profile: string) (blob: byte[]) (opts: Opts) : Result<Pipeline, ItbError> =
        ItbError.attempt (fun () ->
            Itb.Pipeline.Open(profile, ReadOnlySpan blob, Opts.toNative opts))

    /// <c>openBlob</c> with explicit (non-empty) parallax + wrapper
    /// masters overriding the blob-embedded ones; both must be
    /// supplied.
    let openWithMasters
        (profile: string)
        (blob: byte[])
        (opts: Opts)
        (permMaster: byte[])
        (wrapMaster: byte[])
        : Result<Pipeline, ItbError> =
        ItbError.attempt (fun () ->
            Itb.Pipeline.Open(profile, ReadOnlySpan blob, Opts.toNative opts, permMaster, wrapMaster))

    /// Registers a user-defined Triple profile under <c>name</c> so
    /// subsequent <c>init</c> / <c>openBlob</c> calls resolve it. The
    /// opts follow the register-profile grammar validated by Go —
    /// build them with <c>Opts.withRaw</c> plus the typed setters
    /// where key names coincide. A duplicate name fails with
    /// <c>Status.ProfileExists</c>.
    let registerProfile (name: string) (opts: Opts) : Result<unit, ItbError> =
        ItbError.attempt (fun () -> Itb.Pipeline.RegisterProfile(name, Opts.toNative opts))

    /// The exported session bundle bytes for the receiver side.
    let blob (pipe: Pipeline) : byte[] = pipe.Blob.ToArray()

    /// Rotates the parallax + wrapper masters and refreshes
    /// <c>blob</c>. Must not run concurrently with cipher calls or
    /// open stream sessions on the same Pipeline.
    let rekey (pipe: Pipeline) (permMaster: byte[]) (wrapMaster: byte[]) : Result<unit, ItbError> =
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
