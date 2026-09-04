// Status codes mirrored from the libitb C ABI. Numeric values are
// stable across releases; the C# binding surfaces them unchanged.

namespace EveraniumItb.FSharp

/// Structural status code carried by every failing libitb call.
/// Codes without a named case (reserved ranges, future additions)
/// surface as <c>Unknown</c> with the raw code preserved.
[<RequireQualifiedAccess>]
type Status =
    | Ok
    | BadHash
    | BadKeyBits
    | BadHandle
    | BadInput
    | BufferTooSmall
    | EncryptFailed
    | DecryptFailed
    | SeedWidthMix
    | BadMac
    | MacFailure
    | BlobMalformedRecipe
    | RecipePrimitiveUnknown
    | UnknownProfile
    | BlobModeMismatch
    | BlobMalformed
    | BlobVersionTooNew
    | BlobTooManyOpts
    | StreamTruncated
    | StreamAfterFinal
    | TripleClosed
    | ProfileExists
    | Internal
    | Unknown of code: int

[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Status =

    /// Maps a raw libitb return code to the discriminated union.
    let ofCode (code: int) : Status =
        match code with
        | 0 -> Status.Ok
        | 1 -> Status.BadHash
        | 2 -> Status.BadKeyBits
        | 3 -> Status.BadHandle
        | 4 -> Status.BadInput
        | 5 -> Status.BufferTooSmall
        | 6 -> Status.EncryptFailed
        | 7 -> Status.DecryptFailed
        | 8 -> Status.SeedWidthMix
        | 9 -> Status.BadMac
        | 10 -> Status.MacFailure
        | 11 -> Status.BlobMalformedRecipe
        | 12 -> Status.RecipePrimitiveUnknown
        | 13 -> Status.UnknownProfile
        | 19 -> Status.BlobModeMismatch
        | 20 -> Status.BlobMalformed
        | 21 -> Status.BlobVersionTooNew
        | 22 -> Status.BlobTooManyOpts
        | 23 -> Status.StreamTruncated
        | 24 -> Status.StreamAfterFinal
        | 25 -> Status.TripleClosed
        | 26 -> Status.ProfileExists
        | 99 -> Status.Internal
        | c -> Status.Unknown c

    /// Inverse of <c>ofCode</c>; <c>Unknown</c> yields the raw code
    /// it preserves.
    let toCode (status: Status) : int =
        match status with
        | Status.Ok -> 0
        | Status.BadHash -> 1
        | Status.BadKeyBits -> 2
        | Status.BadHandle -> 3
        | Status.BadInput -> 4
        | Status.BufferTooSmall -> 5
        | Status.EncryptFailed -> 6
        | Status.DecryptFailed -> 7
        | Status.SeedWidthMix -> 8
        | Status.BadMac -> 9
        | Status.MacFailure -> 10
        | Status.BlobMalformedRecipe -> 11
        | Status.RecipePrimitiveUnknown -> 12
        | Status.UnknownProfile -> 13
        | Status.BlobModeMismatch -> 19
        | Status.BlobMalformed -> 20
        | Status.BlobVersionTooNew -> 21
        | Status.BlobTooManyOpts -> 22
        | Status.StreamTruncated -> 23
        | Status.StreamAfterFinal -> 24
        | Status.TripleClosed -> 25
        | Status.ProfileExists -> 26
        | Status.Internal -> 99
        | Status.Unknown c -> c
