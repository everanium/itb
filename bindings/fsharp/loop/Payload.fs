// Plaintext content: the payload modes, the seeded per-worker
// generator, and the buffer fill from the operating-system CSPRNG.

module Everanium.Itb3.FSharp.Loop.Payload

open System
open System.Runtime.InteropServices

/// Payload mode selector values for the --payload-mode flag.
///
///   - Fixed: one CSPRNG-generated buffer per worker, held unchanged
///     for the whole run (the default).
///   - Rotating: the buffer is regenerated before every iteration, so
///     no two encrypt calls see the same plaintext.
///   - PatternZero / PatternFf: degenerate constant fills (all 0x00 /
///     all 0xFF) probing minimum-entropy plaintext handling.
///   - PatternAscii: a repeating 'A'..'Z' ramp probing low-entropy
///     structured text.
type PayloadMode =
    | Fixed
    | Rotating
    | PatternZero
    | PatternFf
    | PatternAscii

let private names =
    [ "fixed", Fixed
      "rotating", Rotating
      "pattern-zero", PatternZero
      "pattern-ff", PatternFf
      "pattern-ascii", PatternAscii ]

let modeName (mode: PayloadMode) : string =
    names
    |> List.tryPick (fun (n, m) -> if m = mode then Some n else None)
    |> Option.defaultValue "fixed"

let parseMode (s: string) : PayloadMode option =
    names |> List.tryPick (fun (n, m) -> if n = s then Some m else None)

/// Seeded plaintext. The seed makes plaintext content reproducible so
/// a failing iteration can be replayed with the same bytes; it governs
/// nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
/// so a seeded run is a reproduction aid and never a security test.
/// Each worker's stream is domain-separated by its id so seeded
/// workers still hold pairwise-distinct buffers under the fixed and
/// rotating modes. The generator is splitmix64: a few lines in any
/// language, which is why it is the one every binding uses.
let seedWorker (seed: uint64) (workerId: int) : uint64 = seed + uint64 workerId + 1UL

let private splitmix64 (state: byref<uint64>) : uint64 =
    state <- state + 0x9E3779B97F4A7C15UL
    let mutable z = state
    z <- (z ^^^ (z >>> 30)) * 0xBF58476D1CE4E5B9UL
    z <- (z ^^^ (z >>> 27)) * 0x94D049BB133111EBUL
    z ^^^ (z >>> 31)

[<DllImport("libc", EntryPoint = "getrandom", SetLastError = true)>]
extern nativeint private getrandom(nativeint buf, unativeint buflen, uint32 flags)

/// Fills buf from the operating-system CSPRNG.
///
/// .NET-specific. The glibc entry is called directly rather than
/// through RandomNumberGenerator: the .NET native layer reaches the
/// kernel through arc4random_buf, a userspace generator that reseeds on
/// its own schedule, so the number of kernel draws no longer tracks the
/// number of fills and the plaintext-content flags become unobservable
/// from outside the process. Going straight to the libc entry keeps one
/// draw per fill, which is what makes --payload-mode and --seed
/// checkable against a run that never touches them. The entry returns
/// short on a signal and caps a single draw, so the fill loops until
/// every byte is in place. False on failure.
let fillRandom (buf: byte[]) : bool =
    let handle = GCHandle.Alloc(buf, GCHandleType.Pinned)

    try
        let basePtr = handle.AddrOfPinnedObject()
        let mutable off = 0
        let mutable ok = true

        while ok && off < buf.Length do
            let r = getrandom (basePtr + nativeint off, unativeint (buf.Length - off), 0u)

            if r <= 0n then ok <- false else off <- off + int r

        ok
    finally
        handle.Free()

/// Writes one plaintext buffer according to the payload mode. The fixed
/// and rotating modes draw from the seeded generator when the run is
/// seeded and from the OS CSPRNG otherwise; the pattern modes are
/// deterministic regardless of the seed. False when the CSPRNG fails.
let fill (mode: PayloadMode) (seeded: bool) (rng: byref<uint64>) (buf: byte[]) : bool =
    match mode with
    | Fixed
    | Rotating ->
        if not seeded then
            fillRandom buf
        else
            let mutable i = 0

            while i < buf.Length do
                let v = splitmix64 &rng
                let n = min 8 (buf.Length - i)

                for k in 0 .. n - 1 do
                    buf[i + k] <- byte (v >>> (8 * k))

                i <- i + 8

            true
    | PatternZero ->
        Array.fill buf 0 buf.Length 0uy
        true
    | PatternFf ->
        Array.fill buf 0 buf.Length 0xFFuy
        true
    | PatternAscii ->
        for i in 0 .. buf.Length - 1 do
            buf[i] <- byte (int 'A' + (i % 26))

        true
