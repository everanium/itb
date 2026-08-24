// Shared helpers for the F# binding test suite.

module EveraniumItb.FSharp.Tests.TestSupport

open EveraniumItb.FSharp

/// Deterministic non-trivial payload (xorshift fill).
let payload (n: int) (seed: uint64) : byte[] =
    let buf = Array.zeroCreate n
    let mutable x = seed ||| 1UL

    for i in 0 .. n - 1 do
        x <- x ^^^ (x <<< 13)
        x <- x ^^^ (x >>> 7)
        x <- x ^^^ (x <<< 17)
        buf[i] <- byte x

    buf

/// Unwraps a Result, failing the test with the ItbError rendering on
/// the error case.
let unwrap (result: Result<'a, ItbError>) : 'a =
    match result with
    | Ok value -> value
    | Error err -> failwith $"unexpected ItbError: {err}"

/// Unwraps the error case, failing the test when the call succeeded.
let unwrapError (result: Result<'a, ItbError>) : ItbError =
    match result with
    | Ok _ -> failwith "expected an ItbError, call succeeded"
    | Error err -> err
