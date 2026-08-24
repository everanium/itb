// Error value shared by every fallible call in the binding.

namespace EveraniumItb.FSharp

/// Error surfaced through the <c>Result</c> values of the binding.
///
/// <c>Status</c> carries the structural code as a discriminated
/// union; <c>Code</c> is the raw integer, preserved even when it has
/// no named case; <c>Detail</c> carries the formatted diagnostic
/// captured by the C# binding immediately after the failing call —
/// it embeds the process-global <c>ITB_LastError</c> text
/// (last-write-wins — under concurrent use the text may belong to a
/// different call; the status code is always attributable).
type ItbError =
    { Status: Status
      Code: int
      Detail: string }

    override this.ToString() =
        if System.String.IsNullOrEmpty this.Detail then
            $"itb: status=%d{this.Code} (%A{this.Status})"
        else
            this.Detail

/// Raised by the throw-based conveniences (<c>ItbError.get</c>, the
/// <c>Stream.transform</c> adapter) so callers preferring exceptions
/// handle one error type carrying the same <c>ItbError</c> value.
exception ItbFailure of ItbError with
    override this.Message =
        match this :> exn with
        | ItbFailure err -> string err
        | _ -> "itb failure"

[<RequireQualifiedAccess>]
module ItbError =

    /// Converts the C# binding's exception, preserving the raw code.
    let internal ofException (e: Itb.ItbException) : ItbError =
        let code = int e.Status
        { Status = Status.ofCode code
          Code = code
          Detail = (if isNull e.Message then "" else e.Message) }

    /// Runs <c>body</c>, mapping the C# binding's exception into the
    /// <c>Result</c> error channel. Non-ITB exceptions propagate.
    let internal attempt (body: unit -> 'a) : Result<'a, ItbError> =
        try
            Ok(body ())
        with :? Itb.ItbException as e ->
            Error(ofException e)

    /// Unwraps a <c>Result</c>, raising <c>ItbFailure</c> on the
    /// error case — the one-liner for throw-based interop.
    let get (result: Result<'a, ItbError>) : 'a =
        match result with
        | Ok value -> value
        | Error err -> raise (ItbFailure err)
