// The itb { } computation expression: Result-based composition with
// IDisposable support, so a whole encrypt / decrypt flow reads as
// straight-line code while every failure short-circuits into the
// ItbError channel and every Pipeline / Session is disposed on exit.

namespace EveraniumItb.FSharp

open System

/// Builder for the <c>itb { }</c> computation expression over
/// <c>Result&lt;_, ItbError&gt;</c>. Supports <c>let!</c> /
/// <c>do!</c> (bind), <c>use</c> / <c>use!</c> (dispose-on-exit for
/// Pipelines and Sessions), <c>return</c> / <c>return!</c>,
/// <c>if</c> without <c>else</c>, sequencing, <c>while</c>, and
/// <c>for</c> — enough for caller-driven stream pump loops:
///
/// <code>
/// itb {
///     use! sender = Pipeline.init "singlemsg-triple-mac-v1" Opts.empty
///     let! wire = Pipeline.encryptMessage sender plaintext
///     return wire
/// }
/// </code>
[<Sealed>]
type ItbBuilder() =

    member _.Return(value: 'a) : Result<'a, ItbError> = Ok value

    member _.ReturnFrom(result: Result<'a, ItbError>) : Result<'a, ItbError> = result

    member _.Bind(result: Result<'a, ItbError>, binder: 'a -> Result<'b, ItbError>) : Result<'b, ItbError> =
        Result.bind binder result

    member _.Zero() : Result<unit, ItbError> = Ok()

    member _.Delay(thunk: unit -> Result<'a, ItbError>) : unit -> Result<'a, ItbError> = thunk

    member _.Run(thunk: unit -> Result<'a, ItbError>) : Result<'a, ItbError> = thunk ()

    member _.Combine(first: Result<unit, ItbError>, rest: unit -> Result<'a, ItbError>) : Result<'a, ItbError> =
        Result.bind rest first

    member _.TryWith(body: unit -> Result<'a, ItbError>, handler: exn -> Result<'a, ItbError>) : Result<'a, ItbError> =
        try
            body ()
        with e ->
            handler e

    member _.TryFinally(body: unit -> Result<'a, ItbError>, compensation: unit -> unit) : Result<'a, ItbError> =
        try
            body ()
        finally
            compensation ()

    member _.Using(resource: 'r :> IDisposable, body: 'r -> Result<'a, ItbError>) : Result<'a, ItbError> =
        try
            body resource
        finally
            if not (obj.ReferenceEquals(resource, null)) then
                resource.Dispose()

    member this.While(guard: unit -> bool, body: unit -> Result<unit, ItbError>) : Result<unit, ItbError> =
        if not (guard ()) then
            Ok()
        else
            Result.bind (fun () -> this.While(guard, body)) (body ())

    member _.For(items: seq<'a>, body: 'a -> Result<unit, ItbError>) : Result<unit, ItbError> =
        use e = items.GetEnumerator()
        let mutable result = Ok()

        while (match result with
               | Ok() -> e.MoveNext()
               | Error _ -> false) do
            result <- body e.Current

        result

/// Auto-opened instance module exposing <c>itb</c>.
[<AutoOpen>]
module ItbBuilderInstance =

    /// The <c>itb { ... }</c> computation expression instance.
    let itb = ItbBuilder()
