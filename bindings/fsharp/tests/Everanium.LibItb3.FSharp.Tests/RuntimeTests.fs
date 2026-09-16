// Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
// heap-profile writer, the pool-counter snapshot and its slot layout,
// and the hash-registry enumeration.

module Everanium.Itb3.FSharp.Tests.RuntimeTests

open System
open System.IO
open Xunit
open Everanium.Itb3.FSharp
open Everanium.Itb3.FSharp.Tests.TestSupport

[<Fact>]
let ``gomaxprocs query set restore`` () =
    let orig = Runtime.setGOMAXPROCS 0
    Assert.True(orig > 0)
    Assert.Equal(orig, Runtime.setGOMAXPROCS -3)
    Assert.Equal(orig, Runtime.setGOMAXPROCS(orig + 1))
    Assert.Equal(orig + 1, Runtime.setGOMAXPROCS 0)
    Assert.Equal(orig + 1, Runtime.setGOMAXPROCS orig)

[<Fact>]
let ``heap profile written and empty path rejected`` () =
    let dir =
        Path.Combine(Path.GetTempPath(), $"itb-loop-test-heap-fsharp-%d{Environment.ProcessId}")

    Directory.CreateDirectory dir |> ignore
    let path = Path.Combine(dir, "heap.prof")
    unwrap (Runtime.writeHeapProfile path)
    Assert.True(FileInfo(path).Length > 0L)
    Directory.Delete(dir, true)

    // The empty path falls back to ITB_MEMPROFILE inside libitb3; with
    // the variable clear there is nothing to fall back to.
    Environment.SetEnvironmentVariable("ITB_MEMPROFILE", null)

    match Runtime.writeHeapProfile "" with
    | Ok() -> failwith "expected an empty path to be rejected"
    | Error err -> Assert.Equal(Status.BadInput, err.Status)

[<Fact>]
let ``pool stats layout`` () =
    let len = Runtime.poolStatsLen ()
    Assert.True(len >= 9)
    let v = unwrap (Runtime.poolStats ())
    Assert.Equal(len, v.Length)
    let tiers = v[0]
    Assert.True(tiers > 0L)
    Assert.Equal(int64 len, 1L + 5L * tiers + 8L)

[<Fact>]
let ``hash names canonical`` () =
    let names = unwrap (Pipeline.hashNames ())
    Assert.Equal("aesitb128", List.head names)
    Assert.Contains("areion512", names)
