// A decrypt session fed a tampered wire fails with a sticky MAC
// failure. Uses a position probe rather than a single bit flip
// because the over-sized container carries CSPRNG residue in the
// non-payload area — a flip that lands inside the residue is
// architecturally inert (residue is not payload) and the session
// finishes clean. Probing 32 evenly-spaced positions makes the
// all-residue probability negligible; the first position that
// surfaces an error must give Status.MacFailure and remain sticky on
// subsequent reads.

module EveraniumItb.FSharp.Tests.StreamStickyTests

open Xunit
open EveraniumItb.FSharp
open EveraniumItb.FSharp.Tests.TestSupport

/// Runs one tampered wire through a fresh decrypt session. Returns
/// None when the session finishes clean (residue hit) and Some with
/// the first error plus the error of a follow-up read otherwise.
let private probeOnce (receiver: Pipeline) (wire: byte[]) : (ItbError * ItbError) option =
    use session = unwrap (Stream.beginDecrypt receiver)

    // Ignore write / finish status — the failure may surface on
    // either side or only on the drain that follows.
    Stream.write session wire |> ignore
    Stream.finish session |> ignore

    let buf = Array.zeroCreate 4096
    let mutable outcome = None
    let mutable draining = true

    while draining do
        match Stream.read session buf with
        | Ok r -> if r.Finished then draining <- false
        | Error err ->
            // Sticky: a subsequent read reports the same status.
            let again = unwrapError (Stream.read session buf)
            outcome <- Some(err, again)
            draining <- false

    outcome

[<Fact>]
let ``tampered wire sticky failure`` () =
    use sender = unwrap (Pipeline.init "streaming-aead-triple-mac-v1" Opts.empty)
    use receiver =
        unwrap (Pipeline.openBlob "streaming-aead-triple-mac-v1" (Pipeline.blob sender) Opts.empty)

    let plain = Array.init 65536 (fun i -> byte (i % 227))
    let baseWire = unwrap (Pipeline.encryptStreamOneShot sender plain)
    Assert.True(baseWire.Length > 128, $"wire too short to place a distributed probe: {baseWire.Length} bytes")

    let probes = 32
    // Evenly spread through the wire body; skip the first / last 16
    // bytes so a hit against the outer envelope framing does not
    // muddy the observation.
    let bodyStart = 16
    let bodyEnd = baseWire.Length - 16
    let stride = (bodyEnd - bodyStart) / probes

    let mutable verified = false
    let mutable probe = 0

    while not verified && probe < probes do
        let idx = bodyStart + probe * stride
        let wire = Array.copy baseWire
        wire[idx] <- wire[idx] ^^^ 0x01uy

        match probeOnce receiver wire with
        | None ->
            // Residue hit at this offset — try the next probe.
            probe <- probe + 1
        | Some(first, again) ->
            Assert.True(
                Status.MacFailure = first.Status,
                $"expected MAC failure on tampered wire at probe {probe} (byte {idx}), got %A{first.Status}"
            )

            Assert.Equal(first.Status, again.Status)
            verified <- true

    Assert.True(
        verified,
        $"no probe among {probes} evenly-spaced positions surfaced a MAC failure — either the probe pattern is degenerate or authentication is not covering the wire body it should"
    )
