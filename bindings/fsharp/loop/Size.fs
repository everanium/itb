// Size and duration parsing and the human renderings of sizes, rates
// and durations. Every rendering here is part of the output contract
// shared with the Go harness and the other bindings' loop utilities,
// so the formats are fixed to the character, not to taste.
//
// .NET-specific. Every conversion and every format specifier names
// CultureInfo.InvariantCulture explicitly. The process also pins its
// default culture at startup, but a formatter that relies on that
// alone renders "1,5MB/s" the day someone runs it under a
// comma-decimal locale with a thread the pin did not reach, and the
// output contract is byte-for-byte.

module Everanium.Itb3.FSharp.Loop.Size

open System
open System.Globalization
open System.Text

let private inv = CultureInfo.InvariantCulture

/// Suffix table for parseSize, matched in order so the longer
/// spellings win over their prefixes.
let private sizeSuffixes =
    [ "KIB", 1L <<< 10
      "KB", 1L <<< 10
      "K", 1L <<< 10
      "MIB", 1L <<< 20
      "MB", 1L <<< 20
      "M", 1L <<< 20
      "GIB", 1L <<< 30
      "GB", 1L <<< 30
      "G", 1L <<< 30
      "B", 1L ]

/// Parses a human byte-size string ("16MB", "1MiB", "512K",
/// "1073741824") into a byte count. Every suffix is a binary multiple:
/// K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
/// bytes; matching is case-insensitive and surrounding whitespace is
/// trimmed. None on a malformed or negative value.
let parseSize (s: string) : int64 option =
    let upper = s.Trim().ToUpperInvariant()

    if upper.Length = 0 then
        None
    else
        let mult, digits =
            match sizeSuffixes |> List.tryFind (fun (suffix, _) -> upper.EndsWith(suffix, StringComparison.Ordinal)) with
            | Some(suffix, m) -> m, upper.Substring(0, upper.Length - suffix.Length)
            | None -> 1L, upper

        let digits = digits.TrimEnd()

        if digits.Length = 0 || not (digits |> Seq.forall Char.IsAsciiDigit) then
            None
        else
            match Int64.TryParse(digits, NumberStyles.None, inv) with
            | true, n ->
                try
                    Some(Checked.(*) n mult)
                with :? OverflowException ->
                    None
            | _ -> None

/// Unit table for parseDuration, matched in order so "ms" wins over
/// "m" followed by a stray "s".
let private durationUnits =
    [ "ns", 1.0; "us", 1e3; "ms", 1e6; "s", 1e9; "m", 60e9; "h", 3600e9 ]

/// Parses the Go duration grammar — a sequence of decimal numbers each
/// followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
/// "1h30m", "1.5s" — into nanoseconds. None on a malformed string.
let parseDuration (s: string) : int64 option =
    if s.Length = 0 then
        None
    else
        let mutable rest = s
        let mutable total = 0.0
        let mutable bad = false

        while not bad && rest.Length > 0 do
            let mutable numLen = 0

            while numLen < rest.Length && (Char.IsAsciiDigit rest[numLen] || rest[numLen] = '.') do
                numLen <- numLen + 1

            if numLen = 0 then
                bad <- true
            else
                match Double.TryParse(rest.Substring(0, numLen), NumberStyles.Float, inv) with
                | false, _ -> bad <- true
                | true, v ->
                    let after = rest.Substring numLen
                    // A unit whose next character is a letter is the
                    // prefix of a longer token that is not a unit at all.
                    let matched =
                        durationUnits
                        |> List.tryPick (fun (unit, ns) ->
                            if after.StartsWith(unit, StringComparison.Ordinal) then
                                let tail = after.Substring unit.Length

                                if tail.Length > 0 && Char.IsAsciiLetter tail[0] then
                                    None
                                else
                                    Some(tail, ns)
                            else
                                None)

                    match matched with
                    | None -> bad <- true
                    | Some(tail, ns) ->
                        rest <- tail
                        total <- total + v * ns

        if bad || total > 9.2e18 then None else Some(int64 total)

/// Renders a byte count with a binary-unit suffix: "1.0GiB",
/// "16.0MiB", "4.0KiB", "512B".
let humanBytes (n: int64) : string =
    if n >= (1L <<< 30) then (float n / float (1L <<< 30)).ToString("F1", inv) + "GiB"
    elif n >= (1L <<< 20) then (float n / float (1L <<< 20)).ToString("F1", inv) + "MiB"
    elif n >= (1L <<< 10) then (float n / float (1L <<< 10)).ToString("F1", inv) + "KiB"
    else n.ToString inv + "B"

/// Renders a possibly-negative byte delta with an explicit sign.
let humanBytesSigned (n: int64) : string =
    if n < 0L then "-" + humanBytes -n else "+" + humanBytes n

/// Binary MiB per second over a nanosecond window; zero when the
/// window is unmeasured.
let mbPerSec (bytes: int64) (ns: int64) : float =
    if ns <= 0L then
        0.0
    else
        float bytes / float (1L <<< 20) / (float ns / 1e9)

/// Renders a throughput as "123.4MB/s" (binary MiB per second) or
/// "n/a" for an unmeasured window.
let humanRate (bytes: int64) (ns: int64) : string =
    if ns <= 0L then
        "n/a"
    else
        (mbPerSec bytes ns).ToString("F1", inv) + "MB/s"

/// The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
/// with trailing zeros removed; empty for zero.
let private fraction (fracNs: int64) : string =
    if fracNs = 0L then
        ""
    else
        "." + fracNs.ToString("D9", inv).TrimEnd '0'

/// Renders a duration the way Go's time.Duration prints: zero as "0s";
/// below one second as milliseconds ("900ms", "1.5ms"); otherwise
/// "[Hh][Mm]Ss" where the hour part appears when non-zero, the minute
/// part when the hour part appears or the minutes are non-zero, and
/// the seconds carry their fraction with trailing zeros removed ("5s",
/// "5.003s", "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
let humanDuration (ns: int64) : string =
    let ns = abs ns

    if ns = 0L then
        "0s"
    elif ns < 1_000_000_000L then
        let ms = ns / 1_000_000L
        let msFrac = (ns % 1_000_000L) * 1000L // scaled to 9 digits
        ms.ToString inv + fraction msFrac + "ms"
    else
        let hours = ns / 3_600_000_000_000L
        let rem = ns % 3_600_000_000_000L
        let minutes = rem / 60_000_000_000L
        let rem = rem % 60_000_000_000L
        let seconds = rem / 1_000_000_000L
        let frac = rem % 1_000_000_000L
        let sb = StringBuilder()

        if hours > 0L then
            sb.Append(hours.ToString inv).Append 'h' |> ignore

        if hours > 0L || minutes > 0L then
            sb.Append(minutes.ToString inv).Append 'm' |> ignore

        sb.Append(seconds.ToString inv).Append(fraction frac).Append 's' |> ignore
        sb.ToString()

/// Rounds a nanosecond count to the nearest multiple of unitNs.
let roundTo (ns: int64) (unitNs: int64) : int64 = (ns + unitNs / 2L) / unitNs * unitNs

/// Fixed-decimal rendering under the invariant culture.
let f (v: float) (decimals: int) : string =
    v.ToString("F" + decimals.ToString inv, inv)

/// Decimal rendering under the invariant culture.
let d (v: int64) : string = v.ToString inv
