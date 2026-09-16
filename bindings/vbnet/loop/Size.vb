' Size and duration parsing and the human renderings of sizes, rates
' and durations. Every rendering here is part of the output contract
' shared with the Go harness and the other bindings' loop utilities, so
' the formats are fixed to the character, not to taste.
'
' .NET-specific. Every conversion and every format specifier names
' CultureInfo.InvariantCulture explicitly. The process also pins its
' default culture at startup, but a formatter that relies on that alone
' renders "1,5MB/s" the day someone runs it under a comma-decimal
' locale with a thread the pin did not reach, and the output contract is
' byte-for-byte.

Imports System.Globalization
Imports System.Text

Friend Module Size

    Friend ReadOnly Inv As CultureInfo = CultureInfo.InvariantCulture

    ''' <summary>Suffix table for ParseSize, matched in order so the
    ''' longer spellings win over their prefixes.</summary>
    Private ReadOnly SizeSuffixes As (Suffix As String, Mult As Long)() = {
        ("KIB", 1L << 10), ("KB", 1L << 10), ("K", 1L << 10),
        ("MIB", 1L << 20), ("MB", 1L << 20), ("M", 1L << 20),
        ("GIB", 1L << 30), ("GB", 1L << 30), ("G", 1L << 30),
        ("B", 1L)}

    ''' <summary>
    ''' Parses a human byte-size string ("16MB", "1MiB", "512K",
    ''' "1073741824") into a byte count. Every suffix is a binary
    ''' multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB =
    ''' 1024^3, B or none = bytes; matching is case-insensitive and
    ''' surrounding whitespace is trimmed. Nothing on a malformed or
    ''' negative value.
    ''' </summary>
    Friend Function ParseSize(s As String) As Long?
        Dim upper As String = s.Trim().ToUpperInvariant()
        If upper.Length = 0 Then Return Nothing

        Dim mult As Long = 1
        Dim digits As String = upper
        For Each entry In SizeSuffixes
            If upper.EndsWith(entry.Suffix, StringComparison.Ordinal) Then
                mult = entry.Mult
                digits = upper.Substring(0, upper.Length - entry.Suffix.Length)
                Exit For
            End If
        Next

        digits = digits.TrimEnd()
        If digits.Length = 0 Then Return Nothing
        For Each c As Char In digits
            If c < "0"c OrElse c > "9"c Then Return Nothing
        Next

        Dim n As Long
        If Not Long.TryParse(digits, NumberStyles.None, Inv, n) Then Return Nothing
        ' A product past the 64-bit range is a malformed size, not a
        ' number. The bound is checked rather than caught: the project
        ' turns the integer overflow checks off for the seeded generator,
        ' so the multiply below would wrap silently instead of raising.
        If mult > 1 AndAlso n > (Long.MaxValue \ mult) Then Return Nothing
        Return n * mult
    End Function

    ''' <summary>Unit table for ParseDuration, matched in order so "ms"
    ''' wins over "m" followed by a stray "s".</summary>
    Private ReadOnly DurationUnits As (Unit As String, Nanos As Double)() = {
        ("ns", 1.0), ("us", 1000.0), ("ms", 1000000.0),
        ("s", 1000000000.0), ("m", 60000000000.0), ("h", 3600000000000.0)}

    ''' <summary>
    ''' Parses the Go duration grammar — a sequence of decimal numbers
    ''' each followed by a unit (h, m, s, ms, us, ns), such as "30s",
    ''' "5m", "1h30m", "1.5s" — into nanoseconds. Nothing on a
    ''' malformed string.
    ''' </summary>
    Friend Function ParseDuration(s As String) As Long?
        If s.Length = 0 Then Return Nothing

        Dim rest As String = s
        Dim total As Double = 0
        Do While rest.Length > 0
            Dim numLen As Integer = 0
            Do While numLen < rest.Length AndAlso
                     (Char.IsAsciiDigit(rest(numLen)) OrElse rest(numLen) = "."c)
                numLen += 1
            Loop
            If numLen = 0 Then Return Nothing

            Dim v As Double
            If Not Double.TryParse(rest.Substring(0, numLen), NumberStyles.Float, Inv, v) Then
                Return Nothing
            End If

            Dim after As String = rest.Substring(numLen)
            Dim nanos As Double = -1
            For Each entry In DurationUnits
                If after.StartsWith(entry.Unit, StringComparison.Ordinal) Then
                    Dim tail As String = after.Substring(entry.Unit.Length)
                    ' A unit whose next character is a letter is the
                    ' prefix of a longer token that is not a unit at all.
                    If tail.Length > 0 AndAlso Char.IsAsciiLetter(tail(0)) Then Continue For
                    rest = tail
                    nanos = entry.Nanos
                    Exit For
                End If
            Next
            If nanos < 0 Then Return Nothing
            total += v * nanos
        Loop

        If total > 9.2E+18 Then Return Nothing
        Return CLng(total)
    End Function

    ''' <summary>Renders a byte count with a binary-unit suffix:
    ''' "1.0GiB", "16.0MiB", "4.0KiB", "512B".</summary>
    Friend Function HumanBytes(n As Long) As String
        If n >= (1L << 30) Then Return (CDbl(n) / CDbl(1L << 30)).ToString("F1", Inv) & "GiB"
        If n >= (1L << 20) Then Return (CDbl(n) / CDbl(1L << 20)).ToString("F1", Inv) & "MiB"
        If n >= (1L << 10) Then Return (CDbl(n) / CDbl(1L << 10)).ToString("F1", Inv) & "KiB"
        Return n.ToString(Inv) & "B"
    End Function

    ''' <summary>Renders a possibly-negative byte delta with an explicit
    ''' sign.</summary>
    Friend Function HumanBytesSigned(n As Long) As String
        Return If(n < 0, "-" & HumanBytes(-n), "+" & HumanBytes(n))
    End Function

    ''' <summary>Binary MiB per second over a nanosecond window; zero
    ''' when the window is unmeasured.</summary>
    Friend Function MbPerSec(bytes As Long, ns As Long) As Double
        If ns <= 0 Then Return 0.0
        Return CDbl(bytes) / CDbl(1L << 20) / (CDbl(ns) / 1000000000.0)
    End Function

    ''' <summary>Renders a throughput as "123.4MB/s" (binary MiB per
    ''' second) or "n/a" for an unmeasured window.</summary>
    Friend Function HumanRate(bytes As Long, ns As Long) As String
        If ns <= 0 Then Return "n/a"
        Return MbPerSec(bytes, ns).ToString("F1", Inv) & "MB/s"
    End Function

    ''' <summary>The fractional part of a nanosecond remainder
    ''' (0 .. 1e9) as ".ddd" with trailing zeros removed; empty for
    ''' zero.</summary>
    Private Function Fraction(fracNs As Long) As String
        If fracNs = 0 Then Return ""
        Return "." & fracNs.ToString("D9", Inv).TrimEnd("0"c)
    End Function

    ''' <summary>
    ''' Renders a duration the way Go's Duration prints: zero as "0s";
    ''' below one second as milliseconds ("900ms", "1.5ms"); otherwise
    ''' "[Hh][Mm]Ss" where the hour part appears when non-zero, the
    ''' minute part when the hour part appears or the minutes are
    ''' non-zero, and the seconds carry their fraction with trailing
    ''' zeros removed ("5s", "5.003s", "1m0s", "1m5.25s", "1h0m0s").
    ''' The caller rounds first.
    ''' </summary>
    Friend Function HumanDuration(nanos As Long) As String
        Dim ns As Long = Math.Abs(nanos)
        If ns = 0 Then Return "0s"

        If ns < 1000000000L Then
            Dim ms As Long = ns \ 1000000L
            Dim msFrac As Long = (ns Mod 1000000L) * 1000L ' scaled to 9 digits
            Return ms.ToString(Inv) & Fraction(msFrac) & "ms"
        End If

        Dim hours As Long = ns \ 3600000000000L
        Dim rem1 As Long = ns Mod 3600000000000L
        Dim minutes As Long = rem1 \ 60000000000L
        Dim rem2 As Long = rem1 Mod 60000000000L
        Dim seconds As Long = rem2 \ 1000000000L
        Dim frac As Long = rem2 Mod 1000000000L

        Dim sb As New StringBuilder()
        If hours > 0 Then sb.Append(hours.ToString(Inv)).Append("h"c)
        If hours > 0 OrElse minutes > 0 Then sb.Append(minutes.ToString(Inv)).Append("m"c)
        sb.Append(seconds.ToString(Inv)).Append(Fraction(frac)).Append("s"c)
        Return sb.ToString()
    End Function

    ''' <summary>Rounds a nanosecond count to the nearest multiple of
    ''' unitNs.</summary>
    Friend Function RoundTo(ns As Long, unitNs As Long) As Long
        ' VB-specific. The multiplication binds tighter than the
        ' integer division here, so the second division is
        ' parenthesised: without it the expression divides by the
        ' square of the unit and every rounded duration renders 0s.
        Return ((ns + unitNs \ 2) \ unitNs) * unitNs
    End Function

    ''' <summary>Fixed-decimal rendering under the invariant
    ''' culture.</summary>
    Friend Function Fx(v As Double, decimals As Integer) As String
        Return v.ToString("F" & decimals.ToString(Inv), Inv)
    End Function

    ''' <summary>Decimal rendering under the invariant culture.</summary>
    Friend Function Dx(v As Long) As String
        Return v.ToString(Inv)
    End Function
End Module
