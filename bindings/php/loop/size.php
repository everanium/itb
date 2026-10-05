<?php

/**
 * Size and duration parsing, the monotonic clock, and the human
 * renderings of sizes, rates and durations. Every rendering here is
 * part of the output contract shared with the Go harness and the other
 * bindings' loop utilities, so the formats are fixed to the character,
 * not to taste.
 */

declare(strict_types=1);

namespace Everanium\Itb3\Loop;

/**
 * Byte-size suffixes, longest first so "KIB" is matched before "K" and
 * "B" never swallows the tail of another suffix. Every multiple is
 * binary.
 */
const SIZE_SUFFIXES = [
    'KIB' => 1024,
    'KB' => 1024,
    'K' => 1024,
    'MIB' => 1048576,
    'MB' => 1048576,
    'M' => 1048576,
    'GIB' => 1073741824,
    'GB' => 1073741824,
    'G' => 1073741824,
    'B' => 1,
];

/**
 * Duration units in the order the grammar probes them, so "ms" is
 * taken before "m" and "s", and "ns" / "us" before "s".
 */
const DURATION_UNITS = [
    ['ns', 1.0],
    ['us', 1e3],
    ['ms', 1e6],
    ['s', 1e9],
    ['m', 60e9],
    ['h', 3600e9],
];

/**
 * Parses a human byte-size string ("16MB", "1MiB", "512K",
 * "1073741824") into a byte count. Every suffix is a binary multiple:
 * K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
 * bytes; matching is case-insensitive and surrounding whitespace is
 * trimmed. Returns null on a malformed or negative value.
 */
function parse_size(string $s): ?int
{
    $upper = \strtoupper(\trim($s));
    if ($upper === '') {
        return null;
    }
    $mult = 1;
    $digits = $upper;
    foreach (SIZE_SUFFIXES as $suffix => $m) {
        if (\substr($upper, -\strlen($suffix)) === $suffix) {
            $mult = $m;
            $digits = \substr($upper, 0, \strlen($upper) - \strlen($suffix));
            break;
        }
    }
    $digits = \rtrim($digits);
    if ($digits === '' || !\ctype_digit($digits)) {
        return null;
    }
    // PHP integers overflow into floats rather than wrapping, so the
    // product is bounded before it is taken rather than checked after.
    if (\strlen($digits) > 19) {
        return null;
    }
    $n = (int) $digits;
    if ($mult > 1 && $n > \intdiv(\PHP_INT_MAX, $mult)) {
        return null;
    }
    return $n * $mult;
}

/**
 * Parses the Go duration grammar — a sequence of decimal numbers each
 * followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
 * "1h30m", "3s500ms", "1.5s" — into nanoseconds. Returns null on a
 * malformed string.
 */
function parse_duration(string $s): ?int
{
    if ($s === '') {
        return null;
    }
    $total = 0.0;
    $pos = 0;
    $len = \strlen($s);
    while ($pos < $len) {
        $start = $pos;
        while ($pos < $len && (\ctype_digit($s[$pos]) || $s[$pos] === '.')) {
            $pos++;
        }
        if ($pos === $start) {
            return null;
        }
        $digits = \substr($s, $start, $pos - $start);
        if (!\is_numeric($digits)) {
            return null;
        }
        $value = (float) $digits;
        if ($value < 0.0) {
            return null;
        }
        $mult = 0.0;
        foreach (DURATION_UNITS as [$unit, $ns]) {
            $after = $pos + \strlen($unit);
            if (\substr($s, $pos, \strlen($unit)) !== $unit) {
                continue;
            }
            if ($after < $len && \ctype_alpha($s[$after])) {
                continue;
            }
            $mult = $ns;
            $pos = $after;
            break;
        }
        if ($mult === 0.0) {
            return null;
        }
        $total += $value * $mult;
    }
    if ($total > 9.2e18) {
        return null;
    }
    return (int) $total;
}

/** Monotonic wall clock in nanoseconds. */
function now_ns(): int
{
    return \hrtime(true);
}

/**
 * Renders a byte count with a binary-unit suffix: "1.0GiB",
 * "16.0MiB", "4.0KiB", "512B".
 */
function human_bytes(int $n): string
{
    if ($n >= 1073741824) {
        return \sprintf('%.1fGiB', $n / 1073741824);
    }
    if ($n >= 1048576) {
        return \sprintf('%.1fMiB', $n / 1048576);
    }
    if ($n >= 1024) {
        return \sprintf('%.1fKiB', $n / 1024);
    }
    return $n . 'B';
}

/** Renders a possibly-negative byte delta with an explicit sign. */
function human_bytes_signed(int $n): string
{
    return $n < 0 ? '-' . human_bytes(-$n) : '+' . human_bytes($n);
}

/**
 * Binary MiB per second over a nanosecond window; 0 when the window is
 * unmeasured.
 */
function mb_per_sec(int $byteCount, int $ns): float
{
    if ($ns <= 0) {
        return 0.0;
    }
    return $byteCount / 1048576 / ($ns / 1e9);
}

/**
 * Renders a throughput as "123.4MB/s" (binary MiB per second) or "n/a"
 * for an unmeasured window.
 */
function human_rate(int $byteCount, int $ns): string
{
    if ($ns <= 0) {
        return 'n/a';
    }
    return \sprintf('%.1fMB/s', mb_per_sec($byteCount, $ns));
}

/**
 * The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
 * with trailing zeros removed; empty for zero.
 */
function duration_fraction(int $fracNs): string
{
    if ($fracNs === 0) {
        return '';
    }
    return '.' . \rtrim(\sprintf('%09d', $fracNs), '0');
}

/**
 * Renders a duration the way Go's time.Duration prints: below one
 * second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
 * where the hour part appears when non-zero, the minute part when the
 * hour part appears or the minutes are non-zero, and the seconds carry
 * their fraction with trailing zeros removed ("5s", "5.003s", "1m0s",
 * "1m5.25s", "1h0m0s"). The caller rounds first.
 */
function human_duration(int $ns): string
{
    $ns = \abs($ns);
    if ($ns === 0) {
        return '0s';
    }
    if ($ns < 1000000000) {
        // Scale the sub-millisecond remainder to nine digits so the
        // fraction renderer sees the same shape it does for seconds.
        return \intdiv($ns, 1000000)
            . duration_fraction(($ns % 1000000) * 1000) . 'ms';
    }
    $hours = \intdiv($ns, 3600000000000);
    $rem = $ns % 3600000000000;
    $minutes = \intdiv($rem, 60000000000);
    $rem %= 60000000000;
    $seconds = \intdiv($rem, 1000000000);
    $frac = $rem % 1000000000;
    $out = $hours > 0 ? $hours . 'h' : '';
    if ($hours > 0 || $minutes > 0) {
        $out .= $minutes . 'm';
    }
    return $out . $seconds . duration_fraction($frac) . 's';
}

/** Rounds a nanosecond count to the nearest multiple of $unitNs. */
function round_ns(int $ns, int $unitNs): int
{
    return \intdiv($ns + \intdiv($unitNs, 2), $unitNs) * $unitNs;
}

/**
 * Renders a 64-bit value as unsigned decimal.
 *
 * PHP-specific. PHP has one integer type and it is signed, so a value
 * above 2^63-1 is carried as the negative pattern with the same bits;
 * the unsigned conversion specifier reads that pattern back the way
 * every other implementation prints it.
 */
function u64_dec(int $v): string
{
    return \sprintf('%u', $v);
}
