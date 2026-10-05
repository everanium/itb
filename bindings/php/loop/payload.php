<?php

/**
 * Plaintext content: the payload modes, the seeded per-worker
 * generator, and the buffer fill from the operating-system CSPRNG.
 */

declare(strict_types=1);

namespace Everanium\Itb3\Loop;

/*
 * Payload mode selectors for the --payload-mode flag.
 *
 *   - fixed: one CSPRNG-generated buffer per worker, held unchanged
 *     for the whole run (the default).
 *   - rotating: the buffer is regenerated before every iteration, so
 *     no two encrypt calls see the same plaintext.
 *   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
 *     all 0xFF) probing minimum-entropy plaintext handling.
 *   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
 *     structured text.
 */
const PAYLOAD_FIXED = 0;
const PAYLOAD_ROTATING = 1;
const PAYLOAD_PATTERN_ZERO = 2;
const PAYLOAD_PATTERN_FF = 3;
const PAYLOAD_PATTERN_ASCII = 4;

const PAYLOAD_NAMES = [
    'fixed',
    'rotating',
    'pattern-zero',
    'pattern-ff',
    'pattern-ascii',
];

function payload_mode_name(int $mode): string
{
    return PAYLOAD_NAMES[$mode];
}

function parse_payload_mode(string $s): ?int
{
    $i = \array_search($s, PAYLOAD_NAMES, true);
    return $i === false ? null : (int) $i;
}

/**
 * Seeded plaintext. The seed makes plaintext content reproducible so a
 * failing iteration can be replayed with the same bytes; it governs
 * nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
 * so a seeded run is a reproduction aid and never a security test.
 * Each worker's stream is domain-separated by its id so seeded workers
 * still hold pairwise-distinct buffers under the fixed and rotating
 * modes. The generator is splitmix64: a few lines in any language,
 * which is why it is the one every binding uses.
 */
function seed_worker(int $seed, int $workerId): int
{
    return add64($seed, $workerId + 1);
}

/**
 * Wrapping 64-bit addition.
 *
 * PHP-specific. PHP integers are signed 64-bit and an arithmetic
 * overflow promotes the result to a float instead of wrapping, which
 * would silently stop being splitmix64 after the first carry out of
 * bit 63. The bitwise operators do work on the full 64-bit pattern, so
 * the sum is carried between two 32-bit halves and reassembled with a
 * shift that discards what leaves the top — two's complement
 * arithmetic, performed by hand.
 */
function add64(int $a, int $b): int
{
    $lo = ($a & 0xFFFFFFFF) + ($b & 0xFFFFFFFF);
    $hi = (($a >> 32) & 0xFFFFFFFF) + (($b >> 32) & 0xFFFFFFFF) + (($lo >> 32) & 0xFFFFFFFF);
    return (($hi & 0xFFFFFFFF) << 32) | ($lo & 0xFFFFFFFF);
}

/**
 * Wrapping 64-bit multiplication.
 *
 * PHP-specific. For the reason given at add64, and over 16-bit limbs
 * rather than 32-bit ones: a product of two 32-bit halves reaches 2^64
 * and would overflow into a float before it could be masked, while a
 * product of two 16-bit limbs stays under 2^32 and every partial sum
 * stays well inside the signed range.
 */
function mul64(int $a, int $b): int
{
    $a0 = $a & 0xFFFF;
    $a1 = ($a >> 16) & 0xFFFF;
    $a2 = ($a >> 32) & 0xFFFF;
    $a3 = ($a >> 48) & 0xFFFF;
    $b0 = $b & 0xFFFF;
    $b1 = ($b >> 16) & 0xFFFF;
    $b2 = ($b >> 32) & 0xFFFF;
    $b3 = ($b >> 48) & 0xFFFF;

    $c0 = $a0 * $b0;
    $c1 = $a0 * $b1 + $a1 * $b0 + ($c0 >> 16);
    $c2 = $a0 * $b2 + $a1 * $b1 + $a2 * $b0 + ($c1 >> 16);
    $c3 = $a0 * $b3 + $a1 * $b2 + $a2 * $b1 + $a3 * $b0 + ($c2 >> 16);

    return (($c3 & 0xFFFF) << 48)
        | (($c2 & 0xFFFF) << 32)
        | (($c1 & 0xFFFF) << 16)
        | ($c0 & 0xFFFF);
}

/**
 * Logical right shift of a 64-bit pattern.
 *
 * PHP-specific. PHP's >> is arithmetic, so a value whose bit 63 is set
 * would be sign-extended; the mask clears the bits the shift would
 * otherwise have carried down.
 */
function shr64(int $v, int $n): int
{
    return ($v >> $n) & ((1 << (64 - $n)) - 1);
}

/** One splitmix64 draw; returns the advanced state and the output. */
function splitmix64(int $state): array
{
    $state = add64($state, -7046029254386353131); // 0x9E3779B97F4A7C15
    $z = $state;
    $z = mul64($z ^ shr64($z, 30), -4658895280553007687); // 0xBF58476D1CE4E5B9
    $z = mul64($z ^ shr64($z, 27), -7723592293110705685); // 0x94D049BB133111EB
    return [$state, $z ^ shr64($z, 31)];
}

/** Draws $n bytes from the operating-system CSPRNG. */
function fill_random(int $n): string
{
    return \random_bytes($n);
}

/**
 * Builds one plaintext buffer according to the payload mode and
 * returns it with the advanced generator state. The fixed and rotating
 * modes draw from the seeded generator when the run is seeded and from
 * the OS CSPRNG otherwise; the pattern modes are deterministic
 * regardless of the seed.
 *
 * @return array{0: string, 1: int}
 */
function fill_payload(int $mode, bool $seeded, int $rng, int $n): array
{
    if ($mode === PAYLOAD_FIXED || $mode === PAYLOAD_ROTATING) {
        if (!$seeded) {
            return [fill_random($n), $rng];
        }
        $parts = [];
        $remaining = $n;
        while ($remaining > 0) {
            [$rng, $value] = splitmix64($rng);
            $word = \pack('P', $value);
            $parts[] = $remaining >= 8 ? $word : \substr($word, 0, $remaining);
            $remaining -= 8;
        }
        return [\implode('', $parts), $rng];
    }
    if ($mode === PAYLOAD_PATTERN_ZERO) {
        return [\str_repeat("\x00", $n), $rng];
    }
    if ($mode === PAYLOAD_PATTERN_FF) {
        return [\str_repeat("\xFF", $n), $rng];
    }
    $ramp = '';
    for ($i = 0; $i < 26; $i++) {
        $ramp .= \chr(0x41 + $i);
    }
    return [\substr(\str_repeat($ramp, \intdiv($n, 26) + 1), 0, $n), $rng];
}
