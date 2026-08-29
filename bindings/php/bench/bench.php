<?php

/**
 * Micro-benchmarks for the PHP binding: encryptMessage (Single
 * Message shape) and stream-session encrypt (Streaming Non-AEAD
 * shape) throughput at 1 MiB / 16 MiB / 64 MiB. Wall-clock via
 * hrtime; output is a fixed-width table:
 *
 *     bench             size     mb_per_sec
 *     message           1 MiB    <n>
 *     ...
 *
 * Configuration is driven by environment variables so a side-by-side
 * comparison with the root Go bench harness is straightforward:
 *
 *     ITB_NONCE_BITS      512         shipped secure default
 *     ITB_KEY_BITS        1024        matches root Go BENCH3.md 1024-bit table
 *     ITB_WITH_PARALLAX   false       root Go bench runs without parallax
 *     ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
 *     ITB_INNER_HASH      (profile)   opaque hash name
 *     ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
 *     ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
 *     ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)
 */

declare(strict_types=1);

require __DIR__ . '/../autoload.php';

use Everanium\Itb\FFIBridge;
use Everanium\Itb\Itb;
use Everanium\Itb\Pipeline;
use Everanium\Itb\StreamSession;

// 64 MiB plaintexts plus wire copies exceed the default PHP CLI
// memory_limit; lift it for the bench process only.
ini_set('memory_limit', '-1');

const SIZES = [1 << 20, 16 << 20, 64 << 20];
const BENCH_MIN_ITERS = 3;

function bench_min_seconds(): float
{
    $raw = getenv('ITB_BENCH_MIN_SEC');
    $v = is_string($raw) ? (float) $raw : 0.0;
    return $v > 0.0 ? $v : 5.0;
}

/**
 * Reads the bench-shape env vars into an opts array. Defaults match
 * root Go BENCH3.md so numbers are directly comparable.
 *
 * @return array<string, bool|int|string>
 */
function build_opts(): array
{
    $opts = [
        'nonceBits' => (int) (getenv('ITB_NONCE_BITS') ?: 512),
        'keyBits' => (int) (getenv('ITB_KEY_BITS') ?: 1024),
        'withParallax' => in_array(getenv('ITB_WITH_PARALLAX'), ['true', '1'], true),
        'withWrapper' => in_array(getenv('ITB_WITH_WRAPPER'), ['true', '1'], true),
    ];
    $inner = getenv('ITB_INNER_HASH');
    if (is_string($inner) && $inner !== '') {
        $opts['innerHash'] = $inner;
    }
    $macName = getenv('ITB_MAC_NAME');
    if (is_string($macName) && $macName !== '') {
        $opts['macName'] = $macName;
    }
    return $opts;
}

function profile_name(string $shape_env, string $fallback): string
{
    $s = getenv($shape_env);
    if (is_string($s) && $s !== '') {
        return $s;
    }
    $env = getenv('ITB_PROFILE');
    return is_string($env) && $env !== '' ? $env : $fallback;
}

function size_label(int $size): string
{
    return $size >= (1 << 20) ? ($size >> 20) . ' MiB' : ($size >> 10) . ' KiB';
}

/** Runs $fn until the wall-clock budget is spent (with an iteration
 * floor + one untimed warm-up), then prints one table row. */
function bench_case(string $name, int $size, callable $fn): void
{
    $fn(); // warm-up
    $budget = bench_min_seconds();
    $start = hrtime(true);
    $elapsed = 0.0;
    $iters = 0;
    while ($elapsed < $budget || $iters < BENCH_MIN_ITERS) {
        $fn();
        $iters++;
        $elapsed = (hrtime(true) - $start) / 1e9;
    }
    $mb = $size * $iters / (1024.0 * 1024.0);
    printf("%-17s %-8s %.1f\n", $name, size_label($size), $mb / $elapsed);
}

function main(): void
{
    // Bench-scale allocation churn leaks Go scratch heap unboundedly
    // without a soft memory cap + aggressive GC; the return values
    // report the previous settings, not an error.
    Itb::setMemoryLimit(512 << 20);
    Itb::setGcPercent(20);

    printf("%-17s %-8s mb_per_sec\n", 'bench', 'size');

    // Single Message shape via encryptMessageInto with one reusable
    // caller-owned output scratch per size (allocated outside the
    // timing loop), so the measured path carries no per-iteration
    // output allocation or PHP-string copy.
    $ffi = FFIBridge::get();
    $pipe = Itb::create(profile_name('ITB_MSG_PROFILE', 'singlemsg-triple-nomac-v1'), build_opts());
    foreach (SIZES as $size) {
        // CSPRNG-fill so plaintext content matches the root Go bench
        // (crypto/rand). Not in the timing loop.
        $plain = random_bytes($size);
        $cap = intdiv($size * 5, 4) + 131072;
        $out = $ffi->new("char[$cap]");
        bench_case('message', $size, static function () use ($pipe, $plain, $out, $cap): void {
            $pipe->encryptMessageInto($plain, $out, $cap);
        });
        // Pre-encrypt one wire outside the decrypt timing loop.
        $dec_wire = $pipe->encryptMessage($plain);
        bench_case('message-dec', $size, static function () use ($pipe, $dec_wire): void {
            $pipe->decryptMessage($dec_wire);
        });
        unset($plain, $out, $dec_wire);
    }
    $pipe->free();

    // Streaming Non-AEAD shape via an incremental session per
    // iteration: one write, then a readInto drain to completion
    // through one reusable slice buffer shared by every iteration.
    $pipe = Itb::create(profile_name('ITB_STREAM_PROFILE', 'streaming-noaead-triple-v1'), build_opts());
    $slice = $ffi->new('char[' . StreamSession::READ_BUF . ']');
    foreach (SIZES as $size) {
        $plain = random_bytes($size);
        bench_case('stream_session', $size, static function () use ($pipe, $plain, $slice): void {
            $sess = $pipe->encryptStream();
            $sess->write($plain);
            $sess->end();
            $finished = false;
            while (!$finished) {
                [, $finished] = $sess->readInto($slice, StreamSession::READ_BUF);
            }
            $sess->free();
        });
        // Pre-encrypt one wire outside the decrypt timing loop.
        $enc_sess = $pipe->encryptStream();
        $enc_sess->write($plain);
        $enc_sess->end();
        $wire_parts = [];
        while (!$enc_sess->isFinished()) {
            $data = $enc_sess->read(StreamSession::READ_BUF);
            if ($data !== '') { $wire_parts[] = $data; }
        }
        $enc_sess->free();
        $dec_wire = implode('', $wire_parts);
        bench_case('stream_session-dec', $size, static function () use ($pipe, $dec_wire, $slice): void {
            $sess = $pipe->decryptStream();
            $sess->write($dec_wire);
            $sess->end();
            $finished = false;
            while (!$finished) {
                [, $finished] = $sess->readInto($slice, StreamSession::READ_BUF);
            }
            $sess->free();
        });
        unset($plain, $dec_wire, $wire_parts);
    }
    unset($slice);
    $pipe->free();

    // Whole-buffer stream: one FFI round trip through
    // encryptStreamOneShot / decryptStreamOneShot per iteration.
    $pipe = Itb::create(profile_name('ITB_STREAM_PROFILE', 'streaming-noaead-triple-v1'), build_opts());
    foreach (SIZES as $size) {
        $plain = random_bytes($size);
        bench_case('stream_one_shot', $size, static function () use ($pipe, $plain): void {
            $pipe->encryptStreamOneShot($plain);
        });
        // Pre-encrypt one wire outside the decrypt timing loop.
        $dec_wire = $pipe->encryptStreamOneShot($plain);
        bench_case('stream_one_shot-dec', $size, static function () use ($pipe, $dec_wire): void {
            $pipe->decryptStreamOneShot($dec_wire);
        });
        unset($plain, $dec_wire);
    }
    $pipe->free();
}

main();
