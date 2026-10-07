<?php

/**
 * Long-run stress harness. The loop utility holds one Pipeline handle
 * per exercised cipher surface for minutes, hammers it with
 * encrypt -> decrypt -> compare round-trips, rotates the outer masters
 * and reopens the handle from its session blob on a schedule, and
 * reports whether the process survived with every byte intact. It is
 * the PHP binding's counterpart of the Go harness under tools/loop:
 * the same flags, the same round structure, the same summary in both
 * renderings.
 *
 * The default shape is full production: the Streaming AEAD profile with
 * parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
 * 1024-bit keys, and the compile-in 512-bit nonce width, driven through
 * a stream session for five minutes on 16 MiB plaintexts. The worker
 * owns a CSPRNG-generated plaintext held for the whole run, so any
 * cross-call state leakage inside the Pipeline surfaces as a data
 * mismatch rather than cancelling out.
 *
 * A failure is one of two things. A cipher, rekey or load call that
 * returns a non-OK status is a worker error: the run stops, the summary
 * lists it, the verdict is FAIL and the exit code 1. A round-trip that
 * returns without error but with different bytes is a data mismatch:
 * the process terminates on the spot with exit code 3, printing the
 * worker, the iteration and the first differing offset, and no summary
 * — the state that produced the wrong bytes is the evidence. A crash
 * inside the shared library or the host runtime has no exit code of its
 * own here; surfacing it is what the utility is for.
 *
 * Usage:
 *
 *   php loop/main.php --duration 5m --goroutines 3 --shape stream \
 *       --hash areion512 --mac hmac-blake3 --payload-size 16MB \
 *       --memlimit auto --parallax on --wrapper on
 *
 * Ctrl-C triggers a graceful shutdown: the in-flight iteration
 * completes, then the partial summary prints.
 */

declare(strict_types=1);

namespace Everanium\Itb3\Loop;

use Everanium\Itb3\Itb;
use Everanium\Itb3\ItbException;
use Everanium\Itb3\Pipeline;

require_once __DIR__ . '/../autoload.php';
require_once __DIR__ . '/size.php';
require_once __DIR__ . '/payload.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/ops.php';
require_once __DIR__ . '/worker.php';
require_once __DIR__ . '/summary.php';

/** Profiles the shape-based pair is built against when --profile is empty. */
const DEFAULT_STREAM_PROFILE = 'streaming-aead-triple-mac-v1';
const DEFAULT_MESSAGE_PROFILE = 'singlemsg-triple-mac-v1';

/**
 * The primitive supplied for the parallax palette and the outer cipher
 * when a profile leaves them unnamed. AES-CMAC is PRF-grade, so it is
 * sound outside the Interlocked Barrier, and it is the closest relative
 * of the AES-based inner primitive whose profiles need this fill.
 */
const KEYSTREAM_FILL_CIPHER = 'aescmac';

/* Flag value kinds. */
const KIND_INT = 0;
const KIND_INT64 = 1;
const KIND_UINT64 = 2;
const KIND_STRING = 3;
const KIND_BOOL = 4;

/**
 * One command-line flag: its name, the type label the usage prints, its
 * kind, its default, and its help text. Values are validated after the
 * whole line is parsed. The table is in alphabetical order, which is
 * the order the usage prints.
 */
function flag_table(): array
{
    return [
        ['barrier-fill', 'int', KIND_INT, 0,
            'DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)'],
        ['blob-cycle-every', 'int', KIND_INT64, 0,
            'reopen each pipeline from its session blob every N iterations per worker; '
            . '0 = never'],
        ['blob-mode', 'int', KIND_INT, 1,
            'container floor sizing mode: 1 (per-region, default) | 2 (per-container)'],
        ['chunk-size', 'string', KIND_STRING, '0',
            'streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure '
            . 'message shape'],
        ['drbg', 'string', KIND_STRING, '',
            'DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)'],
        ['duration', 'duration', KIND_STRING, '5m',
            'run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0'],
        ['gogc', 'int', KIND_INT, 0,
            'GC trigger percentage; 0 = leave the runtime default'],
        ['gomaxprocs', 'int', KIND_INT, 0,
            'Go runtime GOMAXPROCS override; 0 = inherit from the environment'],
        ['goroutines', 'int', KIND_INT, 3,
            'concurrent workers (1..10); on runtimes without parallelism values above 1 '
            . 'are clamped to 1'],
        ['hash', 'string', KIND_STRING, 'areion512',
            'inner ITB hash primitive name'],
        ['iterations', 'int', KIND_INT64, 0,
            'fixed per-worker iteration count; 0 = duration-based'],
        ['json-output', '', KIND_BOOL, false,
            'print the final summary as one compact JSON object instead of log lines'],
        ['key-bits', 'int', KIND_INT, 0,
            'per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)'],
        ['mac', 'string', KIND_STRING, 'hmac-blake3',
            'MAC primitive name'],
        ['memlimit', 'string', KIND_STRING, 'auto',
            'Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied '
            . 'only when the runtime has no limit) or a size (e.g. 512MB)'],
        ['memprofile', 'string', KIND_STRING, '',
            'write a Go runtime heap profile (pprof) to this path at the end of the run; '
            . 'empty = none'],
        ['nonce-bits', 'int', KIND_INT, 0,
            'on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)'],
        ['parallax', 'string', KIND_STRING, 'on',
            'parallax layer: on | off'],
        ['payload-mode', 'string', KIND_STRING, 'fixed',
            'plaintext content: fixed | rotating | pattern-zero | pattern-ff | '
            . 'pattern-ascii'],
        ['payload-size', 'string', KIND_STRING, '16MB',
            'per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)'],
        ['profile', 'string', KIND_STRING, '',
            'exercise this single registered triple profile (overrides --shape with the '
            . "profile's surface); empty = shape-based profile pair"],
        ['rekey-every', 'int', KIND_INT64, 0,
            'rotate the parallax + wrapper masters via Rekey every N iterations per '
            . 'worker; 0 = never'],
        ['seed', 'uint', KIND_UINT64, 0,
            'deterministic plaintext RNG seed for bug reproduction, NOT for security '
            . 'testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts'],
        ['shape', 'string', KIND_STRING, 'stream',
            'cipher surface to exercise: stream | message | stream_one_shot | both'],
        ['wrapper', 'string', KIND_STRING, 'on',
            'wrapper layer: on | off'],
    ];
}

const INT32_MAX = 2147483647;
const UINT64_MAX_DIGITS = '18446744073709551615';

function usage(): void
{
    $out = "Usage of loop:\n";
    foreach (flag_table() as [$name, $label, $kind, $default, $help]) {
        $out .= '  -' . $name . ($label === '' ? '' : ' ' . $label) . "\n";
        $line = "    \t" . $help;
        // The default-value suffix follows the shape a Go flag set
        // prints: an integer default only when it is non-zero, a string
        // default only when it is non-empty.
        if ($kind === KIND_INT && $default !== 0) {
            $line .= ' (default ' . $default . ')';
        } elseif ($kind === KIND_STRING && $default !== '') {
            $line .= ' (default "' . $default . '")';
        }
        $out .= $line . "\n";
    }
    \fwrite(\STDERR, $out);
    \fflush(\STDERR);
}

/**
 * Parses a decimal digit run into a wrapped 64-bit value, rejecting
 * anything above 2^64-1.
 *
 * PHP-specific. PHP has one integer type and it is signed, and an
 * arithmetic overflow promotes to a float rather than wrapping, so the
 * accumulation runs through the wrapping helpers the seeded generator
 * already needs and the ceiling is checked on the digit string before
 * a single digit is folded in.
 */
function parse_uint64(string $digits): ?int
{
    if ($digits === '' || !\ctype_digit($digits)) {
        return null;
    }
    $trimmed = \ltrim($digits, '0');
    if ($trimmed === '') {
        return 0;
    }
    if (\strlen($trimmed) > \strlen(UINT64_MAX_DIGITS)
        || (\strlen($trimmed) === \strlen(UINT64_MAX_DIGITS)
            && \strcmp($trimmed, UINT64_MAX_DIGITS) > 0)) {
        return null;
    }
    $acc = 0;
    $len = \strlen($trimmed);
    for ($i = 0; $i < $len; $i++) {
        $acc = add64(mul64($acc, 10), \ord($trimmed[$i]) - 0x30);
    }
    return $acc;
}

/** Parses one value into its flag slot; null on a malformed value. */
function assign_value(int $kind, string $value)
{
    if ($kind === KIND_INT || $kind === KIND_INT64) {
        $sign = \substr($value, 0, 1);
        $body = ($sign === '+' || $sign === '-') ? \substr($value, 1) : $value;
        if ($body === '' || !\ctype_digit($body) || \strlen($body) > 19) {
            return null;
        }
        $n = (int) $value;
        if ($kind === KIND_INT && ($n > INT32_MAX || $n < -INT32_MAX)) {
            return null;
        }
        return $n;
    }
    if ($kind === KIND_UINT64) {
        $body = \substr($value, 0, 1) === '+' ? \substr($value, 1) : $value;
        return parse_uint64($body);
    }
    if ($kind === KIND_STRING) {
        return $value;
    }
    if ($value === 'true') {
        return true;
    }
    if ($value === 'false') {
        return false;
    }
    return null;
}

/**
 * Parses argv into the raw flag values. Accepts -name value,
 * --name value, -name=value and --name=value; a boolean flag takes no
 * value unless given as -name=true / -name=false. Returns
 * [0, values] on success, [1, []] for -h / --help (usage printed), or
 * [-1, []] after printing the error.
 *
 * @param list<string> $argv
 * @return array{0: int, 1: array<string, mixed>}
 */
function parse_argv(array $argv): array
{
    $raw = [];
    $byName = [];
    foreach (flag_table() as [$name, $label, $kind, $default, $help]) {
        $raw[$name] = $default;
        $byName[$name] = $kind;
    }
    $i = 0;
    $n = \count($argv);
    while ($i < $n) {
        $arg = $argv[$i];
        if ($arg === '' || $arg === '-' || \substr($arg, 0, 1) !== '-') {
            err_line('unexpected positional arguments: [' . $arg . ']');
            return [-1, []];
        }
        $name = \substr($arg, 0, 2) === '--' ? \substr($arg, 2) : \substr($arg, 1);
        if ($name === 'h' || $name === 'help') {
            usage();
            return [1, []];
        }
        $eq = \strpos($name, '=');
        $value = null;
        if ($eq !== false) {
            $value = \substr($name, $eq + 1);
            $name = \substr($name, 0, $eq);
        }
        if (!\array_key_exists($name, $byName)) {
            err_line('flag provided but not defined: -' . $name);
            usage();
            return [-1, []];
        }
        $kind = $byName[$name];
        if ($value === null) {
            if ($kind === KIND_BOOL) {
                $value = 'true';
            } elseif ($i + 1 < $n) {
                $i++;
                $value = $argv[$i];
            } else {
                err_line('flag needs an argument: -' . $name);
                return [-1, []];
            }
        }
        $parsed = assign_value($kind, $value);
        if ($parsed === null) {
            err_line('invalid value "' . $value . '" for flag -' . $name);
            return [-1, []];
        }
        $raw[$name] = $parsed;
        $i++;
    }
    return [0, $raw];
}

function parse_on_off(string $v): ?bool
{
    if ($v === 'on') {
        return true;
    }
    if ($v === 'off') {
        return false;
    }
    return null;
}

/** Whether $name is in the shipped hash registry the binding enumerates. */
function hash_registered(string $name): bool
{
    try {
        return \in_array($name, Itb::hashNames(), true);
    } catch (ItbException $e) {
        return false;
    }
}

/**
 * Resolves a registered profile to the shape family its record's mode
 * exposes by reading the record through the binding's lookup: a mode
 * beginning with "streaming" exposes the stream surfaces, one beginning
 * with "singlemsg" the message surface, "blob-only" none. Prints the
 * validation message and returns null on rejection.
 */
function profile_surface(string $name): ?int
{
    try {
        $record = Itb::lookup($name);
    } catch (ItbException $e) {
        err_line('--profile "' . $name . '" is not a registered triple profile');
        return null;
    }
    $mode = isset($record['mode']) ? (string) $record['mode'] : '';
    if (\strncmp($mode, 'streaming', 9) === 0) {
        return SHAPE_STREAM;
    }
    if (\strncmp($mode, 'singlemsg', 9) === 0) {
        return SHAPE_MESSAGE;
    }
    err_line('--profile "' . $name . '" carries no cipher surface (blob-only mode)');
    return null;
}

/**
 * Applies a --profile's surface to the requested shape: a
 * message-surface profile forces message; a stream-surface profile
 * keeps stream or stream_one_shot as requested and turns message or
 * both into stream.
 */
function narrow_shape(int $requested, int $surface): int
{
    if ($surface === SHAPE_MESSAGE) {
        return SHAPE_MESSAGE;
    }
    return $requested === SHAPE_STREAM_ONE_SHOT ? SHAPE_STREAM_ONE_SHOT : SHAPE_STREAM;
}

/**
 * Builds the resolved config from argv. Returns [0, cfg], [1, cfg] for
 * help, or [-1, cfg] after printing "loop: <message>" for the first
 * failing rule.
 *
 * @param list<string> $argv
 * @return array{0: int, 1: Config}
 */
function parse_flags(array $argv): array
{
    $cfg = new Config();
    [$rc, $raw] = parse_argv($argv);
    if ($rc !== 0) {
        return [$rc, $cfg];
    }

    $durationNs = parse_duration((string) $raw['duration']);
    if ($durationNs === null || $durationNs <= 0) {
        err_line('--duration must be positive, got ' . $raw['duration']);
        return [-1, $cfg];
    }
    $cfg->durationNs = $durationNs;
    $cfg->iterations = (int) $raw['iterations'];
    if ($cfg->iterations < 0) {
        err_line('--iterations must be >= 0, got ' . $cfg->iterations);
        return [-1, $cfg];
    }
    $goroutines = (int) $raw['goroutines'];
    if ($goroutines < 1 || $goroutines > MAX_WORKERS) {
        err_line('--goroutines must be in 1..' . MAX_WORKERS . ', got ' . $goroutines);
        return [-1, $cfg];
    }
    // Concurrency mode. This binding runs single, so the requested count
    // is recorded and the effective one clamped to 1; the summary
    // reports both so a fleet report cannot read a clamped run as a
    // concurrent one.
    $cfg->workersRequested = $goroutines;
    $cfg->workers = 1;
    $shape = parse_shape((string) $raw['shape']);
    if ($shape === null) {
        err_line('--shape must be stream | message | stream_one_shot | both, got "'
            . $raw['shape'] . '"');
        return [-1, $cfg];
    }
    $cfg->shape = $shape;
    if (!hash_registered((string) $raw['hash'])) {
        err_line('--hash "' . $raw['hash'] . '" is not a registered hash primitive');
        return [-1, $cfg];
    }
    $cfg->hash = (string) $raw['hash'];
    // Validated by Init: the C ABI enumerates no MAC names.
    $cfg->mac = (string) $raw['mac'];
    $payload = parse_size((string) $raw['payload-size']);
    if ($payload === null) {
        err_line('--payload-size: invalid size "' . $raw['payload-size'] . '"');
        return [-1, $cfg];
    }
    $cfg->payload = $payload;
    if ($cfg->payload < 1) {
        err_line('--payload-size must be at least 1 byte');
        return [-1, $cfg];
    }
    if ((string) $raw['memlimit'] === 'auto') {
        $cfg->memlimitAuto = true;
        $cfg->memlimit = $cfg->workers <= 3 ? 1073741824 : 268435456;
    } else {
        $memlimit = parse_size((string) $raw['memlimit']);
        if ($memlimit === null) {
            err_line('--memlimit: invalid size "' . $raw['memlimit'] . '"');
            return [-1, $cfg];
        }
        $cfg->memlimit = $memlimit;
    }
    $cfg->gogc = (int) $raw['gogc'];
    if ($cfg->gogc < 0) {
        err_line('--gogc must be >= 0, got ' . $cfg->gogc);
        return [-1, $cfg];
    }
    $parallax = parse_on_off((string) $raw['parallax']);
    if ($parallax === null) {
        err_line('--parallax must be on | off, got "' . $raw['parallax'] . '"');
        return [-1, $cfg];
    }
    $cfg->parallax = $parallax;
    $wrapper = parse_on_off((string) $raw['wrapper']);
    if ($wrapper === null) {
        err_line('--wrapper must be on | off, got "' . $raw['wrapper'] . '"');
        return [-1, $cfg];
    }
    $cfg->wrapper = $wrapper;
    $cfg->profile = (string) $raw['profile'];
    if ($cfg->profile !== '') {
        $surface = profile_surface($cfg->profile);
        if ($surface === null) {
            return [-1, $cfg];
        }
        $cfg->shape = narrow_shape($cfg->shape, $surface);
    }
    $cfg->keyBits = (int) $raw['key-bits'];
    if (!\in_array($cfg->keyBits, [0, 512, 1024, 2048], true)) {
        err_line('--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got '
            . $cfg->keyBits);
        return [-1, $cfg];
    }
    $cfg->nonceBits = (int) $raw['nonce-bits'];
    if (!\in_array($cfg->nonceBits, [0, 128, 256, 512], true)) {
        err_line('--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got '
            . $cfg->nonceBits);
        return [-1, $cfg];
    }
    $cfg->blobMode = (int) $raw['blob-mode'];
    if (!\in_array($cfg->blobMode, [1, 2], true)) {
        err_line('--blob-mode must be 1 (per-region) | 2 (per-container), got '
            . $cfg->blobMode);
        return [-1, $cfg];
    }
    $cfg->barrierFill = (int) $raw['barrier-fill'];
    if (!\in_array($cfg->barrierFill, [0, 1, 2, 4, 8, 16, 32], true)) {
        err_line('--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile '
            . 'default), got ' . $cfg->barrierFill);
        return [-1, $cfg];
    }
    // Validated by Init: the C ABI enumerates no DRBG names.
    $cfg->drbg = (string) $raw['drbg'];
    $chunkSize = parse_size((string) $raw['chunk-size']);
    if ($chunkSize === null) {
        err_line('--chunk-size: invalid size "' . $raw['chunk-size'] . '"');
        return [-1, $cfg];
    }
    $cfg->chunkSize = $chunkSize;
    $cfg->gomaxprocs = (int) $raw['gomaxprocs'];
    if ($cfg->gomaxprocs < 0) {
        err_line('--gomaxprocs must be > 0 when specified, got ' . $cfg->gomaxprocs);
        return [-1, $cfg];
    }
    $cfg->rekeyEvery = (int) $raw['rekey-every'];
    if ($cfg->rekeyEvery < 0) {
        err_line('--rekey-every must be >= 0, got ' . $cfg->rekeyEvery);
        return [-1, $cfg];
    }
    $cfg->blobCycleEvery = (int) $raw['blob-cycle-every'];
    if ($cfg->blobCycleEvery < 0) {
        err_line('--blob-cycle-every must be >= 0, got ' . $cfg->blobCycleEvery);
        return [-1, $cfg];
    }
    $payloadMode = parse_payload_mode((string) $raw['payload-mode']);
    if ($payloadMode === null) {
        err_line('--payload-mode must be ' . \implode(' | ', PAYLOAD_NAMES) . ', got "'
            . $raw['payload-mode'] . '"');
        return [-1, $cfg];
    }
    $cfg->payloadMode = $payloadMode;
    $cfg->seed = (int) $raw['seed'];
    $cfg->jsonOutput = (bool) $raw['json-output'];
    $cfg->memprofile = (string) $raw['memprofile'];
    return [0, $cfg];
}

/**
 * A consumer that stops reading ends the run. The default disposition
 * for SIGPIPE is restored so the process dies from the signal with
 * status 141 and prints nothing — the reference behaviour, and what
 * anyone piping into head or less expects. The PHP CLI SAPI leaves the
 * signal ignored and its stream layer turns the failed write into a
 * false return it then drops, so without this the process prints into
 * nothing and leaves with status 0, its verdict undelivered. Restoring
 * the default is therefore an explicit step here rather than something
 * inherited.
 *
 * It runs before the first line is printed, because the first line is
 * already a write that can fail. The signal entries live in an
 * extension the binding does not require, so a host without it keeps
 * the disposition the runtime installed and the function says so
 * rather than dying on an undefined call.
 */
function restore_sigpipe(): bool
{
    if (!\function_exists('pcntl_signal')) {
        return false;
    }
    \pcntl_signal(\SIGPIPE, \SIG_DFL);
    return true;
}

/**
 * Graceful stop. SIGINT / SIGTERM set the run's stop request, which the
 * worker checks before starting an iteration, so a signal interrupts
 * nothing mid-call — the in-flight encrypt / decrypt / compare
 * completes, the worker returns, and the partial summary prints with
 * the verdict the completed iterations earned. Asynchronous dispatch is
 * enabled so the handler runs between interpreter instructions; a
 * signal that arrives inside a library call stays pending and is
 * delivered the moment the call returns. On a host without the signal
 * extension no handler is installed and an interrupt keeps the
 * runtime's default disposition, which ends the process where it
 * stands without a summary.
 */
function install_signals(RunState $r): void
{
    if (!\function_exists('pcntl_signal')) {
        return;
    }
    \pcntl_async_signals(true);
    $request = static function () use ($r): void {
        $r->stop = true;
    };
    \pcntl_signal(\SIGINT, $request);
    \pcntl_signal(\SIGTERM, $request);
}

/**
 * String value of $key in a profile record, or "-" when absent or
 * empty.
 *
 * @param array<string, mixed> $record
 */
function record_str(array $record, string $key): string
{
    if (!isset($record[$key]) || !\is_string($record[$key]) || $record[$key] === '') {
        return '-';
    }
    return $record[$key];
}

/**
 * @param array<string, mixed> $record
 */
function record_int(array $record, string $key): int
{
    return isset($record[$key]) ? (int) $record[$key] : 0;
}

/**
 * Prints the construction line with the recipe read back from the blob
 * the Pipeline handed out, not echoed from the flags: every
 * construction override is proven to have reached the library by the
 * value the receiver would see. Record values that are empty (a No MAC
 * profile's MAC, a mixed profile's single hash) print as "-".
 */
function log_pipeline_initialised(string $profile, string $blob): void
{
    try {
        $record = Itb::inspect($blob);
    } catch (ItbException $e) {
        log_line(\sprintf(
            'pipeline initialised: profile=%s blob=%d bytes (inspect: %s)',
            $profile,
            \strlen($blob),
            $e->getDetail()
        ));
        return;
    }
    $line = \sprintf(
        'pipeline initialised: profile=%s blob=%d bytes hash=%s key-bits=%d '
        . 'nonce-bits=%d barrier-fill=%d chunk-size=%d mac=%s parallax=%s wrapper=%s',
        $profile,
        \strlen($blob),
        record_str($record, 'hash'),
        record_int($record, 'keybits'),
        record_int($record, 'nonce_bits'),
        record_int($record, 'barrier_fill'),
        record_int($record, 'chunk'),
        record_str($record, 'mac'),
        on_off((bool) ($record['parallax'] ?? false)),
        on_off((bool) ($record['wrapper'] ?? false))
    );
    if (record_int($record, 'container_mode') === 2) {
        $line .= ' container-mode=2';
    }
    if (record_str($record, 'drbg') !== '-') {
        $line .= ' drbg=' . $record['drbg'];
    }
    log_line($line);
}

/**
 * Returns a copy of a wrap-layer session blob whose inner blob's "mode"
 * field is set to $targetMode (1 = per-region, 2 = per-container);
 * throws \RuntimeException when the blob is not a JSON object or
 * carries no inner blob mode field. The wrap layer's profile record
 * carries its own "mode" (a string); the target is the inner blob's
 * ("ib") integer field. Objects decode as objects rather than arrays so
 * an empty object re-encodes as {}, and slashes in the base64 fields
 * stay unescaped.
 */
function edit_inner_blob_mode(string $blob, int $targetMode): string
{
    $doc = \json_decode($blob, false);
    if (!$doc instanceof \stdClass || !isset($doc->ib) || !$doc->ib instanceof \stdClass
        || !\property_exists($doc->ib, 'mode')) {
        throw new \RuntimeException('inner blob mode field not found');
    }
    $doc->ib->mode = $targetMode;
    $out = \json_encode($doc, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE);
    if ($out === false) {
        throw new \RuntimeException(\json_last_error_msg());
    }
    return $out;
}

/**
 * Folds a keystream primitive into $opts for any layer the named
 * profile leaves unfilled but the operator asked for.
 *
 * A profile built around a primitive that is safe only inside the
 * Interlocked Barrier ships with no parallax palette and no outer
 * cipher: both layers run outside the barrier, where that primitive
 * would stand bare, so the recipe leaves them unnamed rather than
 * naming a primitive that must not key them. Engaging either layer
 * therefore needs a keystream-capable primitive supplied from outside
 * the recipe; without it construction fails on a palette below its
 * minimum or an unnamed outer cipher, and the primitive that most
 * deserves stressing becomes the one that cannot be stressed with those
 * layers engaged.
 *
 * Overrides fold into the resolved record the blob carries, so the
 * receiver rebuilds the same shape from the blob alone.
 *
 * Returns 1 when a layer was filled, 0 when none needed it, -1 on a
 * lookup failure (message already printed).
 *
 * @param array<string, bool|int|float|string> $opts
 */
function fill_keystream_layers(
    string $name,
    array &$opts,
    bool $wantParallax,
    bool $wantWrapper
): int {
    try {
        $record = Itb::lookup($name);
    } catch (ItbException $e) {
        err_line('--profile "' . $name . '" is not a registered triple profile');
        return -1;
    }
    $filled = 0;
    if ($wantParallax && !isset($record['palette'])) {
        $opts['parallaxPalette'] = \implode(',', \array_fill(0, 3, KEYSTREAM_FILL_CIPHER));
        if (!isset($record['segment'])) {
            // A recipe that never carried a palette never carried a
            // segment size either, and the schedule rejects zero.
            $opts['parallaxSegmentSize'] = 4093;
        }
        $filled = 1;
    }
    if ($wantWrapper && !isset($record['outer'])) {
        $opts['outerCipher'] = KEYSTREAM_FILL_CIPHER;
        $filled = 1;
    }
    return $filled;
}

/**
 * Constructs one Pipeline against $profile with every flag-carried
 * override in the opts string (zero values included — the shared
 * library treats zero as "profile default"), then obtains the Init blob
 * once through save: the binding's create entry does not hand the blob
 * back, and the bytes are the ones Init produced. Later blob reopens
 * use the retained blob; save is never called again.
 *
 * @return array{0: Pipeline, 1: string}|null
 */
function build_pipeline(Config $cfg, string $profile): ?array
{
    $opts = [
        'innerHash' => $cfg->hash,
        'macName' => $cfg->mac,
        'withParallax' => $cfg->parallax,
        'withWrapper' => $cfg->wrapper,
        'keyBits' => $cfg->keyBits,
        'nonceBits' => $cfg->nonceBits,
        'barrierFill' => $cfg->barrierFill,
        'drbg' => $cfg->drbg,
        'chunkSize' => $cfg->chunkSize,
    ];
    if ($cfg->profile !== '') {
        $filled = fill_keystream_layers($cfg->profile, $opts, $cfg->parallax, $cfg->wrapper);
        if ($filled < 0) {
            return null;
        }
        if ($filled > 0) {
            err_line($cfg->profile . ' leaves the requested keystream layers unnamed; '
                . KEYSTREAM_FILL_CIPHER . ' supplied for them');
        }
    }
    try {
        $pipe = Itb::create($profile, $opts);
    } catch (ItbException $e) {
        err_line('Init(' . $profile . '): ' . status_detail($e));
        return null;
    }
    try {
        $blob = $pipe->save();
    } catch (ItbException $e) {
        err_line('Save(' . $profile . '): ' . status_detail($e));
        $pipe->free();
        return null;
    }
    if ($cfg->blobMode === 2) {
        // The sizing mode is not an Opts knob: the Init blob is edited
        // and the pipeline reopened from it, so the retained blob (the
        // one blob-cycle reopens from) carries the edited mode.
        try {
            $edited = edit_inner_blob_mode($blob, 2);
        } catch (\RuntimeException $e) {
            err_line('rewrite blob mode: ' . $e->getMessage());
            $pipe->free();
            return null;
        }
        $pipe->free();
        try {
            $pipe = Itb::load($edited);
        } catch (ItbException $e) {
            err_line('reload Mode 2 blob: ' . status_detail($e));
            return null;
        }
        $blob = $edited;
    }
    log_pipeline_initialised($profile, $blob);
    return [$pipe, $blob];
}

/**
 * @param list<string> $argv
 */
function run(array $argv): int
{
    [$rc, $cfg] = parse_flags($argv);
    if ($rc === 1) {
        return 0;
    }
    if ($rc !== 0) {
        return 2;
    }

    $r = new RunState($cfg);

    // Runtime shaping. A long run under allocation churn grows the Go
    // heap inside the shared library without bound unless a soft limit
    // paces the collector, so a limit is always in force: an explicit
    // --memlimit is set as given, and auto caps the heap only when the
    // runtime reports no limit at all (a limit already installed from
    // the environment is left standing). The GC percentage and
    // GOMAXPROCS are set only when their flag is non-zero — a zero flag
    // skips the setter rather than calling it with zero, because zero is
    // a real value to the GC-percent setter, and a call would clobber
    // whatever the environment installed. All of it lands before any
    // Pipeline exists so the baselines are taken under the shaped
    // runtime, in the order heap limit, GC percent, GOMAXPROCS.
    if ($cfg->memlimitAuto) {
        if (Itb::setMemoryLimit(-1) === \PHP_INT_MAX) {
            Itb::setMemoryLimit($cfg->memlimit);
        }
    } else {
        Itb::setMemoryLimit($cfg->memlimit);
    }
    $cfg->memlimit = Itb::setMemoryLimit(-1);
    if ($cfg->gogc > 0) {
        Itb::setGcPercent($cfg->gogc);
    }
    if ($cfg->gomaxprocs > 0) {
        Itb::setGomaxprocs($cfg->gomaxprocs);
    }

    log_line(\sprintf(
        'start: duration=%s iterations=%d goroutines=%d workers=%d concurrency=%s '
        . 'shape=%s hash=%s mac=%s payload=%s memlimit=%s parallax=%s wrapper=%s',
        human_duration($cfg->durationNs),
        $cfg->iterations,
        $cfg->workersRequested,
        $cfg->workers,
        CONCURRENCY,
        shape_name($cfg->shape),
        $cfg->hash,
        $cfg->mac,
        human_bytes($cfg->payload),
        human_bytes($cfg->memlimit),
        on_off($cfg->parallax),
        on_off($cfg->wrapper)
    ));
    log_line(\sprintf(
        'overrides: profile="%s" key-bits=%d nonce-bits=%d chunk-size=%s '
        . 'barrier-fill=%d gomaxprocs=%d rekey-every=%d blob-cycle-every=%d '
        . 'payload-mode=%s seed=%s json-output=%s',
        $cfg->profile,
        $cfg->keyBits,
        $cfg->nonceBits,
        human_bytes($cfg->chunkSize),
        $cfg->barrierFill,
        $cfg->gomaxprocs,
        $cfg->rekeyEvery,
        $cfg->blobCycleEvery,
        payload_mode_name($cfg->payloadMode),
        u64_dec($cfg->seed),
        $cfg->jsonOutput ? 'true' : 'false'
    )
        . ($cfg->blobMode !== 1 ? ' blob-mode=' . $cfg->blobMode : '')
        . ($cfg->drbg !== '' ? ' drbg=' . $cfg->drbg : ''));
    log_line(\sprintf(
        'policy: microbatch-tiers=%s hashpool-starters=%s',
        policy_label(\getenv('ITB_MICROBATCH_TIERS')),
        policy_label(\getenv('ITB_HASHPOOL_STARTERS'))
    ));

    // Pipeline construction — one handle per exercised shape. stream
    // and stream_one_shot share the streaming handle.
    $r->streamProfile = $cfg->profile !== '' ? $cfg->profile : DEFAULT_STREAM_PROFILE;
    $r->msgProfile = $cfg->profile !== '' ? $cfg->profile : DEFAULT_MESSAGE_PROFILE;
    if ($cfg->shape === SHAPE_STREAM || $cfg->shape === SHAPE_STREAM_ONE_SHOT
        || $cfg->shape === SHAPE_BOTH) {
        $built = build_pipeline($cfg, $r->streamProfile);
        if ($built === null) {
            return 1;
        }
        [$r->streamPipe, $r->streamBlob] = $built;
    }
    if ($cfg->shape === SHAPE_MESSAGE || $cfg->shape === SHAPE_BOTH) {
        $built = build_pipeline($cfg, $r->msgProfile);
        if ($built === null) {
            return 1;
        }
        [$r->msgPipe, $r->msgBlob] = $built;
    }

    // Allocation posture. The per-worker plaintext is built once and
    // held for the whole run (rotating mode replaces it per iteration);
    // the wire and round-trip buffers are the strings the binding
    // returns per call and the engine reclaims them when the iteration
    // drops them, and the pump loop accumulates its slices into one
    // joined buffer per direction. Under the default fixed CSPRNG mode
    // every worker's buffer is distinct, so cross-worker data crossover
    // is detectable; pattern modes trade that property for content
    // edge-case coverage.
    for ($i = 0; $i < $cfg->workers; $i++) {
        $w = new Worker($i, $r);
        $w->payloadMode = $cfg->payloadMode;
        $w->seeded = $cfg->seed !== 0;
        $w->rng = seed_worker($cfg->seed, $i);
        try {
            [$w->plaintext, $w->rng] = fill_payload(
                $cfg->payloadMode,
                $w->seeded,
                $w->rng,
                $cfg->payload
            );
        } catch (\Throwable $e) {
            err_line('payload alloc: ' . $e->getMessage());
            return 1;
        }
        $r->workers[] = $w;
    }

    $r->poolWarmup = pool_snapshot();
    $r->poolSteady = $r->poolWarmup;
    if ($r->poolWarmup === []) {
        err_line('pool snapshot alloc failed');
        return 1;
    }

    install_signals($r);

    // Warmup barrier. The worker runs one iteration before the clock
    // starts, so the first-call costs (pool warm-up, lazy kernel
    // dispatch, page faults on the payload buffer) fall outside the
    // measured window, and the RSS and pool baselines taken here
    // describe a process that has already run the whole cipher path
    // once. With one worker the barrier is that worker's own first
    // iteration; the rendezvous the shared-handle bindings need has no
    // second party to wait for.
    $warmupStart = now_ns();
    $warmupOk = warmup($r->workers[0]);
    [$r->rssWarmup, $r->rssPeak] = read_rss();
    $r->poolWarmup = pool_snapshot();
    $warmupNs = now_ns() - $warmupStart;
    log_line(\sprintf(
        'warmup: %d workers x 1 iter completed in %s (baseline rss=%s)',
        $cfg->workers,
        human_duration(round_ns($warmupNs, 100000000)),
        human_bytes($r->rssWarmup)
    ));

    $r->startNs = now_ns();
    $r->finishNs = $r->startNs;
    if ($warmupOk) {
        run_worker($r->workers[0]);
    }
    $r->finishNs = now_ns();

    $elapsedNs = $r->finishNs - $r->startNs;
    [$r->rssFinal, $peak] = read_rss();
    if ($peak > $r->rssPeak) {
        $r->rssPeak = $peak;
    }
    $r->poolSteady = pool_snapshot();

    if ($cfg->memprofile !== '') {
        try {
            Itb::writeHeapProfile($cfg->memprofile);
            log_line('memprofile: heap profile written to ' . $cfg->memprofile);
        } catch (ItbException $e) {
            err_line('memprofile: ' . $e->getDetail());
        }
    }

    $code = final_summary($r, $elapsedNs);

    if ($r->streamPipe !== null) {
        $r->streamPipe->free();
    }
    if ($r->msgPipe !== null) {
        $r->msgPipe->free();
    }
    return $code;
}

// Payload-sized plaintexts plus their wire and round-trip copies
// exceed the default PHP CLI memory_limit; lift it for this process
// only, the way the bench and eitb entry points do.
\ini_set('memory_limit', '-1');

restore_sigpipe();
exit(run(\array_slice($argv, 1)));
