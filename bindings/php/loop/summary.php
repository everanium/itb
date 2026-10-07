<?php

/**
 * The final summary in both renderings, and the two measurements it
 * folds in that are not per-worker counters: the process resident set
 * and the shared library's pool counters.
 */

declare(strict_types=1);

namespace Everanium\Itb3\Loop;

use Everanium\Itb3\Itb;
use Everanium\Itb3\ItbException;

/**
 * Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
 * zero on any parse failure.
 */
function status_kb(string $line): int
{
    $fields = \preg_split('/\s+/', \trim($line));
    if ($fields === false || \count($fields) < 2 || !\ctype_digit($fields[1])) {
        return 0;
    }
    return ((int) $fields[1]) * 1024;
}

/**
 * The process's current resident set and its high-water mark in bytes,
 * from /proc/self/status (VmRSS and VmHWM, reported in kB). Both are
 * zero on a platform without that file; the figures are informational
 * and never enter the verdict.
 *
 * @return array{0: int, 1: int}
 */
function read_rss(): array
{
    $text = @\file_get_contents('/proc/self/status');
    if ($text === false) {
        return [0, 0];
    }
    $current = 0;
    $peak = 0;
    foreach (\explode("\n", $text) as $line) {
        if (\strncmp($line, 'VmRSS:', 6) === 0) {
            $current = status_kb($line);
        } elseif (\strncmp($line, 'VmHWM:', 6) === 0) {
            $peak = status_kb($line);
        }
    }
    return [$current, $peak];
}

/**
 * Pool counters. The shared library keeps process-wide monotonic totals
 * at every pool checkout of its cipher core: per hash-array tier the
 * starter width, checkouts, constructor misses, regrow replacements and
 * bytes allocated; for the scratch byte pool and the parallax chunk
 * pool the checkouts, constructor misses, regrows and regrow bytes. Two
 * snapshots bracketing the main loop are differenced into per-run hit /
 * miss figures that tell whether a pool keeps its items warm between
 * calls or evicts them across GC cycles. The slot layout is read from
 * the library: slot 0 carries the tier count T, tier i occupies the
 * five slots at 1 + 5*i, and the two byte pools occupy the eight slots
 * at 1 + 5*T; the vector is sized from the binding's length query,
 * never from a constant.
 *
 * @return list<int>
 */
function pool_snapshot(): array
{
    try {
        return Itb::poolStats();
    } catch (ItbException $e) {
        return [];
    }
}

/** The differenced pool figures of one run. */
final class PoolDelta
{
    /** @var int */
    public $tiers = 0;
    /** @var list<int> */
    public $starter = [];
    /** @var list<int> */
    public $get = [];
    /** @var list<int> */
    public $new = [];
    /** @var list<int> */
    public $regrow = [];
    /** @var list<int> */
    public $newBytes = [];
    /** @var list<int> get, new, regrow, regrow_bytes */
    public $buf = [0, 0, 0, 0];
    /** @var list<int> get, new, regrow, regrow_bytes */
    public $chunk = [0, 0, 0, 0];

    /**
     * @param list<int> $warmup
     * @param list<int> $steady
     */
    public function __construct(array $warmup, array $steady)
    {
        $n = \count($steady);
        if ($warmup === [] || $n < 9 || \count($warmup) !== $n) {
            return;
        }
        $tiers = $steady[0];
        if ($tiers < 0 || 1 + 5 * $tiers + 8 > $n) {
            return;
        }
        $this->tiers = $tiers;
        for ($i = 0; $i < $tiers; $i++) {
            $base = 1 + 5 * $i;
            $this->starter[] = $steady[$base];
            $this->get[] = $steady[$base + 1] - $warmup[$base + 1];
            $this->new[] = $steady[$base + 2] - $warmup[$base + 2];
            $this->regrow[] = $steady[$base + 3] - $warmup[$base + 3];
            $this->newBytes[] = $steady[$base + 4] - $warmup[$base + 4];
        }
        $tail = 1 + 5 * $tiers;
        for ($i = 0; $i < 4; $i++) {
            $this->buf[$i] = $steady[$tail + $i] - $warmup[$tail + $i];
            $this->chunk[$i] = $steady[$tail + 4 + $i] - $warmup[$tail + 4 + $i];
        }
    }
}

/**
 * Misses over checkouts as a percentage; zero when nothing was checked
 * out.
 */
function miss_percent(int $miss, int $get): float
{
    if ($get <= 0) {
        return 0.0;
    }
    return 100.0 * $miss / $get;
}

/**
 * The effective GC percentage as the runtime reports it: the query form
 * of the setter (a set-and-restore round trip inside the library) so
 * the field is the same whether the value came from the flag, the
 * environment, or the runtime default.
 */
function effective_gogc(int $flag): int
{
    if ($flag > 0) {
        return $flag;
    }
    return Itb::setGcPercent(-1);
}

/** Renders $s as a JSON string literal with the escapes JSON requires. */
function json_string(string $s): string
{
    return \json_encode($s, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE);
}

/**
 * Output contract. Both renderings are shared with the Go harness and
 * every other binding's loop utility field for field: the same lines in
 * the same order, the same keys in the same order, floats with a fixed
 * number of decimals so the JSON is byte-identical across
 * implementations. The Go harness alone adds its runtime-internal lines
 * after rss: and its runtime-internal keys after parallax_chunk_pool;
 * nothing here reproduces them because nothing they read is reachable
 * through the C ABI.
 */
function final_summary(RunState $r, int $elapsedNs): int
{
    $cfg = $r->cfg;
    $workers = \array_slice($r->workers, 0, $cfg->workers);
    $totalIters = 0;
    $totalEnc = 0;
    $totalDec = 0;
    $nanosEnc = 0;
    $nanosDec = 0;
    $errors = [];
    foreach ($workers as $w) {
        $totalIters += $w->iters;
        $totalEnc += $w->bytesEnc;
        $totalDec += $w->bytesDec;
        $nanosEnc += $w->nanosEnc;
        $nanosDec += $w->nanosDec;
        if ($w->failed) {
            $errors[] = $w->error;
        }
    }

    // Throughput. Per-direction throughput divides the sum of every
    // worker's wall time in that direction by the worker count — the
    // equivalent single-stream wall time under N-way concurrency — so
    // each direction reports the aggregate rate it sustained rather
    // than collapsing to combined/2 (every iteration moves equal
    // encrypt and decrypt bytes, so a total-elapsed denominator would
    // give both directions the same figure). The combined rate keeps
    // total elapsed as the one-glance overall figure.
    $avgEnc = $nanosEnc > 0 ? \intdiv($nanosEnc, $cfg->workers) : 0;
    $avgDec = $nanosDec > 0 ? \intdiv($nanosDec, $cfg->workers) : 0;

    $rssDelta = $r->rssFinal - $r->rssWarmup;
    $rssGrowth = $r->rssWarmup > 0 ? 100.0 * $rssDelta / $r->rssWarmup : 0.0;

    $pd = new PoolDelta($r->poolWarmup, $r->poolSteady);
    $passed = $errors === [];
    $gomaxprocs = Itb::setGomaxprocs(0);
    $streamProfile = $r->streamPipe !== null ? $r->streamProfile : '';
    $msgProfile = $r->msgPipe !== null ? $r->msgProfile : '';

    if ($cfg->jsonOutput) {
        emit_json(
            $r,
            $elapsedNs,
            $workers,
            $totalIters,
            $totalEnc,
            $totalDec,
            $avgEnc,
            $avgDec,
            $errors,
            $passed,
            $pd,
            $rssGrowth,
            $gomaxprocs,
            $streamProfile,
            $msgProfile
        );
        return $passed ? 0 : 1;
    }

    log_line('=== FINAL ===');
    log_line('  duration: ' . human_duration(round_ns($elapsedNs, 1000000)));
    $parts = [];
    foreach ($workers as $w) {
        $parts[] = (string) $w->iters;
    }
    log_line('  iterations: ' . \implode(' + ', $parts) . ' = ' . $totalIters . ' total');
    log_line(\sprintf(
        '  throughput: encrypt %s, decrypt %s, combined %s',
        human_rate($totalEnc, $avgEnc),
        human_rate($totalDec, $avgDec),
        human_rate($totalEnc + $totalDec, $elapsedNs)
    ));
    log_line(\sprintf(
        '  bytes: %s encrypted, %s decrypted',
        human_bytes($totalEnc),
        human_bytes($totalDec)
    ));
    log_line(\sprintf('  data integrity: %d/%d PASS', $totalIters, $totalIters));
    log_line(\sprintf(
        '  concurrency: %s, workers %d (requested %d)',
        CONCURRENCY,
        $cfg->workers,
        $cfg->workersRequested
    ));
    log_line(\sprintf(
        '  rss: warmup %s, peak %s, final %s (delta %s, %.1f%% growth)',
        human_bytes($r->rssWarmup),
        human_bytes($r->rssPeak),
        human_bytes($r->rssFinal),
        human_bytes_signed($rssDelta),
        $rssGrowth
    ));
    for ($i = 0; $i < $pd->tiers; $i++) {
        if ($pd->starter[$i] === 0) {
            continue;
        }
        $miss = $pd->new[$i] + $pd->regrow[$i];
        log_line(\sprintf(
            '  hash pool tier %d (starter %d): get %d, miss %d (new %d + regrow %d), '
            . 'miss %.2f%%, %s allocated',
            $i,
            $pd->starter[$i],
            $pd->get[$i],
            $miss,
            $pd->new[$i],
            $pd->regrow[$i],
            miss_percent($miss, $pd->get[$i]),
            human_bytes($pd->newBytes[$i])
        ));
    }
    log_line(\sprintf(
        '  buf pool: get %d, regrow %d (of which fresh %d), miss %.2f%%, %s regrown',
        $pd->buf[0],
        $pd->buf[2],
        $pd->buf[1],
        miss_percent($pd->buf[2], $pd->buf[0]),
        human_bytes($pd->buf[3])
    ));
    log_line(\sprintf(
        '  parallax chunk pool: get %d, regrow %d (of which fresh %d), miss %.2f%%, '
        . '%s regrown',
        $pd->chunk[0],
        $pd->chunk[2],
        $pd->chunk[1],
        miss_percent($pd->chunk[2], $pd->chunk[0]),
        human_bytes($pd->chunk[3])
    ));
    if ($r->rekeys > 0) {
        log_line('  rekeys: ' . $r->rekeys);
    }
    if ($r->blobCycles > 0) {
        log_line('  blob cycles: ' . $r->blobCycles);
    }
    foreach ($errors as $text) {
        log_line('  ERROR: ' . $text);
    }
    if ($passed) {
        log_line('  verdict: PASS');
        return 0;
    }
    log_line(\sprintf('  verdict: FAIL (errors=%d)', \count($errors)));
    return 1;
}

/**
 * One compact object on one line, keys in the contract's order, floats
 * with the contract's decimal counts and never in exponent form.
 *
 * @param list<Worker> $workers
 * @param list<string> $errors
 */
function emit_json(
    RunState $r,
    int $elapsedNs,
    array $workers,
    int $totalIters,
    int $totalEnc,
    int $totalDec,
    int $avgEnc,
    int $avgDec,
    array $errors,
    bool $passed,
    PoolDelta $pd,
    float $rssGrowth,
    int $gomaxprocs,
    string $streamProfile,
    string $msgProfile
): void {
    $cfg = $r->cfg;

    $perWorker = [];
    foreach ($workers as $w) {
        $perWorker[] = (string) $w->iters;
    }
    $errorList = [];
    foreach ($errors as $e) {
        $errorList[] = json_string($e);
    }
    $tiers = [];
    for ($i = 0; $i < $pd->tiers; $i++) {
        if ($pd->starter[$i] === 0) {
            continue;
        }
        $tiers[] = \sprintf(
            '{"tier":%d,"starter":%d,"get":%d,"new":%d,"regrow":%d,"new_bytes":%d,'
            . '"miss_percent":%.2f}',
            $i,
            $pd->starter[$i],
            $pd->get[$i],
            $pd->new[$i],
            $pd->regrow[$i],
            $pd->newBytes[$i],
            miss_percent($pd->new[$i] + $pd->regrow[$i], $pd->get[$i])
        );
    }

    $out = \sprintf('{"duration_seconds":%.3f', $elapsedNs / 1e9)
        . \sprintf(',"iterations":%d', $totalIters)
        . ',"per_worker_iterations":[' . \implode(',', $perWorker) . ']'
        . \sprintf(',"bytes_encrypted":%d', $totalEnc)
        . \sprintf(',"bytes_decrypted":%d', $totalDec)
        . \sprintf(',"encrypt_mb_per_sec":%.1f', mb_per_sec($totalEnc, $avgEnc))
        . \sprintf(',"decrypt_mb_per_sec":%.1f', mb_per_sec($totalDec, $avgDec))
        . \sprintf(',"combined_mb_per_sec":%.1f', mb_per_sec($totalEnc + $totalDec, $elapsedNs))
        . \sprintf(',"rekeys":%d', $r->rekeys)
        . \sprintf(',"blob_cycles":%d', $r->blobCycles)
        . ',"worker_errors":[' . \implode(',', $errorList) . ']'
        . ',"verdict":"' . ($passed ? 'PASS' : 'FAIL') . '"'
        . ',"shape":"' . shape_name($cfg->shape) . '"'
        . ',"stream_profile":' . json_string($streamProfile)
        . ',"message_profile":' . json_string($msgProfile)
        . ',"hash":' . json_string($cfg->hash)
        . ',"mac":' . json_string($cfg->mac)
        . \sprintf(',"payload_bytes":%d', $cfg->payload)
        . ',"payload_mode":"' . payload_mode_name($cfg->payloadMode) . '"'
        . \sprintf(',"seed":%d', $cfg->seed)
        . \sprintf(',"key_bits":%d', $cfg->keyBits)
        . \sprintf(',"nonce_bits":%d', $cfg->nonceBits)
        . \sprintf(',"blob_mode":%d', $cfg->blobMode)
        . ',"drbg":' . json_string($cfg->drbg)
        . ',"drbg_auto_tier":' . json_string(Itb::drbgAutoTier())
        . \sprintf(',"chunk_size_bytes":%d', $cfg->chunkSize)
        . \sprintf(',"barrier_fill":%d', $cfg->barrierFill)
        . ',"parallax":"' . on_off($cfg->parallax) . '"'
        . ',"wrapper":"' . on_off($cfg->wrapper) . '"'
        . \sprintf(',"goroutines_requested":%d', $cfg->workersRequested)
        . \sprintf(',"goroutines":%d', $cfg->workers)
        . ',"concurrency":"' . CONCURRENCY . '"'
        . \sprintf(',"gogc":"%d"', effective_gogc($cfg->gogc))
        . \sprintf(',"memlimit_bytes":%d', $cfg->memlimit)
        . \sprintf(',"gomaxprocs":%d', $gomaxprocs)
        . ',"microbatch_tiers":'
        . json_string(policy_label(\getenv('ITB_MICROBATCH_TIERS')))
        . ',"hashpool_starters":'
        . json_string(policy_label(\getenv('ITB_HASHPOOL_STARTERS')))
        . \sprintf(',"rss_warmup_bytes":%d', $r->rssWarmup)
        . \sprintf(',"rss_peak_bytes":%d', $r->rssPeak)
        . \sprintf(',"rss_final_bytes":%d', $r->rssFinal)
        . \sprintf(',"rss_growth_percent":%.2f', $rssGrowth)
        . ',"hash_pool_tiers":[' . \implode(',', $tiers) . ']'
        . \sprintf(
            ',"buf_pool":{"get":%d,"new":%d,"regrow":%d,"regrow_bytes":%d,"miss_percent":%.2f}',
            $pd->buf[0],
            $pd->buf[1],
            $pd->buf[2],
            $pd->buf[3],
            miss_percent($pd->buf[2], $pd->buf[0])
        )
        . \sprintf(
            ',"parallax_chunk_pool":{"get":%d,"new":%d,"regrow":%d,"regrow_bytes":%d,'
            . '"miss_percent":%.2f}',
            $pd->chunk[0],
            $pd->chunk[1],
            $pd->chunk[2],
            $pd->chunk[3],
            miss_percent($pd->chunk[2], $pd->chunk[0])
        )
        . "}\n";
    \fwrite(\STDOUT, $out);
    \fflush(\STDOUT);
}
