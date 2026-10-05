<?php

/**
 * Shared declarations of the loop stress harness: the cipher-surface
 * selectors, the concurrency mode this binding runs, the resolved
 * configuration, the per-worker state, the run state, and the output
 * helpers every unit writes through.
 *
 * PHP-specific. An include is evaluated the first time it is reached,
 * so two units that name each other's declarations cannot both be
 * pulled in at the top: the worker unit drives maintenance and the ops
 * unit reads the run state, which is exactly that shape. A
 * declarations unit holding what both sides need is the same answer the
 * C reference reaches with its header.
 */

declare(strict_types=1);

namespace Everanium\Itb3\Loop;

use Everanium\Itb3\ItbException;
use Everanium\Itb3\Pipeline;

/* Cipher surfaces the --shape flag selects. */
const SHAPE_STREAM = 0;          // session pump: begin / write / read / end
const SHAPE_MESSAGE = 1;         // Single Message: one whole-buffer call
const SHAPE_STREAM_ONE_SHOT = 2; // stream surface, one whole-buffer call
const SHAPE_BOTH = 3;            // all three, rotating by iteration number

const SHAPE_NAMES = ['stream', 'message', 'stream_one_shot', 'both'];

/**
 * --goroutines ceiling; the harness targets modest hosts and each
 * worker pins payload-sized buffers for the whole run.
 */
const MAX_WORKERS = 10;

/**
 * Concurrency mode. This binding runs single: the PHP CLI SAPI is one
 * thread around one interpreter, and a stock build ships no thread
 * primitive at all — the extensions that would supply one (parallel,
 * pthreads) require a ZTS build and are not part of the binding's
 * declared requirements, which are PHP plus the FFI extension. So the
 * single-threaded core is the whole of it and --goroutines above 1 is
 * clamped to 1 rather than silently pretending to concurrency.
 */
const CONCURRENCY = 'single';

/**
 * Largest slice fed to a stream session per write; the drain after
 * every write uses the same bound.
 */
const PUMP_SLICE = 1048576;

function shape_name(int $shape): string
{
    return SHAPE_NAMES[$shape];
}

function parse_shape(string $s): ?int
{
    $i = \array_search($s, SHAPE_NAMES, true);
    return $i === false ? null : (int) $i;
}

/** The resolved command line. */
final class Config
{
    /** Run duration in nanoseconds; ignored when iterations > 0. */
    public $durationNs = 0;
    /** Per-worker count incl. warmup; 0 = duration-based. */
    public $iterations = 0;
    /** The --goroutines value as given. */
    public $workersRequested = 0;
    /** The effective worker count. */
    public $workers = 0;
    public $shape = SHAPE_STREAM;
    public $hash = '';
    public $mac = '';
    /** Plaintext bytes per iteration. */
    public $payload = 0;
    /** Resolved bytes; the effective limit once shaped. */
    public $memlimit = 0;
    /** --memlimit auto: cap only when the runtime has none. */
    public $memlimitAuto = false;
    /** 0 = leave the runtime default. */
    public $gogc = 0;
    public $parallax = true;
    public $wrapper = true;

    /** Empty = shape-based profile pair. */
    public $profile = '';
    /** 0 = profile default. */
    public $keyBits = 0;
    /** 0 = profile default. */
    public $nonceBits = 0;
    /** 0 = profile default. */
    public $chunkSize = 0;
    /** 0 = profile default. */
    public $barrierFill = 0;
    /** 0 = inherit from the environment. */
    public $gomaxprocs = 0;
    /** Per-worker iterations between rotations; 0 = never. */
    public $rekeyEvery = 0;
    /** Per-worker iterations between reopens; 0 = never. */
    public $blobCycleEvery = 0;
    public $payloadMode = PAYLOAD_FIXED;
    /** 0 = OS CSPRNG plaintexts. */
    public $seed = 0;
    public $jsonOutput = false;
    /** Empty = none. */
    public $memprofile = '';
}

/**
 * One worker's private state: its plaintext, its generator, its
 * counters, and the error it stopped on.
 */
final class Worker
{
    /** @var int */
    public $id = 0;
    /** @var RunState */
    public $run;

    /** @var string */
    public $plaintext = '';
    /** @var int */
    public $payloadMode = PAYLOAD_FIXED;
    /** @var bool */
    public $seeded = false;
    /** @var int splitmix64 state when seeded */
    public $rng = 0;

    /* Counters the summary reads after the worker has returned. */
    /** @var int */
    public $iters = 0;
    /** @var int */
    public $bytesEnc = 0;
    /** @var int */
    public $bytesDec = 0;
    /** @var int */
    public $nanosEnc = 0;
    /** @var int */
    public $nanosDec = 0;

    /** @var bool */
    public $failed = false;
    /** @var string */
    public $error = '';

    public function __construct(int $id, RunState $run)
    {
        $this->id = $id;
        $this->run = $run;
    }
}

/**
 * The state the run shares: the Pipeline handles, the retained blobs,
 * the stop request, and the baselines the summary reads.
 */
final class RunState
{
    /** @var Config */
    public $cfg;

    /** @var Pipeline|null null unless the shape uses it */
    public $streamPipe = null;
    /** @var Pipeline|null null unless the shape uses it */
    public $msgPipe = null;
    /** @var string */
    public $streamProfile = '';
    /** @var string */
    public $msgProfile = '';

    /**
     * The blob Init handed out, replaced by every rekey; the input of
     * the next blob reopen.
     *
     * @var string
     */
    public $streamBlob = '';
    /** @var string */
    public $msgBlob = '';

    /** @var int */
    public $rekeys = 0;
    /** @var int */
    public $blobCycles = 0;

    /** @var list<Worker> */
    public $workers = [];

    /**
     * Set by the duration deadline, by a signal, or by a failing
     * worker; checked before every iteration.
     *
     * @var bool
     */
    public $stop = false;

    /** @var int */
    public $startNs = 0;
    /** @var int */
    public $finishNs = 0;

    /* Baselines taken after the warmup iteration and at shutdown. */
    /** @var int */
    public $rssWarmup = 0;
    /** @var int */
    public $rssPeak = 0;
    /** @var int */
    public $rssFinal = 0;
    /** @var list<int> */
    public $poolWarmup = [];
    /** @var list<int> */
    public $poolSteady = [];

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
    }
}

/**
 * Prints one prefixed status line to stdout.
 *
 * The line is assembled with its newline and handed over in a single
 * write, so nothing can land between a text and the newline that
 * terminates it.
 */
function log_line(string $text): void
{
    \fwrite(\STDOUT, '[loop] ' . $text . "\n");
    \fflush(\STDOUT);
}

/** Prints one prefixed diagnostic to stderr. */
function err_line(string $text): void
{
    \fwrite(\STDERR, 'loop: ' . $text . "\n");
    \fflush(\STDERR);
}

function on_off(bool $b): string
{
    return $b ? 'on' : 'off';
}

/**
 * Renders an encoder policy env value for the summary: the raw string
 * when set, "default" when the shipped ladder applies.
 */
function policy_label($env): string
{
    if (!\is_string($env)) {
        return 'default';
    }
    $env = \ltrim($env, " \t");
    return $env === '' ? 'default' : $env;
}

/**
 * The failure detail a log line carries: the numeric status the
 * binding's own surface exposes and the finished sentence the library
 * left behind. Nothing is composed here — the wording arrives whole
 * from the failing call.
 */
function status_detail(ItbException $e): string
{
    $status = $e->getStatus();
    if ($status === null) {
        return $e->getDetail();
    }
    return 'status ' . $status . ': ' . $e->getDetail();
}

/**
 * Records the worker's error text (first error wins) and requests a
 * stop of the whole run.
 */
function worker_fail(Worker $w, string $text): void
{
    if (!$w->failed) {
        $w->error = $text;
        $w->failed = true;
    }
    $w->run->stop = true;
}
