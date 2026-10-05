<?php

/**
 * The worker: its warmup iteration, its main loop, one iteration, the
 * session pump loop the stream shape drives, and the round-trip
 * comparison that decides between a worker error and a data mismatch.
 */

declare(strict_types=1);

namespace Everanium\Itb3\Loop;

use Everanium\Itb3\ItbException;
use Everanium\Itb3\Pipeline;

/**
 * Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair and
 * ITB drives the chunk loop internally; the C ABI has no reader /
 * writer entry, so the caller drives it: open a session, feed slices of
 * at most 1 MiB, drain whatever the session has produced after every
 * write (a read before end never blocks), end, then drain until the
 * session reports finished (after end, a read on an empty spool blocks
 * until the terminal bytes arrive). The loop is written here rather
 * than delegated to the binding's drainAll convenience so it stands in
 * the utility, at the same place, in every language.
 */
function pump(Pipeline $pipe, bool $encrypt, string $src): string
{
    $session = $encrypt ? $pipe->encryptStream() : $pipe->decryptStream();
    try {
        $parts = [];
        $off = 0;
        $total = \strlen($src);
        while ($off < $total) {
            $end = \min($off + PUMP_SLICE, $total);
            $session->write(\substr($src, $off, $end - $off));
            $off = $end;
            while (true) {
                $chunk = $session->read(PUMP_SLICE);
                if ($chunk === '') {
                    break;
                }
                $parts[] = $chunk;
            }
        }
        $session->end();
        while (true) {
            $chunk = $session->read(PUMP_SLICE);
            if ($chunk !== '') {
                $parts[] = $chunk;
            }
            if ($session->isFinished()) {
                break;
            }
        }
        return \implode('', $parts);
    } finally {
        $session->free();
    }
}

/**
 * First offset at which $a and $b differ; the shorter length when one
 * is a prefix of the other.
 */
function first_difference(string $a, string $b): int
{
    $n = \min(\strlen($a), \strlen($b));
    for ($i = 0; $i < $n; $i++) {
        if ($a[$i] !== $b[$i]) {
            return $i;
        }
    }
    return $n;
}

/**
 * Up to 16 bytes of $buf from $off as lowercase hex, or "-" when $buf
 * has no bytes there.
 */
function hex_window(string $buf, int $off): string
{
    if ($off >= \strlen($buf)) {
        return '-';
    }
    return \bin2hex(\substr($buf, $off, 16));
}

/**
 * Leaves the process on the spot with the mismatch code, without
 * unwinding.
 *
 * PHP-specific. exit() runs every shutdown function and every object
 * destructor on the way out, and the Pipeline destructor closes the
 * handle whose state is the evidence a mismatch leaves behind. The
 * libc entry that ends a process without any of that is reached
 * through the same FFI mechanism the binding itself uses; where it
 * cannot be resolved, exit() is taken instead and the handles are
 * released as it leaves.
 */
function terminate_mismatch(): void
{
    try {
        $libc = \FFI::cdef('void _exit(int code);');
        $libc->_exit(3);
    } catch (\Throwable $e) {
        exit(3);
    }
}

/** Records a worker error for a failed cipher call. */
function cipher_fail(Worker $w, int $it, int $shape, string $direction, ItbException $e): void
{
    worker_fail($w, \sprintf(
        'g%d iter %d shape=%s: %s: %s',
        $w->id,
        $it,
        shape_name($shape),
        $direction,
        status_detail($e)
    ));
}

/**
 * One iteration. In order: refill the plaintext under rotating mode;
 * pick the surface; encrypt (timed); decrypt (timed); compare the
 * round-trip with the plaintext; bump the counters. A shared-handle
 * binding wraps the whole round-trip in a read lock so handle-mutating
 * maintenance never lands between an encrypt and its matching decrypt;
 * under this binding's single mode the one worker is the only caller,
 * maintenance runs after this returns from the worker loop, and there
 * is nothing to exclude. Returns false after recording the worker
 * error.
 */
function iterate(Worker $w, int $it): bool
{
    $r = $w->run;

    if ($w->payloadMode === PAYLOAD_ROTATING) {
        [$w->plaintext, $w->rng] = fill_payload(
            PAYLOAD_ROTATING,
            $w->seeded,
            $w->rng,
            \strlen($w->plaintext)
        );
    }

    // Shape dispatch. message is one whole-buffer call on the Single
    // Message Pipeline; stream_one_shot is one whole-buffer call on the
    // streaming Pipeline (the C ABI's ITB_Triple_EncryptStream, which
    // routes to the same whole-buffer stream entry the Go harness calls
    // by name); stream opens a session on the same streaming Pipeline
    // and drives the chunk loop from here. Under both the three rotate
    // by iteration number so the session path and the whole-buffer path
    // alternate on one handle inside every worker — the cross-path
    // state-reuse hazard this harness exists to catch.
    $shape = $r->cfg->shape;
    if ($shape === SHAPE_BOTH) {
        $shape = [SHAPE_STREAM, SHAPE_MESSAGE, SHAPE_STREAM_ONE_SHOT][$it % 3];
    }

    $want = $w->plaintext;
    if ($shape === SHAPE_STREAM) {
        $t0 = now_ns();
        try {
            $wire = pump($r->streamPipe, true, $want);
        } catch (ItbException $e) {
            cipher_fail($w, $it, $shape, 'encrypt', $e);
            return false;
        }
        $w->nanosEnc += now_ns() - $t0;
        $t0 = now_ns();
        try {
            $got = pump($r->streamPipe, false, $wire);
        } catch (ItbException $e) {
            cipher_fail($w, $it, $shape, 'decrypt', $e);
            return false;
        }
        $w->nanosDec += now_ns() - $t0;
    } else {
        $pipe = $shape === SHAPE_MESSAGE ? $r->msgPipe : $r->streamPipe;
        $enc = $shape === SHAPE_MESSAGE ? 'encryptMessage' : 'encryptStreamOneShot';
        $dec = $shape === SHAPE_MESSAGE ? 'decryptMessage' : 'decryptStreamOneShot';
        $t0 = now_ns();
        try {
            $wire = $pipe->$enc($want);
        } catch (ItbException $e) {
            cipher_fail($w, $it, $shape, 'encrypt', $e);
            return false;
        }
        $w->nanosEnc += now_ns() - $t0;
        $t0 = now_ns();
        try {
            $got = $pipe->$dec($wire);
        } catch (ItbException $e) {
            cipher_fail($w, $it, $shape, 'decrypt', $e);
            return false;
        }
        $w->nanosDec += now_ns() - $t0;
    }

    // Failure model. A cipher call that returns a non-OK status is a
    // worker error: it is recorded, the run is asked to stop, the other
    // workers finish their in-flight iteration, and the error is listed
    // in the summary with the FAIL verdict. A round-trip that returns
    // OK with different bytes is a data mismatch: the process
    // terminates here, without summary or cleanup, because the Pipeline
    // state that produced the wrong bytes is the evidence and nothing
    // that runs afterwards may touch it.
    if ($got !== $want) {
        $off = first_difference($want, $got);
        \fwrite(\STDERR, \sprintf(
            "loop: DATA MISMATCH g%d iter %d shape=%s: want %d bytes, got %d bytes, "
            . "first difference at offset %d: want %s got %s\n",
            $w->id,
            $it,
            shape_name($shape),
            \strlen($want),
            \strlen($got),
            $off,
            hex_window($want, $off),
            hex_window($got, $off)
        ));
        \fflush(\STDERR);
        terminate_mismatch();
    }

    $w->iters++;
    $w->bytesEnc += \strlen($want);
    $w->bytesDec += \strlen($got);
    return true;
}

/**
 * The warmup iteration, run before the clock starts.
 *
 * Concurrency mode. This binding runs single: the PHP CLI SAPI is one
 * thread around one interpreter and a stock build ships no thread
 * primitive, so nothing can put a second cipher call into the library
 * at the same time. --goroutines is therefore accepted, clamped to 1,
 * and reported next to the requested value, so a fleet reading the
 * summary sees the mode rather than inferring it. The warmup barrier
 * the shared-handle bindings need degenerates to this worker's own
 * first iteration.
 */
function warmup(Worker $w): bool
{
    try {
        return iterate($w, 0);
    } catch (\Throwable $e) {
        worker_fail($w, \sprintf('g%d iter 0: %s', $w->id, $e->getMessage()));
        return false;
    }
}

/**
 * The main loop, entered after the warmup iteration has completed and
 * the baselines have been taken. It runs until a stop is requested, the
 * duration deadline passes, or the fixed per-worker iteration budget
 * (warmup included) is spent.
 */
function run_worker(Worker $w): void
{
    $r = $w->run;
    $cfg = $r->cfg;
    $it = 1;
    while (true) {
        if ($cfg->iterations > 0 && $it >= $cfg->iterations) {
            break;
        }
        if ($r->stop) {
            break;
        }
        if ($cfg->iterations === 0 && now_ns() - $r->startNs >= $cfg->durationNs) {
            break;
        }
        try {
            if (!iterate($w, $it)) {
                break;
            }
            if (!worker_maintenance($w, $it)) {
                break;
            }
        } catch (\Throwable $e) {
            worker_fail($w, \sprintf('g%d iter %d: %s', $w->id, $it, $e->getMessage()));
            break;
        }
        $it++;
    }
}
