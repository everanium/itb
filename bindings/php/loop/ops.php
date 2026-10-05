<?php

/**
 * The maintenance operations that mutate a live Pipeline handle
 * between iterations: master rotation (--rekey-every) and blob reopen
 * (--blob-cycle-every).
 */

declare(strict_types=1);

namespace Everanium\Itb3\Loop;

use Everanium\Itb3\Itb;
use Everanium\Itb3\ItbException;

/**
 * Byte length of each fresh master drawn for a rotation. Matches the
 * size Init auto-generates for both the parallax and the wrapper
 * master.
 */
const REKEY_MASTER_SIZE = 32;

/**
 * Master rotation. Rotates the parallax + wrapper masters on every
 * active Pipeline and retains the refreshed blob for subsequent blob
 * reopens. Masters are drawn fresh from the OS CSPRNG on every rotation
 * regardless of --seed (master rotation is pipeline keying, not
 * plaintext content); a disabled layer passes no bytes, which Rekey
 * ignores. The eight inner seeds and the MAC key are untouched by
 * design — Rekey targets only the two outer-layer master secrets.
 */
function rekey_pipes(Worker $w, int $it): bool
{
    $r = $w->run;
    $perm = $r->cfg->parallax ? \random_bytes(REKEY_MASTER_SIZE) : '';
    $wrap = $r->cfg->wrapper ? \random_bytes(REKEY_MASTER_SIZE) : '';

    if ($r->streamPipe !== null) {
        try {
            $r->streamBlob = $r->streamPipe->rekey($perm, $wrap);
        } catch (ItbException $e) {
            worker_fail($w, \sprintf(
                'g%d iter %d: Rekey(%s): %s',
                $w->id,
                $it,
                $r->streamProfile,
                status_detail($e)
            ));
            return false;
        }
    }
    if ($r->msgPipe !== null) {
        try {
            $r->msgBlob = $r->msgPipe->rekey($perm, $wrap);
        } catch (ItbException $e) {
            worker_fail($w, \sprintf(
                'g%d iter %d: Rekey(%s): %s',
                $w->id,
                $it,
                $r->msgProfile,
                status_detail($e)
            ));
            return false;
        }
    }
    $r->rekeys++;
    log_line(\sprintf(
        'rekey: g%d iter %d rotated parallax + wrapper masters (rekey #%d)',
        $w->id,
        $it,
        $r->rekeys
    ));
    return true;
}

/**
 * Blob reopen. Reopens every active Pipeline from its retained blob: a
 * fresh handle is loaded from the blob, the running handle is freed,
 * and the fresh one is swapped in, so every later iteration
 * round-trips through seeds and masters that survived a blob crossing.
 * The input is the blob Init or the latest Rekey handed out, not a
 * fresh Save: that is what a receiver holds, and reopening from it
 * proves the handed-out bytes rather than the live state. The blob
 * carries the Pipeline's full shape, so no override reaches the reopen.
 * On a Load failure the running handle stays and the failure aborts the
 * run.
 */
function blob_cycle_pipes(Worker $w, int $it): bool
{
    $r = $w->run;
    if ($r->streamPipe !== null) {
        try {
            $fresh = Itb::load($r->streamBlob);
        } catch (ItbException $e) {
            worker_fail($w, \sprintf(
                'g%d iter %d: Load(%s): %s',
                $w->id,
                $it,
                $r->streamProfile,
                status_detail($e)
            ));
            return false;
        }
        $r->streamPipe->free();
        $r->streamPipe = $fresh;
    }
    if ($r->msgPipe !== null) {
        try {
            $fresh = Itb::load($r->msgBlob);
        } catch (ItbException $e) {
            worker_fail($w, \sprintf(
                'g%d iter %d: Load(%s): %s',
                $w->id,
                $it,
                $r->msgProfile,
                status_detail($e)
            ));
            return false;
        }
        $r->msgPipe->free();
        $r->msgPipe = $fresh;
    }
    $r->blobCycles++;
    log_line(\sprintf(
        'blob-cycle: g%d iter %d reopened from session blob (cycle #%d)',
        $w->id,
        $it,
        $r->blobCycles
    ));
    return true;
}

/**
 * Handle mutation. Runs the periodic Pipeline-mutating operations after
 * a completed iteration: master rotation (--rekey-every) and blob
 * reopen (--blob-cycle-every). Both intervals count per-worker
 * iterations; the warmup iteration (iter 0) never triggers because the
 * worker loop calls this for iter >= 1 only. Rekey rewrites the
 * outer-layer keying of a live handle and a blob reopen replaces the
 * handle outright. A shared-handle binding guards both with a write
 * lock so in-flight cipher calls on other workers drain before anything
 * changes; this binding runs single, so the one worker is between
 * iterations whenever either runs, there is no second caller to drain,
 * and no encrypt can be separated from its decrypt by either. Returns
 * false after recording a worker error.
 */
function worker_maintenance(Worker $w, int $it): bool
{
    $cfg = $w->run->cfg;
    if ($cfg->rekeyEvery > 0 && $it % $cfg->rekeyEvery === 0) {
        if (!rekey_pipes($w, $it)) {
            return false;
        }
    }
    if ($cfg->blobCycleEvery > 0 && $it % $cfg->blobCycleEvery === 0) {
        if (!blob_cycle_pipes($w, $it)) {
            return false;
        }
    }
    return true;
}
