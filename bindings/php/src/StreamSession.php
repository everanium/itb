<?php

declare(strict_types=1);

namespace Everanium\Itb;

/**
 * Shared body for the two incremental stream session directions.
 *
 * A session is a dumb byte pump: StreamEncryptor takes plaintext in
 * through write() and yields wire through read() / drainAll();
 * StreamDecryptor is the mirror (wire in, plaintext out). All
 * chunking, MAC, envelope, and wire-format decisions stay inside
 * libitb. Destruction (explicit free() or garbage collection via
 * __destruct) cancels the session and frees the Go-side state.
 *
 * @internal Base class — use Pipeline::encryptStream() /
 *           Pipeline::decryptStream().
 */
abstract class StreamSession
{
    /** Overridden per direction with the Begin symbol name. */
    protected const BEGIN = '';

    /** Default drain slice size for read() / drainAll(). */
    public const READ_BUF = 1048576;

    /**
     * Pin the parent Pipeline via a PHP reference so it cannot be
     * garbage-collected (and its Go-side handle freed) while this
     * session is still live. The Go handle registry would degrade a
     * stale-pipe StreamWrite / StreamRead to a bad-handle status,
     * but the nondeterminism is a correctness trap for a caller that
     * lets the parent go out of scope.
     *
     * @var Pipeline
     */
    private $parent;

    /** @var int */
    private $handle = 0;

    /** @var bool */
    private $ended = false;

    /** @var bool */
    private $finished = false;

    /**
     * Grow-only pooled read buffer backing read(), so repeated drain
     * slices skip the per-call zero-init FFI allocation. Released on
     * free().
     *
     * @var \FFI\CData|null
     */
    private $readBuf = null;

    /** @var int Current capacity of $readBuf in bytes. */
    private $readCap = 0;

    /** @var \FFI\CData|null Pooled size_t out-length cell. */
    private $lenCell = null;

    /** @var \FFI\CData|null Pooled int finished-flag cell. */
    private $finCell = null;

    /** @internal Not part of the public API. */
    public function __construct(Pipeline $parent, int $pipeHandle)
    {
        $this->parent = $parent;
        $ffi = FFIBridge::get();
        $handle = $ffi->new('uintptr_t');
        $begin = static::BEGIN;
        FFIBridge::check($ffi->$begin($pipeHandle, \FFI::addr($handle)));
        $this->handle = (int) $handle->cdata;
    }

    /**
     * Feeds $src into the session. Blocks until the cipher chain
     * accepts the bytes; errors are sticky.
     */
    public function write(string $src): void
    {
        FFIBridge::check(
            FFIBridge::get()->ITB_Triple_StreamWrite($this->handle, $src, \strlen($src))
        );
    }

    /**
     * Signals end-of-input. Idempotent; write() after end() fails
     * with Status::BAD_INPUT.
     */
    public function end(): void
    {
        FFIBridge::check(FFIBridge::get()->ITB_Triple_StreamEnd($this->handle));
        $this->ended = true;
    }

    /**
     * Drains up to $maxBytes produced bytes; '' means nothing is
     * available right now. Partial drains are normal; isFinished()
     * reports whether the session has produced its final byte. After
     * end(), an empty-spool read blocks until the terminal bytes
     * arrive or the session errors.
     */
    public function read(int $maxBytes = self::READ_BUF): string
    {
        if ($this->readBuf === null || $maxBytes > $this->readCap) {
            $this->readBuf = FFIBridge::get()->new("char[$maxBytes]");
            $this->readCap = $maxBytes;
        }
        [$n] = $this->readInto($this->readBuf, $maxBytes);
        return $n > 0 ? \FFI::string($this->readBuf, $n) : '';
    }

    /**
     * Caller-buffer variant of read(): drains up to $cap produced bytes
     * into the caller-owned FFI buffer $buf and returns a
     * [$bytesWritten, $finished] pair. No output allocation happens
     * binding-side, so a caller looping to exhaustion can reuse one
     * buffer for the whole drain. $bytesWritten of 0 means nothing is
     * available right now; $finished mirrors isFinished().
     *
     * @return array{0: int, 1: bool}
     *
     * @throws \InvalidArgumentException when $cap is negative or exceeds
     *         the actual size of $buf (out-of-bounds guard).
     */
    public function readInto(\FFI\CData $buf, int $cap): array
    {
        if ($cap < 0 || $cap > \FFI::sizeof($buf)) {
            throw new \InvalidArgumentException(
                "cap ($cap) out of range for destination buffer size (" . \FFI::sizeof($buf) . ')'
            );
        }
        $ffi = FFIBridge::get();
        if ($this->lenCell === null) {
            $this->lenCell = $ffi->new('size_t');
            $this->finCell = $ffi->new('int');
        }
        FFIBridge::check($ffi->ITB_Triple_StreamRead(
            $this->handle,
            $buf,
            $cap,
            \FFI::addr($this->lenCell),
            \FFI::addr($this->finCell)
        ));
        if ((int) $this->finCell->cdata !== 0) {
            $this->finished = true;
        }
        return [(int) $this->lenCell->cdata, $this->finished];
    }

    /** Whether the session has produced its final output byte. */
    public function isFinished(): bool
    {
        return $this->finished;
    }

    /**
     * Calls end() (if not yet called) and returns every remaining
     * output byte.
     */
    public function drainAll(): string
    {
        if (!$this->ended) {
            $this->end();
        }
        $out = '';
        while (!$this->finished) {
            $out .= $this->read();
        }
        return $out;
    }

    /**
     * Cancels (if still running) and releases the session. Safe to
     * call from any state and more than once.
     */
    public function free(): void
    {
        if ($this->handle === 0) {
            return;
        }
        $handle = $this->handle;
        $this->handle = 0;
        $this->readBuf = null;
        $this->readCap = 0;
        $this->lenCell = null;
        $this->finCell = null;
        try {
            FFIBridge::get()->ITB_Triple_StreamFree($handle);
        } catch (ItbException $e) {
            // Library unavailable — nothing to release.
        }
    }

    public function __destruct()
    {
        $this->free();
    }
}
