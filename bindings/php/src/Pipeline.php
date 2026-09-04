<?php

declare(strict_types=1);

namespace Everanium\Itb;

/**
 * A Triple Pipeline session.
 *
 * save() returns the serialised session blob the receiver feeds to
 * Itb::load(); rekey() refreshes it. Destruction (explicit free() or
 * garbage collection via __destruct) releases the Go-side handle —
 * libitb zeroes key material internally.
 *
 * Streaming-decrypt caveat: chunked Streaming AEAD verifies per
 * chunk, so plaintext of verified chunks is released before a later
 * chunk can fail authentication.
 */
final class Pipeline
{
    /** @var int */
    private $handle;

    /**
     * Grow-only pooled output scratch shared by the string-returning
     * cipher entries, so repeated calls skip the per-call zero-init
     * FFI allocation. Released on free().
     *
     * @var \FFI\CData|null
     */
    private $scratch = null;

    /** @var int Current capacity of $scratch in bytes. */
    private $scratchCap = 0;

    /** @var \FFI\CData|null Pooled size_t out-length cell. */
    private $lenCell = null;

    /** @internal Not part of the public API — use Itb::create() / Itb::load() / Itb::loadF(). */
    public function __construct(int $handle)
    {
        $this->handle = $handle;
    }

    /**
     * The current serialised session blob — the bytes create()
     * produced, the bytes load() re-marshalled, or the bytes of the
     * latest rekey().
     */
    public function save(): string
    {
        $ffi = FFIBridge::get();
        $handle = $this->handle;
        return FFIBridge::retryOnce(
            Itb::BLOB_CAP,
            static function ($buf, int $cap, $lenPtr) use ($ffi, $handle): int {
                return $ffi->ITB_Triple_Save($handle, $buf, $cap, $lenPtr);
            }
        );
    }

    /**
     * Writes the current session blob to $path inside the library
     * (mode 0600; the containing directory must exist).
     */
    public function saveF(string $path): void
    {
        FFIBridge::check(FFIBridge::get()->ITB_Triple_SaveF($this->handle, $path));
    }

    /**
     * Sets the worker cap for every subsequent cipher call. $n is
     * clamped, never rejected: n <= 0 selects auto (runtime.NumCPU),
     * 1..256 pins the cap, larger values are treated as 256. The cap
     * is per-machine tuning and is never written to the blob.
     */
    public function maxWorkers(int $n): void
    {
        FFIBridge::check(FFIBridge::get()->ITB_Triple_MaxWorkers($this->handle, $n));
    }

    /**
     * Rotates the parallax + wrapper masters and returns the
     * refreshed session blob (also observable through save()).
     * Passing null for a master generates a fresh 32-byte CSPRNG
     * value binding-side. Must not run concurrently with cipher
     * calls or open stream sessions on the same Pipeline.
     */
    public function rekey(?string $permMaster = null, ?string $wrapMaster = null): string
    {
        $ffi = FFIBridge::get();
        $pm = $permMaster ?? \random_bytes(32);
        $wm = $wrapMaster ?? \random_bytes(32);
        $handle = $this->handle;

        return FFIBridge::retryOnce(
            Itb::BLOB_CAP,
            static function ($buf, int $cap, $lenPtr) use ($ffi, $handle, $pm, $wm): int {
                return $ffi->ITB_Triple_Rekey(
                    $handle,
                    $pm,
                    \strlen($pm),
                    $wm,
                    \strlen($wm),
                    $buf,
                    $cap,
                    $lenPtr
                );
            }
        );
    }

    /**
     * Zeroes the Pipeline's key material and marks it closed.
     * Idempotent; subsequent cipher calls throw ItbException with
     * Status::TRIPLE_CLOSED.
     */
    public function close(): void
    {
        FFIBridge::check(FFIBridge::get()->ITB_Triple_Close($this->handle));
    }

    /** Single Message encrypt: one call, one self-contained wire. */
    public function encryptMessage(string $plaintext): string
    {
        return $this->cipher('ITB_Triple_EncryptMessage', $plaintext);
    }

    /**
     * Caller-buffer variant of encryptMessage(): writes the wire into the
     * caller-owned FFI buffer $dst (at most $cap bytes) and returns
     * the number of bytes written. No output allocation happens
     * binding-side, so a caller looping over many messages can reuse
     * one buffer sized via the pre-allocation formula
     * max(131072, payload * 5/4 + 131072). An undersized buffer
     * surfaces as ItbException with Status::BUFFER_TOO_SMALL — no
     * automatic retry, since growing the buffer is the caller's call.
     *
     * @throws \InvalidArgumentException when $cap is negative or exceeds
     *         the actual size of $dst (out-of-bounds guard).
     */
    public function encryptMessageInto(string $plaintext, \FFI\CData $dst, int $cap): int
    {
        if ($cap < 0 || $cap > \FFI::sizeof($dst)) {
            throw new \InvalidArgumentException(
                "cap ($cap) out of range for destination buffer size (" . \FFI::sizeof($dst) . ')'
            );
        }
        $len = $this->lenCell();
        FFIBridge::check(FFIBridge::get()->ITB_Triple_EncryptMessage(
            $this->handle,
            $plaintext,
            \strlen($plaintext),
            $dst,
            $cap,
            \FFI::addr($len)
        ));
        return (int) $len->cdata;
    }

    /** Receive-side counterpart of encryptMessage(). */
    public function decryptMessage(string $wire): string
    {
        return $this->cipher('ITB_Triple_DecryptMessage', $wire);
    }

    /**
     * One-shot stream encrypt for callers holding the whole
     * plaintext in memory. For bounded-memory streaming use
     * encryptStream().
     */
    public function encryptStreamOneShot(string $plaintext): string
    {
        return $this->cipher('ITB_Triple_EncryptStream', $plaintext);
    }

    /** Receive-side counterpart of encryptStreamOneShot(). */
    public function decryptStreamOneShot(string $wire): string
    {
        return $this->cipher('ITB_Triple_DecryptStream', $wire);
    }

    /** Opens an incremental encrypt session (plaintext in, wire out). */
    public function encryptStream(): StreamEncryptor
    {
        return new StreamEncryptor($this, $this->handle);
    }

    /** Opens an incremental decrypt session (wire in, plaintext out). */
    public function decryptStream(): StreamDecryptor
    {
        return new StreamDecryptor($this, $this->handle);
    }

    /**
     * Releases the Pipeline handle (libitb closes and zeroes key
     * material first). Safe to call more than once.
     */
    public function free(): void
    {
        if ($this->handle === 0) {
            return;
        }
        $handle = $this->handle;
        $this->handle = 0;
        $this->scratch = null;
        $this->scratchCap = 0;
        $this->lenCell = null;
        try {
            FFIBridge::get()->ITB_Triple_Free($handle);
        } catch (ItbException $e) {
            // Library unavailable — nothing to release.
        }
    }

    public function __destruct()
    {
        $this->free();
    }

    /**
     * Shared body for the four buffer-in / buffer-out cipher entries.
     * Output goes through the Pipeline's grow-only pooled scratch
     * (skipping a fresh zero-init FFI allocation per call); the
     * returned bytes are copied out into a PHP string before the
     * next call can touch the scratch. Pre-allocation formula:
     * max(131072, payload * 5/4 + 131072); on BUFFER_TOO_SMALL with
     * a strictly larger reported length the call retries once with
     * exactly the reported size.
     */
    private function cipher(string $symbol, string $src): string
    {
        $ffi = FFIBridge::get();
        $srcLen = \strlen($src);
        $cap = max(\intdiv($srcLen * 5, 4) + 131072, 131072);
        $buf = $this->scratchBuf($cap);
        $len = $this->lenCell();
        $lenPtr = \FFI::addr($len);

        $rc = $ffi->$symbol($this->handle, $src, $srcLen, $buf, $this->scratchCap, $lenPtr);
        // Retry only when the reported length strictly exceeds the
        // current capacity.
        if ($rc === Status::BUFFER_TOO_SMALL && (int) $len->cdata > $this->scratchCap) {
            $buf = $this->scratchBuf((int) $len->cdata);
            $rc = $ffi->$symbol($this->handle, $src, $srcLen, $buf, $this->scratchCap, $lenPtr);
        }
        FFIBridge::check($rc);
        $n = (int) $len->cdata;
        return $n > 0 ? \FFI::string($buf, $n) : '';
    }

    /** Grow-only pooled output scratch of at least $cap bytes. */
    private function scratchBuf(int $cap): \FFI\CData
    {
        if ($this->scratch === null || $cap > $this->scratchCap) {
            $this->scratch = FFIBridge::get()->new("char[$cap]");
            $this->scratchCap = $cap;
        }
        return $this->scratch;
    }

    /** Pooled size_t out-length cell, allocated on first use. */
    private function lenCell(): \FFI\CData
    {
        if ($this->lenCell === null) {
            $this->lenCell = FFIBridge::get()->new('size_t');
        }
        return $this->lenCell;
    }
}
